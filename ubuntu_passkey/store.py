"""Credential storage.

Every credential ID is self-contained: it carries the credential's private
key encrypted (AES-256-GCM) under a key derived from the master key, bound to
the relying party's ID hash. This is the same "key wrapping" approach used by
hardware security keys and allows an unlimited number of non-discoverable
credentials.

Discoverable credentials (passkeys) additionally have a metadata record
(relying party, user handle, account name, ...) in an encrypted file so that
they can be found without an allow list, listed and deleted. A wrapped
credential marked as discoverable is only honoured while its record exists,
so deleting a passkey really revokes it.
"""

import base64
import json
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import cbor, keys, paths

CRED_ID_VERSION = 1
STORE_VERSION = 1


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive(master, info):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(master)


class Credential:
    """A credential recovered from its ID (and its record, if discoverable)."""

    __slots__ = (
        "id", "alg", "private_key", "resident", "cred_protect", "hmac_seed", "record"
    )

    def __init__(self, cred_id, alg, private_key, resident, cred_protect, hmac_seed,
                 record):
        self.id = cred_id
        self.hmac_seed = hmac_seed
        self.alg = alg
        self.private_key = private_key
        self.resident = resident
        self.cred_protect = cred_protect
        self.record = record


class CredentialStore:
    def __init__(self, master_key, directory=None):
        self.directory = directory or paths.data_dir()
        self.path = os.path.join(self.directory, "credentials.enc")
        self._lock = threading.RLock()
        self._listeners = []
        self._set_master(master_key)
        self._load()

    # -- keys -------------------------------------------------------------

    def _set_master(self, master_key):
        self._wrap = AESGCM(_derive(master_key, b"ubuntu-passkey credential wrap"))
        self._seal = AESGCM(_derive(master_key, b"ubuntu-passkey store"))

    # -- persistence ------------------------------------------------------

    def _load(self):
        self._records = {}
        self._counter = 0
        try:
            with open(self.path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return
        if len(blob) < 13 or blob[0] != STORE_VERSION:
            raise ValueError("unsupported credential store format")
        try:
            plain = self._seal.decrypt(blob[1:13], blob[13:], blob[:1])
        except InvalidTag:
            raise ValueError(
                "credential store cannot be decrypted with the current master key"
            )
        data = json.loads(plain)
        self._counter = int(data.get("counter", 0))
        for rec in data.get("credentials", []):
            self._records[rec["id"]] = rec

    def _save(self):
        data = {
            "counter": self._counter,
            "credentials": sorted(self._records.values(), key=lambda r: r["created"]),
        }
        nonce = os.urandom(12)
        header = bytes([STORE_VERSION])
        blob = header + nonce + self._seal.encrypt(
            nonce, json.dumps(data).encode(), header
        )
        paths.atomic_write(self.path, blob)
        for listener in list(self._listeners):
            listener()

    def add_listener(self, callback):
        self._listeners.append(callback)

    # -- credential IDs ---------------------------------------------------

    def create(self, rp_id_hash, alg, resident, cred_protect=1):
        """Generate a key pair; return (credential_id, private_key)."""
        private_key = keys.generate(alg)
        payload = cbor.encode(
            {
                1: alg,
                2: keys.private_bytes(alg, private_key),
                3: bool(resident),
                4: cred_protect,
                5: os.urandom(32),  # hmac-secret CredRandom seed
            }
        )
        nonce = os.urandom(12)
        header = bytes([CRED_ID_VERSION])
        cred_id = header + nonce + self._wrap.encrypt(
            nonce, payload, header + rp_id_hash
        )
        return cred_id, private_key

    def lookup(self, rp_id_hash, cred_id):
        """Return the Credential for ``cred_id`` or None if it is not ours."""
        if len(cred_id) < 1 + 12 + 16 or cred_id[0] != CRED_ID_VERSION:
            return None
        try:
            payload = cbor.decode(
                self._wrap.decrypt(
                    cred_id[1:13], cred_id[13:], cred_id[:1] + rp_id_hash
                )
            )
            alg, raw, resident = payload[1], payload[2], payload[3]
            cred_protect = payload.get(4, 1)
            hmac_seed = payload.get(5)
            private_key = keys.load(alg, raw)
        except (InvalidTag, cbor.CBORError, KeyError, TypeError, ValueError):
            return None
        record = None
        if resident:
            with self._lock:
                record = self._records.get(b64e(cred_id))
            if record is None:
                return None  # deleted passkey
        return Credential(
            cred_id, alg, private_key, resident, cred_protect, hmac_seed, record
        )

    # -- discoverable credentials ----------------------------------------

    def add_resident(self, cred_id, rp, user, alg, cred_protect):
        now = int(time.time())
        rec = {
            "id": b64e(cred_id),
            "rp_id": rp["id"],
            "rp_name": rp.get("name") or rp["id"],
            "user_id": b64e(user["id"]),
            "user_name": user.get("name") or "",
            "display_name": user.get("displayName") or "",
            "alg": alg,
            "cred_protect": cred_protect,
            "created": now,
            "last_used": None,
            "use_count": 0,
        }
        with self._lock:
            # A new credential for the same account replaces the old one.
            for key, old in list(self._records.items()):
                if old["rp_id"] == rec["rp_id"] and old["user_id"] == rec["user_id"]:
                    del self._records[key]
            self._records[rec["id"]] = rec
            self._save()
        return rec

    def residents_for(self, rp_id):
        with self._lock:
            recs = [dict(r) for r in self._records.values() if r["rp_id"] == rp_id]
        # Most recently used/created first.
        recs.sort(key=lambda r: (r["last_used"] or 0, r["created"]), reverse=True)
        return recs

    def list(self):
        with self._lock:
            return [dict(r) for r in self._records.values()]

    def delete(self, cred_id_b64):
        with self._lock:
            if self._records.pop(cred_id_b64, None) is None:
                return False
            self._save()
            return True

    def mark_used(self, cred_id):
        with self._lock:
            rec = self._records.get(b64e(cred_id))
            if rec is not None:
                rec["last_used"] = int(time.time())
                rec["use_count"] = rec.get("use_count", 0) + 1
                self._save()

    def next_counter(self):
        with self._lock:
            self._counter += 1
            self._save()
            return self._counter

    def reset(self, new_master_key):
        """Forget every credential and switch to a new master key."""
        with self._lock:
            self._set_master(new_master_key)
            self._records = {}
            self._counter = 0
            self._save()
