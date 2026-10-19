import hashlib
import os

import pytest

from ubuntu_passkey import keys
from ubuntu_passkey.masterkey import MasterKeyError, MasterKeyManager
from ubuntu_passkey.store import CredentialStore

RP_HASH = hashlib.sha256(b"example.com").digest()


def test_wrapped_credential_roundtrip(store):
    cred_id, key = store.create(RP_HASH, keys.ES256, resident=False)
    cred = store.lookup(RP_HASH, cred_id)
    assert cred is not None and not cred.resident
    assert keys.cose_public_key(keys.ES256, cred.private_key) == keys.cose_public_key(
        keys.ES256, key
    )
    # Bound to the relying party and to the master key.
    assert store.lookup(hashlib.sha256(b"other.com").digest(), cred_id) is None
    tampered = cred_id[:-1] + bytes([cred_id[-1] ^ 1])
    assert store.lookup(RP_HASH, tampered) is None


def test_persistence_and_encryption(env, master_key):
    store = CredentialStore(master_key)
    cred_id, _ = store.create(RP_HASH, keys.EDDSA, resident=True)
    store.add_resident(cred_id, {"id": "example.com"}, {"id": b"u1", "name": "secret-name"}, keys.EDDSA, 1)
    store.next_counter()

    raw = open(store.path, "rb").read()
    assert b"secret-name" not in raw and b"example.com" not in raw
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"

    again = CredentialStore(master_key)
    assert [r["user_name"] for r in again.residents_for("example.com")] == ["secret-name"]
    assert again.next_counter() == 2
    assert again.lookup(RP_HASH, cred_id).resident

    with pytest.raises(ValueError):
        CredentialStore(os.urandom(32))


def test_same_account_replaces_old_passkey(store):
    first, _ = store.create(RP_HASH, keys.ES256, True)
    store.add_resident(first, {"id": "example.com"}, {"id": b"u"}, keys.ES256, 1)
    second, _ = store.create(RP_HASH, keys.ES256, True)
    store.add_resident(second, {"id": "example.com"}, {"id": b"u"}, keys.ES256, 1)
    assert len(store.list()) == 1
    assert store.lookup(RP_HASH, first) is None
    assert store.lookup(RP_HASH, second) is not None


def test_reset_invalidates_everything(store):
    cred_id, _ = store.create(RP_HASH, keys.ES256, False)
    store.reset(os.urandom(32))
    assert store.lookup(RP_HASH, cred_id) is None


def test_master_key_file_backend(env):
    mgr = MasterKeyManager(prefer="file")
    key = mgr.get()
    assert len(key) == 32 and mgr.get() == key
    assert mgr.backend_name == "file"
    assert MasterKeyManager(prefer="auto").get() == key  # recorded backend wins
    assert mgr.rotate() != key


def test_master_key_never_silently_regenerated(env):
    mgr = MasterKeyManager(prefer="file")
    mgr.get()
    os.unlink(mgr._file.path)
    with pytest.raises(MasterKeyError):
        mgr.get()


def test_keyring_marker_without_keyring_fails(env, monkeypatch):
    mgr = MasterKeyManager(prefer="file")
    os.makedirs(mgr.directory, exist_ok=True)
    with open(mgr.marker, "w") as f:
        f.write("keyring\n")
    monkeypatch.setattr(
        "ubuntu_passkey.masterkey.SecretServiceBackend.available", lambda self: False
    )
    with pytest.raises(MasterKeyError):
        mgr.get()
