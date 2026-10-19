"""Storage of the 256-bit master key that protects every credential.

The key lives in the user's login keyring (GNOME Keyring via the Secret
Service API) when one is available, otherwise in a 0600 file inside the data
directory. The chosen backend is recorded so that a temporarily unavailable
keyring never causes a new key to be generated, which would orphan every
existing passkey.
"""

import base64
import logging
import os

from . import paths

log = logging.getLogger(__name__)

KEY_SIZE = 32
SCHEMA_NAME = "io.github.haythmkenway.Passkey.MasterKey"


def schema_name():
    """The keyring schema for this installation.

    The snap keeps its passkeys apart from a package install's, and the two
    share one login keyring, so each needs its own item: storing a key
    replaces any item with the same schema and attributes.
    """
    if os.environ.get("SNAP"):
        return SCHEMA_NAME + ".Snap"
    return SCHEMA_NAME


class MasterKeyError(RuntimeError):
    pass


class FileBackend:
    name = "file"

    def __init__(self, directory):
        self.path = os.path.join(directory, "master.key")

    def available(self):
        return True

    def load(self):
        try:
            with open(self.path, "rb") as f:
                raw = base64.b64decode(f.read().strip())
        except FileNotFoundError:
            return None
        if len(raw) != KEY_SIZE:
            raise MasterKeyError("corrupt master key file %s" % self.path)
        return raw

    def save(self, key):
        paths.atomic_write(self.path, base64.b64encode(key) + b"\n")


class SecretServiceBackend:
    name = "keyring"

    def __init__(self):
        self._secret = None
        self._schema = None
        try:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            self._secret = Secret
            self._schema = Secret.Schema.new(
                schema_name(),
                Secret.SchemaFlags.NONE,
                {"purpose": Secret.SchemaAttributeType.STRING},
            )
        except (ImportError, ValueError) as e:
            log.debug("libsecret unavailable: %s", e)

    def available(self):
        if self._secret is None:
            return False
        try:
            self._secret.Service.get_sync(self._secret.ServiceFlags.NONE, None)
            return True
        except Exception as e:  # GLib.Error when no Secret Service is running
            log.debug("Secret Service unavailable: %s", e)
            return False

    def load(self):
        try:
            value = self._secret.password_lookup_sync(
                self._schema, {"purpose": "master-key"}, None
            )
        except Exception as e:
            raise MasterKeyError("cannot read master key from keyring: %s" % e)
        if value is None:
            return None
        raw = base64.b64decode(value)
        if len(raw) != KEY_SIZE:
            raise MasterKeyError("corrupt master key in keyring")
        return raw

    def save(self, key):
        try:
            ok = self._secret.password_store_sync(
                self._schema,
                {"purpose": "master-key"},
                self._secret.COLLECTION_DEFAULT,
                "Linux Passkey master key",
                base64.b64encode(key).decode(),
                None,
            )
        except Exception as e:
            raise MasterKeyError("cannot store master key in keyring: %s" % e)
        if not ok:
            raise MasterKeyError("keyring refused to store the master key")


class MasterKeyManager:
    def __init__(self, directory=None, prefer="auto"):
        self.directory = directory or paths.data_dir()
        self.marker = os.path.join(self.directory, "key-backend")
        self.prefer = prefer
        self._file = FileBackend(self.directory)
        self._keyring = None

    def _keyring_backend(self):
        if self._keyring is None:
            self._keyring = SecretServiceBackend()
        return self._keyring

    def _recorded_backend(self):
        try:
            with open(self.marker, encoding="utf-8") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

    def _backend(self):
        recorded = self._recorded_backend()
        if recorded == "file":
            return self._file
        if recorded == "keyring":
            backend = self._keyring_backend()
            if not backend.available():
                raise MasterKeyError(
                    "the master key is stored in the login keyring, "
                    "but the keyring is not available"
                )
            return backend
        if self.prefer != "file":
            backend = self._keyring_backend()
            if backend.available():
                return backend
            if self.prefer == "keyring":
                raise MasterKeyError("no Secret Service keyring available")
        return self._file

    def get(self):
        """Return the master key, creating it on first use."""
        backend = self._backend()
        key = backend.load()
        if key is None:
            if self._recorded_backend() is not None:
                raise MasterKeyError(
                    "master key missing from %s backend" % backend.name
                )
            key = os.urandom(KEY_SIZE)
            backend.save(key)
            paths.atomic_write(self.marker, backend.name.encode() + b"\n")
            log.info("created new master key in %s backend", backend.name)
        return key

    def rotate(self):
        """Replace the master key; every existing credential becomes unusable."""
        backend = self._backend()
        key = os.urandom(KEY_SIZE)
        backend.save(key)
        paths.atomic_write(self.marker, backend.name.encode() + b"\n")
        return key

    @property
    def backend_name(self):
        return self._recorded_backend() or "unset"
