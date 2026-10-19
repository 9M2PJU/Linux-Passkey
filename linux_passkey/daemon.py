"""passkeyd: the Linux Passkey authenticator daemon."""

import argparse
import logging
import os
import signal
import sys
import threading
import time

import gi

gi.require_version("Gio", "2.0")
from gi.repository import GLib  # noqa: E402

from . import __version__, browsers  # noqa: E402
from .broker import ApprovalBroker  # noqa: E402
from .config import Config  # noqa: E402
from .ctap2 import ERR_NOT_ALLOWED, Authenticator  # noqa: E402
from .ctaphid import CtapHidDevice  # noqa: E402
from .masterkey import MasterKeyError, MasterKeyManager  # noqa: E402
from .service import PasskeyService  # noqa: E402
from .store import CredentialStore  # noqa: E402
from .uhid import UHID_PATH, UhidDevice, UhidError  # noqa: E402
from .verify import NoVerifier, PolkitVerifier  # noqa: E402

log = logging.getLogger("passkeyd")


class Daemon:
    """Owns the credential store, the authenticator and the virtual device.

    Problems opening the store (a locked or missing keyring, a damaged file)
    do not stop the daemon: it stays on the bus, reports the error through
    GetStatus, retries periodically and can be reset from the Passkeys app.
    """

    RETRY_SECONDS = 30

    def __init__(self, uhid_path=UHID_PATH, key_backend="auto", usb_id=None):
        self.config = Config()
        self.keys = MasterKeyManager(prefer=key_backend)
        self.store = None
        self.store_error = ""
        self.authenticator = None
        verifier = PolkitVerifier()
        if self.config.get("verification") == "polkit" and not verifier.available():
            log.warning("pkcheck is missing; user verification is unavailable")
            verifier = NoVerifier()
            self.config.override("verification", "none")
        self.broker = ApprovalBroker(self.config, verifier)
        self.hid = CtapHidDevice(self, self._send_report)
        self.device = UhidDevice(self.hid.handle_report, path=uhid_path, usb_id=usb_id)
        self.device_error = ""
        self.loop = None
        self._lock = threading.Lock()
        self._retry_id = 0
        self.service = PasskeyService(self)
        self.device.on_state = lambda opened: self.service.emit("StatusChanged")

    # -- storage ----------------------------------------------------------

    def open_store(self):
        """Open the credential store on a worker thread (keyring access may
        block on an unlock prompt)."""

        def work():
            try:
                store, error = CredentialStore(self.keys.get()), ""
            except (MasterKeyError, ValueError, OSError) as e:
                store, error = None, str(e)
            GLib.idle_add(self._store_opened, store, error)

        threading.Thread(target=work, name="open-store", daemon=True).start()

    def _store_opened(self, store, error):
        if store is not None:
            self._attach(store)
        else:
            self.store_error = error
            log.error("passkey storage unavailable: %s", error)
            if not self._retry_id:
                self._retry_id = GLib.timeout_add_seconds(self.RETRY_SECONDS, self._retry)
        self.service.emit("StatusChanged")
        return False

    def _retry(self):
        self._retry_id = 0
        if self.store is None:
            self.open_store()
        return False

    def retry(self):
        if self.store is None:
            self.open_store()

    def _attach(self, store):
        with self._lock:
            self.store = store
            self.store_error = ""
            self.authenticator = Authenticator(
                store, self.broker, self.config, on_reset=self.reset
            )
        store.add_listener(lambda: self.service.emit("CredentialsChanged"))
        self.service.emit("CredentialsChanged")
        try:
            self.device.start()
            self.device_error = ""
        except (UhidError, OSError) as e:
            self.device_error = e.strerror or str(e)
            log.error("cannot create the virtual security key: %s", e)

    def require_store(self):
        store = self.store
        if store is None:
            raise RuntimeError("passkey storage is unavailable: %s" % self.store_error)
        return store

    def reset(self):
        """Delete every passkey and replace the master key."""
        key = self.keys.rotate()
        if self.store is not None:
            self.store.reset(key)
            return
        # The old store could not be opened: keep it aside instead of
        # deleting it, in case the old key turns up again.
        path = CredentialStore.default_path()
        if os.path.exists(path):
            aside = "%s.unreadable-%d" % (path, int(time.time()))
            os.replace(path, aside)
            log.warning("moved unreadable credential store to %s", aside)
        store = CredentialStore(key)
        GLib.idle_add(lambda: self._store_opened(store, "") and False)

    # -- authenticator interface used by CtapHidDevice ---------------------

    def process(self, data, request=None):
        authenticator = self.authenticator
        if authenticator is None:
            return bytes([ERR_NOT_ALLOWED])
        return authenticator.process(data, request)

    def _send_report(self, report):
        self.device.send(report)

    def status(self):
        store = self.store
        if store is not None:
            state = "ready"
        elif self.store_error:
            state = "error"
        else:
            state = "starting"
        return {
            "version": __version__,
            "state": state,
            "error": self.store_error,
            "device_active": store is not None and self.device_error == "",
            "device_open": self.device.opened,
            "device_error": self.device_error,
            "credential_count": len(store.list()) if store is not None else 0,
            "agent_count": self.broker.agent_count,
            "verification": self.config.get("verification"),
            "key_backend": self.keys.backend_name,
        }

    def register_browsers(self):
        """Point the browsers' extension at our native messaging host."""
        host = os.environ.get("PASSKEY_NATIVE_HOST", "")
        # A snap's /snap/bin command is outside its confinement view.
        if not host or (not os.environ.get("SNAP") and not os.access(host, os.X_OK)):
            log.info("no native messaging host installed; the browser extension is unavailable")
            return
        try:
            browsers.register(host)
        except OSError as e:
            log.warning("cannot register the browser extension host: %s", e)

    def run(self):
        self.loop = loop = GLib.MainLoop()

        def name_lost():
            log.error("another passkey daemon is already running")
            loop.quit()

        self.service.own_name(name_lost)
        self.open_store()
        self.register_browsers()
        for signum in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, loop.quit)
        loop.run()
        self.service.close()
        self.device.stop()


def _usb_id(text):
    try:
        vid, pid = text.split(":")
        return int(vid, 16), int(pid, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("expected VID:PID in hexadecimal")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="passkeyd", description="Linux Passkey authenticator daemon"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--uhid", default=UHID_PATH, help="path to the uhid device")
    parser.add_argument(
        "--key-backend",
        choices=("auto", "keyring", "file"),
        default="auto",
        help="where to keep the master key (default: keyring if available)",
    )
    parser.add_argument(
        "--usb-id",
        type=_usb_id,
        metavar="VID:PID",
        help="USB vendor and product ID reported by the virtual key (hex)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    daemon = Daemon(uhid_path=args.uhid, key_backend=args.key_backend, usb_id=args.usb_id)
    daemon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
