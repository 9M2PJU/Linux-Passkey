"""passkeyd: the Ubuntu Passkey authenticator daemon."""

import argparse
import logging
import signal
import sys

import gi

gi.require_version("Gio", "2.0")
from gi.repository import GLib  # noqa: E402

from . import __version__  # noqa: E402
from .broker import ApprovalBroker  # noqa: E402
from .config import Config  # noqa: E402
from .ctap2 import Authenticator  # noqa: E402
from .ctaphid import CtapHidDevice  # noqa: E402
from .masterkey import MasterKeyError, MasterKeyManager  # noqa: E402
from .service import PasskeyService  # noqa: E402
from .store import CredentialStore  # noqa: E402
from .uhid import UHID_PATH, UhidDevice, UhidError  # noqa: E402
from .verify import NoVerifier, PolkitVerifier  # noqa: E402

log = logging.getLogger("passkeyd")


class Daemon:
    def __init__(self, uhid_path=UHID_PATH, key_backend="auto", usb_id=None):
        self.config = Config()
        self.keys = MasterKeyManager(prefer=key_backend)
        self.store = CredentialStore(self.keys.get())
        verifier = PolkitVerifier()
        if self.config.get("verification") == "polkit" and not verifier.available():
            log.warning("pkcheck is missing; user verification is unavailable")
            verifier = NoVerifier()
            self.config.override("verification", "none")
        self.broker = ApprovalBroker(self.config, verifier)
        self.authenticator = Authenticator(
            self.store, self.broker, self.config, on_reset=self.reset
        )
        self.hid = CtapHidDevice(self.authenticator, self._send_report)
        self.device = UhidDevice(self.hid.handle_report, path=uhid_path, usb_id=usb_id)
        self.device_error = ""
        self.loop = None
        self.service = PasskeyService(self)
        self.store.add_listener(lambda: self.service.emit("CredentialsChanged"))
        self.device.on_state = lambda opened: self.service.emit("StatusChanged")

    def _send_report(self, report):
        self.device.send(report)

    def reset(self):
        self.store.reset(self.keys.rotate())

    def status(self):
        return {
            "version": __version__,
            "device_active": self.device_error == "",
            "device_open": self.device.opened,
            "device_error": self.device_error,
            "credential_count": len(self.store.list()),
            "agent_count": self.broker.agent_count,
            "verification": self.config.get("verification"),
            "key_backend": self.keys.backend_name,
        }

    def run(self):
        self.loop = loop = GLib.MainLoop()

        def name_lost():
            log.error("another passkey daemon is already running")
            loop.quit()

        self.service.own_name(name_lost)
        try:
            self.device.start()
        except (UhidError, OSError) as e:
            self.device_error = e.strerror or str(e)
            log.error("cannot create the virtual security key: %s", e)

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
        prog="passkeyd", description="Ubuntu Passkey authenticator daemon"
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
    try:
        daemon = Daemon(
            uhid_path=args.uhid, key_backend=args.key_backend, usb_id=args.usb_id
        )
    except (MasterKeyError, ValueError) as e:
        log.error("%s", e)
        return 1
    daemon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
