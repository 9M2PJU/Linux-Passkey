"""Linux Passkey: a software FIDO2 / WebAuthn authenticator for Linux."""

__version__ = "0.1.0"

APP_ID = "io.github.haythmkenway.Passkey"
# The app itself owns APP_ID on the session bus (GApplication), so the
# daemon uses its own name.
DBUS_NAME = APP_ID + ".Daemon"
DBUS_PATH = "/io/github/haythmkenway/Passkey/Daemon"
DBUS_INTERFACE = "io.github.haythmkenway.Passkey1"
