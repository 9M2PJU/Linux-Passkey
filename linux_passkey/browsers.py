"""Registers the native messaging host with the user's browsers.

Browsers look for native messaging host manifests in per-user folders. The
daemon writes ours into the folder of every browser that has a profile here
each time it starts, so the browser extension finds passkeyd without any
setup, whichever way Linux Passkey was installed (package, snap, source).
"""

import json
import logging
import os

from . import paths

log = logging.getLogger(__name__)

HOST_NAME = "io.github.haythmkenway.passkey"
CHROMIUM_EXTENSION_IDS = ["inchejkdadnaiiohleldjcchpebjnbnh"]
FIREFOX_EXTENSION_ID = "linux-passkey@haythmkenway.github.io"

# Chromium-based browsers: their folder under ~/.config.
CHROMIUM_BROWSERS = (
    "google-chrome",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "BraveSoftware/Brave-Browser",
    "BraveSoftware/Brave-Browser-Beta",
    "BraveSoftware/Brave-Browser-Nightly",
    "microsoft-edge",
    "microsoft-edge-beta",
    "microsoft-edge-dev",
    "vivaldi",
    "vivaldi-snapshot",
)
# Firefox-based browsers: their folder under the home directory, and where
# their profiles.ini shows the browser has been used. The snap Firefox
# reaches hosts through the WebExtensions portal, which reads
# ~/.mozilla/native-messaging-hosts.
FIREFOX_BROWSERS = {
    ".mozilla": (".mozilla/firefox", "snap/firefox/common/.mozilla/firefox"),
    ".librewolf": (".librewolf",),
    ".floorp": (".floorp",),
    ".waterfox": (".waterfox",),
    ".zen": (".zen",),
}


def manifests(host_path):
    chromium = {
        "name": HOST_NAME,
        "description": "Linux Passkey",
        "path": host_path,
        "type": "stdio",
        "allowed_origins": ["chrome-extension://%s/" % i for i in CHROMIUM_EXTENSION_IDS],
    }
    firefox = {
        "name": HOST_NAME,
        "description": "Linux Passkey",
        "path": host_path,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    }
    return chromium, firefox


def host_folders(home=None):
    """Yield (folder, kind) for each browser installed for this user."""
    if home is None and os.environ.get("SNAP_REAL_HOME"):
        # In a snap, HOME and XDG_CONFIG_HOME are the snap's own folders; the
        # browsers read the user's real ones (the personal-files plug).
        home = os.environ["SNAP_REAL_HOME"]
        config = os.path.join(home, ".config")
    else:
        home = home or os.path.expanduser("~")
        config = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    # A real profile, not just the folder: other tools, and snapd for a
    # personal-files plug, create the host folders of browsers never used.
    for name in CHROMIUM_BROWSERS:
        if os.path.isfile(os.path.join(config, name, "Local State")):
            yield os.path.join(config, name, "NativeMessagingHosts"), "chromium"
    for name, profiles in FIREFOX_BROWSERS.items():
        if any(os.path.isfile(os.path.join(home, p, "profiles.ini")) for p in profiles):
            yield os.path.join(home, name, "native-messaging-hosts"), "firefox"


def register(host_path, home=None):
    """Write the host manifest for every browser found; return the paths written."""
    chromium, firefox = manifests(host_path)
    written = []
    for folder, kind in host_folders(home):
        path = os.path.join(folder, HOST_NAME + ".json")
        data = json.dumps(chromium if kind == "chromium" else firefox, indent=2).encode() + b"\n"
        try:
            with open(path, "rb") as f:
                if f.read() == data:
                    continue
        except OSError:
            pass
        try:
            paths.atomic_write(path, data, mode=0o644)
        except OSError as e:
            log.warning("cannot register the browser extension host in %s: %s", folder, e)
            continue
        written.append(path)
    if written:
        log.info("registered the browser extension host for %d browser(s)", len(written))
    return written
