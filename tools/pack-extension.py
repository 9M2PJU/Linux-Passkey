#!/usr/bin/python3
"""Build the browser extension zips for the Chrome Web Store and addons.mozilla.org.

The source manifest serves both families for unpacked development; each
store gets only the keys it accepts:
  * Chromium: no "key" (the store assigns the ID), no Firefox settings, a
    service worker background;
  * Firefox: no "key", no Chrome-only fields, background scripts.
"""

import json
import os
import sys
import zipfile

SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "browser-extension")
FILES = ("background.js", "bridge.js", "page.js", "icon-128.png")


def manifests():
    with open(os.path.join(SOURCE, "manifest.json"), encoding="utf-8") as f:
        base = json.load(f)
    base.pop("key", None)
    chromium = dict(base)
    chromium.pop("browser_specific_settings", None)
    chromium["background"] = {"service_worker": base["background"]["service_worker"]}
    firefox = dict(base)
    firefox.pop("minimum_chrome_version", None)
    firefox["background"] = {"scripts": base["background"]["scripts"]}
    return {"chromium": chromium, "firefox": firefox}


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for name, manifest in manifests().items():
        path = os.path.join(out_dir, "linux-passkey-%s-%s.zip" % (name, manifest["version"]))
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
            for f in FILES:
                z.write(os.path.join(SOURCE, f), f)
        print("Built %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))
