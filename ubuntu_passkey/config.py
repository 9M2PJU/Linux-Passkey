"""User configuration (~/.config/ubuntu-passkey/config.json)."""

import json
import os
import threading

from . import paths

DEFAULTS = {
    # Ask for system authentication (password / fingerprint) on every use,
    # even when the website does not request user verification.
    "always_verify": False,
    # How user verification is performed: "polkit" or "none".
    "verification": "polkit",
    # Seconds to wait for the user to answer an approval prompt.
    "approval_timeout": 30,
    # Algorithms offered to websites, in order of preference.
    "algorithms": ["ES256", "EdDSA"],
}

VALIDATORS = {
    "always_verify": lambda v: isinstance(v, bool),
    "verification": lambda v: v in ("polkit", "none"),
    "approval_timeout": lambda v: isinstance(v, int) and 5 <= v <= 300,
    "algorithms": lambda v: isinstance(v, list)
    and v
    and all(a in ("ES256", "EdDSA") for a in v),
}


class Config:
    def __init__(self, path=None):
        self.path = path or os.path.join(paths.config_dir(), "config.json")
        self._lock = threading.Lock()
        self._values = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        with self._lock:
            for key, value in data.items():
                if key in VALIDATORS and VALIDATORS[key](value):
                    self._values[key] = value

    def get(self, key):
        with self._lock:
            return self._values[key]

    def as_dict(self):
        with self._lock:
            return dict(self._values)

    def override(self, key, value):
        """Change a value for this run only, without saving it."""
        with self._lock:
            self._values[key] = value

    def set(self, key, value):
        if key not in VALIDATORS:
            raise KeyError(key)
        if not VALIDATORS[key](value):
            raise ValueError("invalid value for %s: %r" % (key, value))
        with self._lock:
            self._values[key] = value
            data = dict(self._values)
        paths.atomic_write(self.path, json.dumps(data, indent=2).encode())
