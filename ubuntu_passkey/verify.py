"""User verification through polkit.

polkit shows the desktop's authentication dialog (GNOME Shell's own prompt),
which accepts the account password or, when enabled with
``pam-auth-update``, a fingerprint.
"""

import logging
import os
import shutil
import subprocess
import time

from .ctap2 import Cancelled, Timeout

log = logging.getLogger(__name__)

ACTION_ID = "io.github.haythmkenway.passkey.verify"


class PolkitVerifier:
    def __init__(self, timeout=60, action_id=ACTION_ID):
        self.timeout = timeout
        self.action_id = action_id

    def available(self):
        return shutil.which("pkcheck") is not None

    def verify(self, cancel):
        """Run the polkit prompt; return True on success.

        Raises Cancelled if ``cancel`` is set while waiting, Timeout on timeout.
        """
        pkcheck = shutil.which("pkcheck")
        if pkcheck is None:
            log.error("pkcheck not found; cannot verify the user")
            return False
        cmd = [
            pkcheck,
            "--action-id",
            self.action_id,
            "--process",
            str(os.getpid()),
            "--allow-user-interaction",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                try:
                    code = proc.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if cancel.is_set():
                    raise Cancelled()
                if time.monotonic() > deadline:
                    raise Timeout()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if code != 0:
            err = (proc.stderr.read() or "").strip()
            log.info("polkit verification failed (exit %d): %s", code, err)
        return code == 0


class NoVerifier:
    def available(self):
        return False

    def verify(self, cancel):
        return False
