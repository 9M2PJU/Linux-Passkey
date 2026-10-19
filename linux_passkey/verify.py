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

from .ctap2 import Cancelled, Denied, Timeout

log = logging.getLogger(__name__)

ACTION_ID = "io.github.haythmkenway.passkey.verify"

# pkcheck(1) exit statuses
PKCHECK_AUTHORIZED = 0
PKCHECK_NOT_AUTHORIZED = 1
PKCHECK_DISMISSED = 3


class PolkitVerifier:
    def __init__(self, timeout=60, action_id=ACTION_ID):
        self.timeout = timeout
        self.action_id = action_id

    def available(self):
        return shutil.which("pkcheck") is not None

    def verify(self, cancel):
        """Run the polkit prompt.

        Returns True when the user proved their identity and False when they
        failed to. Raises Denied when the prompt was dismissed or could not
        be shown, Cancelled if ``cancel`` is set while waiting, and Timeout.
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
        if code == PKCHECK_AUTHORIZED:
            return True
        err = (proc.stderr.read() or "").strip()
        if code == PKCHECK_NOT_AUTHORIZED:
            log.info("user verification failed: %s", err)
            return False
        if code == PKCHECK_DISMISSED:
            log.info("user verification dismissed")
        else:
            log.warning("user verification unavailable (pkcheck exit %d): %s", code, err)
        raise Denied()


class NoVerifier:
    def available(self):
        return False

    def verify(self, cancel):
        return False
