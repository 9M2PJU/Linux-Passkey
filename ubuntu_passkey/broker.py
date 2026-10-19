"""Routes approval prompts to user interface agents.

Agents are the GNOME Shell extension and the Passkeys app; both register on
D-Bus and receive ``ApprovalRequested`` signals. When no agent is running a
stand-alone GTK prompt is spawned instead.
"""

import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time

from .ctap2 import Cancelled, Denied, Timeout

log = logging.getLogger(__name__)


class _Pending:
    def __init__(self, request_id, prompt):
        self.id = request_id
        self.prompt = prompt
        self.event = threading.Event()
        self.approved = False
        self.choice = 0


class ApprovalBroker:
    def __init__(self, config, verifier):
        self.config = config
        self.verifier = verifier
        self.emit = lambda name, *args: None  # set by the D-Bus service
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._pending = {}
        self._agents = set()

    # -- agents -----------------------------------------------------------

    def add_agent(self, name):
        with self._lock:
            self._agents.add(name)
        log.info("approval agent registered: %s", name)

    def remove_agent(self, name):
        with self._lock:
            self._agents.discard(name)
        log.info("approval agent gone: %s", name)

    def is_agent(self, name):
        with self._lock:
            return name in self._agents

    @property
    def agent_count(self):
        with self._lock:
            return len(self._agents)

    def respond(self, request_id, approved, choice):
        with self._lock:
            pending = self._pending.get(request_id)
        if pending is None or pending.event.is_set():
            return False
        pending.approved = bool(approved)
        pending.choice = int(choice)
        pending.event.set()
        return True

    def pending_requests(self):
        with self._lock:
            return list(self._pending.values())

    # -- Authenticator UI interface --------------------------------------

    def confirm(self, prompt, request):
        timeout = self.config.get("approval_timeout")
        if self.agent_count:
            return self._confirm_agents(prompt, request, timeout)
        return self._confirm_fallback(prompt, request, timeout)

    def verify(self, prompt, request):
        return self.verifier.verify(request.cancel)

    # -- implementation ---------------------------------------------------

    def _confirm_agents(self, prompt, request, timeout):
        pending = _Pending(next(self._ids), prompt)
        with self._lock:
            self._pending[pending.id] = pending
        self.emit(
            "ApprovalRequested",
            pending.id,
            prompt.operation,
            prompt.rp_id,
            prompt.rp_name,
            prompt.accounts,
            prompt.verify,
        )
        deadline = time.monotonic() + timeout
        try:
            while not pending.event.wait(0.05):
                if request.cancel.is_set():
                    raise Cancelled()
                if time.monotonic() > deadline:
                    raise Timeout()
                if not self.agent_count:
                    # The last agent disappeared; fall back to the GTK prompt.
                    return self._confirm_fallback(
                        prompt, request, max(1, deadline - time.monotonic())
                    )
        finally:
            with self._lock:
                self._pending.pop(pending.id, None)
            self.emit("ApprovalClosed", pending.id)
        if not pending.approved:
            raise Denied()
        return pending.choice

    def _fallback_command(self):
        exe = shutil.which("ubuntu-passkey")
        if exe:
            return [exe, "--prompt"]
        return [sys.executable, "-m", "ubuntu_passkey.app", "--prompt"]

    def _confirm_fallback(self, prompt, request, timeout):
        if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
            log.warning("no approval agent and no display; denying request")
            raise Denied()
        spec = json.dumps(
            {
                "operation": prompt.operation,
                "rp_id": prompt.rp_id,
                "rp_name": prompt.rp_name,
                "accounts": prompt.accounts,
                "verify": prompt.verify,
                "timeout": int(timeout),
            }
        )
        # The request goes through stdin: command lines are visible to every
        # local user in /proc, and the site and account names are private.
        proc = subprocess.Popen(
            self._fallback_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            proc.stdin.write(spec)
            proc.stdin.close()
        except OSError:
            pass
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    proc.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if request.cancel.is_set():
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
        out = (proc.stdout.read() or "").strip()
        if proc.returncode == 0 and out.startswith("approve"):
            parts = out.split()
            return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        raise Denied()
