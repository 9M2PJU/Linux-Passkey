import os
import queue
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubuntu_passkey import ctap2  # noqa: E402
from ubuntu_passkey.config import Config  # noqa: E402
from ubuntu_passkey.ctaphid import CtapHidDevice  # noqa: E402
from ubuntu_passkey.store import CredentialStore  # noqa: E402


class FakeUI:
    """Approves everything unless told otherwise and records each prompt."""

    def __init__(self):
        self.prompts = []
        self.verifications = 0
        self.answer = 0  # int choice, or an exception class to raise
        self.verify_result = True
        self.block = None  # threading.Event to wait on (simulates a slow user)

    def confirm(self, prompt, request):
        self.prompts.append(prompt)
        if self.block is not None:
            while not self.block.wait(0.01):
                if request.cancel.is_set():
                    raise ctap2.Cancelled()
        if isinstance(self.answer, type) and issubclass(self.answer, Exception):
            raise self.answer()
        return self.answer

    def verify(self, prompt, request):
        self.verifications += 1
        return self.verify_result


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return tmp_path


@pytest.fixture
def config(env):
    return Config()


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(env, master_key):
    return CredentialStore(master_key)


@pytest.fixture
def ui():
    return FakeUI()


@pytest.fixture
def authenticator(store, ui, config, master_key):
    return ctap2.Authenticator(
        store, ui, config, on_reset=lambda: store.reset(os.urandom(32))
    )


class LoopbackConnection:
    """fido2 CtapHidConnection wired straight into our CTAPHID device."""

    def __init__(self, authenticator):
        self.inbox = queue.Queue()
        self.device = CtapHidDevice(authenticator, self.inbox.put)

    def read_packet(self):
        return self.inbox.get(timeout=10)

    def write_packet(self, data):
        # Simulate hidraw: a leading report ID byte of 0.
        threading.Thread(
            target=self.device.handle_report, args=(b"\0" + bytes(data),)
        ).run()

    def close(self):
        pass


@pytest.fixture
def hid_device(authenticator):
    from fido2.hid import CtapHidDevice as ClientDevice
    from fido2.hid.base import HidDescriptor

    descriptor = HidDescriptor("loopback", 0x1209, 0x0001, 64, 64, "Ubuntu Passkey", "1")
    return ClientDevice(descriptor, LoopbackConnection(authenticator))
