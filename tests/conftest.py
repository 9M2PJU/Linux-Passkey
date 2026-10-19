import os
import queue
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from linux_passkey import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH, ctap2  # noqa: E402
from linux_passkey.config import Config  # noqa: E402
from linux_passkey.ctaphid import CtapHidDevice  # noqa: E402
from linux_passkey.store import CredentialStore  # noqa: E402


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
        if isinstance(self.verify_result, type) and issubclass(self.verify_result, Exception):
            raise self.verify_result()
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

    descriptor = HidDescriptor("loopback", 0x1209, 0x0001, 64, 64, "Linux Passkey", "1")
    return ClientDevice(descriptor, LoopbackConnection(authenticator))


# -- a private session bus with a running daemon ----------------------------

try:
    import gi

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib
except (ImportError, ValueError):
    Gio = GLib = None

needs_dbus = pytest.mark.skipif(
    not any(
        os.access(os.path.join(p, "dbus-daemon"), os.X_OK)
        for p in os.environ.get("PATH", "").split(os.pathsep)
    ),
    reason="dbus-daemon not installed",
)


@pytest.fixture(scope="session")
def bus():
    # Session-scoped: GIO keeps one session bus connection per process.
    proc = subprocess.Popen(
        ["dbus-daemon", "--session", "--nofork", "--print-address"],
        stdout=subprocess.PIPE,
        text=True,
    )
    address = proc.stdout.readline().strip()
    old = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = address
    yield address
    proc.terminate()
    proc.wait()
    if old is None:
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
    else:
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = old


@pytest.fixture
def daemon(bus, env, monkeypatch):
    from linux_passkey.daemon import Daemon

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    d = Daemon(uhid_path="/nonexistent/uhid", key_backend="file")
    d.config.override("verification", "none")  # no polkit in tests
    thread = threading.Thread(target=d.run, daemon=True)
    thread.start()
    client = connect()
    wait_for_state(client, ("ready",))
    yield d
    GLib.idle_add(d.loop.quit)
    thread.join(timeout=5)
    for _ in range(100):
        if not name_has_owner(client):
            break
        time.sleep(0.05)


def wait_for_state(conn, states):
    for _ in range(200):
        try:
            if name_has_owner(conn) and call(conn, "GetStatus")[0]["state"] in states:
                return
        except GLib.Error:
            pass
        time.sleep(0.05)
    raise AssertionError("daemon never reached %s" % (states,))


def connect():
    address = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    return Gio.DBusConnection.new_for_address_sync(
        address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )


def name_has_owner(conn):
    reply = conn.call_sync(
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "NameHasOwner", GLib.Variant("(s)", (DBUS_NAME,)), None,
        Gio.DBusCallFlags.NONE, 1000, None,
    )
    return reply.unpack()[0]


def call(conn, method, params=None):
    reply = conn.call_sync(
        DBUS_NAME, DBUS_PATH, DBUS_INTERFACE, method, params, None,
        Gio.DBusCallFlags.NONE, 5000, None,
    )
    return reply.unpack() if reply is not None else ()


