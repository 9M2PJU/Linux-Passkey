"""The daemon's D-Bus API, exercised over a private session bus."""

import hashlib
import os
import subprocess
import threading
import time

import pytest

gi = pytest.importorskip("gi")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from ubuntu_passkey import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH, cbor  # noqa: E402
from ubuntu_passkey.ctap2 import Request  # noqa: E402

pytestmark = pytest.mark.skipif(
    not any(
        os.access(os.path.join(p, "dbus-daemon"), os.X_OK)
        for p in os.environ.get("PATH", "").split(os.pathsep)
    ),
    reason="dbus-daemon not installed",
)


@pytest.fixture(scope="module")
def bus():
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
    from ubuntu_passkey.daemon import Daemon

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    d = Daemon(uhid_path="/nonexistent/uhid", key_backend="file")
    d.config.override("verification", "none")  # no polkit in tests
    thread = threading.Thread(target=d.run, daemon=True)
    thread.start()
    client = connect()
    for _ in range(100):
        if name_has_owner(client):
            break
        time.sleep(0.05)
    yield d
    GLib.idle_add(d.loop.quit)
    thread.join(timeout=5)
    for _ in range(100):
        if not name_has_owner(client):
            break
        time.sleep(0.05)


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


def make_credential(d, name="alice"):
    cdh = hashlib.sha256(b"cd").digest()
    msg = bytes([1]) + cbor.encode(
        {
            1: cdh,
            2: {"id": "example.com", "name": "Example"},
            3: {"id": name.encode(), "name": name},
            4: [{"type": "public-key", "alg": -7}],
            7: {"rk": True},
        }
    )
    return d.authenticator.process(msg, Request())


def test_status_reports_missing_device(daemon):
    status = call(connect(), "GetStatus")[0]
    assert status["device_active"] is False
    assert "not found" in status["device_error"]
    assert status["credential_count"] == 0


def test_agent_approves_request(daemon):
    agent = connect()
    call(agent, "RegisterAgent")
    assert call(agent, "GetStatus")[0]["agent_count"] == 1

    result = {}
    worker = threading.Thread(target=lambda: result.update(r=make_credential(daemon)))
    worker.start()
    pending = []
    for _ in range(100):
        pending = call(agent, "GetPendingRequests")[0]
        if pending:
            break
        time.sleep(0.05)
    assert len(pending) == 1
    request_id, operation, rp_id, rp_name, accounts, verify = pending[0]
    assert (operation, rp_id, rp_name, accounts) == ("register", "example.com", "Example", ["alice"])

    # Only registered agents may answer.
    with pytest.raises(GLib.Error) as err:
        call(connect(), "Respond", GLib.Variant("(ubi)", (request_id, True, 0)))
    assert "AccessDenied" in err.value.message

    call(agent, "Respond", GLib.Variant("(ubi)", (request_id, True, 0)))
    worker.join(timeout=5)
    assert result["r"][0] == 0

    creds = call(agent, "ListCredentials")[0]
    assert len(creds) == 1 and creds[0]["rp_id"] == "example.com"
    assert call(agent, "DeleteCredential", GLib.Variant("(s)", (creds[0]["id"],)))[0]
    assert call(agent, "ListCredentials")[0] == []


def test_agent_denies_request(daemon):
    agent = connect()
    call(agent, "RegisterAgent")
    result = {}
    worker = threading.Thread(target=lambda: result.update(r=make_credential(daemon)))
    worker.start()
    for _ in range(100):
        pending = call(agent, "GetPendingRequests")[0]
        if pending:
            break
        time.sleep(0.05)
    call(agent, "Respond", GLib.Variant("(ubi)", (pending[0][0], False, 0)))
    worker.join(timeout=5)
    assert result["r"] == bytes([0x27])  # CTAP2_ERR_OPERATION_DENIED


def test_no_agent_and_no_display_denies(daemon):
    assert make_credential(daemon) == bytes([0x27])


def test_agent_disconnect_is_noticed(daemon):
    agent = connect()
    call(agent, "RegisterAgent")
    agent.close_sync(None)
    observer = connect()
    for _ in range(100):
        if call(observer, "GetStatus")[0]["agent_count"] == 0:
            break
        time.sleep(0.05)
    assert call(observer, "GetStatus")[0]["agent_count"] == 0


def test_settings(daemon):
    conn = connect()
    call(conn, "SetSetting", GLib.Variant("(sv)", ("always_verify", GLib.Variant("b", True))))
    assert call(conn, "GetSettings")[0]["always_verify"] is True
    with pytest.raises(GLib.Error):
        call(conn, "SetSetting", GLib.Variant("(sv)", ("approval_timeout", GLib.Variant("x", 1))))
    with pytest.raises(GLib.Error):
        call(conn, "SetSetting", GLib.Variant("(sv)", ("bogus", GLib.Variant("b", True))))
