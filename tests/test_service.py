"""The daemon's D-Bus API, exercised over a private session bus."""

import hashlib
import os
import threading
import time

import pytest

gi = pytest.importorskip("gi")
gi.require_version("Gio", "2.0")
from gi.repository import GLib  # noqa: E402

from linux_passkey import cbor  # noqa: E402
from linux_passkey.ctap2 import Request  # noqa: E402

from conftest import call, connect, name_has_owner, needs_dbus, wait_for_state  # noqa: E402

pytestmark = needs_dbus


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


def test_snap_has_no_virtual_key(bus, env, monkeypatch):
    from linux_passkey.daemon import Daemon

    monkeypatch.setenv("SNAP", "/snap/linux-passkey/x1")
    d = Daemon(uhid_path="/nonexistent/uhid", key_backend="file")
    status = d.status()
    assert status["device_supported"] is False
    assert status["device_active"] is False


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


def test_unreadable_store_is_reported_and_recoverable(bus, env, monkeypatch):
    """A store that cannot be decrypted must not crash the daemon: it reports
    the problem, keeps the file aside on reset and starts working again."""
    from linux_passkey import paths
    from linux_passkey.daemon import Daemon

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    os.makedirs(paths.data_dir(), exist_ok=True)
    with open(os.path.join(paths.data_dir(), "credentials.enc"), "wb") as f:
        f.write(b"\x01" + os.urandom(64))  # written under some other key

    d = Daemon(uhid_path="/nonexistent/uhid", key_backend="file")
    d.config.override("verification", "none")
    thread = threading.Thread(target=d.run, daemon=True)
    thread.start()
    conn = connect()
    try:
        wait_for_state(conn, ("error",))
        status = call(conn, "GetStatus")[0]
        assert "cannot be decrypted" in status["error"]
        assert status["device_active"] is False
        with pytest.raises(GLib.Error) as err:
            call(conn, "ListCredentials")
        assert "Unavailable" in err.value.message
        assert d.process(b"\x04") == bytes([0x30])  # CTAP2_ERR_NOT_ALLOWED

        assert call(conn, "ResetAll")[0] is True
        wait_for_state(conn, ("ready",))
        assert call(conn, "ListCredentials")[0] == []
        kept = [n for n in os.listdir(paths.data_dir()) if ".unreadable-" in n]
        assert len(kept) == 1
    finally:
        GLib.idle_add(d.loop.quit)
        thread.join(timeout=5)
        for _ in range(100):
            if not name_has_owner(conn):
                break
            time.sleep(0.05)


def test_security_settings_not_writable_over_dbus(daemon):
    conn = connect()
    with pytest.raises(GLib.Error) as err:
        call(conn, "SetSetting", GLib.Variant("(sv)", ("verification", GLib.Variant("s", "none"))))
    assert "AccessDenied" in err.value.message


def test_fallback_prompt_receives_request_on_stdin(daemon, monkeypatch, tmp_path):
    """Site and account names must not appear on a command line."""
    import json
    import sys

    from linux_passkey.ctap2 import Prompt

    script = tmp_path / "prompt.py"
    record = tmp_path / "seen.json"
    script.write_text(
        "import json, sys\n"
        "json.dump({'argv': sys.argv, 'stdin': json.load(sys.stdin)}, open(%r, 'w'))\n"
        "print('approve 0')\n" % str(record)
    )
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-test")
    monkeypatch.setattr(daemon.broker, "_fallback_command", lambda: [sys.executable, str(script)])
    choice = daemon.broker.confirm(
        Prompt("register", "secret-site.example", "", ["alice"]), Request()
    )
    seen = json.loads(record.read_text())
    assert choice == 0
    assert "secret-site.example" not in " ".join(seen["argv"])
    assert seen["stdin"]["rp_id"] == "secret-site.example"
