"""The browser extension's native messaging host, talking to a real daemon
over a private session bus."""

import io
import json

import pytest

fido2 = pytest.importorskip("fido2")

from fido2.server import Fido2Server  # noqa: E402
from fido2.webauthn import (  # noqa: E402
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
)

from conftest import FakeUI, connect, needs_dbus  # noqa: E402
from linux_passkey import browsers, ctap2, nativehost  # noqa: E402

ORIGIN = "https://example.com"


@pytest.fixture
def host(daemon):
    ui = FakeUI()
    daemon.authenticator.ui = ui
    out = io.BytesIO()
    h = nativehost.Host(connect(), out)
    h.ui = ui
    h.out = out
    return h


def ask(host, message):
    start = host.out.tell()
    host.handle(message)
    host.out.seek(start)
    reply = nativehost.read_message(host.out)
    host.out.seek(0, io.SEEK_END)
    assert reply["id"] == message["id"]
    return reply


def options(obj):
    return json.loads(json.dumps(dict(obj.public_key)))


def test_message_framing():
    data = nativehost.encode_message({"id": 1, "op": "status"})
    assert nativehost.read_message(io.BytesIO(data)) == {"id": 1, "op": "status"}
    assert nativehost.read_message(io.BytesIO(data[:3])) is None
    with pytest.raises(ValueError):
        nativehost.read_message(io.BytesIO(b"\xff\xff\xff\x7f"))


@needs_dbus
def test_status(host):
    assert ask(host, {"id": 1, "op": "status"}) == {"id": 1, "result": {"ready": True}}


@needs_dbus
def test_requests_finish_before_exit(host):
    request = nativehost.encode_message({"id": 9, "op": "status"})
    assert nativehost.serve(host, io.BytesIO(request)) == 0
    host.out.seek(0)
    assert nativehost.read_message(host.out) == {"id": 9, "result": {"ready": True}}


@needs_dbus
def test_register_and_sign_in(host):
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    user = PublicKeyCredentialUserEntity(id=b"bob-handle", name="bob", display_name="Bob")
    reg, state = server.register_begin(
        user, resident_key_requirement=ResidentKeyRequirement.REQUIRED
    )
    reply = ask(host, {"id": 2, "op": "create", "origin": ORIGIN, "options": options(reg)})
    cred = server.register_complete(state, RegistrationResponse.from_dict(reply["result"]))
    assert [p.operation for p in host.ui.prompts] == ["register"]

    auth, state = server.authenticate_begin()
    has = ask(host, {"id": 3, "op": "has", "origin": ORIGIN, "options": options(auth)})
    assert has["result"] is True
    reply = ask(host, {"id": 4, "op": "get", "origin": ORIGIN, "options": options(auth)})
    server.authenticate_complete(
        state, [cred.credential_data], AuthenticationResponse.from_dict(reply["result"])
    )


@needs_dbus
def test_errors_carry_dom_exception_names(host):
    reply = ask(
        host,
        {"id": 5, "op": "has", "origin": "https://evil.com", "options": {"rpId": "example.com"}},
    )
    assert reply["error"]["name"] == "SecurityError"

    host.ui.answer = ctap2.Denied
    reply = ask(
        host,
        {
            "id": 6,
            "op": "create",
            "origin": ORIGIN,
            "options": {
                "rp": {"name": "Example"},
                "user": {"id": "dXNlcg", "name": "u", "displayName": "U"},
                "challenge": "Y2hhbGxlbmdlY2hhbGxlbmdl",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            },
        },
    )
    assert reply["error"]["name"] == "NotAllowedError"

    reply = ask(host, {"id": 7, "op": "launch-missiles"})
    assert reply["error"]["name"] == "TypeError"


def test_register_browsers(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".config" / "BraveSoftware" / "Brave-Browser").mkdir(parents=True)
    (home / "snap" / "firefox").mkdir(parents=True)  # the snap Firefox
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    written = browsers.register("/usr/libexec/linux-passkey/native-host", home=str(home))
    brave = home / ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts" / (browsers.HOST_NAME + ".json")
    firefox = home / ".mozilla/native-messaging-hosts" / (browsers.HOST_NAME + ".json")
    assert sorted(written) == sorted([str(brave), str(firefox)])
    assert json.loads(brave.read_text())["allowed_origins"][0].startswith("chrome-extension://")
    assert json.loads(firefox.read_text())["allowed_extensions"] == [browsers.FIREFOX_EXTENSION_ID]
    # Unchanged manifests are not rewritten.
    assert browsers.register("/usr/libexec/linux-passkey/native-host", home=str(home)) == []


def test_register_browsers_from_a_snap(tmp_path, monkeypatch):
    real = tmp_path / "real"
    (real / ".config" / "google-chrome").mkdir(parents=True)
    monkeypatch.setenv("SNAP_REAL_HOME", str(real))
    monkeypatch.setenv("HOME", str(tmp_path / "snap-home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "snap-home" / ".config"))
    written = browsers.register("/snap/bin/linux-passkey.native-host")
    assert written == [
        str(real / ".config/google-chrome/NativeMessagingHosts" / (browsers.HOST_NAME + ".json"))
    ]
