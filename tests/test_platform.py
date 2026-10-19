"""The platform authenticator path (browser extension -> daemon), verified
by python-fido2's relying party implementation."""

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
    UserVerificationRequirement,
)

from linux_passkey import ctap2, webauthn  # noqa: E402
from linux_passkey.webauthn import WebAuthnError  # noqa: E402

ORIGIN = "https://login.example.com"
RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")


class FakePSL:
    def is_public_suffix(self, domain):
        return domain in ("com", "co.uk", "github.io")


@pytest.fixture(autouse=True)
def psl(monkeypatch):
    monkeypatch.setattr(webauthn, "_psl", FakePSL())


def options_json(options):
    # What the extension sends: the WebAuthn JSON form of the options.
    return json.loads(json.dumps(dict(options.public_key)))


def register(authenticator, name="alice", rk=True, uv="preferred", exclude=None, **extra):
    server = Fido2Server(RP)
    user = PublicKeyCredentialUserEntity(id=name.encode() * 4, name=name, display_name=name.title())
    options, state = server.register_begin(
        user,
        credentials=exclude,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED if rk else ResidentKeyRequirement.DISCOURAGED,
        user_verification=UserVerificationRequirement(uv),
    )
    opts = options_json(options)
    opts.update(extra)
    result = webauthn.create(authenticator, ORIGIN, opts, ctap2.Request())
    auth_data = server.register_complete(state, RegistrationResponse.from_dict(result))
    return server, auth_data.credential_data, result


def authenticate(authenticator, server, credentials, allow=True, origin=ORIGIN, uv="preferred"):
    options, state = server.authenticate_begin(
        credentials if allow else None, user_verification=UserVerificationRequirement(uv)
    )
    result = webauthn.get(authenticator, origin, options_json(options), ctap2.Request())
    server.authenticate_complete(state, credentials, AuthenticationResponse.from_dict(result))
    return result


def test_register_and_sign_in(authenticator, ui, store):
    server, cred, result = register(authenticator, uv="required")
    assert result["authenticatorAttachment"] == "platform"
    assert result["response"]["transports"] == ["internal"]
    assert result["response"]["publicKeyAlgorithm"] == -7
    assert "publicKey" in result["response"]
    client_data = json.loads(webauthn.unb64url(result["response"]["clientDataJSON"]))
    assert client_data == {
        "type": "webauthn.create",
        "challenge": client_data["challenge"],
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    assert [p.operation for p in ui.prompts] == ["register"]
    assert ui.verifications == 1
    assert store.list()[0]["rp_id"] == "example.com"

    result = authenticate(authenticator, server, [cred], allow=False)
    assert webauthn.unb64url(result["response"]["userHandle"]) == b"alice" * 4
    assert ui.verifications == 2


def test_attestation_defaults_to_none(authenticator):
    _, _, result = register(authenticator)
    att = fido2.cbor.decode(webauthn.unb64url(result["response"]["attestationObject"]))
    assert att["fmt"] == "none" and att["attStmt"] == {}


def test_sign_in_with_allow_list(authenticator):
    server, cred, _ = register(authenticator, rk=False)
    result = authenticate(authenticator, server, [cred])
    assert result["response"]["userHandle"] is None


def test_exclude_list_is_invalid_state(authenticator):
    _, cred, _ = register(authenticator)
    with pytest.raises(WebAuthnError) as e:
        register(authenticator, exclude=[cred])
    assert e.value.name == "InvalidStateError"


def test_denied_is_not_allowed(authenticator, ui):
    ui.answer = ctap2.Denied
    with pytest.raises(WebAuthnError) as e:
        register(authenticator)
    assert e.value.name == "NotAllowedError"


def test_cross_platform_request_falls_back(authenticator, ui):
    with pytest.raises(WebAuthnError) as e:
        register(
            authenticator,
            authenticatorSelection={"authenticatorAttachment": "cross-platform"},
        )
    assert e.value.name == "NotSupportedError"
    with pytest.raises(WebAuthnError) as e:
        register(authenticator, hints=["security-key"])
    assert e.value.name == "NotSupportedError"
    assert ui.prompts == []


def test_cred_props_and_prf(authenticator):
    _, _, result = register(authenticator, extensions={"credProps": True, "prf": {}})
    assert result["clientExtensionResults"] == {"credProps": {"rk": True}, "prf": {"enabled": True}}


# -- origin binding: the part the browser would normally enforce ----------


@pytest.mark.parametrize(
    "origin, rp_id, expected",
    [
        ("https://example.com", None, "example.com"),
        ("https://example.com", "example.com", "example.com"),
        ("https://login.example.com", "example.com", "example.com"),
        ("https://Login.Example.com:8443", "example.com", "example.com"),
        ("https://a.b.example.co.uk", "example.co.uk", "example.co.uk"),
        ("http://localhost:8080", None, "localhost"),
        ("http://127.0.0.1:3000", "127.0.0.1", "127.0.0.1"),
    ],
)
def test_rp_id_accepted(origin, rp_id, expected):
    assert webauthn.check_rp_id(rp_id, origin) == expected


@pytest.mark.parametrize(
    "origin, rp_id",
    [
        ("https://evil.com", "example.com"),  # another site
        ("https://notexample.com", "example.com"),  # suffix without a dot
        ("https://example.com", "login.example.com"),  # a subdomain of the origin
        ("https://login.example.com", "com"),  # a public suffix
        ("https://example.co.uk", "co.uk"),
        ("https://user.github.io", "github.io"),
        ("http://example.com", None),  # not a secure context
        ("http://example.localhost.evil.com", None),
        ("https://10.0.0.1", "0.0.1"),  # suffixes of IP addresses
        ("file:///etc/passwd", None),
        ("https://example.com/path", None),
        ("", None),
        (None, None),
    ],
)
def test_rp_id_rejected(origin, rp_id):
    with pytest.raises(WebAuthnError) as e:
        webauthn.check_rp_id(rp_id, origin)
    assert e.value.name == "SecurityError"


def test_phishing_origin_cannot_use_credential(authenticator, ui):
    server, cred, _ = register(authenticator)
    prompts = len(ui.prompts)
    with pytest.raises(WebAuthnError) as e:
        authenticate(authenticator, server, [cred], origin="https://example.com.evil.net")
    assert e.value.name == "SecurityError"
    assert len(ui.prompts) == prompts  # rejected before anyone was asked


def test_signature_names_the_real_origin(authenticator):
    # A sibling subdomain may use the RP ID, but the server sees its origin.
    server, cred, _ = register(authenticator)
    result = webauthn.get(
        authenticator,
        "https://other.example.com",
        {"challenge": webauthn.b64url(b"c" * 32), "rpId": "example.com"},
        ctap2.Request(),
    )
    client_data = json.loads(webauthn.unb64url(result["response"]["clientDataJSON"]))
    assert client_data["origin"] == "https://other.example.com"


def test_cross_origin_client_data():
    data = json.loads(
        webauthn.client_data_json("webauthn.get", b"x", "https://a.com", "https://b.com")
    )
    assert data["crossOrigin"] is True and data["topOrigin"] == "https://b.com"


def test_missing_public_suffix_list_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(webauthn, "_psl", None)
    monkeypatch.setattr(webauthn, "PSL_PATH", str(tmp_path / "missing.dat"))
    assert webauthn.check_rp_id(None, "https://a.example.com") == "a.example.com"
    with pytest.raises(WebAuthnError):
        webauthn.check_rp_id("example.com", "https://a.example.com")


def test_public_suffix_list_rules(tmp_path):
    path = tmp_path / "psl.dat"
    path.write_text("// comment\ncom\nuk\nco.uk\n*.ck\n!www.ck\n公司.cn\n")
    psl = webauthn.PublicSuffixList(str(path))
    assert psl.is_public_suffix("com")
    assert psl.is_public_suffix("co.uk")
    assert not psl.is_public_suffix("example.co.uk")
    assert psl.is_public_suffix("anything.ck")
    assert not psl.is_public_suffix("www.ck")
    assert psl.is_public_suffix("xn--55qx5d.cn")
    assert psl.is_public_suffix("unlisted")  # the implicit "*" rule


def test_system_public_suffix_list():
    try:
        psl = webauthn.PublicSuffixList()
    except OSError:
        pytest.skip("publicsuffix is not installed")
    assert psl.is_public_suffix("github.io")
    assert not psl.is_public_suffix("example.com")


# -- has_credentials (decides between our prompt and the browser's) --------


def test_has_credentials(authenticator, store):
    challenge = webauthn.b64url(b"c" * 32)
    assert not webauthn.has_credentials(store, ORIGIN, {"challenge": challenge, "rpId": "example.com"})
    _, cred, _ = register(authenticator)
    assert webauthn.has_credentials(store, ORIGIN, {"challenge": challenge, "rpId": "example.com"})
    allow = [{"type": "public-key", "id": webauthn.b64url(cred.credential_id)}]
    assert webauthn.has_credentials(
        store, ORIGIN, {"challenge": challenge, "rpId": "example.com", "allowCredentials": allow}
    )
    foreign = [{"type": "public-key", "id": webauthn.b64url(b"\x01" * 64)}]
    assert not webauthn.has_credentials(
        store, ORIGIN, {"challenge": challenge, "rpId": "example.com", "allowCredentials": foreign}
    )


def test_has_credentials_checks_origin(authenticator, store):
    register(authenticator)
    with pytest.raises(WebAuthnError):
        webauthn.has_credentials(store, "https://evil.com", {"rpId": "example.com"})

