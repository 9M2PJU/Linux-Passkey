"""End-to-end WebAuthn ceremonies driven by the python-fido2 client and server."""

import pytest

fido2 = pytest.importorskip("fido2")

from fido2.attestation import PackedAttestation  # noqa: E402
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from fido2.server import Fido2Server  # noqa: E402
from fido2.webauthn import (  # noqa: E402
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ubuntu_passkey import ctap2  # noqa: E402

ORIGIN = "https://example.com"
RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")


def make_client(device):
    return Fido2Client(device, DefaultClientDataCollector(ORIGIN))


def register(device, name="alice", rk=True, uv="preferred", exclude=None):
    server = Fido2Server(RP)
    user = PublicKeyCredentialUserEntity(id=name.encode() * 4, name=name, display_name=name.title())
    options, state = server.register_begin(
        user,
        credentials=exclude,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED if rk else ResidentKeyRequirement.DISCOURAGED,
        user_verification=UserVerificationRequirement(uv),
    )
    result = make_client(device).make_credential(options.public_key)
    auth_data = server.register_complete(state, result)
    return server, auth_data, result


def authenticate(device, server, credentials, uv="preferred", allow=True):
    options, state = server.authenticate_begin(
        credentials if allow else None, user_verification=UserVerificationRequirement(uv)
    )
    selection = make_client(device).get_assertion(options.public_key)
    response = selection.get_response(0)
    server.authenticate_complete(state, credentials, response)
    return response


def test_get_info(hid_device):
    info = Ctap2(hid_device).get_info()
    assert "FIDO_2_0" in info.versions
    assert info.options["rk"] is True
    assert info.options["uv"] is True
    assert info.aaguid == ctap2.AAGUID


def test_register_and_authenticate_discoverable(hid_device, ui, store):
    server, auth_data, result = register(hid_device, uv="required")
    cred = auth_data.credential_data
    assert auth_data.is_user_present() and auth_data.is_user_verified()
    # Built-in UV via a pinUvAuthToken: one prompt, one verification.
    assert [p.operation for p in ui.prompts] == ["register"]
    assert ui.prompts[0].rp_id == "example.com"
    assert ui.verifications == 1

    # Packed self attestation verifies against the credential's own key.
    att = result.response.attestation_object
    assert att.fmt == "packed"
    PackedAttestation().verify(att.att_stmt, att.auth_data, result.response.client_data.hash)

    records = store.list()
    assert len(records) == 1 and records[0]["rp_id"] == "example.com"

    # Usernameless sign-in (no allow list).
    response = authenticate(hid_device, server, [cred], uv="required", allow=False)
    assert response.response.user_handle == b"alice" * 4
    assert store.list()[0]["use_count"] == 1


def test_non_discoverable_with_allow_list(hid_device, ui, store):
    server, auth_data, _ = register(hid_device, rk=False, uv="discouraged")
    assert not auth_data.is_user_verified()
    assert store.list() == []
    authenticate(hid_device, server, [auth_data.credential_data], uv="discouraged")
    assert ui.verifications == 0


def test_account_picker_chooses_credential(hid_device, ui):
    server, a, _ = register(hid_device, name="alice")
    _, b, _ = register(hid_device, name="bob")
    ui.answer = 1  # pick the second listed account
    options, state = server.authenticate_begin(None)
    selection = make_client(hid_device).get_assertion(options.public_key)
    response = selection.get_response(0)
    picked = server.authenticate_complete(
        state, [a.credential_data, b.credential_data], response
    )
    prompt = ui.prompts[-1]
    assert prompt.operation in ("authenticate", "choose")
    assert len(prompt.accounts) == 2
    chosen_name = prompt.accounts[1].split(" (")[1].rstrip(")")
    expected = a if chosen_name == "alice" else b
    assert picked.credential_id == expected.credential_data.credential_id


def test_exclude_list(hid_device, ui):
    server, auth_data, _ = register(hid_device)
    with pytest.raises(ClientError):
        register(hid_device, exclude=[auth_data.credential_data])
    assert ui.prompts[-1].operation == "exclude"


def test_denied(hid_device, ui):
    ui.answer = ctap2.Denied
    with pytest.raises(ClientError):
        register(hid_device)


def test_failed_verification(hid_device, ui):
    ui.verify_result = False
    with pytest.raises(ClientError):
        register(hid_device, uv="required")


def test_deleted_passkey_is_revoked(hid_device, store):
    server, auth_data, _ = register(hid_device)
    assert store.delete(store.list()[0]["id"])
    with pytest.raises(ClientError):
        authenticate(hid_device, server, [auth_data.credential_data])


def test_credential_bound_to_rp(hid_device, store):
    server, auth_data, _ = register(hid_device, rk=False)
    other = PublicKeyCredentialRpEntity(id="evil.example.com", name="Evil")
    client = Fido2Client(hid_device, DefaultClientDataCollector("https://evil.example.com"))
    options, _ = Fido2Server(other).authenticate_begin([auth_data.credential_data])
    with pytest.raises(ClientError):
        client.get_assertion(options.public_key)


def test_always_verify_setting(hid_device, ui, config):
    config.set("always_verify", True)
    _, auth_data, _ = register(hid_device, uv="discouraged")
    assert auth_data.is_user_verified()
    assert ui.verifications == 1


def test_reset(hid_device, store):
    server, auth_data, _ = register(hid_device)
    Ctap2(hid_device).reset()
    assert store.list() == []
    with pytest.raises(ClientError):
        authenticate(hid_device, server, [auth_data.credential_data])


def test_cancel_while_waiting_for_user(hid_device, ui):
    import threading

    ui.block = threading.Event()
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    server = Fido2Server(RP)
    user = PublicKeyCredentialUserEntity(id=b"carol", name="carol", display_name="Carol")
    options, _ = server.register_begin(user)
    with pytest.raises(ClientError):
        make_client(hid_device).make_credential(options.public_key, event=cancel)
    ui.block = None


def test_eddsa(hid_device, config):
    config.set("algorithms", ["EdDSA"])
    server, auth_data, _ = register(hid_device)
    assert auth_data.credential_data.public_key[3] == -8
    authenticate(hid_device, server, [auth_data.credential_data])


def test_prf_extension(hid_device):
    server = Fido2Server(RP)
    user = PublicKeyCredentialUserEntity(id=b"dave", name="dave", display_name="Dave")
    options, state = server.register_begin(
        user, resident_key_requirement=ResidentKeyRequirement.REQUIRED
    )
    client = make_client(hid_device)
    reg = client.make_credential(
        {**dict(options.public_key), "extensions": {"prf": {}}}
    )
    assert reg.client_extension_results["prf"]["enabled"] is True
    auth_data = server.register_complete(state, reg)

    def evaluate(first, second=None):
        opts, st = server.authenticate_begin([auth_data.credential_data])
        salts = {"first": first}
        if second:
            salts["second"] = second
        sel = make_client(hid_device).get_assertion(
            {**dict(opts.public_key), "extensions": {"prf": {"eval": salts}}}
        )
        resp = sel.get_response(0)
        server.authenticate_complete(st, [auth_data.credential_data], resp)
        return resp.client_extension_results["prf"]["results"]

    one = evaluate(b"salt-1" * 5, b"salt-2" * 5)
    two = evaluate(b"salt-1" * 5)
    from ubuntu_passkey.store import b64d

    assert len(b64d(one["first"])) == 32 and len(b64d(one["second"])) == 32
    assert one["first"] == two["first"]  # deterministic per credential and salt
    assert one["first"] != one["second"]


def test_ctap20_uv_option(hid_device, ui):
    """Platforms without pinUvAuthToken support send options.uv directly."""
    import hashlib

    ctap = Ctap2(hid_device)
    cdh = hashlib.sha256(b"client data").digest()
    att = ctap.make_credential(
        cdh,
        {"id": "example.com", "name": "Example"},
        {"id": b"erin", "name": "erin", "displayName": "Erin"},
        [{"type": "public-key", "alg": -7}],
        options={"rk": True, "uv": True},
    )
    assert att.auth_data.is_user_verified()
    assert ui.prompts[-1].accounts == ["Erin (erin)"]
    assert ui.prompts[-1].verify is True
    assertion = ctap.get_assertion("example.com", cdh, options={"uv": True})
    assert assertion.user["name"] == "erin"
    assertion.verify(cdh, att.auth_data.credential_data.public_key)


def test_silent_assertion_lists_all_accounts(hid_device, ui):
    import hashlib

    ctap = Ctap2(hid_device)
    cdh = hashlib.sha256(b"x").digest()
    for name in ("a1", "a2", "a3"):
        ctap.make_credential(
            cdh,
            {"id": "example.com"},
            {"id": name.encode(), "name": name},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
        )
    prompts = len(ui.prompts)
    first = ctap.get_assertion("example.com", cdh, options={"up": False})
    assert first.number_of_credentials == 3
    rest = [ctap.get_next_assertion() for _ in range(2)]
    handles = {first.user["id"]} | {r.user["id"] for r in rest}
    assert handles == {b"a1", b"a2", b"a3"}
    assert not first.auth_data.is_user_present()
    assert len(ui.prompts) == prompts  # silent: nobody was asked
