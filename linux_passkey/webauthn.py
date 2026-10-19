"""WebAuthn client for the platform authenticator path.

Browsers on Linux have no operating system WebAuthn API to call, so the
Linux Passkey browser extension takes ``navigator.credentials.create/get``
calls and hands them to the daemon (through the native messaging host).
That makes this module the WebAuthn *client*: it does what the browser
would otherwise do before talking to an authenticator (WebAuthn Level 3,
sections 5.1.3 and 5.1.4):

  * checks that the caller's origin is a secure context and that the
    requested RP ID is the origin's host or a registrable suffix of it
    (never a public suffix);
  * builds ``clientDataJSON`` itself from that origin, so a website can only
    ever obtain signatures that name its own origin;
  * runs the CTAP command on the shared Authenticator and returns the
    result in the WebAuthn JSON serialization (RegistrationResponseJSON /
    AuthenticationResponseJSON).

The origin must come from the browser (the extension takes it from the
message sender, never from the page).
"""

import base64
import hashlib
import ipaddress
import json
import logging
import struct
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import cbor, keys
from .ctap2 import (
    CMD_GET_ASSERTION,
    CMD_MAKE_CREDENTIAL,
    ERR_CREDENTIAL_EXCLUDED,
    ERR_UNSUPPORTED_ALGORITHM,
    ERR_UNSUPPORTED_OPTION,
    CtapError,
)

log = logging.getLogger(__name__)

PSL_PATH = "/usr/share/publicsuffix/public_suffix_list.dat"

CRED_PROTECT = {
    "userVerificationOptional": 1,
    "userVerificationOptionalWithCredentialIDList": 2,
    "userVerificationRequired": 3,
}
# WebAuthn's default when pubKeyCredParams is empty: ES256, then RS256.
DEFAULT_ALGORITHMS = (keys.ES256, -257)


class WebAuthnError(Exception):
    """An error reported to the website as a DOMException ``name``.

    NotSupportedError and SecurityError make the browser extension fall
    back to the browser's own implementation (security keys, phones), which
    applies its own checks.
    """

    def __init__(self, name, message=""):
        super().__init__(message or name)
        self.name = name


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text, what="value"):
    if not isinstance(text, str):
        raise WebAuthnError("TypeError", "%s must be base64url text" % what)
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise WebAuthnError("TypeError", "%s is not valid base64url" % what)


# -- origins and RP IDs ---------------------------------------------------


class PublicSuffixList:
    """The Public Suffix List (https://publicsuffix.org/) rules."""

    def __init__(self, path=None):
        self.rules = set()
        self.wildcards = set()
        self.exceptions = set()
        with open(path or PSL_PATH, encoding="utf-8") as f:
            for line in f:
                rule = line.split(maxsplit=1)[0] if line.strip() else ""
                if not rule or rule.startswith("//"):
                    continue
                rule = _to_ascii(rule.lower())
                if rule.startswith("!"):
                    self.exceptions.add(rule[1:])
                elif rule.startswith("*."):
                    self.wildcards.add(rule[2:])
                else:
                    self.rules.add(rule)

    def is_public_suffix(self, domain):
        if domain in self.exceptions:
            return False
        if domain in self.rules:
            return True
        labels = domain.split(".")
        if len(labels) == 1:
            return True  # the implicit "*" rule: every TLD is a public suffix
        return ".".join(labels[1:]) in self.wildcards


def _to_ascii(name):
    try:
        return ".".join(
            label.encode("idna").decode("ascii") if label and label != "*" else label
            for label in name.split(".")
        )
    except UnicodeError:
        return name


_psl = None


def public_suffix_list():
    global _psl
    if _psl is None:
        _psl = PublicSuffixList()
    return _psl


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def origin_host(origin):
    """Return the host of a secure ``origin`` or raise SecurityError."""
    if not isinstance(origin, str):
        raise WebAuthnError("SecurityError", "missing origin")
    parts = urlsplit(origin)
    host = (parts.hostname or "").lower()
    if parts.path not in ("", "/") or parts.query or parts.fragment or not host:
        raise WebAuthnError("SecurityError", "not an origin: %s" % origin)
    if parts.scheme == "https":
        return host
    # http is a secure context only for loopback hosts.
    if parts.scheme == "http" and (
        host == "localhost" or host.endswith(".localhost") or host in ("127.0.0.1", "::1")
    ):
        return host
    raise WebAuthnError("SecurityError", "%s is not a secure context" % origin)


def check_rp_id(rp_id, origin, psl=None):
    """Return the effective RP ID for ``origin`` (WebAuthn 5.1.3 step 8)."""
    host = origin_host(origin)
    if rp_id is None:
        return host
    if not isinstance(rp_id, str) or not rp_id:
        raise WebAuthnError("SecurityError", "invalid rp.id")
    rp_id = rp_id.lower()
    if rp_id == host:
        return rp_id
    if _is_ip(host) or not host.endswith("." + rp_id):
        raise WebAuthnError("SecurityError", "%s is not valid for %s" % (rp_id, origin))
    try:
        psl = psl or public_suffix_list()
    except OSError:
        # Without the list a suffix cannot be told from a public suffix.
        raise WebAuthnError("SecurityError", "the Public Suffix List is unavailable")
    if psl.is_public_suffix(rp_id):
        raise WebAuthnError("SecurityError", "%s is a public suffix" % rp_id)
    return rp_id


def client_data_json(type_, challenge, origin, top_origin=None):
    """Serialize CollectedClientData (WebAuthn 5.8.1.1) with fields in order."""
    parts = [
        '"type":' + json.dumps(type_),
        '"challenge":' + json.dumps(b64url(challenge)),
        '"origin":' + json.dumps(origin, ensure_ascii=False),
        '"crossOrigin":' + ("true" if top_origin else "false"),
    ]
    if top_origin:
        parts.append('"topOrigin":' + json.dumps(top_origin, ensure_ascii=False))
    return ("{" + ",".join(parts) + "}").encode("utf-8")


# -- helpers --------------------------------------------------------------


def _dict(value, what):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise WebAuthnError("TypeError", "%s must be an object" % what)
    return value


def _credential_list(items, what):
    if items is None:
        return []
    if not isinstance(items, list):
        raise WebAuthnError("TypeError", "%s must be a list" % what)
    out = []
    for item in items:
        item = _dict(item, what)
        if item.get("type", "public-key") != "public-key":
            continue
        out.append({"type": "public-key", "id": unb64url(item.get("id"), what + ".id")})
    return out


def _wants_cross_platform(options):
    selection = _dict(options.get("authenticatorSelection"), "authenticatorSelection")
    if selection.get("authenticatorAttachment") == "cross-platform":
        return True
    hints = options.get("hints") or []
    return bool(hints) and hints[0] in ("security-key", "hybrid")


def _run(authenticator, cmd, params, request):
    try:
        return authenticator.execute(cmd, params, request)
    except CtapError as e:
        log.info("platform command 0x%02x failed: %s", cmd, e)
        if e.code == ERR_CREDENTIAL_EXCLUDED:
            raise WebAuthnError("InvalidStateError", "this device is already registered")
        if e.code in (ERR_UNSUPPORTED_ALGORITHM, ERR_UNSUPPORTED_OPTION):
            raise WebAuthnError("NotSupportedError", str(e))
        raise WebAuthnError("NotAllowedError", str(e))


def _parse_attested(auth_data):
    """Return (credential_id, cose_key) from attested credential data."""
    pos = 32 + 1 + 4 + 16
    (length,) = struct.unpack(">H", auth_data[pos:pos + 2])
    cred_id = auth_data[pos + 2:pos + 2 + length]
    cose, _ = cbor.decode_from(auth_data[pos + 2 + length:])
    return cred_id, cose


def _spki(cose):
    alg = cose[3]
    if alg == keys.ES256:
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()
        ).public_key()
    elif alg == keys.EDDSA:
        public = ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    else:
        return None
    return public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# -- ceremonies -----------------------------------------------------------


def create(authenticator, origin, options, request, top_origin=None):
    """navigator.credentials.create() for PublicKeyCredentialCreationOptionsJSON."""
    options = _dict(options, "publicKey")
    if _wants_cross_platform(options):
        raise WebAuthnError("NotSupportedError", "the site asked for another device")
    rp = _dict(options.get("rp"), "rp")
    rp_id = check_rp_id(rp.get("id"), origin)
    user = _dict(options.get("user"), "user")
    user_id = unb64url(user.get("id"), "user.id")
    if not 0 < len(user_id) <= 64:
        raise WebAuthnError("TypeError", "user.id must be 1 to 64 bytes")
    challenge = unb64url(options.get("challenge"), "challenge")

    algs = []
    for p in options.get("pubKeyCredParams") or []:
        p = _dict(p, "pubKeyCredParams")
        if p.get("type") == "public-key" and isinstance(p.get("alg"), int):
            algs.append(p["alg"])
    if not options.get("pubKeyCredParams"):
        algs = list(DEFAULT_ALGORITHMS)

    selection = _dict(options.get("authenticatorSelection"), "authenticatorSelection")
    resident = selection.get("residentKey")
    if resident is None:
        resident = "required" if selection.get("requireResidentKey") else "discouraged"
    rk = resident in ("required", "preferred")
    uv_requirement = selection.get("userVerification", "preferred")
    # Like other platform authenticators, verify unless the site says not to;
    # discoverable credentials always need it (see Authenticator.make_credential).
    uv = rk or uv_requirement != "discouraged"
    if uv and not authenticator.uv_available:
        if uv_requirement == "required":
            raise WebAuthnError("NotSupportedError", "user verification is turned off")
        uv = False

    extensions = _dict(options.get("extensions"), "extensions")
    ctap_ext = {}
    policy = extensions.get("credentialProtectionPolicy")
    if policy in CRED_PROTECT:
        ctap_ext["credProtect"] = CRED_PROTECT[policy]
    if "prf" in extensions:
        ctap_ext["hmac-secret"] = True

    client_data = client_data_json("webauthn.create", challenge, origin, top_origin)
    params = {
        1: hashlib.sha256(client_data).digest(),
        2: {"id": rp_id, "name": str(rp.get("name") or rp_id)},
        3: {
            "id": user_id,
            "name": str(user.get("name") or ""),
            "displayName": str(user.get("displayName") or ""),
        },
        4: [{"type": "public-key", "alg": alg} for alg in algs],
        7: {"rk": rk, "uv": uv},
    }
    exclude = _credential_list(options.get("excludeCredentials"), "excludeCredentials")
    if exclude:
        params[5] = exclude
    if ctap_ext:
        params[6] = ctap_ext

    result = _run(authenticator, CMD_MAKE_CREDENTIAL, params, request)
    auth_data = result[2]
    if options.get("attestation") in ("direct", "enterprise", "indirect"):
        fmt, statement = result[1], result[3]
    else:
        fmt, statement = "none", {}
    attestation = cbor.encode({"fmt": fmt, "attStmt": statement, "authData": auth_data})
    cred_id, cose = _parse_attested(auth_data)

    ext_out = {}
    if extensions.get("credProps"):
        ext_out["credProps"] = {"rk": rk}
    if "prf" in extensions:
        ext_out["prf"] = {"enabled": True}

    response = {
        "clientDataJSON": b64url(client_data),
        "attestationObject": b64url(attestation),
        "authenticatorData": b64url(auth_data),
        "transports": ["internal"],
        "publicKeyAlgorithm": cose[3],
    }
    spki = _spki(cose)
    if spki is not None:
        response["publicKey"] = b64url(spki)
    return {
        "id": b64url(cred_id),
        "rawId": b64url(cred_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
        "clientExtensionResults": ext_out,
    }


def get(authenticator, origin, options, request, top_origin=None):
    """navigator.credentials.get() for PublicKeyCredentialRequestOptionsJSON."""
    options = _dict(options, "publicKey")
    rp_id = check_rp_id(options.get("rpId"), origin)
    challenge = unb64url(options.get("challenge"), "challenge")
    uv = options.get("userVerification", "preferred") != "discouraged"
    if uv and not authenticator.uv_available:
        if options.get("userVerification") == "required":
            raise WebAuthnError("NotSupportedError", "user verification is turned off")
        uv = False

    client_data = client_data_json("webauthn.get", challenge, origin, top_origin)
    params = {
        1: rp_id,
        2: hashlib.sha256(client_data).digest(),
        5: {"uv": uv},
    }
    allow = _credential_list(options.get("allowCredentials"), "allowCredentials")
    if allow:
        params[3] = allow

    result = _run(authenticator, CMD_GET_ASSERTION, params, request)
    cred_id = result[1]["id"]
    user = result.get(4) or {}
    return {
        "id": b64url(cred_id),
        "rawId": b64url(cred_id),
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64url(client_data),
            "authenticatorData": b64url(result[2]),
            "signature": b64url(result[3]),
            "userHandle": b64url(user["id"]) if "id" in user else None,
        },
        "clientExtensionResults": {},
    }


def has_credentials(store, origin, options):
    """True if a get() with ``options`` could find one of our credentials.

    The extension asks this first, so sign-ins with another authenticator
    (a hardware key or a phone) go straight to the browser's own dialog.
    """
    options = _dict(options, "publicKey")
    rp_id = check_rp_id(options.get("rpId"), origin)
    allow = _credential_list(options.get("allowCredentials"), "allowCredentials")
    if not allow:
        return bool(store.residents_for(rp_id))
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    return any(store.lookup(rp_id_hash, c["id"]) is not None for c in allow)
