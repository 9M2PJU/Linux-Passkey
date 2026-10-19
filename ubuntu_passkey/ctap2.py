"""CTAP2 authenticator logic (FIDO Client to Authenticator Protocol 2.0)."""

import hashlib
import hmac
import logging
import os
import struct
import threading
import time
import uuid

from . import cbor, keys
from .pinuv import PROTOCOLS, KeyAgreement, ProtocolError
from .store import b64d, b64e

log = logging.getLogger(__name__)

AAGUID = uuid.UUID("5a5b2c1e-6f3d-4b7a-9c2e-8d1f0a3b4c5d").bytes

# Commands
CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08
CMD_CREDENTIAL_MANAGEMENT = 0x0A
CMD_SELECTION = 0x0B

# Status codes
OK = 0x00
ERR_INVALID_COMMAND = 0x01
ERR_INVALID_PARAMETER = 0x02
ERR_INVALID_LENGTH = 0x03
ERR_INVALID_CBOR = 0x12
ERR_CBOR_UNEXPECTED_TYPE = 0x11
ERR_MISSING_PARAMETER = 0x14
ERR_CREDENTIAL_EXCLUDED = 0x19
ERR_UNSUPPORTED_ALGORITHM = 0x26
ERR_OPERATION_DENIED = 0x27
ERR_UNSUPPORTED_OPTION = 0x2B
ERR_INVALID_OPTION = 0x2C
ERR_KEEPALIVE_CANCEL = 0x2D
ERR_NO_CREDENTIALS = 0x2E
ERR_USER_ACTION_TIMEOUT = 0x2F
ERR_NOT_ALLOWED = 0x30
ERR_PIN_AUTH_INVALID = 0x33
ERR_PIN_NOT_SET = 0x35
ERR_PUAT_REQUIRED = 0x36
ERR_INVALID_SUBCOMMAND = 0x3E
ERR_UV_INVALID = 0x3F
ERR_UNAUTHORIZED_PERMISSION = 0x40
ERR_OTHER = 0x7F

# Keepalive status
STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2

# authenticatorData flags
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80

ALG_NAMES = {"ES256": keys.ES256, "EdDSA": keys.EDDSA}
MAX_CRED_IDS_IN_LIST = 16
MAX_CRED_ID_LENGTH = 128
NEXT_ASSERTION_TIMEOUT = 30
TOKEN_LIFETIME = 30

# clientPin subcommands
PIN_GET_RETRIES = 0x01
PIN_GET_KEY_AGREEMENT = 0x02
PIN_GET_TOKEN_USING_UV = 0x06
PIN_GET_UV_RETRIES = 0x07

PERMISSION_MC = 0x01
PERMISSION_GA = 0x02
PERMISSION_CM = 0x04

# authenticatorCredentialManagement subcommands
CM_GET_METADATA = 0x01
CM_ENUMERATE_RPS_BEGIN = 0x02
CM_ENUMERATE_RPS_NEXT = 0x03
CM_ENUMERATE_CREDS_BEGIN = 0x04
CM_ENUMERATE_CREDS_NEXT = 0x05
CM_DELETE_CREDENTIAL = 0x06
CM_UPDATE_USER = 0x07

# No fixed limit; reported as the remaining discoverable credential capacity.
RESIDENT_CAPACITY = 10000

# authenticatorReset is only honoured this soon after the device appears
# (CTAP 2.1 section 6.6); the Passkeys app offers a reset at any time.
RESET_WINDOW = 10


class CtapError(Exception):
    def __init__(self, code, message=""):
        super().__init__(message or "CTAP error 0x%02x" % code)
        self.code = code


# Raised by the user interface layer.
class Denied(Exception):
    pass


class Timeout(Exception):
    pass


class Cancelled(Exception):
    pass


class Request:
    """Context for one CTAP command: cancellation and keepalive reporting."""

    def __init__(self, cancel=None, keepalive=None):
        self.cancel = cancel or threading.Event()
        self._keepalive = keepalive

    def status(self, code):
        if self._keepalive:
            self._keepalive(code)


class Prompt:
    """Describes what the user is asked to approve."""

    def __init__(self, operation, rp_id="", rp_name="", accounts=(), verify=False):
        # register | authenticate | choose | exclude | select | reset
        self.operation = operation
        self.rp_id = rp_id
        self.rp_name = rp_name or rp_id
        self.accounts = list(accounts)
        self.verify = verify


def _require(params, key, kind):
    if key not in params:
        raise CtapError(ERR_MISSING_PARAMETER, "missing parameter %r" % key)
    value = params[key]
    if not isinstance(value, kind):
        raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "parameter %r has wrong type" % key)
    return value


def _optional(params, key, kind, default=None):
    if key not in params:
        return default
    value = params[key]
    if not isinstance(value, kind):
        raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "parameter %r has wrong type" % key)
    return value


def _options(params, key):
    opts = _optional(params, key, dict, {})
    for name, value in opts.items():
        if not isinstance(name, str) or not isinstance(value, bool):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad options map")
    return opts


def _credential_list(params, key):
    out = []
    for desc in _optional(params, key, list, []):
        if not isinstance(desc, dict):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad credential descriptor")
        cid = desc.get("id")
        ctype = desc.get("type")
        if not isinstance(cid, bytes) or not isinstance(ctype, str):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad credential descriptor")
        if ctype == "public-key":
            out.append(cid)
    return out


def account_label(name, display_name):
    if display_name and name and display_name != name:
        return "%s (%s)" % (display_name, name)
    return display_name or name or "Unnamed account"


class _Token:
    """A pinUvAuthToken obtained through built-in user verification."""

    def __init__(self, protocol, permissions, rp_id, user_present):
        self.value = os.urandom(32)
        self.protocol = protocol
        self.permissions = permissions
        self.rp_id = rp_id
        self.user_present = user_present
        self.expires = time.monotonic() + TOKEN_LIFETIME

    @property
    def valid(self):
        return time.monotonic() < self.expires


class _HmacSecretInput:
    """Validated input of the hmac-secret extension for getAssertion."""

    def __init__(self, key_agreement, ext):
        if not isinstance(ext, dict):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad hmac-secret input")
        version = ext.get(4, 1)
        protocol = PROTOCOLS.get(version)
        if protocol is None:
            raise CtapError(ERR_INVALID_PARAMETER, "unsupported PIN/UV protocol")
        salt_enc, salt_auth = ext.get(2), ext.get(3)
        if not isinstance(salt_enc, bytes) or not isinstance(salt_auth, bytes):
            raise CtapError(ERR_MISSING_PARAMETER, "hmac-secret salts missing")
        try:
            self.shared = key_agreement.shared_secret(protocol, ext.get(1))
        except ProtocolError as e:
            raise CtapError(ERR_INVALID_PARAMETER, str(e))
        if not protocol.verify(self.shared, salt_enc, salt_auth):
            raise CtapError(ERR_PIN_AUTH_INVALID, "bad hmac-secret saltAuth")
        try:
            salts = protocol.decrypt(self.shared, salt_enc)
        except ProtocolError as e:
            raise CtapError(ERR_INVALID_LENGTH, str(e))
        if len(salts) not in (32, 64):
            raise CtapError(ERR_INVALID_LENGTH, "bad hmac-secret salt length")
        self.protocol = protocol
        self.salts = [salts[:32]] + ([salts[32:]] if len(salts) == 64 else [])

    def output(self, seed, uv):
        cred_random = hmac.new(seed, b"uv" if uv else b"no-uv", hashlib.sha256).digest()
        out = b"".join(
            hmac.new(cred_random, salt, hashlib.sha256).digest() for salt in self.salts
        )
        return self.protocol.encrypt(self.shared, out)


class Authenticator:
    """Implements CTAP2 commands on top of a CredentialStore.

    ``ui`` must provide:
      * ``confirm(prompt, request) -> int``: ask the user to approve; returns the
        index of the chosen account (0 when there is no choice) or raises
        Denied / Timeout / Cancelled.
      * ``verify(prompt, request) -> bool``: perform user verification.
    """

    def __init__(self, store, ui, config, on_reset=None):
        self.store = store
        self.ui = ui
        self.config = config
        self.on_reset = on_reset
        self._next = None  # pending getNextAssertion state
        self._cm_state = None  # pending credential management enumeration
        self._token = None
        self.key_agreement = KeyAgreement()
        self.powered_up = time.monotonic()

    # -- helpers ----------------------------------------------------------

    @property
    def uv_available(self):
        return self.config.get("verification") != "none"

    def _allowed_algorithms(self):
        return [ALG_NAMES[a] for a in self.config.get("algorithms") if a in ALG_NAMES]

    def _confirm(self, prompt, request):
        request.status(STATUS_UPNEEDED)
        try:
            return self.ui.confirm(prompt, request)
        except Denied:
            raise CtapError(ERR_OPERATION_DENIED, "user denied the request")
        except Timeout:
            raise CtapError(ERR_USER_ACTION_TIMEOUT, "approval timed out")
        except Cancelled:
            raise CtapError(ERR_KEEPALIVE_CANCEL, "cancelled by the client")
        finally:
            request.status(STATUS_PROCESSING)

    def _verify(self, prompt, request):
        request.status(STATUS_UPNEEDED)
        try:
            ok = self.ui.verify(prompt, request)
        except Denied:
            raise CtapError(ERR_OPERATION_DENIED, "user verification dismissed")
        except Cancelled:
            raise CtapError(ERR_KEEPALIVE_CANCEL, "cancelled by the client")
        except Timeout:
            raise CtapError(ERR_USER_ACTION_TIMEOUT, "verification timed out")
        finally:
            request.status(STATUS_PROCESSING)
        if request.cancel.is_set():
            raise CtapError(ERR_KEEPALIVE_CANCEL, "cancelled by the client")
        if not ok:
            # The platform may let the user try again (CTAP 2.1 section 6.5.5.7.3).
            raise CtapError(ERR_UV_INVALID, "user verification failed")

    def _auth_data(self, rp_id_hash, flags, attested=b"", extensions=None):
        if extensions:
            flags |= FLAG_ED
        data = rp_id_hash + bytes([flags]) + struct.pack(">I", self.store.next_counter())
        data += attested
        if extensions:
            data += cbor.encode(extensions)
        return data

    def _pin_uv_auth(
        self, params, key, client_data_hash, permission, rp_id, request, use_presence=True
    ):
        """Validate pinUvAuthParam; return (user_verified, user_present).

        The presence collected while issuing the token is spent only by a
        request that needs it, so silent (up=false) probes leave it intact.
        """
        if key not in params:
            return False, False
        pin_auth = params[key]
        if not isinstance(pin_auth, bytes):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad pinUvAuthParam")
        if len(pin_auth) == 0:
            # Platform probe used to let the user pick an authenticator.
            self._confirm(Prompt("select"), request)
            raise CtapError(ERR_PIN_NOT_SET)
        version = params.get(key + 1)
        if version is None:
            raise CtapError(ERR_MISSING_PARAMETER, "pinUvAuthProtocol missing")
        protocol = PROTOCOLS.get(version)
        if protocol is None:
            raise CtapError(ERR_INVALID_PARAMETER, "unsupported PIN/UV protocol")
        token = self._token
        if token is None or not token.valid or token.protocol is not protocol:
            raise CtapError(ERR_PIN_AUTH_INVALID, "no valid pinUvAuthToken")
        if not protocol.verify(token.value, client_data_hash, pin_auth):
            raise CtapError(ERR_PIN_AUTH_INVALID, "pinUvAuthParam mismatch")
        if not token.permissions & permission:
            raise CtapError(ERR_PIN_AUTH_INVALID, "token lacks permission")
        if token.rp_id is None:
            token.rp_id = rp_id
        elif token.rp_id != rp_id:
            raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to another RP")
        user_present = token.user_present and use_presence
        if use_presence:
            token.user_present = False
        if permission == PERMISSION_MC:
            token.permissions &= ~PERMISSION_MC
        return True, user_present

    # -- dispatch ---------------------------------------------------------

    def process(self, data, request=None):
        """Process one CTAP2 message; return status byte + CBOR response."""
        request = request or Request()
        if not data:
            return bytes([ERR_INVALID_LENGTH])
        cmd, payload = data[0], data[1:]
        try:
            params = {}
            if payload:
                try:
                    params = cbor.decode(payload)
                except cbor.CBORError:
                    raise CtapError(ERR_INVALID_CBOR, "invalid CBOR")
                if not isinstance(params, dict):
                    raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "expected a map")
            handler = {
                CMD_MAKE_CREDENTIAL: self.make_credential,
                CMD_GET_ASSERTION: self.get_assertion,
                CMD_GET_INFO: self.get_info,
                CMD_CLIENT_PIN: self.client_pin,
                CMD_RESET: self.reset,
                CMD_GET_NEXT_ASSERTION: self.get_next_assertion,
                CMD_SELECTION: self.selection,
                CMD_CREDENTIAL_MANAGEMENT: self.credential_management,
            }.get(cmd)
            if handler is None:
                raise CtapError(ERR_INVALID_COMMAND, "unsupported command 0x%02x" % cmd)
            if cmd != CMD_GET_NEXT_ASSERTION:
                self._next = None
            if cmd != CMD_CREDENTIAL_MANAGEMENT:
                self._cm_state = None
            result = handler(params, request)
        except CtapError as e:
            log.info("command 0x%02x failed: %s", cmd, e)
            return bytes([e.code])
        except Exception:
            log.exception("command 0x%02x crashed", cmd)
            return bytes([ERR_OTHER])
        if result is None:
            return bytes([OK])
        return bytes([OK]) + cbor.encode(result)

    # -- commands ---------------------------------------------------------

    def get_info(self, params, request):
        options = {"rk": True, "up": True, "plat": False, "makeCredUvNotRqd": True}
        if self.uv_available:
            options["uv"] = True
            options["pinUvAuthToken"] = True
            options["credMgmt"] = True
        return {
            1: ["FIDO_2_0", "FIDO_2_1"],
            2: ["credProtect", "hmac-secret"],
            3: AAGUID,
            4: options,
            5: 1200,
            6: [2, 1],
            7: MAX_CRED_IDS_IN_LIST,
            8: MAX_CRED_ID_LENGTH,
            9: ["usb"],
            10: [
                {"type": "public-key", "alg": alg}
                for alg in self._allowed_algorithms()
            ],
            14: 1,
            20: max(0, RESIDENT_CAPACITY - len(self.store.list())),
        }

    def client_pin(self, params, request):
        sub = _require(params, 2, int)
        if sub == PIN_GET_KEY_AGREEMENT:
            if _require(params, 1, int) not in PROTOCOLS:
                raise CtapError(ERR_INVALID_PARAMETER, "unsupported PIN/UV protocol")
            return {1: self.key_agreement.cose()}
        if sub == PIN_GET_RETRIES:
            return {3: 8}
        if sub == PIN_GET_UV_RETRIES:
            return {5: 8}
        if sub == PIN_GET_TOKEN_USING_UV:
            return self._token_using_uv(params, request)
        raise CtapError(ERR_INVALID_SUBCOMMAND, "unsupported clientPin subcommand")

    def _token_using_uv(self, params, request):
        if not self.uv_available:
            raise CtapError(ERR_NOT_ALLOWED, "user verification disabled")
        protocol = PROTOCOLS.get(_require(params, 1, int))
        if protocol is None:
            raise CtapError(ERR_INVALID_PARAMETER, "unsupported PIN/UV protocol")
        peer = _require(params, 3, dict)
        permissions = _require(params, 9, int)
        rp_id = _optional(params, 10, str)
        if permissions == 0:
            raise CtapError(ERR_INVALID_PARAMETER, "no permissions requested")
        if permissions & ~(PERMISSION_MC | PERMISSION_GA | PERMISSION_CM):
            raise CtapError(ERR_UNAUTHORIZED_PERMISSION)
        try:
            shared = self.key_agreement.shared_secret(protocol, peer)
        except ProtocolError as e:
            raise CtapError(ERR_INVALID_PARAMETER, str(e))
        self._token = None
        if permissions & PERMISSION_MC:
            operation = "register"
        elif permissions & PERMISSION_GA:
            operation = "authenticate"
        else:
            operation = "manage"
        prompt = Prompt(operation, rp_id or "", rp_id or "", [], True)
        self._confirm(prompt, request)
        self._verify(prompt, request)
        token = _Token(protocol, permissions, rp_id, user_present=True)
        self._token = token
        return {2: protocol.encrypt(shared, token.value)}

    def make_credential(self, params, request):
        client_data_hash = _require(params, 1, bytes)
        rp = _require(params, 2, dict)
        user = _require(params, 3, dict)
        cred_params = _require(params, 4, list)
        rp_id = rp.get("id")
        if not isinstance(rp_id, str) or not rp_id:
            raise CtapError(ERR_MISSING_PARAMETER, "rp.id missing")
        user_id = user.get("id")
        if not isinstance(user_id, bytes) or not 0 < len(user_id) <= 64:
            raise CtapError(ERR_INVALID_PARAMETER, "bad user.id")
        if len(client_data_hash) != 32:
            raise CtapError(ERR_INVALID_LENGTH, "bad clientDataHash")
        for field in ("name",):
            if not isinstance(rp.get(field, ""), str):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad rp entity")
        for field in ("name", "displayName"):
            if not isinstance(user.get(field, ""), str):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad user entity")

        alg = None
        allowed = self._allowed_algorithms()
        for p in cred_params:
            if not isinstance(p, dict):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad pubKeyCredParams")
            if p.get("type") == "public-key" and p.get("alg") in allowed:
                alg = p["alg"]
                break
        if alg is None:
            raise CtapError(ERR_UNSUPPORTED_ALGORITHM)

        if 10 in params:
            # enterpriseAttestation needs the "ep" option, which is not offered.
            raise CtapError(ERR_INVALID_PARAMETER, "enterprise attestation unsupported")
        exclude = _credential_list(params, 5)
        extensions = _optional(params, 6, dict, {})
        options = _options(params, 7)
        if options.get("up") is False:
            raise CtapError(ERR_INVALID_OPTION, "up=false is invalid for makeCredential")
        if options.get("uv") and not self.uv_available:
            raise CtapError(ERR_UNSUPPORTED_OPTION, "user verification disabled")
        rk = options.get("rk", False)

        account = account_label(user.get("name", ""), user.get("displayName", ""))
        token_uv, token_up = self._pin_uv_auth(
            params, 8, client_data_hash, PERMISSION_MC, rp_id, request
        )
        if rp_id == ".dummy":
            # Browsers use a dummy registration to let the user pick a device.
            if not token_up:
                self._confirm(Prompt("select"), request)
            raise CtapError(ERR_OPERATION_DENIED)

        if (
            rk
            and self.uv_available
            and not token_uv
            and not options.get("uv")
            and not self.config.get("always_verify")
        ):
            # Discoverable credentials always need user verification when the
            # authenticator is protected by it (CTAP 2.1 section 6.1.2, step 11).
            raise CtapError(ERR_PUAT_REQUIRED)

        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        for cid in exclude:
            if self.store.lookup(rp_id_hash, cid) is not None:
                self._confirm(
                    Prompt("exclude", rp_id, rp.get("name", ""), [account]), request
                )
                raise CtapError(ERR_CREDENTIAL_EXCLUDED)

        cred_protect = extensions.get("credProtect", 1)
        if not isinstance(cred_protect, int) or cred_protect not in (1, 2, 3):
            cred_protect = 1

        need_uv = not token_uv and self.uv_available and (
            options.get("uv", False) or self.config.get("always_verify")
        )
        prompt = Prompt("register", rp_id, rp.get("name", ""), [account], need_uv)
        if not token_up:
            self._confirm(prompt, request)
        if need_uv:
            self._verify(prompt, request)
        do_uv = token_uv or need_uv

        cred_id, private_key = self.store.create(rp_id_hash, alg, rk, cred_protect)
        attested = (
            AAGUID
            + struct.pack(">H", len(cred_id))
            + cred_id
            + cbor.encode(keys.cose_public_key(alg, private_key))
        )
        ext_out = {}
        if cred_protect > 1:
            ext_out["credProtect"] = cred_protect
        if extensions.get("hmac-secret") is True:
            ext_out["hmac-secret"] = True
        flags = FLAG_UP | FLAG_AT | (FLAG_UV if do_uv else 0)
        auth_data = self._auth_data(rp_id_hash, flags, attested, ext_out)
        if rk:
            self.store.add_resident(cred_id, rp, user, alg, cred_protect)
        sig = keys.sign(alg, private_key, auth_data + client_data_hash)
        # Site names stay out of the journal unless debugging.
        log.debug("registered %s credential for %s", "discoverable" if rk else "", rp_id)
        return {1: "packed", 2: auth_data, 3: {"alg": alg, "sig": sig}}

    def get_assertion(self, params, request):
        rp_id = _require(params, 1, str)
        client_data_hash = _require(params, 2, bytes)
        if len(client_data_hash) != 32:
            raise CtapError(ERR_INVALID_LENGTH, "bad clientDataHash")
        allow = _credential_list(params, 3)
        extensions = _optional(params, 4, dict, {})
        options = _options(params, 5)
        if "rk" in options:
            raise CtapError(ERR_INVALID_OPTION, "rk is invalid for getAssertion")
        if options.get("uv") and not self.uv_available:
            raise CtapError(ERR_UNSUPPORTED_OPTION, "user verification disabled")
        up = options.get("up", True)
        token_uv, token_up = self._pin_uv_auth(
            params, 6, client_data_hash, PERMISSION_GA, rp_id, request, use_presence=up
        )
        need_uv = not token_uv and self.uv_available and (
            options.get("uv", False) or (up and self.config.get("always_verify"))
        )
        do_uv = token_uv or need_uv
        hmac_input = None
        if "hmac-secret" in extensions:
            hmac_input = _HmacSecretInput(self.key_agreement, extensions["hmac-secret"])

        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        creds = []
        if allow:
            for cid in allow:
                cred = self.store.lookup(rp_id_hash, cid)
                if cred is None:
                    continue
                if cred.cred_protect == 3 and not do_uv:
                    continue
                creds.append(cred)
        else:
            for rec in self.store.residents_for(rp_id):
                cred = self.store.lookup(rp_id_hash, b64d(rec["id"]))
                if cred is None:
                    continue
                if cred.cred_protect >= 2 and not do_uv:
                    continue
                creds.append(cred)
        if not creds:
            raise CtapError(ERR_NO_CREDENTIALS)

        if allow:
            # Use the first matching credential, as the specification requires.
            creds = creds[:1]

        chosen = 0
        user_selected = False
        if up or need_uv:
            accounts = [
                account_label(c.record["user_name"], c.record["display_name"])
                if c.record
                else ""
                for c in creds
            ]
            if up and token_up:
                # Presence was confirmed while issuing the token; only an
                # account choice is still needed.
                if len(creds) > 1:
                    chosen = self._confirm(
                        Prompt("choose", rp_id, rp_id, accounts), request
                    )
            elif up:
                chosen = self._confirm(
                    Prompt("authenticate", rp_id, rp_id, accounts, need_uv), request
                )
            if not 0 <= chosen < len(creds):
                chosen = 0
            user_selected = up and len(creds) > 1
            if need_uv:
                self._verify(Prompt("authenticate", rp_id, rp_id, accounts, True), request)
            creds = [creds[chosen]]

        flags = (FLAG_UP if up else 0) | (FLAG_UV if do_uv else 0)
        response = self._assertion(
            creds[0], rp_id_hash, client_data_hash, flags, do_uv, hmac_input
        )
        if user_selected:
            response[6] = True
        if len(creds) > 1:
            # Silent discoverable lookup: the platform iterates with getNextAssertion.
            response[5] = len(creds)
            self._next = {
                "creds": creds[1:],
                "rp_id_hash": rp_id_hash,
                "client_data_hash": client_data_hash,
                "flags": flags,
                "uv": do_uv,
                "hmac": hmac_input,
                "deadline": time.monotonic() + NEXT_ASSERTION_TIMEOUT,
            }
        return response

    def get_next_assertion(self, params, request):
        state = self._next
        if not state or not state["creds"] or time.monotonic() > state["deadline"]:
            self._next = None
            raise CtapError(ERR_NOT_ALLOWED)
        cred = state["creds"].pop(0)
        state["deadline"] = time.monotonic() + NEXT_ASSERTION_TIMEOUT
        return self._assertion(
            cred,
            state["rp_id_hash"],
            state["client_data_hash"],
            state["flags"],
            state["uv"],
            state["hmac"],
        )

    def _assertion(self, cred, rp_id_hash, client_data_hash, flags, uv, hmac_input=None):
        ext_out = None
        if hmac_input is not None and cred.hmac_seed:
            ext_out = {"hmac-secret": hmac_input.output(cred.hmac_seed, uv)}
        auth_data = self._auth_data(rp_id_hash, flags, extensions=ext_out)
        sig = keys.sign(cred.alg, cred.private_key, auth_data + client_data_hash)
        response = {
            1: {"type": "public-key", "id": cred.id},
            2: auth_data,
            3: sig,
        }
        if cred.record:
            user = {"id": b64d(cred.record["user_id"])}
            if uv:
                if cred.record["user_name"]:
                    user["name"] = cred.record["user_name"]
                if cred.record["display_name"]:
                    user["displayName"] = cred.record["display_name"]
            response[4] = user
            if flags & FLAG_UP:
                self.store.mark_used(cred.id)
        return response

    def selection(self, params, request):
        self._confirm(Prompt("select"), request)
        return None

    def reset(self, params, request):
        if time.monotonic() - self.powered_up > RESET_WINDOW:
            raise CtapError(ERR_NOT_ALLOWED, "reset is only allowed right after power-up")
        prompt = Prompt("reset", verify=self.uv_available)
        self._confirm(prompt, request)
        if self.uv_available:
            self._verify(prompt, request)
        if self.on_reset is None:
            raise CtapError(ERR_NOT_ALLOWED)
        self.on_reset()
        self._token = None
        self.key_agreement.regenerate()
        log.warning("authenticator reset: all credentials deleted")
        return None

    # -- authenticatorCredentialManagement -------------------------------

    def credential_management(self, params, request):
        sub = _require(params, 1, int)
        if sub == CM_ENUMERATE_RPS_NEXT:
            return self._cm_next("rps")
        if sub == CM_ENUMERATE_CREDS_NEXT:
            return self._cm_next("creds")
        self._cm_state = None
        sub_params = _optional(params, 2, dict)
        token = self._cm_token(params, sub, sub_params)

        if sub == CM_GET_METADATA:
            if token.rp_id is not None:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to an RP")
            count = len(self.store.list())
            return {1: count, 2: max(0, RESIDENT_CAPACITY - count)}

        if sub == CM_ENUMERATE_RPS_BEGIN:
            if token.rp_id is not None:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to an RP")
            rps = {}
            for rec in sorted(self.store.list(), key=lambda r: r["rp_id"]):
                rps.setdefault(rec["rp_id"], rec.get("rp_name") or "")
            if not rps:
                raise CtapError(ERR_NO_CREDENTIALS)
            items = []
            for rp_id, name in rps.items():
                entity = {"id": rp_id}
                if name and name != rp_id:
                    entity["name"] = name
                items.append({3: entity, 4: hashlib.sha256(rp_id.encode()).digest()})
            first = dict(items[0])
            first[5] = len(items)
            self._cm_state = ("rps", items[1:])
            return first

        if sub == CM_ENUMERATE_CREDS_BEGIN:
            rp_id_hash = _require(sub_params or {}, 1, bytes)
            self._cm_check_rp(token, rp_id_hash)
            items = [
                self._cm_credential(rec, rp_id_hash)
                for rec in self._records_for_hash(rp_id_hash)
            ]
            items = [i for i in items if i is not None]
            if not items:
                raise CtapError(ERR_NO_CREDENTIALS)
            first = dict(items[0])
            first[9] = len(items)
            self._cm_state = ("creds", items[1:])
            return first

        if sub in (CM_DELETE_CREDENTIAL, CM_UPDATE_USER):
            desc = _require(sub_params or {}, 2, dict)
            cred_id = desc.get("id")
            if not isinstance(cred_id, bytes):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad credential descriptor")
            rec = self.store.record(b64e(cred_id))
            if rec is None:
                raise CtapError(ERR_NO_CREDENTIALS)
            self._cm_check_rp(token, hashlib.sha256(rec["rp_id"].encode()).digest())
            if sub == CM_DELETE_CREDENTIAL:
                self.store.delete(rec["id"])
                return None
            user = _require(sub_params, 3, dict)
            if user.get("id") != b64d(rec["user_id"]):
                raise CtapError(ERR_INVALID_PARAMETER, "user.id does not match")
            for field in ("name", "displayName"):
                if not isinstance(user.get(field, ""), str):
                    raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "bad user entity")
            self.store.update_user(
                rec["id"], user.get("name", ""), user.get("displayName", "")
            )
            return None

        raise CtapError(ERR_INVALID_SUBCOMMAND)

    def _cm_token(self, params, sub, sub_params):
        if 4 not in params:
            raise CtapError(ERR_PUAT_REQUIRED)
        pin_auth = _require(params, 4, bytes)
        protocol = PROTOCOLS.get(_require(params, 3, int))
        if protocol is None:
            raise CtapError(ERR_INVALID_PARAMETER, "unsupported PIN/UV protocol")
        token = self._token
        if token is None or not token.valid or token.protocol is not protocol:
            raise CtapError(ERR_PIN_AUTH_INVALID, "no valid pinUvAuthToken")
        message = bytes([sub]) + (cbor.encode(sub_params) if sub_params is not None else b"")
        if not protocol.verify(token.value, message, pin_auth):
            raise CtapError(ERR_PIN_AUTH_INVALID, "pinUvAuthParam mismatch")
        if not token.permissions & PERMISSION_CM:
            raise CtapError(ERR_PIN_AUTH_INVALID, "token lacks permission")
        return token

    def _cm_check_rp(self, token, rp_id_hash):
        if token.rp_id is not None:
            if hashlib.sha256(token.rp_id.encode()).digest() != rp_id_hash:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to another RP")

    def _cm_next(self, kind):
        state = self._cm_state
        if not state or state[0] != kind or not state[1]:
            self._cm_state = None
            raise CtapError(ERR_NOT_ALLOWED)
        return state[1].pop(0)

    def _records_for_hash(self, rp_id_hash):
        return [
            rec
            for rec in sorted(self.store.list(), key=lambda r: r["created"])
            if hashlib.sha256(rec["rp_id"].encode()).digest() == rp_id_hash
        ]

    def _cm_credential(self, rec, rp_id_hash):
        cred = self.store.lookup(rp_id_hash, b64d(rec["id"]))
        if cred is None:
            return None
        user = {"id": b64d(rec["user_id"])}
        if rec.get("user_name"):
            user["name"] = rec["user_name"]
        if rec.get("display_name"):
            user["displayName"] = rec["display_name"]
        return {
            6: user,
            7: {"type": "public-key", "id": cred.id},
            8: keys.cose_public_key(cred.alg, cred.private_key),
            10: cred.cred_protect,
        }


def describe_record(rec):
    """Human readable summary of a stored passkey record (for UIs)."""
    return {
        "id": rec["id"],
        "rp_id": rec["rp_id"],
        "rp_name": rec.get("rp_name") or rec["rp_id"],
        "user_name": rec.get("user_name", ""),
        "display_name": rec.get("display_name", ""),
        "algorithm": {keys.ES256: "ES256", keys.EDDSA: "EdDSA"}.get(rec["alg"], "?"),
        "created": rec["created"],
        "last_used": rec.get("last_used") or 0,
        "use_count": rec.get("use_count", 0),
    }


__all__ = ["Authenticator", "CtapError", "Denied", "Timeout", "Cancelled", "b64e"]
