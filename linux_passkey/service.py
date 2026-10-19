"""D-Bus interface of the passkey daemon (session bus)."""

import json
import logging
import threading

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from . import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH, __version__, webauthn  # noqa: E402
from .ctap2 import Cancelled, Prompt, Request, Timeout, describe_record  # noqa: E402

log = logging.getLogger(__name__)

# WebAuthn errors reach the browser extension as these D-Bus error names; the
# part after the last dot is the DOMException name the website sees.
WEBAUTHN_ERROR = "io.github.haythmkenway.Passkey.WebAuthn."

INTERFACE_XML = """
<node>
  <interface name="%s">
    <method name="RegisterAgent"/>
    <method name="UnregisterAgent"/>
    <method name="Respond">
      <arg type="u" name="request_id" direction="in"/>
      <arg type="b" name="approved" direction="in"/>
      <arg type="i" name="choice" direction="in"/>
    </method>
    <method name="GetPendingRequests">
      <arg type="a(usssasb)" name="requests" direction="out"/>
    </method>
    <method name="ListCredentials">
      <arg type="aa{sv}" name="credentials" direction="out"/>
    </method>
    <method name="DeleteCredential">
      <arg type="s" name="id" direction="in"/>
      <arg type="b" name="deleted" direction="out"/>
    </method>
    <method name="Retry"/>
    <method name="ResetAll">
      <arg type="b" name="done" direction="out"/>
    </method>
    <method name="GetStatus">
      <arg type="a{sv}" name="status" direction="out"/>
    </method>
    <method name="WebAuthnCreate">
      <arg type="s" name="origin" direction="in"/>
      <arg type="s" name="top_origin" direction="in"/>
      <arg type="s" name="options" direction="in"/>
      <arg type="s" name="handle" direction="in"/>
      <arg type="s" name="credential" direction="out"/>
    </method>
    <method name="WebAuthnGet">
      <arg type="s" name="origin" direction="in"/>
      <arg type="s" name="top_origin" direction="in"/>
      <arg type="s" name="options" direction="in"/>
      <arg type="s" name="handle" direction="in"/>
      <arg type="s" name="credential" direction="out"/>
    </method>
    <method name="WebAuthnHasCredentials">
      <arg type="s" name="origin" direction="in"/>
      <arg type="s" name="options" direction="in"/>
      <arg type="b" name="found" direction="out"/>
    </method>
    <method name="WebAuthnCancel">
      <arg type="s" name="handle" direction="in"/>
    </method>
    <method name="GetSettings">
      <arg type="a{sv}" name="settings" direction="out"/>
    </method>
    <method name="SetSetting">
      <arg type="s" name="key" direction="in"/>
      <arg type="v" name="value" direction="in"/>
    </method>
    <signal name="ApprovalRequested">
      <arg type="u" name="request_id"/>
      <arg type="s" name="operation"/>
      <arg type="s" name="rp_id"/>
      <arg type="s" name="rp_name"/>
      <arg type="as" name="accounts"/>
      <arg type="b" name="verify"/>
    </signal>
    <signal name="ApprovalClosed">
      <arg type="u" name="request_id"/>
    </signal>
    <signal name="CredentialsChanged"/>
    <signal name="StatusChanged"/>
  </interface>
</node>
""" % DBUS_INTERFACE

SIGNAL_TYPES = {
    "ApprovalRequested": "(usssasb)",
    "ApprovalClosed": "(u)",
    "CredentialsChanged": None,
    "StatusChanged": None,
}


def _json(value):
    return json.dumps(value, separators=(",", ":"))


def _variant(value):
    if isinstance(value, bool):
        return GLib.Variant("b", value)
    if isinstance(value, int):
        return GLib.Variant("x", value)
    if isinstance(value, str):
        return GLib.Variant("s", value)
    if isinstance(value, list):
        return GLib.Variant("as", [str(v) for v in value])
    raise TypeError(type(value))


class PasskeyService:
    def __init__(self, daemon):
        self.daemon = daemon
        self.broker = daemon.broker
        self.connection = None
        self._registration = None
        self._owner_id = 0
        self._watches = {}
        self._ceremonies = {}  # (sender, handle) -> cancel event
        self._ceremonies_lock = threading.Lock()
        self._node = Gio.DBusNodeInfo.new_for_xml(INTERFACE_XML)
        self.broker.emit = self.emit

    # -- bus setup --------------------------------------------------------

    def own_name(self, on_lost):
        def acquired(connection, name):
            log.info("acquired D-Bus name %s", name)

        def bus_acquired(connection, name):
            self.connection = connection
            self._registration = connection.register_object(
                DBUS_PATH,
                self._node.interfaces[0],
                self._on_call,
                None,
                None,
            )

        def lost(connection, name):
            on_lost()

        self._owner_id = Gio.bus_own_name(
            Gio.BusType.SESSION,
            DBUS_NAME,
            Gio.BusNameOwnerFlags.DO_NOT_QUEUE,
            bus_acquired,
            acquired,
            lost,
        )

    def close(self):
        for watch in self._watches.values():
            Gio.bus_unwatch_name(watch)
        self._watches.clear()
        if self._registration:
            self.connection.unregister_object(self._registration)
            self._registration = None
        if self._owner_id:
            Gio.bus_unown_name(self._owner_id)
            self._owner_id = 0
        self.connection = None

    def emit(self, name, *args):
        if self.connection is None:
            return
        signature = SIGNAL_TYPES[name]
        params = GLib.Variant(signature, args) if signature else None
        try:
            self.connection.emit_signal(None, DBUS_PATH, DBUS_INTERFACE, name, params)
        except GLib.Error as e:
            log.warning("failed to emit %s: %s", name, e)

    # -- method calls -----------------------------------------------------

    def _on_call(self, connection, sender, path, iface, method, params, invocation):
        handler = getattr(self, "_m_" + method, None)
        if handler is None:
            invocation.return_dbus_error(
                "org.freedesktop.DBus.Error.UnknownMethod", method
            )
            return
        try:
            handler(sender, params.unpack(), invocation)
        except RuntimeError as e:
            invocation.return_dbus_error(
                "io.github.haythmkenway.Passkey.Error.Unavailable", str(e)
            )
        except PermissionError as e:
            invocation.return_dbus_error(
                "org.freedesktop.DBus.Error.AccessDenied", str(e)
            )
        except (KeyError, ValueError, TypeError) as e:
            invocation.return_dbus_error(
                "org.freedesktop.DBus.Error.InvalidArgs", str(e)
            )
        except Exception as e:
            log.exception("D-Bus method %s failed", method)
            invocation.return_dbus_error("org.freedesktop.DBus.Error.Failed", str(e))

    def _m_RegisterAgent(self, sender, args, invocation):
        if sender not in self._watches:
            self._watches[sender] = Gio.bus_watch_name_on_connection(
                self.connection,
                sender,
                Gio.BusNameWatcherFlags.NONE,
                None,
                lambda conn, name: self._agent_vanished(name),
            )
            self.broker.add_agent(sender)
            self.emit("StatusChanged")
        invocation.return_value(None)

    def _agent_vanished(self, name):
        watch = self._watches.pop(name, None)
        if watch is not None:
            Gio.bus_unwatch_name(watch)
        self.broker.remove_agent(name)
        self.emit("StatusChanged")

    def _m_UnregisterAgent(self, sender, args, invocation):
        self._agent_vanished(sender)
        invocation.return_value(None)

    def _m_Respond(self, sender, args, invocation):
        if not self.broker.is_agent(sender):
            raise PermissionError("only registered agents may respond")
        request_id, approved, choice = args
        self.broker.respond(request_id, approved, choice)
        invocation.return_value(None)

    def _m_GetPendingRequests(self, sender, args, invocation):
        reqs = [
            (p.id, p.prompt.operation, p.prompt.rp_id, p.prompt.rp_name,
             p.prompt.accounts, p.prompt.verify)
            for p in self.broker.pending_requests()
        ]
        invocation.return_value(GLib.Variant("(a(usssasb))", (reqs,)))

    def _m_ListCredentials(self, sender, args, invocation):
        creds = []
        for rec in self.daemon.require_store().list():
            info = describe_record(rec)
            creds.append({k: _variant(v) for k, v in info.items()})
        invocation.return_value(GLib.Variant("(aa{sv})", (creds,)))

    def _m_DeleteCredential(self, sender, args, invocation):
        (cred_id,) = args
        deleted = self.daemon.require_store().delete(cred_id)
        invocation.return_value(GLib.Variant("(b)", (deleted,)))

    def _m_ResetAll(self, sender, args, invocation):
        # Verification blocks, so it runs off the main loop.
        def work():
            done = False
            try:
                if self.daemon.config.get("verification") != "none":
                    ok = self.broker.verify(Prompt("reset", verify=True), Request())
                else:
                    ok = True
                if ok:
                    self.daemon.reset()
                    done = True
            except (Cancelled, Timeout):
                pass
            except Exception:
                log.exception("reset failed")
            GLib.idle_add(lambda: invocation.return_value(GLib.Variant("(b)", (done,))))

        threading.Thread(target=work, daemon=True).start()

    def _m_Retry(self, sender, args, invocation):
        self.daemon.retry()
        invocation.return_value(None)

    def _m_GetStatus(self, sender, args, invocation):
        status = self.daemon.status()
        invocation.return_value(
            GLib.Variant("(a{sv})", ({k: _variant(v) for k, v in status.items()},))
        )

    # -- WebAuthn (browser extension) ------------------------------------

    def _m_WebAuthnCreate(self, sender, args, invocation):
        self._ceremony(sender, args, invocation, webauthn.create)

    def _m_WebAuthnGet(self, sender, args, invocation):
        self._ceremony(sender, args, invocation, webauthn.get)

    def _ceremony(self, sender, args, invocation, run):
        origin, top_origin, options, handle = args
        authenticator = self.daemon.authenticator
        if authenticator is None:
            raise RuntimeError("passkey storage is unavailable: %s" % self.daemon.store_error)
        options = self._options(options)
        request = Request()
        key = (sender, handle)
        with self._ceremonies_lock:
            if key in self._ceremonies:
                raise ValueError("handle %r is already in use" % handle)
            self._ceremonies[key] = request.cancel

        # Approval and verification block, so the ceremony runs off the main loop.
        def work():
            try:
                result = run(authenticator, origin, options, request, top_origin or None)
                reply = ("(s)", (_json(result),))
            except webauthn.WebAuthnError as e:
                reply = (WEBAUTHN_ERROR + e.name, str(e))
            except Exception as e:
                log.exception("WebAuthn ceremony failed")
                reply = (WEBAUTHN_ERROR + "UnknownError", str(e))
            finally:
                with self._ceremonies_lock:
                    self._ceremonies.pop(key, None)

            def finish():
                if reply[0].startswith("("):
                    invocation.return_value(GLib.Variant(*reply))
                else:
                    invocation.return_dbus_error(*reply)

            GLib.idle_add(finish)

        threading.Thread(target=work, name="webauthn", daemon=True).start()

    def _m_WebAuthnHasCredentials(self, sender, args, invocation):
        origin, options = args
        options = self._options(options)
        try:
            found = webauthn.has_credentials(self.daemon.require_store(), origin, options)
        except webauthn.WebAuthnError as e:
            invocation.return_dbus_error(WEBAUTHN_ERROR + e.name, str(e))
            return
        invocation.return_value(GLib.Variant("(b)", (found,)))

    def _m_WebAuthnCancel(self, sender, args, invocation):
        (handle,) = args
        # Only the caller that started a ceremony can cancel it.
        with self._ceremonies_lock:
            cancel = self._ceremonies.get((sender, handle))
        if cancel is not None:
            cancel.set()
        invocation.return_value(None)

    @staticmethod
    def _options(text):
        try:
            return json.loads(text)
        except ValueError:
            raise ValueError("options are not valid JSON")

    def _m_GetSettings(self, sender, args, invocation):
        settings = self.daemon.config.as_dict()
        invocation.return_value(
            GLib.Variant("(a{sv})", ({k: _variant(v) for k, v in settings.items()},))
        )

    # Settings that weaken security (verification, algorithms) can only be
    # changed in the configuration file, not by any process on the bus.
    SETTABLE = ("always_verify", "approval_timeout")

    def _m_SetSetting(self, sender, args, invocation):
        key, value = args
        if key not in self.SETTABLE:
            raise PermissionError("%s cannot be changed over D-Bus" % key)
        self.daemon.config.set(key, value)
        self.emit("StatusChanged")
        invocation.return_value(None)


__all__ = ["PasskeyService", "INTERFACE_XML", "__version__"]
