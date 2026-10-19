"""Thin D-Bus client for the passkey daemon."""

from gi.repository import Gio, GLib

from .. import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH


class DaemonClient:
    def __init__(self, on_change=None):
        self.on_change = on_change
        self.proxy = Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SESSION,
            Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES,
            None,
            DBUS_NAME,
            DBUS_PATH,
            DBUS_INTERFACE,
            None,
        )
        self.proxy.connect("g-signal", self._on_signal)
        self.proxy.connect("notify::g-name-owner", lambda *a: self._changed())

    @property
    def running(self):
        return self.proxy.get_name_owner() is not None

    def _changed(self):
        if self.on_change:
            self.on_change()

    def _on_signal(self, proxy, sender, signal, params):
        if signal in ("CredentialsChanged", "StatusChanged"):
            self._changed()

    def _call(self, method, params=None, timeout=5000):
        result = self.proxy.call_sync(
            method, params, Gio.DBusCallFlags.NONE, timeout, None
        )
        return result.unpack() if result is not None else ()

    def call_async(self, method, params, callback, timeout=120000):
        def done(proxy, res):
            try:
                value = proxy.call_finish(res).unpack()
                callback(value, None)
            except GLib.Error as e:
                callback(None, e)

        self.proxy.call(method, params, Gio.DBusCallFlags.NONE, timeout, None, done)

    def status(self):
        return self._call("GetStatus")[0]

    def settings(self):
        return self._call("GetSettings")[0]

    def set_setting(self, key, variant):
        self._call("SetSetting", GLib.Variant("(sv)", (key, variant)))

    def credentials(self):
        return self._call("ListCredentials")[0]

    def delete(self, cred_id):
        return self._call("DeleteCredential", GLib.Variant("(s)", (cred_id,)))[0]
