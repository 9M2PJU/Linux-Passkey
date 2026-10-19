import Gio from 'gi://Gio';

export const BUS_NAME = 'io.github.haythmkenway.Passkey.Daemon';
export const OBJECT_PATH = '/io/github/haythmkenway/Passkey/Daemon';

const INTERFACE_XML = `
<node>
  <interface name="io.github.haythmkenway.Passkey1">
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
    <method name="GetStatus">
      <arg type="a{sv}" name="status" direction="out"/>
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
</node>`;

export const PasskeyProxy = Gio.DBusProxy.makeProxyWrapper(INTERFACE_XML);

/**
 * Unpack an a{sv} result into a plain object.
 *
 * @param {object} dict object of GLib.Variant values
 * @returns {object}
 */
export function unpackDict(dict) {
    const out = {};
    for (const [key, value] of Object.entries(dict ?? {}))
        out[key] = value?.recursiveUnpack ? value.recursiveUnpack() : value;
    return out;
}
