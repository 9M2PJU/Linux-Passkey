import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension, gettext as _, ngettext} from 'resource:///org/gnome/shell/extensions/extension.js';

import {BUS_NAME, OBJECT_PATH, PasskeyProxy, unpackDict} from './dbus.js';
import {ApprovalDialog} from './dialog.js';

const APP_DESKTOP_ID = 'io.github.haythmkenway.Passkey.desktop';

const PasskeyIndicator = GObject.registerClass(
class PasskeyIndicator extends PanelMenu.Button {
    _init(extension) {
        super._init(0.0, _('Linux Passkey'));
        this._extension = extension;

        this._icon = new St.Icon({
            gicon: Gio.icon_new_for_string(`${extension.path}/icons/passkey-symbolic.svg`),
            style_class: 'system-status-icon',
        });
        this.add_child(this._icon);

        this._statusItem = new PopupMenu.PopupMenuItem('', {reactive: false});
        this.menu.addMenuItem(this._statusItem);
        this._countItem = new PopupMenu.PopupMenuItem('', {reactive: false});
        this.menu.addMenuItem(this._countItem);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._verifyItem = new PopupMenu.PopupSwitchMenuItem(_('Always Verify Identity'), false);
        this._verifyItem.connect('toggled', (item, state) => extension.setAlwaysVerify(state));
        this.menu.addMenuItem(this._verifyItem);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addAction(_('Manage Passkeys'), () => extension.openApp());

        this.setStatus(null, null);
    }

    setStatus(status, settings) {
        if (!status) {
            this._statusItem.label.text = _('Passkey service not running');
            this._countItem.visible = false;
            this._verifyItem.visible = false;
            return;
        }
        if (status.state === 'error')
            this._statusItem.label.text = _('Passkeys cannot be opened');
        else if (status.state === 'starting')
            this._statusItem.label.text = _('Opening passkeys…');
        else if (status.device_active || status.device_supported === false)
            this._statusItem.label.text = _('Passkeys ready');
        else
            this._statusItem.label.text = _('Security key unavailable');
        const count = status.credential_count ?? 0;
        this._countItem.label.text = ngettext('%d passkey', '%d passkeys', count).format(count);
        this._countItem.visible = true;
        this._verifyItem.visible = status.verification === 'polkit';
        this._verifyItem.setToggleState(Boolean(settings?.always_verify));
    }

    setActive(active) {
        if (active)
            this._icon.add_style_class_name('passkey-active');
        else
            this._icon.remove_style_class_name('passkey-active');
    }
});

export default class PasskeyExtension extends Extension {
    enable() {
        this._dialogs = new Map();
        this._proxy = null;
        this._signalIds = [];
        this._indicator = new PasskeyIndicator(this);
        Main.panel.addToStatusArea(this.uuid, this._indicator);
        this._watchId = Gio.bus_watch_name(
            Gio.BusType.SESSION,
            BUS_NAME,
            Gio.BusNameWatcherFlags.NONE,
            () => this._onDaemonAppeared(),
            () => this._onDaemonVanished());
    }

    disable() {
        if (this._watchId) {
            Gio.bus_unwatch_name(this._watchId);
            this._watchId = 0;
        }
        if (this._proxy) {
            try {
                this._proxy.UnregisterAgentRemote(() => {});
            } catch (e) {
                console.error('Linux Passkey: failed to unregister', e);
            }
        }
        this._disconnectProxy();
        this._indicator?.destroy();
        this._indicator = null;
        this._dialogs = null;
    }

    _onDaemonAppeared() {
        if (this._proxy)
            return;
        new PasskeyProxy(Gio.DBus.session, BUS_NAME, OBJECT_PATH, (proxy, error) => {
            if (error) {
                console.error('Linux Passkey: cannot connect to the daemon', error);
                return;
            }
            if (!this._indicator) // disabled meanwhile
                return;
            this._proxy = proxy;
            this._signalIds = [
                proxy.connectSignal('ApprovalRequested', (p, sender, args) => {
                    const [id, operation, rpId, rpName, accounts, verify] = args;
                    this._showRequest({id, operation, rpId, rpName, accounts, verify});
                }),
                proxy.connectSignal('ApprovalClosed', (p, sender, [id]) => this._closeRequest(id)),
                proxy.connectSignal('StatusChanged', () => this._refresh()),
                proxy.connectSignal('CredentialsChanged', () => this._refresh()),
            ];
            proxy.RegisterAgentRemote((result, err) => {
                if (err) {
                    console.error('Linux Passkey: RegisterAgent failed', err);
                    return;
                }
                proxy.GetPendingRequestsRemote((reply, err2) => {
                    if (err2 || proxy !== this._proxy)
                        return;
                    for (const [id, operation, rpId, rpName, accounts, verify] of reply[0])
                        this._showRequest({id, operation, rpId, rpName, accounts, verify});
                });
            });
            this._refresh();
        }, null, Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES);
    }

    _onDaemonVanished() {
        this._disconnectProxy();
        this._indicator?.setStatus(null, null);
    }

    _disconnectProxy() {
        if (this._dialogs) {
            for (const dialog of this._dialogs.values())
                dialog.dismiss();
            this._dialogs.clear();
        }
        this._indicator?.setActive(false);
        if (this._proxy) {
            for (const id of this._signalIds)
                this._proxy.disconnectSignal(id);
        }
        this._signalIds = [];
        this._proxy = null;
    }

    _refresh() {
        const proxy = this._proxy;
        if (!proxy)
            return;
        proxy.GetStatusRemote((status, error) => {
            if (error || proxy !== this._proxy)
                return;
            proxy.GetSettingsRemote((settings, err2) => {
                if (err2 || proxy !== this._proxy)
                    return;
                this._indicator?.setStatus(unpackDict(status[0]), unpackDict(settings[0]));
            });
        });
    }

    _showRequest(request) {
        if (!this._dialogs || this._dialogs.has(request.id))
            return;
        const dialog = new ApprovalDialog(request, (approved, choice) => {
            this._proxy?.RespondRemote(request.id, approved, choice, (r, error) => {
                if (error)
                    console.error('Linux Passkey: Respond failed', error);
            });
        });
        dialog.connect('destroy', () => {
            this._dialogs?.delete(request.id);
            this._indicator?.setActive(this._dialogs?.size > 0);
        });
        this._dialogs.set(request.id, dialog);
        this._indicator.setActive(true);
        if (!dialog.open(global.get_current_time())) {
            // Another modal grab is active; fall back to declining.
            this._proxy?.RespondRemote(request.id, false, 0, () => {});
            dialog.destroy();
        }
    }

    _closeRequest(id) {
        this._dialogs?.get(id)?.dismiss();
    }

    setAlwaysVerify(state) {
        this._proxy?.SetSettingRemote('always_verify', new GLib.Variant('b', state), (r, error) => {
            if (error)
                console.error('Linux Passkey: SetSetting failed', error);
        });
    }

    openApp() {
        const app = Gio.DesktopAppInfo.new(APP_DESKTOP_ID);
        if (app)
            app.launch([], global.create_app_launch_context(0, -1));
        else
            Main.notify(_('Linux Passkey'), _('The Passkeys app is not installed.'));
    }
}
