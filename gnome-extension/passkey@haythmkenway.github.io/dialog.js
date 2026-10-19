import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import St from 'gi://St';

import * as Dialog from 'resource:///org/gnome/shell/ui/dialog.js';
import * as ModalDialog from 'resource:///org/gnome/shell/ui/modalDialog.js';
import {gettext as _} from 'resource:///org/gnome/shell/extensions/extension.js';

import {describe} from './prompts.js';

/**
 * System-modal prompt asking the user to approve a passkey operation.
 * `onResponse(approved, choice)` is called exactly once unless the request
 * is closed by the daemon first (see `dismiss()`).
 */
export const ApprovalDialog = GObject.registerClass(
class PasskeyApprovalDialog extends ModalDialog.ModalDialog {
    _init(request, onResponse) {
        super._init({styleClass: 'passkey-dialog', destroyOnClose: true});
        this._onResponse = onResponse;
        this._responded = false;
        this._choice = 0;

        const {operation, rpId, accounts, verify} = request;
        const {title, body, action} = describe(operation, rpId, accounts);

        const icon = new St.Icon({
            gicon: Gio.ThemedIcon.new_from_names([
                'io.github.haythmkenway.Passkey',
                'dialog-password-symbolic',
            ]),
            icon_size: 48,
            style_class: 'passkey-dialog-icon',
            x_align: Clutter.ActorAlign.CENTER,
        });
        this.contentLayout.add_child(icon);

        const content = new Dialog.MessageDialogContent({title, description: body});
        this.contentLayout.add_child(content);

        const named = accounts.filter(a => a);
        if ((operation === 'authenticate' || operation === 'choose') && accounts.length > 1)
            this._addAccountPicker(accounts);
        else if (operation === 'authenticate' && named.length === 1)
            this._addLabel(named[0], 'passkey-dialog-account');

        if (verify)
            this._addLabel(_('You will be asked to confirm your identity next.'), 'passkey-dialog-hint');

        const buttons = [];
        if (operation !== 'exclude') {
            buttons.push({
                label: _('Cancel'),
                action: () => this._respond(false),
                key: Clutter.KEY_Escape,
            });
        }
        buttons.push({
            label: action,
            action: () => this._respond(operation !== 'exclude'),
            default: true,
            key: operation === 'exclude' ? Clutter.KEY_Escape : undefined,
        });
        this.setButtons(buttons);
    }

    _addLabel(text, styleClass) {
        const label = new St.Label({
            text,
            style_class: styleClass,
            x_align: Clutter.ActorAlign.CENTER,
        });
        label.clutter_text.line_wrap = true;
        this.contentLayout.add_child(label);
    }

    _addAccountPicker(accounts) {
        const box = new St.BoxLayout({
            style_class: 'passkey-account-list',
            x_expand: true,
        });
        // GNOME 48 renamed `vertical` to `orientation`.
        if ('orientation' in box)
            box.orientation = Clutter.Orientation.VERTICAL;
        else
            box.vertical = true;

        this._accountButtons = accounts.map((account, index) => {
            const button = new St.Button({
                style_class: 'passkey-account',
                label: account || _('Unnamed account'),
                toggle_mode: true,
                can_focus: true,
                x_expand: true,
                checked: index === 0,
            });
            button.connect('clicked', () => this._select(index));
            box.add_child(button);
            return button;
        });
        this.contentLayout.add_child(box);
    }

    _select(index) {
        this._choice = index;
        this._accountButtons.forEach((button, i) => {
            button.checked = i === index;
        });
    }

    _respond(approved) {
        if (this._responded)
            return;
        this._responded = true;
        this._onResponse(approved, this._choice);
        this.close(global.get_current_time());
    }

    /** Close without answering (the daemon already closed the request). */
    dismiss() {
        if (this._responded)
            return;
        this._responded = true;
        this.close(global.get_current_time());
    }
});
