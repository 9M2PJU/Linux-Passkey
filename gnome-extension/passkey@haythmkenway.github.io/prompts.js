import {gettext as _} from 'resource:///org/gnome/shell/extensions/extension.js';

/**
 * Wording of approval prompts (mirrors ubuntu_passkey/prompts.py).
 *
 * @param {string} operation register | authenticate | choose | exclude | select | reset
 * @param {string} rpId relying party ID (website domain)
 * @param {string[]} accounts account labels
 * @returns {{title: string, body: string, action: string}}
 */
export function describe(operation, rpId, accounts) {
    const rp = rpId || _('A website');
    switch (operation) {
    case 'register': {
        const account = accounts?.[0];
        return {
            title: _('Create a Passkey?'),
            body: account
                ? _('%s wants to create a passkey for %s.').format(rp, account)
                : _('%s wants to create a passkey.').format(rp),
            action: _('Create'),
        };
    }
    case 'authenticate':
        return {
            title: _('Sign In With a Passkey?'),
            body: _('%s wants to sign you in with a passkey.').format(rp),
            action: _('Sign In'),
        };
    case 'choose':
        return {
            title: _('Choose an Account'),
            body: _('Choose the account to sign in to %s with.').format(rp),
            action: _('Sign In'),
        };
    case 'exclude':
        return {
            title: _('Passkey Already Exists'),
            body: _('You already have a passkey for %s on this device.').format(rp),
            action: _('OK'),
        };
    case 'manage':
        return {
            title: _('Manage Passkeys?'),
            body: _('A browser wants to view and manage the passkeys on this device.'),
            action: _('Allow'),
        };
    case 'reset':
        return {
            title: _('Delete All Passkeys?'),
            body: _('A website or app asked to reset Ubuntu Passkey. Every passkey will be permanently deleted.'),
            action: _('Delete All'),
        };
    default:
        return {
            title: _('Use Ubuntu Passkey?'),
            body: _('A website wants to use the passkeys on this device.'),
            action: _('Use'),
        };
    }
}
