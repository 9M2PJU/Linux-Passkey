"""Wording of approval prompts, shared by the app and the fallback window.

The GNOME Shell extension has the same texts in prompts.js.
"""

from .i18n import N_, _

TEXTS = {
    "register": (
        N_("Create a Passkey?"),
        N_("{rp} wants to create a passkey for {account}."),
        N_("{rp} wants to create a passkey."),
        N_("Create"),
    ),
    "authenticate": (
        N_("Sign In With a Passkey?"),
        N_("{rp} wants to sign you in with a passkey."),
        None,
        N_("Sign In"),
    ),
    "choose": (
        N_("Choose an Account"),
        N_("Choose the account to sign in to {rp} with."),
        None,
        N_("Sign In"),
    ),
    "exclude": (
        N_("Passkey Already Exists"),
        N_("You already have a passkey for {rp} on this device."),
        None,
        N_("OK"),
    ),
    "manage": (
        N_("Manage Passkeys?"),
        N_("A browser wants to view and manage the passkeys on this device."),
        None,
        N_("Allow"),
    ),
    "select": (
        N_("Use Ubuntu Passkey?"),
        N_("A website wants to use the passkeys on this device."),
        None,
        N_("Use"),
    ),
    "reset": (
        N_("Delete All Passkeys?"),
        N_(
            "A website or app asked to reset Ubuntu Passkey. Every passkey "
            "will be permanently deleted."
        ),
        None,
        N_("Delete All"),
    ),
}


def describe(operation, rp_id="", rp_name="", accounts=()):
    """Return translated (title, body, approve_label) for a prompt."""
    title, body, body_without_account, action = TEXTS.get(operation, TEXTS["select"])
    rp = rp_id or rp_name or _("A website")
    account = accounts[0] if accounts else ""
    if body_without_account and not account:
        body = body_without_account
    return _(title), _(body).format(rp=rp, account=account), _(action)
