"""Wording of approval prompts, shared by every user interface."""

TEXTS = {
    "register": ("Create a Passkey?", "{rp} wants to create a passkey{for_account}.", "Create"),
    "authenticate": ("Sign In With a Passkey?", "{rp} wants to sign you in with a passkey.", "Sign In"),
    "choose": ("Choose an Account", "Choose the account to sign in to {rp} with.", "Sign In"),
    "exclude": ("Passkey Already Exists", "You already have a passkey for {rp} on this device.", "OK"),
    "select": ("Use Ubuntu Passkey?", "A website wants to use the passkeys on this device.", "Use"),
    "reset": ("Delete All Passkeys?", "A website or app asked to reset Ubuntu Passkey. Every passkey will be permanently deleted.", "Delete All"),
}


def describe(operation, rp_id="", rp_name="", accounts=()):
    """Return (title, body, approve_label) for a prompt."""
    title, body, action = TEXTS.get(operation, TEXTS["select"])
    rp = rp_id or rp_name or "A website"
    for_account = ""
    if operation == "register" and accounts and accounts[0]:
        for_account = " for " + accounts[0]
    return title, body.format(rp=rp, for_account=for_account), action
