"""gettext setup shared by the app and the daemon."""

import gettext

DOMAIN = "ubuntu-passkey"

_translation = gettext.translation(DOMAIN, fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext


def N_(message):
    """Mark a string for translation without translating it yet."""
    return message
