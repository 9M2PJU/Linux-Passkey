"""Passkeys: the Ubuntu Passkey manager application."""

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import APP_ID, __version__  # noqa: E402
from ..i18n import _  # noqa: E402


class PasskeyApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._add_action("about", self.on_about)
        self._add_action("quit", lambda *a: self.quit(), ["<primary>q"])

    def _add_action(self, name, callback, accels=None):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        if accels:
            self.set_accels_for_action("app." + name, accels)

    def do_activate(self):
        from .window import PasskeyWindow

        win = self.props.active_window
        if win is None:
            win = PasskeyWindow(application=self)
        win.present()

    def on_about(self, *args):
        about = Adw.AboutDialog(
            application_name="Passkeys",
            application_icon=APP_ID,
            developer_name=_("Ubuntu Passkey contributors"),
            version=__version__,
            website="https://github.com/HaythmKenway/Ubuntu-Passkey",
            issue_url="https://github.com/HaythmKenway/Ubuntu-Passkey/issues",
            license_type=Gtk.License.GPL_3_0,
            comments=_("Passkeys for Ubuntu: a FIDO2 authenticator built into your desktop."),
        )
        about.present(self.props.active_window)


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) >= 2 and argv[1] == "--prompt":
        from .prompt import run_prompt

        # The daemon passes the request on stdin to keep it out of /proc.
        return run_prompt(sys.stdin.read())
    if len(argv) >= 2 and argv[1] == "--version":
        print(__version__)
        return 0
    GLib.set_application_name("Passkeys")
    return PasskeyApplication().run(argv)
