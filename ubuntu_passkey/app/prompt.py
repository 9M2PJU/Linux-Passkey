"""Stand-alone approval prompt used when the GNOME Shell extension is absent.

Invoked by the daemon as ``ubuntu-passkey --prompt '<json>'``; prints
``approve <index>`` and exits 0 when the user approves.
"""

import json
import sys

from gi.repository import Adw, GLib, Gtk

from ..prompts import describe

APPROVE_EXIT = 0
DENY_EXIT = 1


class PromptWindow(Adw.ApplicationWindow):
    def __init__(self, app, spec):
        super().__init__(application=app, title="Ubuntu Passkey")
        self.spec = spec
        self.result = None
        self.set_default_size(420, -1)
        self.set_resizable(False)

        operation = spec.get("operation", "select")
        accounts = [a for a in spec.get("accounts", [])]
        title, body, action = describe(
            operation, spec.get("rp_id", ""), spec.get("rp_name", ""), accounts
        )

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        icon = Gtk.Image.new_from_icon_name("io.github.haythmkenway.Passkey")
        icon.set_pixel_size(64)
        box.append(icon)

        heading = Gtk.Label(label=title, wrap=True, justify=Gtk.Justification.CENTER)
        heading.add_css_class("title-2")
        box.append(heading)

        label = Gtk.Label(label=body, wrap=True, justify=Gtk.Justification.CENTER)
        box.append(label)

        self.choice = 0
        shown = [a for a in accounts if a]
        if operation in ("authenticate", "choose") and len(shown) > 1:
            group = Adw.PreferencesGroup(title="Account")
            first = None
            for index, account in enumerate(accounts):
                check = Gtk.CheckButton()
                if first is None:
                    first = check
                    check.set_active(True)
                else:
                    check.set_group(first)
                check.connect("toggled", self._on_toggle, index)
                row = Adw.ActionRow(title=account or "Unnamed account")
                row.add_prefix(check)
                row.set_activatable_widget(check)
                group.add(row)
            box.append(group)
        elif operation == "authenticate" and shown:
            account = Gtk.Label(label=shown[0])
            account.add_css_class("heading")
            box.append(account)

        if spec.get("verify"):
            hint = Gtk.Label(
                label="You will be asked to confirm your identity next.", wrap=True
            )
            hint.add_css_class("dim-label")
            box.append(hint)

        buttons = Gtk.Box(spacing=12, homogeneous=True)
        buttons.set_margin_top(12)
        if operation != "exclude":
            deny = Gtk.Button(label="Cancel")
            deny.connect("clicked", lambda *_: self.finish(False))
            buttons.append(deny)
        approve = Gtk.Button(label=action)
        approve.add_css_class(
            "destructive-action" if operation == "reset" else "suggested-action"
        )
        approve.connect("clicked", lambda *_: self.finish(True))
        buttons.append(approve)
        box.append(buttons)

        handle = Gtk.WindowHandle(child=box)
        self.set_content(handle)
        self.set_default_widget(approve)
        approve.grab_focus()

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._on_key)
        self.add_controller(keys)
        self.connect("close-request", lambda *_: self.finish(False) or True)
        GLib.timeout_add_seconds(int(spec.get("timeout", 30)), self.finish, False)

    def _on_toggle(self, button, index):
        if button.get_active():
            self.choice = index

    def _on_key(self, controller, keyval, keycode, state):
        from gi.repository import Gdk

        if keyval == Gdk.KEY_Escape:
            self.finish(False)
            return True
        return False

    def finish(self, approved):
        if self.result is None:
            self.result = approved
            if approved:
                print("approve %d" % self.choice, flush=True)
            self.get_application().quit()
        return False


def run_prompt(spec_json):
    try:
        spec = json.loads(spec_json)
    except ValueError:
        print("invalid prompt specification", file=sys.stderr)
        return DENY_EXIT
    from gi.repository import Gio

    app = Adw.Application(
        application_id="io.github.haythmkenway.Passkey.Prompt",
        flags=Gio.ApplicationFlags.NON_UNIQUE,
    )
    holder = {}

    def activate(app):
        holder["win"] = PromptWindow(app, spec)
        holder["win"].present()

    app.connect("activate", activate)
    app.run([sys.argv[0]])
    win = holder.get("win")
    return APPROVE_EXIT if win is not None and win.result else DENY_EXIT
