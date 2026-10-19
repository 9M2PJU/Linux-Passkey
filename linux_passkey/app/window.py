"""Main window: list, inspect and delete passkeys; daemon status and settings."""

import subprocess
import time

from gi.repository import Adw, Gio, GLib, GObject, Gtk

from ..i18n import _, ngettext
from .client import DaemonClient

SERVICE = "linux-passkey.service"


def _ago(ts):
    if not ts:
        return _("Never")
    delta = max(0, int(time.time() - ts))
    if delta >= 86400:
        n = delta // 86400
        return ngettext("%d day ago", "%d days ago", n) % n
    if delta >= 3600:
        n = delta // 3600
        return ngettext("%d hour ago", "%d hours ago", n) % n
    if delta >= 60:
        n = delta // 60
        return ngettext("%d minute ago", "%d minutes ago", n) % n
    return _("Just now")


def _label_icon_button(button, label, tooltip=None):
    """Icon-only buttons need an accessible name as well as a tooltip."""
    button.set_tooltip_text(tooltip or label)
    button.update_property([Gtk.AccessibleProperty.LABEL], [label])


def _date(ts):
    return time.strftime("%x", time.localtime(ts)) if ts else ""


class PasskeyWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(title="Passkeys", **kwargs)
        self.set_default_size(640, 720)
        self._refresh_pending = False

        menu = Gio.Menu()
        section = Gio.Menu()
        section.append(_("Delete All Passkeys…"), "win.reset")
        menu.append_section(None, section)
        section = Gio.Menu()
        section.append(_("About Passkeys"), "app.about")
        menu.append_section(None, section)
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        _label_icon_button(menu_button, _("Main Menu"))

        header = Adw.HeaderBar()
        header.pack_end(menu_button)
        self.search_button = Gtk.ToggleButton(icon_name="system-search-symbolic")
        _label_icon_button(self.search_button, _("Search Passkeys"))
        header.pack_start(self.search_button)

        self.search = Gtk.SearchEntry(placeholder_text=_("Search passkeys"))
        self.search.connect("search-changed", lambda *_: self.refresh())
        search_bar = Gtk.SearchBar(child=self.search)
        search_bar.connect_entry(self.search)
        search_bar.set_key_capture_widget(self)
        self.search_button.bind_property(
            "active",
            search_bar,
            "search-mode-enabled",
            GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE,
        )

        self.banner = Adw.Banner()
        self._banner_action = None
        self.banner.connect("button-clicked", self.on_banner_clicked)

        self.page = Adw.PreferencesPage()
        self.passkeys_group = Adw.PreferencesGroup(
            title="Passkeys",
            description=_("Passkeys stored on this computer. Websites see this "
            "computer as a security key."),
        )
        self.page.add(self.passkeys_group)
        self._passkey_rows = []

        self._build_settings()
        self._build_status()

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self.banner)
        content.append(search_bar)
        content.append(self.page)
        self.page.set_vexpand(True)

        self.toasts = Adw.ToastOverlay(child=content)
        view = Adw.ToolbarView(content=self.toasts)
        view.add_top_bar(header)
        self.set_content(view)

        self._add_win_action("reset", self.on_reset)

        try:
            self.client = DaemonClient(on_change=self.schedule_refresh)
        except GLib.Error as e:
            self.client = None
            self.banner.set_title(_("Cannot connect to the session bus: %s") % e.message)
            self.banner.set_revealed(True)
        self.refresh()

    # -- construction -----------------------------------------------------

    def _add_win_action(self, name, callback):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)

    def _build_settings(self):
        group = Adw.PreferencesGroup(title=_("Security"))
        self.always_verify = Adw.SwitchRow(
            title=_("Always Verify Identity"),
            subtitle=_("Ask for your password or fingerprint every time a passkey is "
            "used, even if the website does not require it"),
        )
        self.always_verify.connect("notify::active", self.on_always_verify)
        group.add(self.always_verify)

        adjustment = Gtk.Adjustment(lower=5, upper=300, step_increment=5, page_increment=30)
        self.timeout = Adw.SpinRow(
            title=_("Approval Timeout"),
            subtitle=_("Seconds to wait for you to answer a prompt"),
            adjustment=adjustment,
        )
        self.timeout.connect("notify::value", self.on_timeout)
        group.add(self.timeout)
        self.page.add(group)
        self._updating = False

    def _build_status(self):
        group = Adw.PreferencesGroup(title=_("Status"))
        self.service_row = Adw.ActionRow(title=_("Passkey Service"))
        self.device_row = Adw.ActionRow(title=_("Virtual Security Key"))
        self.verify_row = Adw.ActionRow(title=_("Identity Verification"))
        self.key_row = Adw.ActionRow(title=_("Encryption Key Storage"))
        self.prompt_row = Adw.ActionRow(title=_("Approval Prompts"))
        for row in (
            self.service_row,
            self.device_row,
            self.verify_row,
            self.key_row,
            self.prompt_row,
        ):
            row.add_css_class("property")
            group.add(row)
        self.page.add(group)

    # -- refresh ----------------------------------------------------------

    def schedule_refresh(self):
        if not self._refresh_pending:
            self._refresh_pending = True
            GLib.idle_add(self._do_refresh)

    def _do_refresh(self):
        self._refresh_pending = False
        self.refresh()
        return False

    def refresh(self):
        if self.client is None:
            return
        try:
            status = self.client.status()
            settings = self.client.settings()
        except GLib.Error as e:
            self._show_stopped(e.message)
            return
        state = status.get("state", "ready")
        creds = []
        if state == "ready":
            try:
                creds = self.client.credentials()
            except GLib.Error as e:
                self.toasts.add_toast(Adw.Toast(title=_("Could not load passkeys: %s") % e.message))

        if state == "error":
            self._show_banner(
                _("Your passkeys cannot be opened: %s") % status.get("error", ""),
                _("Try Again"),
                self._retry,
            )
        elif state == "starting":
            self._show_banner(_("Opening your passkeys…"))
        elif status.get("device_supported", True) and not status.get("device_active", False):
            self._show_banner(
                _("The virtual security key is unavailable: %s") % status.get("device_error", ""),
                _("Help"),
                self._open_help,
            )
        else:
            self.banner.set_revealed(False)

        self.service_row.set_subtitle(_("Running (version %s)") % status.get("version", "?"))
        if not status.get("device_supported", True):
            self.device_row.set_subtitle(_("Not included in the snap; browsers use the extension"))
        else:
            self.device_row.set_subtitle(
                (_("In use by a browser") if status.get("device_open") else _("Ready"))
                if status.get("device_active")
                else _("Unavailable")
            )
        self.verify_row.set_subtitle(
            _("System authentication (password or fingerprint)")
            if status.get("verification") == "polkit"
            else _("Disabled")
        )
        self.key_row.set_subtitle(
            {"keyring": _("Login keyring"), "file": _("Protected file")}.get(
                status.get("key_backend"), _("Not created yet")
            )
        )
        agents = status.get("agent_count", 0)
        self.prompt_row.set_subtitle(
            _("GNOME Shell extension") if agents else _("Stand-alone window (extension not active)")
        )

        self._updating = True
        self.always_verify.set_active(bool(settings.get("always_verify")))
        self.timeout.set_value(settings.get("approval_timeout", 30))
        self._updating = False
        self._fill(creds)

    def _show_banner(self, title, button=None, action=None):
        self.banner.set_title(title)
        self.banner.set_button_label(button)
        self._banner_action = action
        self.banner.set_revealed(True)

    def _show_stopped(self, message):
        self._show_banner(_("The passkey service is not running"), _("Start"), self._start_service)
        self.service_row.set_subtitle(_("Stopped"))
        for row in (self.device_row, self.verify_row, self.key_row, self.prompt_row):
            row.set_subtitle("—")
        self._fill([])

    def _fill(self, creds):
        for row in self._passkey_rows:
            self.passkeys_group.remove(row)
        self._passkey_rows = []
        query = self.search.get_text().strip().lower()
        creds = sorted(creds, key=lambda c: (c["rp_id"], c["user_name"]))
        shown = 0
        for cred in creds:
            haystack = " ".join(
                (cred["rp_id"], cred["rp_name"], cred["user_name"], cred["display_name"])
            ).lower()
            if query and query not in haystack:
                continue
            shown += 1
            self._add_row(cred)
        if not creds:
            row = Adw.ActionRow(
                title=_("No passkeys yet"),
                subtitle=_("When a website offers to create a passkey, choose "
                "“security key” and approve the prompt. It will appear here."),
            )
            row.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            self.passkeys_group.add(row)
            self._passkey_rows.append(row)
        elif not shown:
            row = Adw.ActionRow(title=_("No passkeys match your search"))
            self.passkeys_group.add(row)
            self._passkey_rows.append(row)

    def _add_row(self, cred):
        account = cred["display_name"] or cred["user_name"] or _("Unnamed account")
        if cred["display_name"] and cred["user_name"] and cred["display_name"] != cred["user_name"]:
            account = "%s · %s" % (cred["display_name"], cred["user_name"])
        row = Adw.ExpanderRow(title=GLib.markup_escape_text(cred["rp_id"]))
        row.set_subtitle(GLib.markup_escape_text(account))
        avatar = Adw.Avatar(size=32, text=cred["rp_name"] or cred["rp_id"], show_initials=True)
        row.add_prefix(avatar)

        for title, value in (
            (_("Website"), cred["rp_name"]),
            (_("Created"), _date(cred["created"])),
            (_("Last used"), _ago(cred["last_used"])),
            (_("Times used"), str(cred["use_count"])),
            (_("Algorithm"), cred["algorithm"]),
        ):
            detail = Adw.ActionRow(title=title, subtitle=GLib.markup_escape_text(value or "—"))
            detail.add_css_class("property")
            row.add_row(detail)

        delete = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
        delete.add_css_class("flat")
        _label_icon_button(
            delete,
            _("Delete Passkey for {site}").format(site=cred["rp_id"]),
            _("Delete Passkey"),
        )
        delete.connect("clicked", self.on_delete, cred)
        row.add_suffix(delete)
        self.passkeys_group.add(row)
        self._passkey_rows.append(row)

    # -- actions ----------------------------------------------------------

    def on_banner_clicked(self, banner):
        if self._banner_action is not None:
            self._banner_action()

    def _start_service(self):
        subprocess.Popen(["systemctl", "--user", "start", SERVICE])
        GLib.timeout_add(1500, lambda: self.refresh() or False)

    def _retry(self):
        self.client.call_async("Retry", None, lambda value, error: self.refresh())

    def _open_help(self):
        Gtk.UriLauncher.new(
            "https://github.com/HaythmKenway/Linux-Passkey#troubleshooting"
        ).launch(self, None, None, None)

    def on_delete(self, button, cred):
        dialog = Adw.AlertDialog(
            heading=_("Delete Passkey?"),
            body=_("You will no longer be able to sign in to %s as %s with this "
            "passkey. Make sure you have another way to sign in.")
            % (cred["rp_id"], cred["user_name"] or cred["display_name"] or "this account"),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("delete", _("Delete"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def responded(dialog, response):
            if response != "delete":
                return
            try:
                self.client.delete(cred["id"])
                self.toasts.add_toast(Adw.Toast(title=_("Passkey deleted")))
            except GLib.Error as e:
                self.toasts.add_toast(Adw.Toast(title=_("Could not delete: %s") % e.message))
            self.refresh()

        dialog.connect("response", responded)
        dialog.present(self)

    def on_reset(self, *args):
        dialog = Adw.AlertDialog(
            heading=_("Delete All Passkeys?"),
            body=_("Every passkey on this computer will be permanently deleted and "
            "the encryption key replaced. You will be asked to confirm your identity."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("reset", _("Delete All"))
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def done(value, error):
            if error is not None:
                self.toasts.add_toast(Adw.Toast(title=_("Reset failed: %s") % error.message))
            elif value and value[0]:
                self.toasts.add_toast(Adw.Toast(title=_("All passkeys deleted")))
            else:
                self.toasts.add_toast(Adw.Toast(title=_("Reset cancelled")))
            self.refresh()

        def responded(dialog, response):
            if response == "reset" and self.client is not None:
                self.client.call_async("ResetAll", None, done)

        dialog.connect("response", responded)
        dialog.present(self)

    def on_always_verify(self, row, pspec):
        if self._updating or self.client is None:
            return
        self._set("always_verify", GLib.Variant("b", row.get_active()))

    def on_timeout(self, row, pspec):
        if self._updating or self.client is None:
            return
        self._set("approval_timeout", GLib.Variant("x", int(row.get_value())))

    def _set(self, key, variant):
        try:
            self.client.set_setting(key, variant)
        except GLib.Error as e:
            self.toasts.add_toast(Adw.Toast(title=_("Could not save setting: %s") % e.message))
            self.refresh()

