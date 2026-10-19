# Linux Passkey for Fedora, RHEL 10 and its rebuilds, and openSUSE Tumbleweed.
#
#   make rpm        builds it from the committed tree into dist/
#
# One spec serves both families; only the names of the libraries differ.
# openSUSE ships each GObject introspection typelib as its own package,
# Fedora inside the library's package.

Name:           linux-passkey
Version:        0.1.0
Release:        1%{?dist}
Summary:        Passkeys for Linux (FIDO2 / WebAuthn authenticator)
License:        GPL-3.0-or-later
URL:            https://github.com/HaythmKenway/Linux-Passkey
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  make
BuildRequires:  python3

Requires:       python3 >= 3.10
Requires:       python3-cryptography
Requires:       python3-gobject
Requires:       polkit
Requires:       systemd
Requires:       hicolor-icon-theme
Requires(post): systemd
Requires(preun): systemd
%if 0%{?suse_version}
Requires:       typelib-1_0-GLib-2_0
Requires:       typelib-1_0-Gio-2_0
Requires:       typelib-1_0-Gtk-4_0
Requires:       typelib-1_0-Adw-1 >= 1.5
Requires:       typelib-1_0-Secret-1
Requires:       publicsuffix
Requires:       udev
%else
Requires:       glib2
Requires:       gtk4
Requires:       libadwaita >= 1.5
Requires:       libsecret
Requires:       publicsuffix-list
Requires:       systemd-udev
%endif
Recommends:     gnome-shell-extension-linux-passkey
Recommends:     gnome-keyring

%description
Linux Passkey lets the computer store passkeys and confirm them with the
user's password or fingerprint, the way Windows Hello does, so they can be
created and used on websites without extra hardware.

It provides a per-user daemon that browsers reach through the Linux Passkey
browser extension (as a built-in authenticator) or as a virtual USB security
key through /dev/uhid. Credentials are encrypted with a key kept in the login
keyring, the user is verified through polkit, and the Passkeys application
manages stored passkeys.

%package -n gnome-shell-extension-linux-passkey
Summary:        GNOME Shell integration for Linux Passkey
Requires:       %{name} = %{version}-%{release}
Requires:       gnome-shell >= 45

%description -n gnome-shell-extension-linux-passkey
Shows system-modal approval prompts in GNOME Shell when a website wants to
create or use a passkey, and adds a Passkeys status menu to the top bar.

%prep
%autosetup

%build

%install
%make_install PREFIX=%{_prefix}

%post
# Start the service in every graphical session, as the .deb does; D-Bus
# activation alone would leave the virtual security key absent until the
# app or the browser extension first asks for it.
if [ $1 -eq 1 ]; then
    systemctl --global enable linux-passkey.service >/dev/null 2>&1 || :
fi
# Load the user-space HID driver now; modules-load.d covers later boots.
modprobe uhid >/dev/null 2>&1 || :
udevadm control --reload-rules >/dev/null 2>&1 || :
udevadm trigger --subsystem-match=misc --sysname-match=uhid >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl --global disable linux-passkey.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/passkeyd
%{_bindir}/linux-passkey
%{_prefix}/libexec/linux-passkey/
%{_datadir}/linux-passkey/
%{_prefix}/lib/systemd/user/linux-passkey.service
%{_prefix}/lib/udev/rules.d/70-linux-passkey.rules
%{_prefix}/lib/modules-load.d/linux-passkey.conf
%{_datadir}/dbus-1/services/io.github.haythmkenway.Passkey.Daemon.service
%{_datadir}/polkit-1/actions/io.github.haythmkenway.passkey.policy
%{_datadir}/applications/io.github.haythmkenway.Passkey.desktop
%{_datadir}/metainfo/io.github.haythmkenway.Passkey.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg
%{_datadir}/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg
%{_mandir}/man1/passkeyd.1*
%{_mandir}/man1/linux-passkey.1*

%files -n gnome-shell-extension-linux-passkey
%{_datadir}/gnome-shell/extensions/passkey@haythmkenway.github.io/

%changelog
* Mon Oct 19 2026 Linux Passkey contributors <noreply@github.com> - 0.1.0-1
- Initial release: CTAP 2.1 software authenticator with virtual uhid
  security key, Passkeys GTK app and GNOME Shell extension.
