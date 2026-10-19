# Ubuntu Passkey
#
#   make check                 run the test suite
#   sudo make install          install everything under /usr/local
#   make extension-zip         build the GNOME Shell extension for extensions.gnome.org
#   make deb                   build Debian packages in ../

PREFIX ?= /usr/local
DESTDIR ?=
PYTHON ?= python3

bindir = $(PREFIX)/bin
datadir = $(PREFIX)/share
pkgdatadir = $(datadir)/ubuntu-passkey
# udev, systemd, modules-load and polkit only look in /usr and /etc.
libdir_sys = /usr/lib
polkitdir = /usr/share/polkit-1/actions

EXTENSION_UUID = passkey@haythmkenway.github.io
EXTENSION_DIR = gnome-extension/$(EXTENSION_UUID)
VERSION = $(shell $(PYTHON) -c 'import ubuntu_passkey; print(ubuntu_passkey.__version__)')

SUBST = sed -e 's|@bindir@|$(bindir)|g' -e 's|@pkgdatadir@|$(pkgdatadir)|g'

.PHONY: all check lint install install-app install-extension uninstall extension-zip deb clean

all:
	@echo "Nothing to build. Try 'make check' or 'sudo make install'."

check:
	$(PYTHON) -m pytest -q tests

lint:
	$(PYTHON) -m pyflakes ubuntu_passkey tests
	for f in $(EXTENSION_DIR)/*.js; do cp $$f /tmp/ubuntu-passkey-check.mjs && node --check /tmp/ubuntu-passkey-check.mjs || exit 1; done

install: install-app install-extension

install-app:
	install -d $(DESTDIR)$(pkgdatadir)/ubuntu_passkey/app
	install -m 644 ubuntu_passkey/*.py $(DESTDIR)$(pkgdatadir)/ubuntu_passkey/
	install -m 644 ubuntu_passkey/app/*.py $(DESTDIR)$(pkgdatadir)/ubuntu_passkey/app/
	install -d $(DESTDIR)$(bindir)
	$(SUBST) bin/passkeyd.in > $(DESTDIR)$(bindir)/passkeyd
	$(SUBST) bin/ubuntu-passkey.in > $(DESTDIR)$(bindir)/ubuntu-passkey
	chmod 755 $(DESTDIR)$(bindir)/passkeyd $(DESTDIR)$(bindir)/ubuntu-passkey
	install -d $(DESTDIR)$(libdir_sys)/systemd/user
	$(SUBST) data/ubuntu-passkey.service.in > $(DESTDIR)$(libdir_sys)/systemd/user/ubuntu-passkey.service
	install -d $(DESTDIR)$(datadir)/dbus-1/services
	$(SUBST) data/io.github.haythmkenway.Passkey.Daemon.service.in > $(DESTDIR)$(datadir)/dbus-1/services/io.github.haythmkenway.Passkey.Daemon.service
	install -Dm 644 data/70-ubuntu-passkey.rules $(DESTDIR)$(libdir_sys)/udev/rules.d/70-ubuntu-passkey.rules
	install -Dm 644 data/ubuntu-passkey-modules.conf $(DESTDIR)$(libdir_sys)/modules-load.d/ubuntu-passkey.conf
	install -Dm 644 data/io.github.haythmkenway.passkey.policy $(DESTDIR)$(polkitdir)/io.github.haythmkenway.passkey.policy
	install -Dm 644 data/io.github.haythmkenway.Passkey.desktop $(DESTDIR)$(datadir)/applications/io.github.haythmkenway.Passkey.desktop
	install -Dm 644 data/io.github.haythmkenway.Passkey.metainfo.xml $(DESTDIR)$(datadir)/metainfo/io.github.haythmkenway.Passkey.metainfo.xml
	install -Dm 644 data/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg
	install -Dm 644 data/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg $(DESTDIR)$(datadir)/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg

install-extension:
	install -d $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/icons
	install -m 644 $(EXTENSION_DIR)/*.js $(EXTENSION_DIR)/metadata.json $(EXTENSION_DIR)/stylesheet.css \
		$(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/
	install -m 644 $(EXTENSION_DIR)/icons/*.svg $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/icons/

uninstall:
	rm -rf $(DESTDIR)$(pkgdatadir) $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)
	rm -f $(DESTDIR)$(bindir)/passkeyd $(DESTDIR)$(bindir)/ubuntu-passkey
	rm -f $(DESTDIR)$(libdir_sys)/systemd/user/ubuntu-passkey.service
	rm -f $(DESTDIR)$(datadir)/dbus-1/services/io.github.haythmkenway.Passkey.Daemon.service
	rm -f $(DESTDIR)$(libdir_sys)/udev/rules.d/70-ubuntu-passkey.rules
	rm -f $(DESTDIR)$(libdir_sys)/modules-load.d/ubuntu-passkey.conf
	rm -f $(DESTDIR)$(polkitdir)/io.github.haythmkenway.passkey.policy
	rm -f $(DESTDIR)$(datadir)/applications/io.github.haythmkenway.Passkey.desktop
	rm -f $(DESTDIR)$(datadir)/metainfo/io.github.haythmkenway.Passkey.metainfo.xml
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg

extension-zip:
	mkdir -p dist
	rm -f dist/$(EXTENSION_UUID).shell-extension.zip
	cd $(EXTENSION_DIR) && zip -qr ../../dist/$(EXTENSION_UUID).shell-extension.zip \
		metadata.json extension.js dbus.js dialog.js prompts.js stylesheet.css icons
	@echo "Built dist/$(EXTENSION_UUID).shell-extension.zip"

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf dist build .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
