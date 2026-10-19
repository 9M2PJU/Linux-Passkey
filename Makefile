# Linux Passkey
#
#   make check                 run the test suite
#   sudo make install          install everything under /usr/local
#   make extension-zip         build the GNOME Shell extension for extensions.gnome.org
#   make browser-extension-zip build the browser extension for its stores
#   make deb                   build Debian packages in ../

PREFIX ?= /usr/local
DESTDIR ?=
PYTHON ?= python3

bindir = $(PREFIX)/bin
libexecdir = $(PREFIX)/libexec/linux-passkey
datadir = $(PREFIX)/share
pkgdatadir = $(datadir)/linux-passkey
# udev, systemd, modules-load and polkit only look in /usr and /etc.
libdir_sys = /usr/lib
polkitdir = /usr/share/polkit-1/actions

EXTENSION_UUID = passkey@haythmkenway.github.io
EXTENSION_DIR = gnome-extension/$(EXTENSION_UUID)
VERSION = $(shell $(PYTHON) -c 'import linux_passkey; print(linux_passkey.__version__)')

SUBST = sed -e 's|@bindir@|$(bindir)|g' -e 's|@pkgdatadir@|$(pkgdatadir)|g' -e 's|@libexecdir@|$(libexecdir)|g'

LINGUAS = $(shell cat po/LINGUAS 2>/dev/null)

.PHONY: all check lint pot install install-app install-locale install-extension uninstall extension-zip browser-extension-zip deb clean

all:
	@echo "Nothing to build. Try 'make check' or 'sudo make install'."

check:
	$(PYTHON) -m pytest -q tests

lint:
	$(PYTHON) -m pyflakes linux_passkey tests tools
	for f in $(EXTENSION_DIR)/*.js; do cp $$f /tmp/linux-passkey-check.mjs && node --check /tmp/linux-passkey-check.mjs || exit 1; done
	cd gnome-extension && npx --yes eslint@9.15.0 $(EXTENSION_UUID)/*.js
	for f in browser-extension/*.js; do node --check $$f || exit 1; done
	cd browser-extension && npx --yes eslint@9.15.0 *.js
	$(PYTHON) -c 'import json; json.load(open("browser-extension/manifest.json"))'
	desktop-file-validate data/io.github.haythmkenway.Passkey.desktop
	appstreamcli validate --no-net data/io.github.haythmkenway.Passkey.metainfo.xml
	xmllint --noout --dtdvalid /usr/share/polkit-1/policyconfig-1.dtd data/io.github.haythmkenway.passkey.policy

install: install-app install-locale install-extension

# Regenerate the translation template from the Python and JavaScript sources.
pot:
	xgettext --from-code=UTF-8 --package-name=linux-passkey --package-version=$(VERSION) \
		--keyword=_ --keyword=N_ --keyword=ngettext:1,2 --add-comments=Translators \
		-o po/linux-passkey.pot $$(grep -v '\.js$$' po/POTFILES)
	xgettext --from-code=UTF-8 --language=JavaScript --join-existing \
		--keyword=_ --keyword=ngettext:1,2 --add-comments=Translators \
		-o po/linux-passkey.pot $$(grep '\.js$$' po/POTFILES)

install-locale:
	for lang in $(LINGUAS); do \
		install -d $(DESTDIR)$(datadir)/locale/$$lang/LC_MESSAGES; \
		msgfmt -o $(DESTDIR)$(datadir)/locale/$$lang/LC_MESSAGES/linux-passkey.mo po/$$lang.po || exit 1; \
	done

install-app:
	install -d $(DESTDIR)$(pkgdatadir)/linux_passkey/app
	install -m 644 linux_passkey/*.py $(DESTDIR)$(pkgdatadir)/linux_passkey/
	install -m 644 linux_passkey/app/*.py $(DESTDIR)$(pkgdatadir)/linux_passkey/app/
	install -d $(DESTDIR)$(bindir)
	$(SUBST) bin/passkeyd.in > $(DESTDIR)$(bindir)/passkeyd
	$(SUBST) bin/linux-passkey.in > $(DESTDIR)$(bindir)/linux-passkey
	chmod 755 $(DESTDIR)$(bindir)/passkeyd $(DESTDIR)$(bindir)/linux-passkey
	install -d $(DESTDIR)$(libexecdir)
	$(SUBST) bin/native-host.in > $(DESTDIR)$(libexecdir)/native-host
	chmod 755 $(DESTDIR)$(libexecdir)/native-host
	install -d $(DESTDIR)$(pkgdatadir)/browser-extension
	install -m 644 browser-extension/manifest.json browser-extension/*.js browser-extension/*.png \
		$(DESTDIR)$(pkgdatadir)/browser-extension/
	install -d $(DESTDIR)$(libdir_sys)/systemd/user
	$(SUBST) data/linux-passkey.service.in > $(DESTDIR)$(libdir_sys)/systemd/user/linux-passkey.service
	install -d $(DESTDIR)$(datadir)/dbus-1/services
	$(SUBST) data/io.github.haythmkenway.Passkey.Daemon.service.in > $(DESTDIR)$(datadir)/dbus-1/services/io.github.haythmkenway.Passkey.Daemon.service
	install -Dm 644 data/70-linux-passkey.rules $(DESTDIR)$(libdir_sys)/udev/rules.d/70-linux-passkey.rules
	install -Dm 644 data/linux-passkey-modules.conf $(DESTDIR)$(libdir_sys)/modules-load.d/linux-passkey.conf
	install -Dm 644 data/io.github.haythmkenway.passkey.policy $(DESTDIR)$(polkitdir)/io.github.haythmkenway.passkey.policy
	install -Dm 644 data/io.github.haythmkenway.Passkey.desktop $(DESTDIR)$(datadir)/applications/io.github.haythmkenway.Passkey.desktop
	install -Dm 644 data/io.github.haythmkenway.Passkey.metainfo.xml $(DESTDIR)$(datadir)/metainfo/io.github.haythmkenway.Passkey.metainfo.xml
	install -Dm 644 data/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg
	install -Dm 644 data/man/passkeyd.1 $(DESTDIR)$(datadir)/man/man1/passkeyd.1
	install -Dm 644 data/man/linux-passkey.1 $(DESTDIR)$(datadir)/man/man1/linux-passkey.1
	install -Dm 644 data/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg $(DESTDIR)$(datadir)/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg

install-extension:
	install -d $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/icons
	install -m 644 $(EXTENSION_DIR)/*.js $(EXTENSION_DIR)/metadata.json $(EXTENSION_DIR)/stylesheet.css \
		$(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/
	install -m 644 $(EXTENSION_DIR)/icons/*.svg $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)/icons/

uninstall:
	rm -rf $(DESTDIR)$(pkgdatadir) $(DESTDIR)$(datadir)/gnome-shell/extensions/$(EXTENSION_UUID)
	rm -f $(DESTDIR)$(bindir)/passkeyd $(DESTDIR)$(bindir)/linux-passkey
	rm -rf $(DESTDIR)$(libexecdir)
	rm -f $(DESTDIR)$(datadir)/man/man1/passkeyd.1 $(DESTDIR)$(datadir)/man/man1/linux-passkey.1
	rm -f $(DESTDIR)$(libdir_sys)/systemd/user/linux-passkey.service
	rm -f $(DESTDIR)$(datadir)/dbus-1/services/io.github.haythmkenway.Passkey.Daemon.service
	rm -f $(DESTDIR)$(libdir_sys)/udev/rules.d/70-linux-passkey.rules
	rm -f $(DESTDIR)$(libdir_sys)/modules-load.d/linux-passkey.conf
	rm -f $(DESTDIR)$(polkitdir)/io.github.haythmkenway.passkey.policy
	rm -f $(DESTDIR)$(datadir)/applications/io.github.haythmkenway.Passkey.desktop
	rm -f $(DESTDIR)$(datadir)/metainfo/io.github.haythmkenway.Passkey.metainfo.xml
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/io.github.haythmkenway.Passkey.svg
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/symbolic/apps/io.github.haythmkenway.Passkey-symbolic.svg

extension-zip:
	mkdir -p dist
	rm -f dist/$(EXTENSION_UUID).shell-extension.zip
	rm -rf build/extension && mkdir -p build/extension
	cp -r $(EXTENSION_DIR)/* build/extension/
	for lang in $(LINGUAS); do \
		install -d build/extension/locale/$$lang/LC_MESSAGES; \
		msgfmt -o build/extension/locale/$$lang/LC_MESSAGES/linux-passkey.mo po/$$lang.po || exit 1; \
	done
	cd build/extension && zip -qr ../../dist/$(EXTENSION_UUID).shell-extension.zip .
	@echo "Built dist/$(EXTENSION_UUID).shell-extension.zip"

browser-extension-zip:
	$(PYTHON) tools/pack-extension.py dist

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf dist build .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
