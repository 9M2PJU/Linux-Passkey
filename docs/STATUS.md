# Project status and test plan

Snapshot after the third development session (19 October 2026).

## Done

### Product
- **`passkeyd`**: a CTAP 2.1 authenticator exposed as a virtual USB security key through `/dev/uhid`. It supports passkeys and second-factor credentials, ES256 and EdDSA, `credProtect`, `hmac-secret` (WebAuthn PRF), credential management, account selection and reset.
- **Storage**: encrypted credential store with the master key in the login keyring. If the store cannot be opened, the daemon stays running, reports the error, retries, and can be reset.
- **User verification**: the polkit system dialog (password, or fingerprint if enabled in PAM).
- **Passkeys app** (GTK4/libadwaita): list, search, inspect and delete passkeys, settings, status, and reset. It also provides the fallback approval window.
- **GNOME Shell extension**: approval prompts with an account picker, and a top-bar menu.
- **Browser extension** (Manifest V3, Chromium- and Firefox-based browsers): makes `passkeyd` a platform authenticator, as Windows Hello is. `passkeyd` acts as the WebAuthn client on this path (origin from the browser, RP ID checked against the Public Suffix List); a native messaging host connects them, and the daemon registers the host with every browser profile it finds.
- **Packaging**: two `.deb` packages (app + service, and the GNOME extension), the GNOME extension zip, browser extension zips for the Chrome Web Store and Firefox Add-ons, a systemd user unit, D-Bus activation, a udev rule, a polkit policy, man pages and AppStream metadata.

### Verified
| What | Where |
|---|---|
| 121 automated tests: CTAP2 and the platform path verified by python-fido2's client and server, origin and RP ID checks, the native messaging host over a private bus, transport, D-Bus, fuzzing | `make check`, CI on Ubuntu 22.04 and 24.04 |
| Validators: lintian `--pedantic`, AppStream, desktop file, polkit DTD, systemd, udev, ESLint | `make lint`, `lintian` |
| Real kernel: `uhid` → `/dev/hidraw0`, udev marks it as a FIDO token with `uaccess`; registration, username-less sign-in and allow-list sign-in over real hidraw; daemon running under the hardened systemd sandbox | Ubuntu 24.04 VM |
| Extension prompt shown, account chosen, assertion signed | GNOME Shell 46 (headless) |
| Identity verification from the systemd user service: polkit showed the password dialog for the daemon's PID | Ubuntu 24.04 desktop, GNOME 46 (X11), polkit 124 |
| Real Chrome 151 over the virtual USB key: registration on webauthn.io with the fallback approval window and polkit | Same laptop |
| A github.com passkey registered with Brave 1.93 | Same laptop |
| Upgrade from the `ubuntu-passkey` packages to `linux-passkey` kept both stored passkeys | Same laptop |
| Standards audit | [COMPLIANCE.md](COMPLIANCE.md) |

## Still to do

### Must verify before release (on a real desktop)
1. **The browser extension in real browsers:** load it unpacked in Brave or Chrome and in Firefox, and confirm that GitHub stops reporting partial passkey support, that registration and sign-in go through our prompt, and that security keys and phones still reach the browser's own dialog.
2. **Snap Firefox through the WebExtensions portal.**
3. **GNOME 50 (Ubuntu 26.04 LTS).** In a headless test VM, GNOME Shell 50.1 crashed even with extensions disabled, so the extension was never actually tested on 50. `metadata.json` lists 45–49 only, so 26.04 users can't enable the extension until "50" is added after a successful test. *Test 7.*
4. **Fingerprint login** through polkit (needs a fingerprint reader). *Test 4b.*

### Known limitations to decide on
- **Snap browsers** (Ubuntu's default Firefox and Chromium): snapd's `u2f-devices` allow-list may hide our USB ID `1209:0001`. Options: register a PID at pid.codes and ask for it to be added to snapd's list; until then, document the `.deb` and Flatpak browsers as supported.
- **Kernels without `uhid`** (server and minimal installs): users must install `linux-modules-extra-$(uname -r)`. The package warns about this.
- **Not FIDO Certified.** That needs the FIDO Alliance's conformance tools and lab, a metadata statement and a registered AAGUID. Optional.
- **No translations yet**; only the `.pot` template is in `po/`.

### Release tasks
- Publish the browser extension to the Chrome Web Store and Firefox Add-ons (`make browser-extension-zip`), then add the store IDs to `CHROMIUM_EXTENSION_IDS` in `linux_passkey/browsers.py`.
- Tag `v0.1.0`; the CI release job attaches the `.deb`s and the extension zips.
- Submit the extension to extensions.gnome.org (`make extension-zip`).
- Register a USB product ID (pid.codes) and replace the test ID.

## Test plan for your system (Ubuntu 24.04 desktop)

```sh
git clone https://github.com/HaythmKenway/Linux-Passkey
cd Linux-Passkey
sudo apt install build-essential debhelper dh-python python3-all gettext
make deb
sudo apt install ../linux-passkey_0.1.0_all.deb ../gnome-shell-extension-linux-passkey_0.1.0_all.deb
```
Then **log out and back in**.

| # | Test | Expected |
|---|---|---|
| 1 | `ls -l /dev/uhid; getfacl /dev/uhid` | The device exists and your user has an `rw` ACL entry |
| 2 | `systemctl --user status linux-passkey` | `active (running)`, no errors |
| 3 | `gnome-extensions enable passkey@haythmkenway.github.io`, then open **Passkeys** | The top-bar icon appears; the app shows Running, Ready, and "GNOME Shell extension" |
| 4 | Visit https://webauthn.io, set *Authenticator Attachment: Cross-Platform* and *Discoverable Credential: Required*, then **Register** | The GNOME prompt says "Create a Passkey?", the polkit password dialog appears, registration succeeds, and the passkey shows in the app |
| 4b | Same as 4 with fingerprint login enabled (`sudo pam-auth-update`) | polkit accepts your fingerprint |
| 5 | On webauthn.io, **Authenticate** without a username | The prompt lists your account, then you are signed in |
| 6 | Repeat 4–5 in Firefox (`.deb` or Flatpak) and in Chrome; also try the snap Firefox | Works, or note which browser fails and at which step |
| 7 | Ubuntu 26.04: add `"50"` to `shell-version` in the installed extension's `metadata.json`, log in again, repeat 3–5 | Prompts work and `journalctl --user -b \| grep -i passkey` shows no JS errors |
| 8 | Chrome → *Settings → Privacy → Security keys → Sign-in data* | Lists and deletes your passkeys (CTAP credential management) |
| 9 | Lock the keyring (`seahorse` → lock "Login"), then restart the service | The app shows "Your passkeys cannot be opened" with *Try Again*; unlocking and retrying recovers |

If something fails, collect:
```sh
journalctl --user -u linux-passkey -b --no-pager | tail -50
journalctl --user -b --no-pager | grep -iE "passkey|JS ERROR" | tail -30
```
For more detail, run `passkeyd --verbose` in a terminal after `systemctl --user stop linux-passkey`.
