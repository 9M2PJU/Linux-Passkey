# Project status and test plan

Snapshot after the second development session. The work is merged into `main`.

## Done

### Product
- **`passkeyd`**: a CTAP 2.1 authenticator exposed as a virtual USB security key through `/dev/uhid`. It supports passkeys and second-factor credentials, ES256 and EdDSA, `credProtect`, `hmac-secret` (WebAuthn PRF), credential management, account selection and reset.
- **Storage**: encrypted credential store with the master key in the login keyring. If the store cannot be opened, the daemon stays running, reports the error, retries, and can be reset.
- **User verification**: the polkit system dialog (password, or fingerprint if enabled in PAM).
- **Passkeys app** (GTK4/libadwaita): list, search, inspect and delete passkeys, settings, status, and reset. It also provides the fallback approval window.
- **GNOME Shell extension**: approval prompts with an account picker, and a top-bar menu.
- **Packaging**: two `.deb` packages (app + service, and the extension), an extension zip, a systemd user unit, D-Bus activation, a udev rule, a polkit policy, man pages and AppStream metadata.

### Verified
| What | Where |
|---|---|
| 75 automated tests: CTAP2 via the python-fido2 client and server, transport, D-Bus, fuzzing | `make check` |
| Validators: lintian `--pedantic`, AppStream, desktop file, polkit DTD, systemd, udev, ESLint | `make lint`, `lintian` |
| Real kernel: `uhid` → `/dev/hidraw0`, udev marks it as a FIDO token with `uaccess`; registration, username-less sign-in and allow-list sign-in over real hidraw; daemon running under the hardened systemd sandbox | Ubuntu 24.04 VM |
| Extension prompt shown, account chosen, assertion signed | GNOME Shell 46 (headless) |
| Standards audit | [COMPLIANCE.md](COMPLIANCE.md) |

## Still to do

### Must verify before release (on a real desktop)
1. **Identity verification from the user service.** `passkeyd` runs as a systemd user service, and polkit must find your graphical session to show its dialog. Creating a passkey requires this check, so if it fails no passkey can be created. *Test 4 below.*
2. **Real browsers.** Never tested with an actual Chrome or Firefox build, only with the python-fido2 reference client. *Tests 5–6.*
3. **GNOME 50 (Ubuntu 26.04 LTS).** In a headless test VM, GNOME Shell 50.1 crashed even with extensions disabled, so the extension was never actually tested on 50. `metadata.json` lists 45–49 only, so 26.04 users can't enable the extension until "50" is added after a successful test. *Test 7.*
4. **Fingerprint login** through polkit (needs a fingerprint reader). *Test 4b.*

### Known limitations to decide on
- **Snap browsers** (Ubuntu's default Firefox and Chromium): snapd's `u2f-devices` allow-list may hide our USB ID `1209:0001`. Options: register a PID at pid.codes and ask for it to be added to snapd's list; until then, document the `.deb` and Flatpak browsers as supported.
- **Kernels without `uhid`** (server and minimal installs): users must install `linux-modules-extra-$(uname -r)`. The package warns about this.
- **Not FIDO Certified.** That needs the FIDO Alliance's conformance tools and lab, a metadata statement and a registered AAGUID. Optional.
- **No translations yet**; only the `.pot` template is in `po/`.

### Release tasks
- Check that CI passes on GitHub (the package job needed `build-essential`).
- Tag `v0.1.0`; the CI release job attaches the `.deb`s and the extension zip.
- Submit the extension to extensions.gnome.org (`make extension-zip`).
- Register a USB product ID (pid.codes) and replace the test ID.

## Test plan for your system (Ubuntu 24.04 desktop)

```sh
git clone https://github.com/HaythmKenway/Ubuntu-Passkey
cd Ubuntu-Passkey
sudo apt install build-essential debhelper dh-python python3-all gettext
make deb
sudo apt install ../ubuntu-passkey_0.1.0_all.deb ../gnome-shell-extension-ubuntu-passkey_0.1.0_all.deb
```
Then **log out and back in**.

| # | Test | Expected |
|---|---|---|
| 1 | `ls -l /dev/uhid; getfacl /dev/uhid` | The device exists and your user has an `rw` ACL entry |
| 2 | `systemctl --user status ubuntu-passkey` | `active (running)`, no errors |
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
journalctl --user -u ubuntu-passkey -b --no-pager | tail -50
journalctl --user -b --no-pager | grep -iE "passkey|JS ERROR" | tail -30
```
For more detail, run `passkeyd --verbose` in a terminal after `systemctl --user stop ubuntu-passkey`.
