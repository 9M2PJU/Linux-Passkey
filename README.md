# Ubuntu Passkey

Passkeys for Ubuntu. Ubuntu Passkey turns your computer into a **FIDO2 security key**, so you can create and use passkeys on websites in any browser without extra hardware. You approve each use in a GNOME Shell prompt and confirm it with your password or fingerprint.

It ships as two pieces:

| Package | What it contains |
|---|---|
| **`ubuntu-passkey`** (the app) | The `passkeyd` authenticator service, the **Passkeys** manager app, and a fallback approval window |
| **`gnome-shell-extension-ubuntu-passkey`** (the GNOME extension) | System-modal approval prompts in GNOME Shell and a Passkeys menu in the top bar |

The app works without the extension: approval prompts then open in a separate window.

<p align="center">
  <img src="docs/screenshots/shell-register.png" width="49%" alt="GNOME Shell prompt for creating a passkey">
  <img src="docs/screenshots/shell-choose-account.png" width="49%" alt="GNOME Shell prompt for choosing an account">
</p>
<p align="center">
  <img src="docs/screenshots/app.png" width="49%" alt="The Passkeys app">
  <img src="docs/screenshots/prompt.png" width="35%" alt="Fallback approval window">
</p>

## Features

- **Works with any browser that supports USB security keys:** Chrome, Chromium, Edge, Brave and Firefox. To the browser, the computer looks like a plugged-in security key.
- **Passkeys and regular security-key logins:** supports discoverable credentials (passkeys, username-less sign-in) and non-discoverable credentials (second factor), with no limit on how many you store.
- **CTAP 2.1:** built-in user verification through `pinUvAuthToken` (protocols 1 and 2), credential management (so browsers' *security key settings* can list, rename and delete passkeys), `credProtect`, `hmac-secret` (so the WebAuthn **PRF** extension works), ES256 and EdDSA keys, account selection, and `authenticatorSelection`. See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for the standards audit.
- **Identity verification uses your system login:** polkit shows GNOME's own authentication dialog. It accepts your password, or your fingerprint if you have enabled fingerprint login.
- **Encrypted at rest:** private keys are wrapped with AES-256-GCM under a master key kept in your **login keyring**. The metadata file is encrypted too.
- **The Passkeys app:** search, inspect and delete passkeys, see the service status, require verification every time, and reset everything.

## Install

### From the Debian packages (Ubuntu 24.04 and later)

Download both `.deb` files from the [latest release](https://github.com/HaythmKenway/Ubuntu-Passkey/releases), then:

```sh
sudo apt install ./ubuntu-passkey_*_all.deb ./gnome-shell-extension-ubuntu-passkey_*_all.deb
```

**Log out and back in.** This lets udev give your session access to `/dev/uhid` and starts the service.

Ubuntu Desktop kernels include the `uhid` module. Minimal and server installs (the `linux-image-virtual` kernel) keep it in `linux-modules-extra`; the package warns at install time if it is missing:

```sh
sudo apt install linux-modules-extra-$(uname -r)
``` Then turn on the extension:

```sh
gnome-extensions enable passkey@haythmkenway.github.io
```

### From source

```sh
sudo apt install python3-gi python3-cryptography gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-secret-1
sudo make install            # installs to /usr/local (udev/systemd/polkit files go to /usr)
sudo modprobe uhid && sudo udevadm control --reload-rules && sudo udevadm trigger
systemctl --user daemon-reload && systemctl --user enable --now ubuntu-passkey.service
gnome-extensions enable passkey@haythmkenway.github.io   # after logging in again
```

### Just the GNOME extension

`make extension-zip` builds `dist/passkey@haythmkenway.github.io.shell-extension.zip` for extensions.gnome.org or for `gnome-extensions install`. It needs the `ubuntu-passkey` service.

## Using it

1. On a website, choose **Create a passkey** (on some sites this is under *Security → Passkeys / Security keys*).
2. When the browser asks where to save it, choose **USB security key** (also shown as "security key" or "external security key").
3. Approve the prompt that GNOME Shell shows, then confirm your identity if asked.

To sign in, choose **Sign in with a passkey** and approve the prompt. If you have several accounts on the site, pick one in the prompt.

Open **Passkeys** from the app grid to view or delete passkeys. Deleting a passkey revokes it straight away.

## How it works

```
 Browser ──WebAuthn/CTAP2 over HID──▶ /dev/hidrawN ◀── kernel uhid ──▶ passkeyd (user service)
                                                                        │  CTAPHID framing, keepalive, cancel
                                                                        │  CTAP2 authenticator
                                                                        │  encrypted credential store ◀─ master key in login keyring
                                                                        │  polkit (pkcheck) ─▶ password / fingerprint dialog
                                                                        └─ D-Bus io.github.haythmkenway.Passkey.Daemon
                                                                               ▲                      ▲
                                                           GNOME Shell extension (prompts)    Passkeys app (management,
                                                                                              fallback prompt window)
```

- **Transport:** `passkeyd` creates a virtual HID device with the FIDO usage page through `/dev/uhid`. systemd's `60-fido-id.rules` recognizes it as a security token and grants the logged-in user access, as it would for a hardware key.
- **Credentials:** every credential ID is self-contained. It holds the private key encrypted with a key derived from the master key and bound to the site's RP ID hash. Discoverable credentials also have a metadata record (site, account name, user handle) in `~/.local/share/ubuntu-passkey/credentials.enc`, which is also encrypted. Discoverable credentials are only honored while their record exists, so deleting one really revokes it.
- **User presence** is an explicit approval in the prompt. **User verification** is polkit action `io.github.haythmkenway.passkey.verify` (`auth_self`, never cached).
- **Attestation:** packed self-attestation (no vendor certificate). AAGUID `5a5b2c1e-6f3d-4b7a-9c2e-8d1f0a3b4c5d`.

### Files

| Path | Purpose |
|---|---|
| `~/.local/share/ubuntu-passkey/credentials.enc` | Encrypted passkey metadata and signature counter |
| `~/.local/share/ubuntu-passkey/key-backend` | Where the master key lives (`keyring` or `file`) |
| Login keyring item "Ubuntu Passkey master key" | The 256-bit master key (or `master.key`, mode 0600, when no keyring exists) |
| `~/.config/ubuntu-passkey/config.json` | Settings |

**Back up your login keyring and `~/.local/share/ubuntu-passkey` together.** Neither works without the other. Passkeys are not synced to other devices.

## Security notes

- Passkeys are protected the same way as other secrets in your session (browser passwords, SSH keys in the keyring). Malware running as your user could talk to the session bus or read the keyring after you log in, so it could misuse them. Hardware security keys protect against that; this project does not.
- The udev rule gives the user at the local seat access to `/dev/uhid` (`TAG+="uaccess"`). uhid can create any kind of HID device, keyboards included. That is a broader permission than this project strictly needs.
- Only agents registered on the session bus (the extension or the fallback window started by the service) can answer approval prompts. Approving still needs a deliberate click, and verification goes through polkit.

## Known limitations

- **It is a "security key", not a "platform authenticator".** Browsers on Linux have no platform-authenticator API, so sites and browsers show it as a USB security key.
- **Snap-packaged browsers.** The snap `u2f-devices` interface only exposes hidraw devices whose USB IDs are on snapd's allow-list. The virtual key reports the pid.codes test ID `1209:0001` by default, which may not be on that list. If a snap browser does not see the key, use the browser's `.deb` or Flatpak build. `passkeyd --usb-id VID:PID` changes the reported ID. Getting a registered ID onto the list is planned.
- U2F/CTAP1 (`CTAPHID_MSG`) is not implemented. All current browsers use CTAP2.
- No client PIN: user verification is always your system login (password or fingerprint).
- Passkeys are device-bound (the WebAuthn *backup eligible* flag is not set) and are not synced. There is deliberately no export feature, because an exportable credential would have to be reported as backup-eligible.

## Troubleshooting

```sh
systemctl --user status ubuntu-passkey.service
journalctl --user -u ubuntu-passkey.service -f
passkeyd --verbose          # run in the foreground (stop the service first)
```

- *"permission denied opening /dev/uhid"*: install the package's udev rule, then log out and back in. Check with `getfacl /dev/uhid`.
- *"/dev/uhid not found"*: run `sudo modprobe uhid`. If the module is missing, install `linux-modules-extra-$(uname -r)`.
- *"Your passkeys cannot be opened"*: the login keyring is locked or unavailable, or the passkey file cannot be decrypted. Unlock the keyring and choose **Try Again**. *Delete All Passkeys…* starts over and keeps the unreadable file aside as `credentials.enc.unreadable-<time>`.
- *The browser doesn't see a security key*: check that `ls -l /dev/hidraw*` lists a device your user can access. If you use a snap browser, see the limitations above.
- *No verification dialog appears*: a polkit authentication agent must be running. GNOME Shell provides one.

## Development

```sh
make check        # unit, CTAPHID, D-Bus, fuzz and end-to-end WebAuthn tests (python-fido2 client + server)
make lint         # pyflakes, ESLint, desktop-file, AppStream and polkit validation
make pot          # regenerate po/ubuntu-passkey.pot for translators
make deb          # build the Debian packages into ../
```

### Translations

Translations live in `po/`. To add a language, run `msginit -i po/ubuntu-passkey.pot -o po/<lang>.po -l <lang>`, translate it, and add the language code to `po/LINGUAS`. The same catalog serves the app and the GNOME extension.

The end-to-end tests drive the authenticator with [python-fido2](https://github.com/Yubico/python-fido2)'s WebAuthn client and verify the results with its server implementation. That covers registration, sign-in, PRF/hmac-secret, exclude lists, cancellation, deletion and reset.

### D-Bus API

Bus name `io.github.haythmkenway.Passkey.Daemon`, object `/io/github/haythmkenway/Passkey/Daemon`, interface `io.github.haythmkenway.Passkey1`:

| Member | Description |
|---|---|
| `RegisterAgent()`, `UnregisterAgent()` | Become or stop being an approval-prompt agent |
| `Respond(u id, b approved, i choice)` | Answer a prompt (registered agents only) |
| `GetPendingRequests() → a(usssasb)` | Prompts waiting for an answer |
| `ListCredentials() → aa{sv}`, `DeleteCredential(s id) → b` | Manage passkeys |
| `ResetAll() → b` | Delete everything (requires verification) |
| `Retry()` | Try to open the passkey storage again (after unlocking the keyring) |
| `GetStatus() → a{sv}`, `GetSettings() → a{sv}`, `SetSetting(s, v)` | Status (`state` is `starting`, `ready` or `error`) and settings. Only `always_verify` and `approval_timeout` can be set over D-Bus |
| signal `ApprovalRequested(u id, s operation, s rp_id, s rp_name, as accounts, b verify)` | A prompt should be shown |
| signal `ApprovalClosed(u id)` | A prompt was answered, cancelled or timed out |
| signals `CredentialsChanged`, `StatusChanged` | Refresh hints |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
