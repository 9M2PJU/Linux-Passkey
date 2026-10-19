# Standards compliance

This document records which standards Ubuntu Passkey follows, how each was checked, and where it falls short. Results come from release 0.1.0's test suite and validators, and from end-to-end runs on real Ubuntu kernels and GNOME Shell (see [Evidence](#evidence)).

Status key: **Pass** means checked with the named tool or test. **Partial** means the required parts are met but some optional parts are not implemented. **No** means not met. **N/A** means it does not apply.

## Summary

| Standard | Status | How it was checked |
|---|---|---|
| FIDO CTAP 2.1: authenticator API | Pass (optional features listed below are not implemented) | python-fido2 2.2 client against the authenticator, unit and fuzz tests, real kernel HID |
| FIDO CTAP 2.1: CTAPHID USB HID transport | Pass | Transport tests; real `/dev/uhid` → `/dev/hidraw` on Ubuntu 24.04 |
| W3C WebAuthn Level 2/3: authenticator model | Pass | python-fido2 `Fido2Server` verifies every registration and assertion; packed attestation verified |
| RFC 8949 (CBOR), CTAP2 canonical encoding | Pass | Byte-identical to python-fido2's encoder; duplicate keys rejected |
| RFC 9052/9053 (COSE keys and algorithms) | Pass | ES256 (P-256) and EdDSA (Ed25519) keys accepted by `Fido2Server` |
| FIDO Certified (functional or security) | **No** | Requires FIDO Alliance testing and fees; see [Certification](#certification) |
| NIST SP 800-63B | Partial (AAL2 capable, not AAL3) | Analysis below |
| freedesktop Desktop Entry spec | Pass | `desktop-file-validate`: no errors or hints |
| AppStream metainfo | Pass | `appstreamcli validate --pedantic`: one pedantic note (uppercase in the reverse-DNS ID, the GNOME convention) |
| polkit policy DTD | Pass | `xmllint --dtdvalid policyconfig-1.dtd` |
| systemd unit | Pass | `systemd-analyze --user verify`; exposure 6.2 (see [systemd](#systemd)) |
| udev rules | Pass | `udevadm verify` |
| Debian Policy | Pass | `lintian --pedantic --info`: clean, one justified override |
| GNOME Shell extension review guidelines | Pass (self-review) | Checklist below; ESLint clean; tested on GNOME Shell 46 |
| GNOME accessibility | Pass for the items listed | Accessible names on icon-only buttons; keyboard operation of prompts |
| Internationalisation (gettext) | Pass (no translations shipped yet) | `po/ubuntu-passkey.pot` with 110 messages, plural forms included |

## FIDO CTAP 2.1 authenticator

Reference: *Client to Authenticator Protocol (CTAP) v2.1*, Proposed Standard (2021-06-15) with errata. The authenticator reports `versions: ["FIDO_2_0", "FIDO_2_1"]`.

### Commands

| Command | Code | Status |
|---|---|---|
| authenticatorMakeCredential | 0x01 | Implemented |
| authenticatorGetAssertion | 0x02 | Implemented |
| authenticatorGetNextAssertion | 0x08 | Implemented |
| authenticatorGetInfo | 0x04 | Implemented |
| authenticatorClientPIN | 0x06 | Subcommands getPinUvAuthTokenUsingUvWithPermissions (0x06), getKeyAgreement (0x02), getUVRetries (0x07), getPINRetries (0x01). PIN subcommands return `CTAP2_ERR_INVALID_SUBCOMMAND`: there is no client PIN. |
| authenticatorReset | 0x07 | Implemented. Allowed only within 10 s of the device appearing (§6.6), with user presence and verification. |
| authenticatorCredentialManagement | 0x0A | Implemented: getCredsMetadata, enumerateRPs, enumerateCredentials, deleteCredential, updateUserInformation |
| authenticatorSelection | 0x0B | Implemented |
| authenticatorBioEnrollment | 0x09 | No: verification is delegated to the OS (polkit/PAM) |
| authenticatorLargeBlobs | 0x0C | No (optional) |
| authenticatorConfig | 0x0D | No (optional) |

### getInfo options

`rk`, `up`, `uv`, `plat=false`, `pinUvAuthToken`, `credMgmt`, `makeCredUvNotRqd`. `clientPin` is absent because there is no PIN. PIN/UV auth protocols `[2, 1]`; protocol 2 is mandatory for 2.1 and is preferred. Also reported: `maxMsgSize`, `maxCredentialCountInList`, `maxCredentialIdLength`, `transports`, `algorithms`, `firmwareVersion`, and `remainingDiscoverableCredentials`.

### Behaviour required by 2.1

- **Built-in user verification** is done with `getPinUvAuthTokenUsingUvWithPermissions`, which supports the `mc`, `ga` and `cm` permissions. Unsupported permissions return `CTAP2_ERR_UNAUTHORIZED_PERMISSION`. A token's RP binding, 30 s lifetime and single-use `mc` permission are enforced. The token's user-presence flag is spent only by an operation that needs presence, so silent (`up=false`) probes don't consume it.
- **Discoverable credentials need user verification** when the authenticator is protected by it. Without a token or `uv`, `rk=true` returns `CTAP2_ERR_PUAT_REQUIRED` (§6.1.2). Non-discoverable credentials can be created without verification (`makeCredUvNotRqd`).
- **Legacy `uv` option.** CTAP 2.0 platforms that send `options.uv` instead of a token are handled with the same built-in verification.
- **Account selection.** When several discoverable credentials match, the user picks one in the prompt and the response carries `userSelected` (0x06). Silent (`up=false`) requests return `numberOfCredentials` for iteration with getNextAssertion.
- **User data in responses.** The user's name and display name are only returned after user verification. Discoverable credentials always return the user ID.
- **Extensions.** `credProtect` (levels 1–3, enforced on getAssertion) and `hmac-secret` (one or two salts, protocols 1 and 2, separate secrets with and without verification) are supported. Platforms map WebAuthn **PRF** onto `hmac-secret`; this was tested with python-fido2's PRF implementation.
- **Rejected inputs.** `enterpriseAttestation` gives `CTAP1_ERR_INVALID_PARAMETER`, because `ep` is not offered. `up=false` in makeCredential and `rk` in getAssertion give `CTAP2_ERR_INVALID_OPTION`. An empty `pinUvAuthParam` probe gets user presence and then returns `CTAP2_ERR_PIN_NOT_SET`.
- **Exclude lists.** A match asks for presence ("passkey already exists"), then returns `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
- **Fuzzing.** 3,000 random requests across all commands never produced `CTAP1_ERR_OTHER`, an unexpected exception or a hang (`tests/test_fuzz.py`).

### Not implemented (all optional in 2.1)

These are not implemented: client PIN, `alwaysUv`, `largeBlobs` and the `largeBlobKey` extension, `credBlob`, `minPinLength`, `authenticatorConfig`, enterprise attestation, bio enrollment, and CTAP1/U2F (`CTAPHID_MSG`; the device advertises `NMSG`). NFC and BLE transports are not applicable.

## CTAPHID (USB HID transport)

- The HID report descriptor uses the FIDO usage page (`0xF1D0`, usage `0x01`) with 64-byte input and output reports. It has been verified with python-fido2's descriptor parser and with systemd's `fido_id` on a real kernel.
- Commands: INIT (broadcast and per-channel resynchronisation), PING, CBOR, CANCEL, KEEPALIVE (`PROCESSING` or `UPNEEDED` every 100 ms), WINK, LOCK, ERROR. Capabilities: `WINK | CBOR | NMSG`.
- Error handling covers `INVALID_CHANNEL`, `INVALID_SEQ`, `INVALID_LEN`, `INVALID_CMD`, `CHANNEL_BUSY` (other channels while a request runs), and `MSG_TIMEOUT` (sent by a watchdog when a continuation packet is more than 500 ms late).
- Messages can be up to 7,609 bytes. The channel table holds at most 64 entries, discarding the oldest.

## WebAuthn (authenticator model)

- **authenticatorData** follows the WebAuthn layout: RP ID hash, flags (UP, UV, AT, ED), a 32-bit signature counter, attested credential data with the AAGUID, and a COSE public key.
- **Attestation** is `packed` self-attestation (`alg`, `sig`, no `x5c`), verified with python-fido2's `PackedAttestation`. The AAGUID is `5a5b2c1e-6f3d-4b7a-9c2e-8d1f0a3b4c5d`.
- **Backup flags.** BE and BS are not set, because credentials are device-bound. There is deliberately no export feature, since an exportable credential would have to be declared backup-eligible.
- **Signature counter.** A single global counter is used, which WebAuthn allows.
- **credProps** is reported by clients from the `rk` result; this was verified.

## Certification

Ubuntu Passkey is **not FIDO Certified**, and the "FIDO Certified" mark must not be used for it. The steps to certify are:

1. **Functional certification.** Pass the FIDO Conformance Tools for CTAP 2.1 authenticators at a FIDO interoperability event or by self-validation, then apply.
2. **Authenticator security certification at Level 1.** This needs a vendor questionnaire and lab review. A software authenticator can reach L1 at most; L2 and above need a restricted operating environment.
3. **Metadata.** Publish a Metadata Statement in the FIDO Metadata Service, so that relying parties can recognise the AAGUID.
4. **USB ID.** Register a USB product ID (for example at pid.codes) instead of the test ID `1209:0001`.

The FIDO Conformance Tools could not be run in this environment. The checks above use python-fido2 2.2, Yubico's reference implementation, which is the client side that Chrome-like platforms implement.

## NIST SP 800-63B

The authenticator is a *multi-factor cryptographic software* authenticator. Possession comes from keys held on the device. The second factor is verification by the operating system (password or fingerprint through polkit and PAM). Keys are bound to the RP ID, so the authenticator resists verifier impersonation (phishing).

- **AAL2: capable.** It meets the requirements for a multi-factor cryptographic software authenticator.
- **AAL3: no.** AAL3 requires a hardware-protected, non-exportable key; these keys live in user-space memory and files.

## Linux and freedesktop integration

### systemd

`systemd-analyze --user verify` passes. `systemd-analyze security` rates the unit 6.2 ("MEDIUM"), down from 9.1 before hardening. The hardening options in use are:

- `UMask=0077`
- `NoNewPrivileges`
- `RestrictNamespaces`
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK`
- `SystemCallFilter=@system-service`
- `SystemCallArchitectures=native`
- `RestrictSUIDSGID`
- `RestrictRealtime`
- `LockPersonality`

The remaining exposure comes from options that need user namespaces in a user unit (`ProtectSystem`, `PrivateTmp`, and similar). Ubuntu restricts unprivileged user namespaces, so those options would make the service fail to start. `MemoryDenyWriteExecute` is left out because PyGObject's libffi closures need writable and executable memory. The hardened unit was run on a real Ubuntu 24.04 system and worked: device creation, D-Bus and helper processes all ran.

### udev

The rule gives the seat user access to `/dev/uhid` (`TAG+="uaccess"`) and passes `udevadm verify`. The hidraw node it creates is classified by systemd's own `60-fido-id.rules`. This was verified on a real kernel: `ID_FIDO_TOKEN=1`, `ID_SECURITY_TOKEN=1`, tags `uaccess`, `seat` and `security-device`.

### Kernel module

`uhid` ships with Ubuntu Desktop kernels. On the `linux-image-virtual` kernel used by cloud and minimal installs it is in `linux-modules-extra-<version>`. The package warns about this at install time, and the daemon's error message names the package.

### Debian packaging

`lintian --pedantic --info` reports nothing for either package. One override is justified in `debian/ubuntu-passkey.lintian-overrides`: the udev rule is for a virtual device, so it has no modalias. Man pages ship for both commands. The systemd user unit is enabled for all users by `dh_installsystemduser`.

## GNOME

### Extension review guidelines (extensions.gnome.org)

| Rule | Status |
|---|---|
| No objects created or signals connected before `enable()` | Pass. Module scope only defines classes and the proxy wrapper class. |
| Everything created in `enable()` is destroyed or disconnected in `disable()` | Pass. Covers the indicator, bus watch, proxy signals and open dialogs. |
| No main-loop sources left behind | Pass. None are used. |
| No GTK or GDK imports in the Shell process | Pass |
| No deprecated modules (`Lang`, `Mainloop`, `ByteArray`) | Pass |
| No excessive logging | Pass. `console.error` is used on failures only. |
| No spawning of processes beyond what is needed | Pass. It only launches the Passkeys app with `Gio.DesktopAppInfo`. |
| Code not minified or obfuscated; GPL-compatible licence | Pass. The licence is GPL-3.0-or-later. |
| External dependency declared in the description | Pass |
| `shell-version` lists only tested releases | Pass. See the GNOME Shell version support note below. |
| Lint | ESLint clean (`gnome-extension/eslint.config.mjs`) |

GNOME Shell version support: tested on GNOME Shell 46 (Ubuntu 24.04). The extension uses only APIs that are unchanged from 45 to 49 (`PanelMenu`, `PopupMenu`, `ModalDialog`, `Dialog.MessageDialogContent`) and handles the GNOME 48 `St.BoxLayout` orientation change.

### Accessibility and HIG

- Icon-only buttons have accessible names that include the site, for example "Delete Passkey for github.com".
- Prompts can be used from the keyboard: Enter approves, Esc cancels, and arrow keys move through accounts.
- Text uses title case for headings and an ellipsis for actions that open a dialog.

## Evidence

| Check | Command or test |
|---|---|
| Unit, transport, D-Bus, fuzz and end-to-end WebAuthn | `make check`: 68 tests |
| Validators | `make lint`, then `lintian --pedantic` on `make deb` output |
| Real kernel | QEMU VM running Ubuntu 24.04 (kernel 6.8.0-147-generic). Daemon under the hardened systemd sandbox, the real `uhid` module, python-fido2 over `/dev/hidraw0`, a D-Bus approval agent. Covered registration of two passkeys with PRF, username-less sign-in with account choice, and allow-list sign-in. |
| GNOME Shell | Headless GNOME Shell 46 with the extension: prompt rendered, account picked, assertion signed for the chosen account |

## Known gaps

- Not FIDO Certified (see [Certification](#certification)).
- Snap-confined browsers only see USB IDs on snapd's allow-list (see the README).
- Not yet tested against a real browser binary (Chrome or Firefox); tested against the python-fido2 reference platform.
- polkit identity verification for a process in a systemd user service relies on polkit finding the user's graphical session. In the VM tests verification was disabled.
