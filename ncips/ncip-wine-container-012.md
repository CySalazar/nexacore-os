---
ncip: 12
title: Windows Application Path — Wine-in-Container
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-07-02
license: CC0-1.0
---

## Abstract

This NCIP specifies how NexaCore OS runs **Windows applications**: under
[Wine](https://www.winehq.org/) inside a NexaCore micro-VM container, with each
Windows window integrated into the NexaCore desktop exactly like a native or
Linux application. It freezes the Wine-specific contracts layered on top of the
existing container engine (`NCIP-Container-006`) and application window
integration (`NCIP-Display-ABI-008`, plan WS9-03): the guest image composition,
the Wine prefix configuration, the executable launch contract, the
Windows-clipboard→MIME mapping, the compatibility database, and the
confidential-VM isolation option. It deliberately **reuses** the Linux app-path
window/clipboard/drag/audio bridges rather than defining new ones.

## Motivation

A "runs everything" desktop must run Windows software, which is the single
largest application ecosystem NexaCore's Linux base cannot execute natively.
Emulating a whole OS is wasteful; the industry-proven approach (Wine, and its
game-focused descendant Proton) translates Win32/DirectX calls to Linux/Vulkan
without a Windows license. NexaCore packages this as *one Windows app = one Wine
process inside one capability-bound container*, so untrusted Windows binaries are
sandboxed by the same micro-VM boundary as every other container, optionally
hardened to a confidential VM. Without a frozen contract, the image builder, the
launcher, and the compatibility tooling would each re-derive Wine's prefix and
path conventions; this NCIP fixes them.

## Specification

### Guest image

A Wine container boots the standard NexaCore guest image
(`GuestImageManifest`, NCIP-Display-ABI-008 / WS9-03) whose PID 1 is the guest
agent running a headless Wayland compositor. The Wine image is that manifest
with a Wine layer added; it MUST require the virtio devices
`Gpu`, `Vsock`, `Snd`, and `Input`. `WineImageBuilder::build` assembles and
validates the manifest, failing closed if the prefix is inconsistent or the
manifest is incomplete.

### Wine prefix

A prefix is `WinePrefix { arch, windows_version, dll_overrides, runtimes }`:

- `arch` ∈ {`Win32`, `Win64`}.
- `windows_version` ∈ {`Win7`, `Win10`, `Win11`} — the version reported to apps.
- `dll_overrides` — a map from DLL name to `{ Native, Builtin, NativeThenBuiltin,
  Disabled }` (`WINEDLLOVERRIDES` semantics).
- `runtimes` — installed components: `Vcrun2022`, `DotNet48`, `Dxvk`,
  `Vkd3dProton`, `CoreFonts`.

`WinePrefix::validate` is fail-closed and enforces: no empty DLL-override name;
and the Direct3D→Vulkan translation layers (`Dxvk`, `Vkd3dProton`) require a
`Win64` prefix.

### Launching a Windows executable

A launch is `WineLaunchSpec { executable, args, working_dir, env }`.
`WineLaunchSpec::validate` rejects an empty path, any path containing a NUL, or a
path not ending in `.exe`/`.bat`/`.com` (case-insensitive). `wine_command()`
produces the guest command line `["wine", <executable>, <args…>]`.

### Window integration (reuse)

Wine windows are reported by the **same guest agent** as Linux windows and flow
through the identical WS9-03 pipeline (`GuestWindowRegistry` → `WindowBridge` →
compositor). This NCIP adds only `wine_app_id(executable) -> String`, deriving a
stable Wayland-style `app_id` from the executable basename
(`C:\\…\\Bar.exe` → `wine.bar`) so the bridge groups and labels Wine windows
like native apps.

### Clipboard / drag / audio (reuse)

Interop reuses the WS9-03 `ClipboardBridge`, `DragSession`, and `AudioBridge`.
This NCIP adds `windows_clipboard_mime(format)` mapping Windows clipboard formats
to the MIME types those bridges carry:

| `CF_*` format | MIME |
|---------------|------|
| `Text`        | `text/plain` |
| `UnicodeText` | `text/plain;charset=utf-8` |
| `Bitmap`      | `image/bmp` |
| `FileList` (`CF_HDROP`) | `text/uri-list` |

### Compatibility database

`CompatDb` records per-app compatibility keyed by `app_id`. `CompatRating` is
ordered `Borked < Bronze < Silver < Gold < Platinum`; `is_playable()` is any
rating above `Borked`. `CompatEntry { app_id, rating, notes }`.

### Isolation

`WineIsolation` selects the container's isolation posture by wrapping the
container engine's `ConfidentialVmConfig` (NCIP-Container-006, WS9-01/WS10):
`standard()` is plain KVM; `hardened(vendor)` selects a confidential VM
(Intel TDX / AMD SEV-SNP) automatically for the host CPU vendor, falling back to
standard on non-confidential hardware. `is_confidential()` reports the effective
posture.

## Rationale

Composing over duplicating is the central choice: the container boundary,
attestation, and the whole window/clipboard/drag/audio path already exist and
are capability-bound, so the Windows path is a thin adapter (image builder,
`app_id`, MIME map, compat DB, isolation selector) rather than a parallel stack.
Requiring `Win64` for DXVK/vkd3d matches upstream reality (32-bit prefixes cannot
host the 64-bit Vulkan translation layers). The ProtonDB-style rating scale is
adopted because it is the vocabulary users already know from Proton.

## Backwards Compatibility

N/A — new subsystem. It adds the `wine` module and types to `nexacore-container`
without altering existing container, app-bridge, or display contracts; the Linux
app path (WS9-03) is unchanged.

## Test Cases

Host unit tests in `crates/nexacore-container/src/wine.rs` cover: default prefix
validity and DXVK-on-`Win32` rejection; image builder requiring gpu/vsock/snd/
input; launch-spec validation (`.exe` accepted, non-executable and empty
rejected) and `wine_command` prefixing; `wine_app_id` derivation from several
path shapes; the clipboard-format→MIME map; `CompatDb` record/lookup/rating and
`is_playable`; and `WineIsolation` standard vs hardened for Intel and AMD.

## Reference Implementation

`crates/nexacore-container/src/wine.rs` (module `nexacore_container::wine`),
composing `crate::appbridge` (WS9-03) and `crate::confidential` (WS9-01/WS10).
Plan task WS9-04. The Wine rootfs build pipeline and the the test VM end-to-end run
(WS9-04.8) are out of scope for this specification.

## Security Considerations

Windows binaries are untrusted. Every Wine container is confined by the same
micro-VM + capability boundary as any other container (NCIP-Container-006), so a
compromised Windows app cannot reach host resources it was not granted.
`WineIsolation::hardened` additionally runs the container as a confidential VM,
so even a compromised host kernel cannot read the container's memory. Launch and
prefix validation are fail-closed. The clipboard/drag transports it reuses are
themselves capability-gated and size-bounded (WS9-03), so a Windows app cannot
exfiltrate host clipboard contents without the grant.

## Privacy Considerations

Compatibility reports (`CompatEntry`) are keyed by a derived `app_id`, not by
user identity, and are a local database; any future community-submission
mechanism MUST be opt-in and MUST NOT attach user or telemetry identifiers. The
clipboard/drag pass-through carries user data only across an explicit
copy/paste/drag action and only when the container holds the corresponding
capability grant.

## Copyright

This document is placed in the public domain under CC0-1.0.
