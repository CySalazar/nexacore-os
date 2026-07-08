# nexacore-driver-pack

**NexaCore OS driver-pack v1 producer** — converts a TOML or JSON driver manifest
plus a Ring 3 ELF image into a signed `NexaCore-Pack v1` (`.opack`) binary blob
that the kernel's `DriverLoad (syscall 73)` handler can ingest.

Specified by **NCIP-Driver-Framework-013 § S5.5** (binary blob layout) +
**§ R4** (TOML as canonical developer-side source format; JSON supported for
backwards compatibility with pre-TASK-007 fixtures). The tool auto-detects
the format from the `--manifest` file extension: `.toml` → TOML, anything
else → JSON.

---

## Quick start

```sh
# Build the release binary once
cargo build --release --manifest-path tools/nexacore-driver-pack/Cargo.toml

# Produce a signed .opack blob
./target/release/nexacore-driver-pack \
  --manifest  crates/nexacore-driver-net-virtio/manifest.json \
  --image     target/x86_64-unknown-none/release/nexacore-driver-net-virtio \
  --signing-key /secure/issuer.seed \
  --output    nexacore-driver-net-virtio.opack
```

---

## CLI flags

| Flag | Required | Description |
|------|----------|-------------|
| `--manifest <path>` | yes | Driver manifest file (`.toml` or `.json` — format auto-detected from extension) |
| `--image <path>` | yes | Ring 3 ELF image |
| `--signing-key <path>` | yes | 64-char hex Ed25519 seed file (32 raw bytes) |
| `--output <path>` | yes | Output `.opack` path |
| `--allow-loose-permissions` | no | Suppress file-permission warning for `--signing-key` |
| `--help` / `-h` | — | Print help and exit 0 |
| `--version` / `-V` | — | Print version and exit 0 |

---

## Exit codes

| Code | Category | When |
|------|----------|------|
| 0 | Success | Blob written to `--output` |
| 1 | Usage / I/O | Missing flag, unreadable file, or unwritable output path |
| 2 | Manifest parse | JSON invalid or schema mismatch |
| 3 | Signing key | Bad hex, wrong length, or key doesn't match `nexacore_issuer_pubkey` |
| 4 | Pack build | Manifest too large (> 16 KiB), total blob too large (> 32 MiB) |

---

## JSON manifest schema

```json
{
  "meta": {
    "name": "nexacore-driver-net-virtio",
    "version": "0.2.0",
    "nexacore_issuer_pubkey": "<64 lowercase hex chars>"
  },
  "capabilities": {
    "mmio_regions": [
      { "MmioRegion": { "phys_base": 4294967296, "len": 65536 } }
    ],
    "dma_windows": [
      { "DmaWindow": { "iova_base": 0, "len": 4294967296 } }
    ],
    "irq_lines": [
      { "IrqLine": 33 }
    ],
    "pci_devices": []
  },
  "matchers": {
    "pci_vendor_device": [
      { "vendor": 6900, "device": 4161 }
    ],
    "acpi_hid": []
  }
}
```

Field notes:

- `nexacore_issuer_pubkey` — Ed25519 verifying key in 64-char lowercase hex (32 raw bytes).
  Must correspond to the `--signing-key` seed; the tool validates the match before
  producing the blob (NCIP-013 § S5.4).
- `mmio_regions` / `dma_windows` / `irq_lines` / `pci_devices` — capability claims
  using serde's externally-tagged format (`{"VariantName": { fields }}`).
- `nexacore_image_hash` and `nexacore_signature` are **not** present in the JSON — the tool
  computes the BLAKE3 image hash from the ELF bytes at pack time and produces the
  Ed25519 signature itself.

---

## Signing key format

A plain-text file containing **exactly 64 lowercase hex characters** (= 32 raw bytes),
optionally followed by a single newline.  This is the Ed25519 seed (the private scalar);
the corresponding verifying key is derived deterministically.

**Recommended permissions:** `chmod 0400 issuer.seed`

The tool warns to stderr if the key file is group-readable (`mode & 0o040`) or
world-readable (`mode & 0o004`).  Pass `--allow-loose-permissions` to silence the
warning (e.g. in CI with secrets management).

Example:
```
9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
```

---

## NexaCore-Pack v1 wire format

```text
Offset  Size  Field
─────── ───── ──────────────────────────────────────────────────
0x00    8     magic            = b"OMNIPACK"
0x08    4     version          = 1u32 (little-endian)
0x0C    4     flags            = 0u32 (reserved, always 0)
0x10    8     manifest_offset  = 0x40 (immediately follows header)
0x18    8     manifest_len     (postcard bytes, ≤ 16 KiB)
0x20    8     signature_offset = 0x40 + manifest_len
0x28    8     signature_len    = 64 (Ed25519 always 64 bytes)
0x30    8     image_offset     = 0x40 + manifest_len + 64
0x38    8     image_len
0x40    *     manifest.pc      postcard-encoded DriverManifestBody
*       64    signature        Ed25519 over manifest.pc
*       *     image.elf        Ring 3 ELF
─────── ───── ──────────────────────────────────────────────────
```

The kernel-side decoder is `nexacore_kernel::driver_manifest::decode_nexacore_pack`.

---

## Building and testing

```sh
# Build
cargo build --release --manifest-path tools/nexacore-driver-pack/Cargo.toml

# Run integration tests
cargo test --manifest-path tools/nexacore-driver-pack/Cargo.toml

# Clippy
cargo clippy --manifest-path tools/nexacore-driver-pack/Cargo.toml \
             --all-targets -- -D warnings

# Format check
cargo fmt --manifest-path tools/nexacore-driver-pack/Cargo.toml -- --check
```

This crate is **workspace-excluded** (like `kernel-runner`) so `cargo build --workspace`
on the main workspace stays clean without the full std toolchain context.

---

## References

- NCIP-Driver-Framework-013 § S5.5 — wire format specification
- NCIP-Driver-Framework-013 § S5.4 — issuer-pubkey / KNOWN_ISSUERS policy
- `crates/nexacore-kernel/src/driver_manifest.rs` — kernel-side decoder
- `docs/protocol/` — canonical driver manifest documentation
