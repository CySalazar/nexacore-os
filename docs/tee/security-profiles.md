# Security profiles and the profile → mesh-capability matrix

**Status:** Living document (WS10-08.10, WS10-08.11)
**Scope:** the [`SealingProvider`] abstraction and the [`SecurityProfile`] it
yields in [`nexacore-tee::sealing`](../../crates/nexacore-tee/src/sealing.rs), and
the mesh capabilities each profile is granted.
**Refs:** the development plan WS10-08, NCIP-024 (trust tiers), `docs/04-security-model.md`,
WS10-01/02 (hardware TEE backends), WS10-03 (cryptographic review).

## 1. Why profiles exist

NexaCore must run **fully** on hardware with no confidential-computing TEE.
Sealing — protecting the PII-vault key, the full-disk-encryption key, and
persistent capabilities at rest — is therefore expressed against a single
[`SealingProvider`] trait with three interchangeable backends, selected
best-available at runtime:

| Backend (`SealingBackendKind`) | Root of trust | `SecurityProfile` | Tier |
|--------------------------------|---------------|-------------------|------|
| `HardwareTee` (TDX / SEV-SNP)  | CPU TEE       | `HardwareTee`     | 1    |
| `Tpm2`                         | TPM 2.0       | `Tpm`             | 2    |
| `SoftwareKeystore`             | passphrase + device salt (Argon2id) | `SoftwareOnly` | 3 |

Selection order is `HardwareTee → Tpm2 → SoftwareKeystore`
([`select_sealing_backend`]); the software keystore is the always-present floor,
so selection never fails. The active profile is surfaced to Settings and to the
Impact Dashboard so a node's trust tier is **explicit and honest**, never hidden.

## 2. Profile → mesh-capability matrix

Per NCIP-024, capabilities scale with the strength of the root of trust. The
matrix below is enforced by the `SecurityProfile` methods.

| Capability                       | `HardwareTee` | `Tpm` | `SoftwareOnly` |
|----------------------------------|:-------------:|:-----:|:--------------:|
| Originate mesh messages          | ✅            | ✅    | ✅             |
| Consume mesh messages            | ✅            | ✅    | ✅             |
| Contribute Tier-2 (relay/compute)| ✅            | ✅    | ❌             |
| `mesh_tier()`                    | 1             | 2     | 3              |

- **Originate / consume — always granted.** Every node, regardless of hardware,
  participates in the mesh as a first-class sender and receiver
  (`can_originate()` / `can_consume()` return `true` for all profiles). This is
  the core guarantee that the software-only profile is *fully functional*.
- **Tier-2 contribution — hardware-rooted only.** Relaying or contributing
  compute for *other* nodes requires a hardware-attestable root of trust, so
  `can_contribute_tier2()` is `true` only for `HardwareTee` and `Tpm`. A
  software-only node consumes Tier-2 capacity but does not provide it (no Sybil
  amplification without a hardware anchor).

## 3. The software keystore

`SoftwareKeystore` is a real, host-tested provider:

- **Master key.** Derived from a user passphrase and a device-bound salt via
  **Argon2id** (RFC 9106, memory-hard) behind the [`MasterKeyKdf`] seam. Argon2id
  needs the `nexacore-crypto` `rng`/std feature, so it binds in at the std
  boundary; the keystore logic is exercised on the host with a deterministic KDF.
- **Subkeys.** `derive_subkey(context)` is HKDF-SHA-256 over the master key, so
  the PII vault, the FDE key, and the capability store each get an independent,
  context-separated key from one master.
- **Sealing.** `seal` / `unseal` use ChaCha20-Poly1305 with a **synthetic,
  content-bound (SIV-style) nonce** — `HKDF(master, label ‖ aad ‖ plaintext)` —
  so no `(key, nonce)` pair is ever reused over different data, including across
  keystore re-instantiations (there is no resettable counter). The AAD binds the
  envelope version **and** the `SealPolicy` (family + measurement), so a blob
  cannot be replayed under a different policy or envelope format.
- **Key separation.** The seal key, the subkey domain (`derive_subkey`), and the
  nonce domain use disjoint HKDF labels, so no caller-supplied context can
  reproduce the seal key (confused-deputy / key-extraction defence).
- **Key protection.** The master key lives in a `KeyMaterial` wrapper that
  **zeroizes on drop** via a volatile write loop + compiler fence (the same
  pattern as `TeeSharedKey`; `nexacore-tee` deliberately avoids the `zeroize`
  dependency). Pinning the key pages with `mlock` is a `std`/OS step applied at
  the process boundary (gated).

## 4. Cryptographic-review scope (WS10-08.11 → WS10-03)

The software keystore is **in scope** for the WS10-03 external cryptographic
review. The review must cover, at minimum:

1. The Argon2id parameters (memory, iterations, parallelism) vs. the OWASP 2026
   cheatsheet and the device's worst-case hardware.
2. The device-salt derivation and its binding (must be per-device, non-exportable
   where the platform allows).
3. The HKDF context-separation labels for the vault / FDE / capability subkeys.
4. The seal envelope (nonce management, AAD policy binding, no nonce reuse across
   the keystore lifetime).
5. The zeroization coverage and any residual copies of key material.

## 5. Migration status (WS10-08.6/.7/.8)

The consumers below are being migrated onto `SealingProvider`; until then they
use their existing per-subsystem sealing:

- **PII vault key** (WS5-06) → `derive_subkey(b"pii-vault")` + provider seal.
- **FDE key** (WS3-07) → `derive_subkey(b"fde-key")` + provider seal.
- **Persistent capability store** → `derive_subkey(b"capabilities")` + provider
  seal.

Each migration is a localized change in the owning subsystem that swaps its
bespoke sealing call for the `SealingProvider` trait; the abstraction and the
software backend (this work) are the precondition.

[`SealingProvider`]: ../../crates/nexacore-tee/src/sealing.rs
[`SecurityProfile`]: ../../crates/nexacore-tee/src/sealing.rs
[`MasterKeyKdf`]: ../../crates/nexacore-tee/src/sealing.rs
[`select_sealing_backend`]: ../../crates/nexacore-tee/src/sealing.rs
