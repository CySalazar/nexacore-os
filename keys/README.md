# NexaCore OS — Release signing keys

This directory holds the **public** halves of the keys used to sign NexaCore OS
release artifacts. Private keys are never committed to the repository.

## Files

| File | Purpose |
|------|---------|
| `nexacore-release-ed25519.pub.pem` | Ed25519 public key verifying the detached `.sig` emitted next to each release ISO (WS0-04.5) |

## Verifying a release ISO

Every release publishes three files: the ISO, a SHA-256 checksum, and a
detached Ed25519 signature over the ISO bytes:

```
nexacore-os-<tag>.iso
nexacore-os-<tag>.iso.sha256
nexacore-os-<tag>.iso.sig
```

Verify integrity, then authenticity:

```bash
sha256sum -c nexacore-os-<tag>.iso.sha256

openssl pkeyutl -verify -pubin \
    -inkey keys/nexacore-release-ed25519.pub.pem \
    -rawin -in nexacore-os-<tag>.iso \
    -sigfile nexacore-os-<tag>.iso.sig
# prints: Signature Verified Successfully
```

From a checkout, `scripts/sig-verify-test.sh --iso <path-to-iso>` runs the
same verification (WS0-04.8); with no arguments it self-tests the whole
sign/verify contract with an ephemeral keypair (no private key needed).

## Signing (release engineers only)

`scripts/build-iso.sh` signs automatically when the private key is
reachable: it looks at `NEXACORE_RELEASE_SIGNING_KEY` (path to the Ed25519
private key in PEM form), falling back to
`~/.nexacore-release/nexacore-release-ed25519.pem`. When neither exists the build
still succeeds and logs that signing was skipped — development builds do
not require the key.

The dedicated keypair was generated with:

```bash
umask 077
openssl genpkey -algorithm ed25519 -out nexacore-release-ed25519.pem
openssl pkey -in nexacore-release-ed25519.pem -pubout -out nexacore-release-ed25519.pub.pem
```

Key custody: the current private key lives on the release build host only.
Rotating it means generating a new pair, replacing the `.pub.pem` here, and
documenting the rotation in `CHANGELOG.md`.
