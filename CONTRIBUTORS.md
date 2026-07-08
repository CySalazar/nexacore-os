# Contributors

NexaCore OS is, today, a single-founder project in the Phase-0 foundation phase. This
document tracks individuals and organizations that have contributed to the project
in any verifiable capacity.

## Roles

| Role | Holder | Period | Notes |
|---|---|---|---|
| **Lead Architect / BDFL** | cySalazar (`hello@nexacoreos.com`) | 2026-05-09 → 2031-05-09 (BDFL veto window) | See [`docs/05-governance.md`](docs/05-governance.md) § "Founder role". |
| **NCIP Editors** | *(TBD — appointment in Phase 0 closure)* | annual rotation | Two editors per term per `NCIP-Process-001`. |
| **Cryptographer (peer review)** | *(TBD)* | engagement TBD | Will be appointed via `docs/audits/cryptographer-engagement-template.md`. |
| **Governing body** | *(TBD — legal-entity setup; form under evaluation)* | Defined at establishment | Composition set by the entity's constitutional documents. |

## Code contributors

All code contributors must:

1. Sign their commits cryptographically (SSH ed25519 or GPG; see
   [`CONTRIBUTING.md`](CONTRIBUTING.md) § "Signing").
2. Sign off on the DCO (`Signed-off-by:` trailer; enforced by
   `.github/workflows/dco.yml`).
3. Be listed below upon their first merged contribution.

Generated automatically from `git log` (script under `scripts/regen-contributors.sh`,
TBD); manual maintenance until that lands.

### Active maintainers

- **cySalazar** — Lead Architect, founder. First commit: `61426d5` (2026-05-09).

### Past contributors

*(none yet)*

## Acknowledgements

- The **RustCrypto** maintainers, whose crates (`chacha20poly1305`,
  `ed25519-dalek`, `x25519-dalek`, `sha2`, `sha3`, `blake3`, `hkdf`, `argon2`,
  `subtle`, `zeroize`) are the cryptographic base of `nexacore-crypto`.
- The **seL4** project, prior art for verified microkernels; cited as a
  long-term aspirational target in [`docs/02-architecture.md`](docs/02-architecture.md).
- The **Tamarin Prover** team for the symbolic protocol verifier used in
  [`protocol-proofs/handshake.spthy`](protocol-proofs/handshake.spthy).
- The **Contributor Covenant** project for the basis of our
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## How to be listed

Submit a pull request that lands a substantive change — code, documentation,
NCIP, security finding, formal-method proof, or translation. Trivial fixes
(typos, lint adjustments) are welcome but do not result in listing.

Listing carries no legal weight. The project's legal entity (once established) maintains
the authoritative list of trustees, employees, and contractors separately.
