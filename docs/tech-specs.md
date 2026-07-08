# Tech Specifications (redirect)

> **The canonical tech-specs document of this project is [`/docs/09-tech-specifications.md`](./09-tech-specifications.md).** This file is a pointer to avoid duplicating version tables.

See: [`/docs/09-tech-specifications.md`](./09-tech-specifications.md) for the authoritative version table covering:

- Language (Rust 1.85+, edition 2024)
- Toolchain (`rustc`, `cargo`, `clippy`, `rustfmt`, `cargo-audit`, `cargo-deny`, `cargo-nextest`, `cargo-llvm-cov`)
- Cryptography deps (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `sha2`, `sha3`, `blake3`, `hkdf`, `argon2`, `subtle`, `zeroize`)
- Networking (`quinn`, `snow`, `hickory-dns`, `libp2p`, `if-watch`)
- Async runtime (`tokio`, `async-trait`, `futures`)
- Serialization (`serde`, `prost`, `capnp`, `postcard`)
- AI / tensors (`candle`, `tch`, `safetensors`, `tokenizers`)
- Sandboxing (`wasmtime` — TBD)
- Testing (`criterion`, `proptest`, `mockall`, `trybuild`, `insta`)
- Observability (`tracing`, `tracing-subscriber`, `metrics`)
- Error handling (`thiserror` v2, `anyhow`)
- TEE-specific (Intel TDX SDK, AMD SEV-SNP attestation, `tdx-quote-verification` TBD)
- License-compliance policy (allowed and forbidden licenses)
- `no_std` policy per crate

Any update to dependency versions MUST go into `/docs/09-tech-specifications.md`. This file is not maintained.
