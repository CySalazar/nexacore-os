//! End-to-end deposit round-trip test.
//!
//! Stages a synthetic `OMNICAPS` deposit page in user-allocated memory,
//! runs [`nexacore_driver_shared::caps::find_token_in_buf`] against it, and
//! asserts that the returned bytes round-trip through
//! [`nexacore_types::wire::decode_canonical::<CapabilityToken>`] to produce
//! an equal token.
//!
//! This test exercises the full wire-format contract end-to-end:
//!
//! ```text
//! CapabilityToken  →  encode_canonical  →  OMNICAPS page bytes
//!                                               ↓  find_token_in_buf
//!                                         &[u8] slice
//!                                               ↓  decode_canonical
//!                                         CapabilityToken  (must equal original)
//! ```
//!
//! Gated `#[cfg(not(target_os = "none"))]` so bare-metal builds, which
//! cannot link `std` or `nexacore-crypto`, skip it automatically.
//!
//! # Dependencies (dev-only)
//!
//! - `nexacore-crypto` — provides [`NexaCoreSigningKey`] to sign a test token.
//! - `nexacore-capability` — provides [`CapabilityToken`], [`TokenPayload`],
//!   [`Scope`], [`Action`], [`Resource`], [`TimeWindow`].
//! - `nexacore-types` — provides [`CapabilityId`], [`NodeId`], and the
//!   [`encode_canonical`] / [`decode_canonical`] wire helpers.

#![cfg(not(target_os = "none"))]
// All `expect` / `unwrap` in tests is intentional — failures produce
// informative panics during `cargo test`.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "integration test relaxations: expect/unwrap/panic/direct-index/cast are \
              acceptable in a test binary"
)]

use nexacore_capability::{Action, CapabilityToken, Resource, Scope, TimeWindow, TokenPayload};
use nexacore_crypto::signing::NexaCoreSigningKey;
use nexacore_driver_shared::{
    ACTION_TAG_DMA_MAP, ACTION_TAG_IRQ_ATTACH, ACTION_TAG_MMIO_MAP, DRIVER_CAP_DEPOSIT_LEN,
    caps::find_token_in_buf,
};
use nexacore_types::{
    identity::{CapabilityId, NodeId},
    wire,
};

// ---------------------------------------------------------------------------
// Helper — build a minimal OMNICAPS page from a list of
//          (action_tag, resource_tag, token_bytes) triples.
// ---------------------------------------------------------------------------

/// Byte length of the fixed header (mirrors the private constant in lib.rs).
const HEADER_LEN: usize = 16;
/// Byte length of each entry descriptor (mirrors the private constant in lib.rs).
const ENTRY_DESCRIPTOR_LEN: usize = 16;

fn build_deposit_page(entries: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut buf = vec![0u8; DRIVER_CAP_DEPOSIT_LEN];

    // Header: magic + version=1 + entry_count (all little-endian)
    buf[0..8].copy_from_slice(b"OMNICAPS");
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    buf[12..16].copy_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());

    // Token blobs start right after header + full descriptor table.
    let mut cursor = HEADER_LEN + entries.len() * ENTRY_DESCRIPTOR_LEN;

    for (i, (action_tag, resource_tag, token_bytes)) in entries.iter().enumerate() {
        let desc = HEADER_LEN + i * ENTRY_DESCRIPTOR_LEN;
        buf[desc..desc + 4].copy_from_slice(&action_tag.to_le_bytes());
        buf[desc + 4..desc + 8].copy_from_slice(&resource_tag.to_le_bytes());
        buf[desc + 8..desc + 12].copy_from_slice(&u32::try_from(cursor).unwrap().to_le_bytes());
        buf[desc + 12..desc + 16]
            .copy_from_slice(&u32::try_from(token_bytes.len()).unwrap().to_le_bytes());
        buf[cursor..cursor + token_bytes.len()].copy_from_slice(token_bytes);
        cursor += token_bytes.len();
    }

    buf
}

// ---------------------------------------------------------------------------
// E2E round-trip test
// ---------------------------------------------------------------------------

/// Stage a complete `CapabilityToken` in a synthetic OMNICAPS deposit
/// page, retrieve it via [`find_token_in_buf`], decode it, and assert
/// the round-trip is lossless.
#[test]
fn deposit_round_trip_mmio_map_token() {
    // ── 1. Create a deterministic Ed25519 signing key. ──────────────────────
    // Using a fixed seed avoids any dependency on OS entropy in CI.
    let seed = [0x42u8; 32];
    let signing_key = NexaCoreSigningKey::from_bytes(seed);

    // ── 2. Construct a TokenPayload for an MmioMap capability. ──────────────
    let cap_id = CapabilityId::from_bytes([0xAB; 16]);
    let subject = NodeId::from_attestation_hash([0u8; 32]); // placeholder subject

    // 90-day window starting at a fixed epoch second.
    let not_before: u64 = 1_000_000;
    let not_after: u64 = not_before + 90 * 24 * 3600;
    let window = TimeWindow::new(not_before, not_after)
        .expect("not_before < not_after — window construction must succeed");

    let resource = Resource::MmioRegion {
        phys_base: 0xFEBC_0000,
        len: 0x0002_0000,
    };
    let scope = Scope {
        action: Action::MmioMap,
        resource,
        window,
        caveats: Vec::new(),
    };
    let payload = TokenPayload {
        id: cap_id,
        subject,
        issuer: signing_key.verifying_key(),
        parent: None,
        scope,
    };

    // ── 3. Sign the payload to produce a CapabilityToken. ───────────────────
    let original_token: CapabilityToken = CapabilityToken::sign_payload(&signing_key, payload)
        .expect("sign_payload must succeed for a well-formed payload");

    // ── 4. Encode the token to its wire representation. ─────────────────────
    let token_bytes: Vec<u8> = wire::encode_canonical(&original_token)
        .expect("encode_canonical must succeed for a well-formed CapabilityToken");

    // ── 5. Build a synthetic OMNICAPS deposit page. ──────────────────────────
    // resource_tag = 1 (MmioRegion), matching the kernel's ACTION_TAG_MMIO_MAP.
    let page = build_deposit_page(&[(ACTION_TAG_MMIO_MAP, 1, &token_bytes)]);

    // ── 6. Run find_token_in_buf against the synthetic page. ────────────────
    let found = find_token_in_buf(&page, ACTION_TAG_MMIO_MAP, |_| true)
        .expect("find_token_in_buf must locate the MmioMap entry we just inserted");

    // The returned slice must point to the exact token bytes we embedded.
    assert_eq!(
        found,
        token_bytes.as_slice(),
        "find_token_in_buf must return the verbatim encoded bytes"
    );

    // ── 7. Decode the returned bytes and verify the round-trip. ─────────────
    let decoded_token: CapabilityToken = wire::decode_canonical(found)
        .expect("decode_canonical must succeed for the bytes we encoded in step 4");

    assert_eq!(
        decoded_token, original_token,
        "decoded token must equal the original token (wire format round-trip)"
    );
}

/// Verify that the predicate filter works end-to-end:
/// a deposit with two MmioMap entries returns only the one for which
/// the predicate returns `true`.
#[test]
fn deposit_round_trip_predicate_filter_selects_correct_token() {
    let signing_key = NexaCoreSigningKey::from_bytes([0x11u8; 32]);

    let make_mmio_token = |phys_base: u64| -> Vec<u8> {
        let payload = TokenPayload {
            id: CapabilityId::from_bytes([phys_base as u8; 16]),
            subject: NodeId::from_attestation_hash([0u8; 32]),
            issuer: signing_key.verifying_key(),
            parent: None,
            scope: Scope {
                action: Action::MmioMap,
                resource: Resource::MmioRegion {
                    phys_base,
                    len: 0x1000,
                },
                window: TimeWindow::new(0, 90 * 86_400).expect("valid window"),
                caveats: Vec::new(),
            },
        };
        let token = CapabilityToken::sign_payload(&signing_key, payload)
            .expect("sign_payload must succeed");
        wire::encode_canonical(&token).expect("encode_canonical must succeed")
    };

    // Two MmioMap tokens for different physical addresses.
    let tok_a = make_mmio_token(0xFEB0_0000);
    let tok_b = make_mmio_token(0xFEC0_0000);

    let page = build_deposit_page(&[
        (ACTION_TAG_MMIO_MAP, 1, &tok_a),
        (ACTION_TAG_MMIO_MAP, 1, &tok_b),
    ]);

    // Predicate: accept only the token whose decoded resource has phys_base == 0xFEC0_0000.
    let selected = find_token_in_buf(&page, ACTION_TAG_MMIO_MAP, |raw| {
        let t: CapabilityToken = wire::decode_canonical(raw).unwrap();
        matches!(
            t.payload.scope.resource,
            Resource::MmioRegion { phys_base, .. } if phys_base == 0xFEC0_0000
        )
    });

    let selected_bytes = selected.expect("predicate-filtered find must return the second token");
    let selected_token: CapabilityToken =
        wire::decode_canonical(selected_bytes).expect("decode must succeed");

    assert!(
        matches!(
            selected_token.payload.scope.resource,
            Resource::MmioRegion { phys_base, .. } if phys_base == 0xFEC0_0000
        ),
        "selected token resource must be the one at phys_base=0xFEC0_0000"
    );
}

// ===========================================================================
// Additional E2E tests added by the test engineer (TASK-003 coverage gaps)
// ===========================================================================

/// Stage a `DmaMap` / `DmaWindow` `CapabilityToken` in a synthetic deposit page,
/// retrieve it via [`find_token_in_buf`], and assert the full
/// encode → deposit → find → decode round-trip is lossless.
#[test]
fn deposit_round_trip_dma_map_token() {
    // ── 1. Fixed signing key for determinism in CI. ─────────────────────────
    let signing_key = NexaCoreSigningKey::from_bytes([0x43u8; 32]);

    // ── 2. Build a DmaMap TokenPayload. ─────────────────────────────────────
    let window = TimeWindow::new(1_000_000, 1_000_000 + 90 * 24 * 3600)
        .expect("valid time window — not_before < not_after");
    let payload = TokenPayload {
        id: CapabilityId::from_bytes([0xBCu8; 16]),
        subject: NodeId::from_attestation_hash([0u8; 32]),
        issuer: signing_key.verifying_key(),
        parent: None,
        scope: Scope {
            action: Action::DmaMap,
            resource: Resource::DmaWindow {
                iova_base: 0x1_0000_0000,
                len: 0x4000,
            },
            window,
            caveats: Vec::new(),
        },
    };

    // ── 3. Sign and encode. ──────────────────────────────────────────────────
    let original_token = CapabilityToken::sign_payload(&signing_key, payload)
        .expect("sign_payload must succeed for a well-formed DmaMap payload");
    let token_bytes = wire::encode_canonical(&original_token)
        .expect("encode_canonical must succeed for a well-formed CapabilityToken");

    // ── 4. Build a synthetic deposit page with one DmaMap entry. ────────────
    // resource_tag = 2 (DmaWindow) per the wire-format table in README.
    let page = build_deposit_page(&[(ACTION_TAG_DMA_MAP, 2, &token_bytes)]);

    // ── 5. Retrieve and verify. ──────────────────────────────────────────────
    let found = find_token_in_buf(&page, ACTION_TAG_DMA_MAP, |_| true)
        .expect("find_token_in_buf must locate the DmaMap entry we inserted");

    assert_eq!(
        found,
        token_bytes.as_slice(),
        "find_token_in_buf must return the verbatim encoded DmaMap bytes"
    );

    let decoded: CapabilityToken = wire::decode_canonical(found)
        .expect("decode_canonical must succeed for the bytes we encoded above");
    assert_eq!(
        decoded, original_token,
        "decoded DmaMap token must equal the original (lossless wire-format round-trip)"
    );
}

/// Stage an `IrqAttach` / `IrqLine` `CapabilityToken` in a synthetic deposit page
/// and assert the full encode → deposit → find → decode round-trip is lossless.
#[test]
fn deposit_round_trip_irq_attach_token() {
    // ── 1. Fixed signing key. ────────────────────────────────────────────────
    let signing_key = NexaCoreSigningKey::from_bytes([0x44u8; 32]);

    // ── 2. Build an IrqAttach TokenPayload for IRQ line 33. ─────────────────
    let payload = TokenPayload {
        id: CapabilityId::from_bytes([0xCDu8; 16]),
        subject: NodeId::from_attestation_hash([0u8; 32]),
        issuer: signing_key.verifying_key(),
        parent: None,
        scope: Scope {
            action: Action::IrqAttach,
            resource: Resource::IrqLine(33),
            window: TimeWindow::new(0, 90 * 86_400).expect("valid window"),
            caveats: Vec::new(),
        },
    };

    // ── 3. Sign and encode. ──────────────────────────────────────────────────
    let original_token = CapabilityToken::sign_payload(&signing_key, payload)
        .expect("sign_payload must succeed for a well-formed IrqAttach payload");
    let token_bytes = wire::encode_canonical(&original_token)
        .expect("encode_canonical must succeed for a well-formed CapabilityToken");

    // ── 4. Build a synthetic deposit page with one IrqAttach entry. ─────────
    // resource_tag = 3 (IrqLine) per the wire-format table in README.
    let page = build_deposit_page(&[(ACTION_TAG_IRQ_ATTACH, 3, &token_bytes)]);

    // ── 5. Retrieve and verify. ──────────────────────────────────────────────
    let found = find_token_in_buf(&page, ACTION_TAG_IRQ_ATTACH, |_| true)
        .expect("find_token_in_buf must locate the IrqAttach entry we inserted");

    assert_eq!(
        found,
        token_bytes.as_slice(),
        "find_token_in_buf must return the verbatim encoded IrqAttach bytes"
    );

    let decoded: CapabilityToken = wire::decode_canonical(found)
        .expect("decode_canonical must succeed for the bytes we encoded above");
    assert_eq!(
        decoded, original_token,
        "decoded IrqAttach token must equal the original (lossless wire-format round-trip)"
    );
}

/// A valid OMNICAPS deposit page with `entry_count=0` must return `None`
/// for every possible `action_tag` value.
#[test]
fn deposit_empty_page_find_returns_none() {
    let page = build_deposit_page(&[]); // valid header, zero entries

    // Check the three defined action tags plus u32::MAX (undefined).
    for action_tag in [
        ACTION_TAG_MMIO_MAP,
        ACTION_TAG_DMA_MAP,
        ACTION_TAG_IRQ_ATTACH,
        u32::MAX,
    ] {
        let result = find_token_in_buf(&page, action_tag, |_| true);
        assert!(
            result.is_none(),
            "empty deposit page must return None for action_tag={action_tag}"
        );
    }
}

/// Build a mixed deposit page (MmioMap + DmaMap + IrqAttach entries) and assert
/// that querying for `ACTION_TAG_IRQ_ATTACH` returns exactly the IrqAttach token
/// — not the MmioMap or DmaMap entry — and that it round-trips correctly.
#[test]
fn deposit_round_trip_mixed_actions_returns_correct_type() {
    let signing_key = NexaCoreSigningKey::from_bytes([0x55u8; 32]);

    // Helper closure: mint a signed token and return its encoded bytes.
    let make_token = |action: Action, resource: Resource| -> Vec<u8> {
        let payload = TokenPayload {
            // Unique-ish IDs (keyed off action discriminant byte).
            id: CapabilityId::from_bytes([0xEEu8; 16]),
            subject: NodeId::from_attestation_hash([0u8; 32]),
            issuer: signing_key.verifying_key(),
            parent: None,
            scope: Scope {
                action,
                resource,
                window: TimeWindow::new(0, 90 * 86_400).expect("valid window"),
                caveats: Vec::new(),
            },
        };
        let t = CapabilityToken::sign_payload(&signing_key, payload)
            .expect("sign_payload must succeed");
        wire::encode_canonical(&t).expect("encode_canonical must succeed")
    };

    let mmio_bytes = make_token(
        Action::MmioMap,
        Resource::MmioRegion {
            phys_base: 0xFEB0_0000,
            len: 0x1000,
        },
    );
    let dma_bytes = make_token(
        Action::DmaMap,
        Resource::DmaWindow {
            iova_base: 0x1_0000_0000,
            len: 0x4000,
        },
    );
    let irq_bytes = make_token(Action::IrqAttach, Resource::IrqLine(42));

    let page = build_deposit_page(&[
        (ACTION_TAG_MMIO_MAP, 1, &mmio_bytes),
        (ACTION_TAG_DMA_MAP, 2, &dma_bytes),
        (ACTION_TAG_IRQ_ATTACH, 3, &irq_bytes),
    ]);

    // Query for IrqAttach specifically — must not return the MmioMap or DmaMap entry.
    let found = find_token_in_buf(&page, ACTION_TAG_IRQ_ATTACH, |_| true)
        .expect("must find the IrqAttach entry in a mixed-action deposit page");

    let decoded: CapabilityToken =
        wire::decode_canonical(found).expect("decode_canonical must succeed");

    assert_eq!(
        decoded.payload.scope.action,
        Action::IrqAttach,
        "decoded token action must be IrqAttach, not MmioMap or DmaMap"
    );
    assert!(
        matches!(decoded.payload.scope.resource, Resource::IrqLine(42)),
        "decoded token resource must be IrqLine(42), found: {:?}",
        decoded.payload.scope.resource
    );
    // Verify the round-trip is bit-exact.
    let re_encoded = wire::encode_canonical(&decoded).expect("re-encode must succeed");
    assert_eq!(
        re_encoded, irq_bytes,
        "re-encoded IrqAttach token must be byte-identical to the original encoding"
    );
}
