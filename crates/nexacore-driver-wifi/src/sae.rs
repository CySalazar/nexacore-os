//! SAE (WPA3) Commit / Confirm message framing and peer state machine
//! (WS2-11.8).
//!
//! Simultaneous Authentication of Equals replaces the WPA2 PSK handshake with a
//! balanced PAKE carried in 802.11 authentication frames (algorithm
//! [`crate::frame::auth_algo::SAE`]): each peer sends a **Commit**
//! (group, scalar, element) then a **Confirm** (send-confirm, confirm hash).
//!
//! This module owns the wire framing and the peer state machine. The actual
//! cryptography — deriving the password element (hunting-and-pecking / hash-to-
//! element), computing the scalar/element and the confirm hash over the chosen
//! finite-field or elliptic-curve group — needs a vetted EC library not present
//! in `nexacore-crypto`, so the scalar/element/confirm are handled as opaque
//! byte strings sized by the group. Framing and sequencing are host-tested.

// Lengths are bounded by the group element size; the `as` casts are checked.
#![allow(clippy::cast_possible_truncation)]

use alloc::vec::Vec;

/// Per-group byte lengths for the SAE field elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupParams {
    /// Finite-cyclic-group / curve id (IANA "Group Description").
    pub group: u16,
    /// Scalar length in bytes (the group order / prime size).
    pub scalar_len: usize,
    /// Element (FFE) length in bytes (2× prime for an ECC affine point).
    pub element_len: usize,
    /// Confirm-hash length in bytes (the KDF hash output).
    pub confirm_len: usize,
}

/// Look up the field lengths for the common WPA3 elliptic-curve groups.
///
/// Group 19 = NIST P-256, 20 = P-384, 21 = P-521 (RFC 7664 / IANA registry).
#[must_use]
pub fn group_params(group: u16) -> Option<GroupParams> {
    let (scalar_len, element_len, confirm_len) = match group {
        19 => (32, 64, 32),
        20 => (48, 96, 48),
        21 => (66, 132, 64),
        _ => return None,
    };
    Some(GroupParams {
        group,
        scalar_len,
        element_len,
        confirm_len,
    })
}

/// A parsed SAE Commit message body (the bytes after the auth fixed fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaeCommit {
    /// Group id.
    pub group: u16,
    /// Scalar (`scalar_len` bytes).
    pub scalar: Vec<u8>,
    /// Element / FFE (`element_len` bytes).
    pub element: Vec<u8>,
    /// Anti-clogging token, present only when the AP requested one.
    pub anti_clogging_token: Option<Vec<u8>>,
}

/// Build a SAE Commit message body: `group ‖ [token] ‖ scalar ‖ element`.
#[must_use]
pub fn build_commit(group: u16, scalar: &[u8], element: &[u8], token: Option<&[u8]>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&group.to_le_bytes());
    if let Some(t) = token {
        v.extend_from_slice(t);
    }
    v.extend_from_slice(scalar);
    v.extend_from_slice(element);
    v
}

/// Parse a SAE Commit body. The token (if any) is whatever precedes the fixed
/// scalar+element tail, so the length is inferred from the group.
#[must_use]
pub fn parse_commit(body: &[u8]) -> Option<SaeCommit> {
    let group = u16::from_le_bytes([*body.first()?, *body.get(1)?]);
    let p = group_params(group)?;
    let rest = body.get(2..)?;
    let fixed = p.scalar_len + p.element_len;
    if rest.len() < fixed {
        return None;
    }
    let token_len = rest.len() - fixed;
    let token = if token_len > 0 {
        Some(rest.get(..token_len)?.to_vec())
    } else {
        None
    };
    let scalar = rest.get(token_len..token_len + p.scalar_len)?.to_vec();
    let element = rest.get(token_len + p.scalar_len..)?.to_vec();
    Some(SaeCommit {
        group,
        scalar,
        element,
        anti_clogging_token: token,
    })
}

/// A parsed SAE Confirm message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaeConfirm {
    /// Send-Confirm counter (anti-replay).
    pub send_confirm: u16,
    /// Confirm hash.
    pub confirm: Vec<u8>,
}

/// Build a SAE Confirm body: `send_confirm(LE) ‖ confirm`.
#[must_use]
pub fn build_confirm(send_confirm: u16, confirm: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + confirm.len());
    v.extend_from_slice(&send_confirm.to_le_bytes());
    v.extend_from_slice(confirm);
    v
}

/// Parse a SAE Confirm body.
#[must_use]
pub fn parse_confirm(body: &[u8]) -> Option<SaeConfirm> {
    let send_confirm = u16::from_le_bytes([*body.first()?, *body.get(1)?]);
    let confirm = body.get(2..)?.to_vec();
    Some(SaeConfirm {
        send_confirm,
        confirm,
    })
}

/// SAE peer state (RFC 7664 / IEEE 802.11 § SAE finite state machine, supplicant
/// view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaeState {
    /// No exchange started.
    Nothing,
    /// Sent our Commit; waiting for the peer's Commit.
    Committed,
    /// Sent our Confirm; waiting for the peer's Confirm.
    Confirmed,
    /// Peer Confirm verified — authenticated.
    Accepted,
    /// A length/group/confirm mismatch aborted the exchange.
    Failed,
}

/// SAE peer driver over the framing above. The crypto (scalar/element/confirm
/// values) is supplied by the caller; this enforces ordering and group
/// agreement and verifies the peer confirm by value.
#[derive(Debug, Clone)]
pub struct SaePeer {
    state: SaeState,
    group: u16,
    peer_commit: Option<SaeCommit>,
}

impl SaePeer {
    /// New peer for the chosen `group`.
    #[must_use]
    pub const fn new(group: u16) -> Self {
        Self {
            state: SaeState::Nothing,
            group,
            peer_commit: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> SaeState {
        self.state
    }

    /// The peer's stored Commit, once received.
    #[must_use]
    pub const fn peer_commit(&self) -> Option<&SaeCommit> {
        self.peer_commit.as_ref()
    }

    /// Build and record our Commit (`Nothing` → `Committed`). Returns the body
    /// bytes to put in the SAE auth frame (seq 1).
    pub fn send_commit(&mut self, scalar: &[u8], element: &[u8], token: Option<&[u8]>) -> Vec<u8> {
        self.state = SaeState::Committed;
        build_commit(self.group, scalar, element, token)
    }

    /// Process the peer's Commit. Must use our group and have well-formed field
    /// lengths, else the exchange fails.
    pub fn on_peer_commit(&mut self, body: &[u8]) -> bool {
        if self.state != SaeState::Committed {
            return false;
        }
        match parse_commit(body) {
            Some(c) if c.group == self.group => {
                self.peer_commit = Some(c);
                true
            }
            _ => {
                self.state = SaeState::Failed;
                false
            }
        }
    }

    /// Build our Confirm (`Committed` → `Confirmed`), after the peer commit is
    /// in. Returns `None` if called out of order.
    pub fn send_confirm(&mut self, send_confirm: u16, confirm: &[u8]) -> Option<Vec<u8>> {
        if self.state != SaeState::Committed || self.peer_commit.is_none() {
            return None;
        }
        self.state = SaeState::Confirmed;
        Some(build_confirm(send_confirm, confirm))
    }

    /// Verify the peer's Confirm against the locally-computed `expected` value
    /// (`Confirmed` → `Accepted`). A mismatch or wrong length fails the
    /// exchange.
    pub fn on_peer_confirm(&mut self, body: &[u8], expected: &[u8]) -> bool {
        if self.state != SaeState::Confirmed {
            return false;
        }
        match parse_confirm(body) {
            Some(c) if c.confirm == expected => {
                self.state = SaeState::Accepted;
                true
            }
            _ => {
                self.state = SaeState::Failed;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_params_known_and_unknown() {
        assert_eq!(group_params(19).unwrap().scalar_len, 32);
        assert_eq!(group_params(20).unwrap().element_len, 96);
        assert!(group_params(99).is_none());
    }

    #[test]
    fn commit_round_trips_without_token() {
        let scalar = alloc::vec![0xAA; 32];
        let element = alloc::vec![0xBB; 64];
        let body = build_commit(19, &scalar, &element, None);
        let c = parse_commit(&body).unwrap();
        assert_eq!(c.group, 19);
        assert_eq!(c.scalar, scalar);
        assert_eq!(c.element, element);
        assert!(c.anti_clogging_token.is_none());
    }

    #[test]
    fn commit_round_trips_with_token() {
        let token = alloc::vec![0x11; 24];
        let scalar = alloc::vec![0xAA; 32];
        let element = alloc::vec![0xBB; 64];
        let body = build_commit(19, &scalar, &element, Some(&token));
        let c = parse_commit(&body).unwrap();
        assert_eq!(c.anti_clogging_token, Some(token));
        assert_eq!(c.scalar, scalar);
        assert_eq!(c.element, element);
    }

    #[test]
    fn commit_parse_rejects_short_body() {
        // Group 19 needs 32+64 bytes of scalar+element.
        let body = build_commit(19, &[0u8; 10], &[0u8; 10], None);
        assert!(parse_commit(&body).is_none());
    }

    #[test]
    fn confirm_round_trips() {
        let confirm = alloc::vec![0xCC; 32];
        let body = build_confirm(1, &confirm);
        let c = parse_confirm(&body).unwrap();
        assert_eq!(c.send_confirm, 1);
        assert_eq!(c.confirm, confirm);
    }

    #[test]
    fn full_exchange_reaches_accepted() {
        let mut peer = SaePeer::new(19);
        // 1. send our commit.
        let _our_commit = peer.send_commit(&[0xAA; 32], &[0xBB; 64], None);
        assert_eq!(peer.state(), SaeState::Committed);
        // 2. receive the peer's commit.
        let peer_commit = build_commit(19, &[0xCC; 32], &[0xDD; 64], None);
        assert!(peer.on_peer_commit(&peer_commit));
        assert!(peer.peer_commit().is_some());
        // 3. send our confirm.
        let _our_confirm = peer.send_confirm(1, &[0xEE; 32]).unwrap();
        assert_eq!(peer.state(), SaeState::Confirmed);
        // 4. verify the peer's confirm.
        let expected = [0x42u8; 32];
        let peer_confirm = build_confirm(1, &expected);
        assert!(peer.on_peer_confirm(&peer_confirm, &expected));
        assert_eq!(peer.state(), SaeState::Accepted);
    }

    #[test]
    fn group_mismatch_fails() {
        let mut peer = SaePeer::new(19);
        peer.send_commit(&[0xAA; 32], &[0xBB; 64], None);
        let wrong_group = build_commit(20, &[0xCC; 48], &[0xDD; 96], None);
        assert!(!peer.on_peer_commit(&wrong_group));
        assert_eq!(peer.state(), SaeState::Failed);
    }

    #[test]
    fn bad_peer_confirm_fails() {
        let mut peer = SaePeer::new(19);
        peer.send_commit(&[0xAA; 32], &[0xBB; 64], None);
        peer.on_peer_commit(&build_commit(19, &[0xCC; 32], &[0xDD; 64], None));
        peer.send_confirm(1, &[0xEE; 32]).unwrap();
        let bad = build_confirm(1, &[0x00; 32]);
        assert!(!peer.on_peer_confirm(&bad, &[0x42; 32]));
        assert_eq!(peer.state(), SaeState::Failed);
    }

    #[test]
    fn confirm_before_commit_is_rejected() {
        let mut peer = SaePeer::new(19);
        assert!(peer.send_confirm(1, &[0xEE; 32]).is_none());
    }
}
