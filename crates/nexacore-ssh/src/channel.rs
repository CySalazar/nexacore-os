//! SSH-2 connection-protocol channel management (RFC 4254).
//!
//! Channels are the multiplexing layer that rides on top of an authenticated,
//! encrypted [`crate::transport::Session`]. A single session carries many
//! independent channels (an interactive shell, an `exec`, several `scp`
//! transfers), each with its own pair of numeric ids and its own flow-control
//! windows.
//!
//! ## Seam
//!
//! [`ChannelTable`] is a pure state machine: its methods *produce* SSH message
//! payloads (`Vec<u8>`, each starting with a `SSH_MSG_CHANNEL_*` type byte) and
//! *consume* payloads received from the peer. It never touches a socket. The
//! caller moves those payloads across the wire with [`Session::send`] /
//! [`Session::recv`], so the same table drives the real encrypted session and
//! the in-memory test doubles identically.
//!
//! [`Session::send`]: crate::transport::Session::send
//! [`Session::recv`]: crate::transport::Session::recv
//!
//! ## Flow control (RFC 4254 §5.2)
//!
//! Each channel tracks two windows:
//!
//! * `send_window` — bytes we may still send to the peer. It starts at the
//!   peer's advertised initial window (learned from `OPEN` / `OPEN_CONFIRMATION`)
//!   and is replenished when the peer sends `CHANNEL_WINDOW_ADJUST`. We refuse
//!   to send past it ([`SshError::WindowExhausted`]).
//! * `recv_window` — bytes the peer may still send to us. We advertise it at
//!   open time, decrement it as data arrives, and top it back up by emitting our
//!   own `CHANNEL_WINDOW_ADJUST`.
//!
//! Data larger than the peer's maximum packet size is split into several
//! `CHANNEL_DATA` messages.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{
    error::SshError,
    wire::{Reader, Writer},
};

/// `SSH_MSG_CHANNEL_OPEN`.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// `SSH_MSG_CHANNEL_DATA`.
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// `SSH_MSG_CHANNEL_EOF`.
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
/// `SSH_MSG_CHANNEL_CLOSE`.
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
/// `SSH_MSG_CHANNEL_REQUEST`.
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// `SSH_MSG_CHANNEL_SUCCESS`.
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// `SSH_MSG_CHANNEL_FAILURE`.
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// `SSH_EXTENDED_DATA_STDERR` — the only extended-data type code in RFC 4254.
pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// `OPEN_FAILURE` reason: administratively prohibited.
pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `OPEN_FAILURE` reason: connect failed.
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
/// `OPEN_FAILURE` reason: unknown channel type.
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
/// `OPEN_FAILURE` reason: resource shortage.
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

/// The teardown state of one direction of a channel: data flows until `Eof`,
/// after which `Close` frees it (RFC 4254 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfState {
    /// Data may still flow in this direction.
    Open,
    /// `CHANNEL_EOF` has been sent/received; no more data, but not yet closed.
    Eof,
    /// `CHANNEL_CLOSE` has been sent/received.
    Closed,
}

/// One multiplexed channel's bookkeeping.
struct Channel {
    /// The id the peer uses to address us (its "recipient channel").
    remote_id: u32,
    /// Bytes we may still send to the peer before a `WINDOW_ADJUST`.
    send_window: u32,
    /// Bytes the peer may still send to us before we grow its window.
    recv_window: u32,
    /// The peer's maximum packet size — the largest `CHANNEL_DATA` chunk.
    remote_max_packet: u32,
    /// Our outbound direction (EOF/CLOSE we have sent).
    local: HalfState,
    /// The peer's inbound direction (EOF/CLOSE the peer has sent).
    remote: HalfState,
}

/// A table of concurrently-open channels multiplexed over one session.
///
/// Local channel ids are allocated densely from zero. See the [module
/// docs](crate::channel) for the flow-control model and the seam contract.
pub struct ChannelTable {
    channels: BTreeMap<u32, Channel>,
    next_id: u32,
}

impl Default for ChannelTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelTable {
    /// An empty channel table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            channels: BTreeMap::new(),
            next_id: 0,
        }
    }

    // ---- accessors ------------------------------------------------------

    /// Whether a channel with this local id is still in the table.
    #[must_use]
    pub fn is_open(&self, local_id: u32) -> bool {
        self.channels.contains_key(&local_id)
    }

    /// The number of open channels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether the table has no open channels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Bytes we may still send on this channel, or `None` if unknown.
    #[must_use]
    pub fn send_window(&self, local_id: u32) -> Option<u32> {
        self.channels.get(&local_id).map(|c| c.send_window)
    }

    /// Bytes the peer may still send us on this channel.
    #[must_use]
    pub fn recv_window(&self, local_id: u32) -> Option<u32> {
        self.channels.get(&local_id).map(|c| c.recv_window)
    }

    /// The peer's id for this channel, once confirmed.
    #[must_use]
    pub fn remote_id(&self, local_id: u32) -> Option<u32> {
        self.channels.get(&local_id).map(|c| c.remote_id)
    }

    /// The peer's maximum packet size for this channel.
    #[must_use]
    pub fn remote_max_packet(&self, local_id: u32) -> Option<u32> {
        self.channels.get(&local_id).map(|c| c.remote_max_packet)
    }

    /// Whether we have signalled `CHANNEL_EOF` (or beyond) on this channel.
    #[must_use]
    pub fn local_eof(&self, local_id: u32) -> Option<bool> {
        self.channels
            .get(&local_id)
            .map(|c| c.local != HalfState::Open)
    }

    /// Whether the peer has signalled `CHANNEL_EOF` (or beyond) on this channel.
    #[must_use]
    pub fn remote_eof(&self, local_id: u32) -> Option<bool> {
        self.channels
            .get(&local_id)
            .map(|c| c.remote != HalfState::Open)
    }

    // ---- open / accept --------------------------------------------------

    /// Allocate a local channel and produce its `CHANNEL_OPEN` payload.
    ///
    /// `initial_window` and `max_packet` are what *we* advertise to the peer.
    /// The returned local id addresses the channel in every later call. The
    /// send window stays zero until the peer's `OPEN_CONFIRMATION` arrives.
    #[must_use]
    pub fn open(
        &mut self,
        channel_type: &str,
        initial_window: u32,
        max_packet: u32,
    ) -> (u32, Vec<u8>) {
        let local_id = self.alloc_id();
        self.channels.insert(
            local_id,
            Channel {
                remote_id: 0,
                send_window: 0,
                recv_window: initial_window,
                remote_max_packet: 0,
                local: HalfState::Open,
                remote: HalfState::Open,
            },
        );

        let mut w = Writer::new();
        w.put_u8(SSH_MSG_CHANNEL_OPEN);
        w.put_string(channel_type.as_bytes());
        w.put_u32(local_id);
        w.put_u32(initial_window);
        w.put_u32(max_packet);
        (local_id, w.into_bytes())
    }

    /// Accept an inbound `CHANNEL_OPEN`, allocating a local id and producing the
    /// `OPEN_CONFIRMATION` payload. `initial_window` / `max_packet` are what we
    /// advertise back.
    ///
    /// # Errors
    /// [`SshError::Protocol`] if the payload is not a well-formed `CHANNEL_OPEN`.
    pub fn accept(
        &mut self,
        open_payload: &[u8],
        initial_window: u32,
        max_packet: u32,
    ) -> Result<(u32, Vec<u8>), SshError> {
        let mut r = Reader::new(open_payload);
        expect(&mut r, SSH_MSG_CHANNEL_OPEN)?;
        let _channel_type = r.get_string()?;
        let remote_id = r.get_u32()?;
        let peer_window = r.get_u32()?;
        let peer_max_packet = r.get_u32()?;

        let local_id = self.alloc_id();
        self.channels.insert(
            local_id,
            Channel {
                remote_id,
                send_window: peer_window,
                recv_window: initial_window,
                remote_max_packet: peer_max_packet,
                local: HalfState::Open,
                remote: HalfState::Open,
            },
        );

        let mut w = Writer::new();
        w.put_u8(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        w.put_u32(remote_id);
        w.put_u32(local_id);
        w.put_u32(initial_window);
        w.put_u32(max_packet);
        Ok((local_id, w.into_bytes()))
    }

    /// Apply an inbound `OPEN_CONFIRMATION`, wiring the peer's id and our send
    /// window. Returns the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if the recipient id is not one we opened.
    pub fn on_open_confirmation(&mut self, payload: &[u8]) -> Result<u32, SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_OPEN_CONFIRMATION)?;
        let local_id = r.get_u32()?;
        let remote_id = r.get_u32()?;
        let peer_window = r.get_u32()?;
        let peer_max_packet = r.get_u32()?;

        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        ch.remote_id = remote_id;
        ch.send_window = peer_window;
        ch.remote_max_packet = peer_max_packet;
        Ok(local_id)
    }

    /// Produce a `CHANNEL_OPEN_FAILURE` for an inbound open we reject.
    #[must_use]
    pub fn open_failure(recipient_remote_id: u32, reason: u32, description: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(SSH_MSG_CHANNEL_OPEN_FAILURE);
        w.put_u32(recipient_remote_id);
        w.put_u32(reason);
        w.put_string(description.as_bytes());
        w.put_string(b""); // language tag
        w.into_bytes()
    }

    /// Apply an inbound `OPEN_FAILURE`, removing the pending channel. Returns
    /// `(local_id, reason_code)`.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if the recipient id is unknown.
    pub fn on_open_failure(&mut self, payload: &[u8]) -> Result<(u32, u32), SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_OPEN_FAILURE)?;
        let local_id = r.get_u32()?;
        let reason = r.get_u32()?;
        if self.channels.remove(&local_id).is_none() {
            return Err(SshError::UnknownChannel);
        }
        Ok((local_id, reason))
    }

    // ---- data + flow control -------------------------------------------

    /// Produce the `CHANNEL_DATA` message(s) for `data`, split to the peer's
    /// maximum packet size and charged against the send window.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown, [`SshError::Protocol`] if the
    /// channel is closed or half-closed for sending, [`SshError::WindowExhausted`]
    /// if `data` is larger than the remaining send window (nothing is sent).
    pub fn data(&mut self, local_id: u32, data: &[u8]) -> Result<Vec<Vec<u8>>, SshError> {
        self.data_inner(local_id, None, data)
    }

    /// Like [`data`](Self::data) but as `CHANNEL_EXTENDED_DATA` of `data_type`
    /// (e.g. [`SSH_EXTENDED_DATA_STDERR`]).
    ///
    /// # Errors
    /// As [`data`](Self::data).
    pub fn extended_data(
        &mut self,
        local_id: u32,
        data_type: u32,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>, SshError> {
        self.data_inner(local_id, Some(data_type), data)
    }

    fn data_inner(
        &mut self,
        local_id: u32,
        data_type: Option<u32>,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>, SshError> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        if ch.local != HalfState::Open {
            return Err(SshError::Protocol("send on closed channel"));
        }
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        if len > ch.send_window {
            return Err(SshError::WindowExhausted);
        }
        ch.send_window -= len;

        let remote_id = ch.remote_id;
        let chunk = if ch.remote_max_packet == 0 {
            data.len().max(1)
        } else {
            ch.remote_max_packet as usize
        };

        let mut out = Vec::new();
        for part in data.chunks(chunk) {
            let mut w = Writer::new();
            match data_type {
                None => {
                    w.put_u8(SSH_MSG_CHANNEL_DATA);
                    w.put_u32(remote_id);
                    w.put_string(part);
                }
                Some(code) => {
                    w.put_u8(SSH_MSG_CHANNEL_EXTENDED_DATA);
                    w.put_u32(remote_id);
                    w.put_u32(code);
                    w.put_string(part);
                }
            }
            out.push(w.into_bytes());
        }
        Ok(out)
    }

    /// Apply an inbound `CHANNEL_DATA`, decrementing the receive window. Returns
    /// `(local_id, data)`.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if unknown.
    pub fn on_data(&mut self, payload: &[u8]) -> Result<(u32, Vec<u8>), SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_DATA)?;
        let local_id = r.get_u32()?;
        let data = r.get_string()?.to_vec();
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        ch.recv_window = ch.recv_window.saturating_sub(len);
        Ok((local_id, data))
    }

    /// Apply an inbound `CHANNEL_EXTENDED_DATA`. Returns
    /// `(local_id, data_type, data)`.
    ///
    /// # Errors
    /// As [`on_data`](Self::on_data).
    pub fn on_extended_data(&mut self, payload: &[u8]) -> Result<(u32, u32, Vec<u8>), SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_EXTENDED_DATA)?;
        let local_id = r.get_u32()?;
        let data_type = r.get_u32()?;
        let data = r.get_string()?.to_vec();
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        ch.recv_window = ch.recv_window.saturating_sub(len);
        Ok((local_id, data_type, data))
    }

    /// Grow our receive window by `add` bytes and produce the outbound
    /// `CHANNEL_WINDOW_ADJUST` telling the peer it may send that much more.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn window_adjust(&mut self, local_id: u32, add: u32) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        ch.recv_window = ch.recv_window.saturating_add(add);
        let remote_id = ch.remote_id;
        let mut w = Writer::new();
        w.put_u8(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        w.put_u32(remote_id);
        w.put_u32(add);
        Ok(w.into_bytes())
    }

    /// Apply an inbound `CHANNEL_WINDOW_ADJUST`, replenishing the send window.
    /// Returns the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if unknown.
    pub fn on_window_adjust(&mut self, payload: &[u8]) -> Result<u32, SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_WINDOW_ADJUST)?;
        let local_id = r.get_u32()?;
        let add = r.get_u32()?;
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        ch.send_window = ch.send_window.saturating_add(add);
        Ok(local_id)
    }

    // ---- teardown -------------------------------------------------------

    /// Mark end-of-data and produce the outbound `CHANNEL_EOF`.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn eof(&mut self, local_id: u32) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        if ch.local == HalfState::Open {
            ch.local = HalfState::Eof;
        }
        Ok(single(SSH_MSG_CHANNEL_EOF, ch.remote_id))
    }

    /// Apply an inbound `CHANNEL_EOF`. Returns the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if unknown.
    pub fn on_eof(&mut self, payload: &[u8]) -> Result<u32, SshError> {
        let local_id = parse_single(payload, SSH_MSG_CHANNEL_EOF)?;
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        if ch.remote == HalfState::Open {
            ch.remote = HalfState::Eof;
        }
        Ok(local_id)
    }

    /// Mark our side closed and produce the outbound `CHANNEL_CLOSE`. Once both
    /// sides have exchanged `CLOSE` the channel is removed from the table.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn close(&mut self, local_id: u32) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        ch.local = HalfState::Closed;
        let msg = single(SSH_MSG_CHANNEL_CLOSE, ch.remote_id);
        if ch.remote == HalfState::Closed {
            self.channels.remove(&local_id);
        }
        Ok(msg)
    }

    /// Apply an inbound `CHANNEL_CLOSE`. If we have already sent our own
    /// `CLOSE`, the channel is removed. Returns the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload, [`SshError::UnknownChannel`]
    /// if unknown.
    pub fn on_close(&mut self, payload: &[u8]) -> Result<u32, SshError> {
        let local_id = parse_single(payload, SSH_MSG_CHANNEL_CLOSE)?;
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        ch.remote = HalfState::Closed;
        if ch.local == HalfState::Closed {
            self.channels.remove(&local_id);
        }
        Ok(local_id)
    }

    // ---- requests -------------------------------------------------------

    /// Produce a `CHANNEL_REQUEST` (e.g. `"exec"`, `"shell"`, `"pty-req"`).
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn request(
        &self,
        local_id: u32,
        request_type: &str,
        want_reply: bool,
        type_data: &[u8],
    ) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        let mut w = Writer::new();
        w.put_u8(SSH_MSG_CHANNEL_REQUEST);
        w.put_u32(ch.remote_id);
        w.put_string(request_type.as_bytes());
        w.put_bool(want_reply);
        w.put_raw(type_data);
        Ok(w.into_bytes())
    }

    /// Parse an inbound `CHANNEL_REQUEST` into
    /// `(local_id, request_type, want_reply, type_data)`.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload.
    pub fn on_request(&self, payload: &[u8]) -> Result<(u32, String, bool, Vec<u8>), SshError> {
        let mut r = Reader::new(payload);
        expect(&mut r, SSH_MSG_CHANNEL_REQUEST)?;
        let local_id = r.get_u32()?;
        let request_type = String::from_utf8(r.get_string()?.to_vec())
            .map_err(|_| SshError::Protocol("request type utf8"))?;
        let want_reply = r.get_bool()?;
        let type_data = r.get_bytes(r.remaining())?.to_vec();
        if !self.channels.contains_key(&local_id) {
            return Err(SshError::UnknownChannel);
        }
        Ok((local_id, request_type, want_reply, type_data))
    }

    /// Produce a `CHANNEL_SUCCESS` reply.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn success(&self, local_id: u32) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        Ok(single(SSH_MSG_CHANNEL_SUCCESS, ch.remote_id))
    }

    /// Produce a `CHANNEL_FAILURE` reply.
    ///
    /// # Errors
    /// [`SshError::UnknownChannel`] if unknown.
    pub fn failure(&self, local_id: u32) -> Result<Vec<u8>, SshError> {
        let ch = self
            .channels
            .get(&local_id)
            .ok_or(SshError::UnknownChannel)?;
        Ok(single(SSH_MSG_CHANNEL_FAILURE, ch.remote_id))
    }

    /// Parse an inbound `CHANNEL_SUCCESS`, returning the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload.
    pub fn on_success(&self, payload: &[u8]) -> Result<u32, SshError> {
        let local_id = parse_single(payload, SSH_MSG_CHANNEL_SUCCESS)?;
        self.require(local_id)
    }

    /// Parse an inbound `CHANNEL_FAILURE`, returning the local id.
    ///
    /// # Errors
    /// [`SshError::Protocol`] on a malformed payload.
    pub fn on_failure(&self, payload: &[u8]) -> Result<u32, SshError> {
        let local_id = parse_single(payload, SSH_MSG_CHANNEL_FAILURE)?;
        self.require(local_id)
    }

    // ---- internal -------------------------------------------------------

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Return `local_id` if it names an open channel, else `UnknownChannel`.
    fn require(&self, local_id: u32) -> Result<u32, SshError> {
        if self.channels.contains_key(&local_id) {
            Ok(local_id)
        } else {
            Err(SshError::UnknownChannel)
        }
    }
}

/// Encode a `byte || uint32` message (EOF/CLOSE/SUCCESS/FAILURE).
fn single(msg: u8, recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(msg);
    w.put_u32(recipient);
    w.into_bytes()
}

/// Decode a `byte || uint32` message, checking the type byte.
fn parse_single(payload: &[u8], msg: u8) -> Result<u32, SshError> {
    let mut r = Reader::new(payload);
    expect(&mut r, msg)?;
    r.get_u32()
}

/// Read and check the leading message-type byte.
fn expect(r: &mut Reader<'_>, msg: u8) -> Result<(), SshError> {
    if r.get_u8()? == msg {
        Ok(())
    } else {
        Err(SshError::Protocol("unexpected channel message type"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// Open a channel client-side and confirm it server-side, wiring both
    /// tables. Returns `(client, client_local, server, server_local)`.
    fn opened(init_window: u32, max_packet: u32) -> (ChannelTable, u32, ChannelTable, u32) {
        let mut client = ChannelTable::new();
        let mut server = ChannelTable::new();
        let (c_id, open_msg) = client.open("session", init_window, max_packet);
        let (s_id, conf_msg) = server.accept(&open_msg, init_window, max_packet).unwrap();
        let confirmed = client.on_open_confirmation(&conf_msg).unwrap();
        assert_eq!(confirmed, c_id);
        (client, c_id, server, s_id)
    }

    #[test]
    fn open_confirmation_assigns_local_and_remote_ids() {
        let (client, c_id, server, s_id) = opened(1000, 1024);
        // The client learns the server's id; the server learns the client's.
        assert_eq!(client.remote_id(c_id), Some(s_id));
        assert_eq!(server.remote_id(s_id), Some(c_id));
        // After confirmation the client may send up to the advertised window.
        assert_eq!(client.send_window(c_id), Some(1000));
        assert_eq!(client.remote_max_packet(c_id), Some(1024));
    }

    #[test]
    fn sending_data_decrements_send_window() {
        let (mut client, c_id, _server, _s_id) = opened(100, 1024);
        let msgs = client.data(c_id, b"0123456789").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(client.send_window(c_id), Some(90));
    }

    #[test]
    fn send_blocks_when_window_exhausted_then_resumes_after_adjust() {
        let (mut client, c_id, mut server, s_id) = opened(10, 1024);

        // Fill the window exactly.
        let msgs = client.data(c_id, b"0123456789").unwrap();
        assert_eq!(client.send_window(c_id), Some(0));

        // The server consumes the data, draining its receive window.
        let (got_id, data) = server.on_data(&msgs[0]).unwrap();
        assert_eq!(got_id, s_id);
        assert_eq!(data, b"0123456789");
        assert_eq!(server.recv_window(s_id), Some(0));

        // Now the client is blocked: no window left.
        assert_eq!(client.data(c_id, b"x"), Err(SshError::WindowExhausted));

        // The server replenishes; the client resumes.
        let adjust = server.window_adjust(s_id, 20).unwrap();
        let adjusted = client.on_window_adjust(&adjust).unwrap();
        assert_eq!(adjusted, c_id);
        assert_eq!(client.send_window(c_id), Some(20));
        assert!(client.data(c_id, b"x").is_ok());
        assert_eq!(client.send_window(c_id), Some(19));
    }

    #[test]
    fn multiplexed_channels_are_independent() {
        let mut client = ChannelTable::new();
        let mut server = ChannelTable::new();

        let (c1, open1) = client.open("session", 50, 1024);
        let (c2, open2) = client.open("session", 50, 1024);
        assert_ne!(c1, c2);

        let (s1, conf1) = server.accept(&open1, 50, 1024).unwrap();
        let (s2, conf2) = server.accept(&open2, 50, 1024).unwrap();
        client.on_open_confirmation(&conf1).unwrap();
        client.on_open_confirmation(&conf2).unwrap();
        assert_ne!(s1, s2);

        // Spend the whole window on channel 1.
        client.data(c1, &[0u8; 50]).unwrap();
        assert_eq!(client.send_window(c1), Some(0));
        // Channel 2 is untouched.
        assert_eq!(client.send_window(c2), Some(50));
        assert!(client.data(c2, b"hi").is_ok());
        assert_eq!(client.send_window(c2), Some(48));
        assert_eq!(client.send_window(c1), Some(0));
    }

    #[test]
    fn eof_then_close_tears_channel_down() {
        let (mut client, c_id, mut server, s_id) = opened(1000, 1024);

        // Client signals EOF, then CLOSE.
        let eof_msg = client.eof(c_id).unwrap();
        assert_eq!(server.on_eof(&eof_msg).unwrap(), s_id);
        assert_eq!(server.remote_eof(s_id), Some(true));

        let close_msg = client.close(c_id).unwrap();
        assert!(client.is_open(c_id)); // still waiting for the peer's CLOSE
        assert_eq!(server.on_close(&close_msg).unwrap(), s_id);

        // Server closes back; both sides free the channel.
        let close_back = server.close(s_id).unwrap();
        assert!(!server.is_open(s_id));
        assert_eq!(client.on_close(&close_back).unwrap(), c_id);
        assert!(!client.is_open(c_id));

        // Operating on a torn-down channel is an error.
        assert_eq!(client.data(c_id, b"x"), Err(SshError::UnknownChannel));
    }

    #[test]
    fn large_data_is_split_into_max_packet_chunks() {
        // The server advertises a tiny max packet; the client must chunk to it.
        let mut client = ChannelTable::new();
        let mut server = ChannelTable::new();
        let (c_id, open_msg) = client.open("session", 1000, 1024);
        let (s_id, conf_msg) = server.accept(&open_msg, 1000, 4).unwrap();
        client.on_open_confirmation(&conf_msg).unwrap();

        let payload = b"0123456789"; // 10 bytes, max packet 4 -> 4 + 4 + 2
        let msgs = client.data(c_id, payload).unwrap();
        assert_eq!(msgs.len(), 3);

        // Reassembling the chunks on the server yields the original data.
        let mut reassembled = Vec::new();
        for m in &msgs {
            let (got, part) = server.on_data(m).unwrap();
            assert_eq!(got, s_id);
            reassembled.extend_from_slice(&part);
        }
        assert_eq!(reassembled, payload);
        // The whole payload was charged once against the send window.
        assert_eq!(client.send_window(c_id), Some(990));
    }

    #[test]
    fn request_and_reply_round_trip() {
        let (client, c_id, server, s_id) = opened(1000, 1024);

        let req = client
            .request(c_id, "exec", true, b"\x00\x00\x00\x02ls")
            .unwrap();
        let (got_id, kind, want_reply, data) = server.on_request(&req).unwrap();
        assert_eq!(got_id, s_id);
        assert_eq!(kind, "exec");
        assert!(want_reply);
        assert_eq!(data, b"\x00\x00\x00\x02ls");

        let ok = server.success(s_id).unwrap();
        assert_eq!(client.on_success(&ok).unwrap(), c_id);
        let no = server.failure(s_id).unwrap();
        assert_eq!(client.on_failure(&no).unwrap(), c_id);
    }

    #[test]
    fn extended_data_round_trips_as_stderr() {
        let (mut client, c_id, mut server, s_id) = opened(1000, 1024);
        let msgs = client
            .extended_data(c_id, SSH_EXTENDED_DATA_STDERR, b"boom")
            .unwrap();
        assert_eq!(msgs.len(), 1);
        let (got, code, data) = server.on_extended_data(&msgs[0]).unwrap();
        assert_eq!(got, s_id);
        assert_eq!(code, SSH_EXTENDED_DATA_STDERR);
        assert_eq!(data, b"boom");
        assert_eq!(client.send_window(c_id), Some(996));
    }

    #[test]
    fn open_failure_removes_pending_channel() {
        let mut client = ChannelTable::new();
        let (c_id, _open) = client.open("session", 1000, 1024);
        let fail = ChannelTable::open_failure(c_id, SSH_OPEN_CONNECT_FAILED, "nope");
        let (local, reason) = client.on_open_failure(&fail).unwrap();
        assert_eq!(local, c_id);
        assert_eq!(reason, SSH_OPEN_CONNECT_FAILED);
        assert!(!client.is_open(c_id));
    }
}
