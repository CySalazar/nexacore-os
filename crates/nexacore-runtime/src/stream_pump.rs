//! Incremental token-yield bridge: decode loop → token channel (WS5-03.3).
//!
//! [`crate::decode::streaming_decode`] produces tokens lazily, one transformer
//! forward pass per [`crate::decode::DecodeToken`]. The `ai_stream` relay needs
//! those tokens delivered into a bounded [`TokenChannel`](crate::token_channel)
//! as `AiTokenChunk`s — incrementally, with backpressure, and with the final
//! token flagged terminal. `StreamPump` is that bridge.
//!
//! Each `StreamPump::pump` call advances the stream by **one token**: it pulls
//! the next decoded token, detokenizes it to UTF-8, wraps it in an
//! `AiTokenChunk` (assigning the running `seq`), and enqueues it. When the
//! channel is full it parks the chunk and reports `PumpStatus::Blocked` so the
//! relay drains the consumer and retries — never dropping a token. A one-token
//! lookahead lets the pump set `AiTokenChunk::is_last` on the final token
//! without a trailing empty marker.
//!
//! The pump is generic over the token source (any
//! `Iterator<Item = Result<DecodeToken>>`) and the detokenizer (`FnMut(u32) ->
//! Vec<u8>`), so the real engine plugs the [`crate::decode::StreamDecoder`] and
//! a streaming detokenizer in, while host tests drive a fixed token list — no
//! model required. `no_std + alloc`.

// Alloc types: std's prelude on host builds, `alloc` without std.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::iter::Peekable;

use nexacore_types::{
    ai::{AiStreamHandle, AiTokenChunk},
    error::Result,
};

use crate::{
    decode::DecodeToken,
    token_channel::{PushError, TokenChannel},
};

/// The outcome of a single [`StreamPump::pump`] step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PumpStatus {
    /// A non-terminal chunk was enqueued; call [`StreamPump::pump`] again.
    Yielded,
    /// The channel is full: a chunk is parked. Drain the consumer, then retry.
    Blocked,
    /// The stream finished — the terminal chunk was enqueued, the source ended,
    /// or the consumer closed the channel. The channel is now closed.
    Done,
    /// The token source errored. The channel was closed; see
    /// [`StreamPump::take_error`].
    Failed,
}

/// Pumps decoded tokens into a [`TokenChannel`] one at a time (WS5-03.3).
pub struct StreamPump<I, D>
where
    I: Iterator<Item = Result<DecodeToken>>,
    D: FnMut(u32) -> Vec<u8>,
{
    tokens: Peekable<I>,
    detok: D,
    handle: AiStreamHandle,
    request_id: u64,
    seq: u32,
    pending: Option<AiTokenChunk>,
    finished: bool,
    error: Option<nexacore_types::error::NexaCoreError>,
}

impl<I, D> StreamPump<I, D>
where
    I: Iterator<Item = Result<DecodeToken>>,
    D: FnMut(u32) -> Vec<u8>,
{
    /// Creates a pump that stamps every chunk with `handle` and `request_id`,
    /// draws tokens from `tokens`, and detokenizes each token id with `detok`.
    pub fn new(handle: AiStreamHandle, request_id: u64, tokens: I, detok: D) -> Self {
        Self {
            tokens: tokens.peekable(),
            detok,
            handle,
            request_id,
            seq: 0,
            pending: None,
            finished: false,
            error: None,
        }
    }

    /// `true` once the stream has finished (success or failure).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Takes the decode error that ended the stream, if any (after
    /// [`PumpStatus::Failed`]).
    #[must_use]
    pub fn take_error(&mut self) -> Option<nexacore_types::error::NexaCoreError> {
        self.error.take()
    }

    /// Advances the stream by one token, enqueuing it into `channel`.
    ///
    /// Returns a [`PumpStatus`] telling the caller whether to keep pumping
    /// ([`PumpStatus::Yielded`]), drain the consumer first
    /// ([`PumpStatus::Blocked`]), or stop ([`PumpStatus::Done`] /
    /// [`PumpStatus::Failed`]).
    pub fn pump(&mut self, channel: &mut TokenChannel) -> PumpStatus {
        if self.finished {
            return PumpStatus::Done;
        }

        // Retry a chunk parked by backpressure before pulling a new token.
        if let Some(chunk) = self.pending.take() {
            return self.try_push(channel, chunk);
        }

        match self.tokens.next() {
            None => {
                // Source exhausted (covers the empty-stream case): close so the
                // consumer knows no more chunks are coming.
                channel.close();
                self.finished = true;
                PumpStatus::Done
            }
            Some(Err(e)) => {
                channel.close();
                self.finished = true;
                self.error = Some(e);
                PumpStatus::Failed
            }
            Some(Ok(tok)) => {
                // One-token lookahead: this is the last token iff nothing valid
                // follows it.
                let is_last = self.tokens.peek().is_none();
                let text = (self.detok)(tok.token_id);
                let chunk = AiTokenChunk::new(
                    self.handle,
                    self.request_id,
                    self.seq,
                    tok.token_id,
                    text,
                    is_last,
                );
                self.seq = self.seq.wrapping_add(1);
                self.try_push(channel, chunk)
            }
        }
    }

    /// Pushes `chunk`, parking it on backpressure and finishing on terminal /
    /// consumer-closed.
    fn try_push(&mut self, channel: &mut TokenChannel, chunk: AiTokenChunk) -> PumpStatus {
        let is_last = chunk.is_last;
        match channel.push(chunk) {
            Ok(_) => {
                if is_last {
                    self.finished = true;
                    PumpStatus::Done
                } else {
                    PumpStatus::Yielded
                }
            }
            Err(PushError::Full(c)) => {
                self.pending = Some(c);
                PumpStatus::Blocked
            }
            Err(PushError::Closed(_)) => {
                // The consumer closed the channel: stop generating.
                self.finished = true;
                PumpStatus::Done
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    use nexacore_types::error::{HalErrorKind, NexaCoreError};

    use super::*;

    type TokResult = Result<DecodeToken>;

    fn tok(id: u32, pos: usize) -> TokResult {
        Ok(DecodeToken {
            token_id: id,
            position: pos,
        })
    }

    /// Detokenizer that maps a token id to a single byte (its low 8 bits).
    fn byte_detok(id: u32) -> Vec<u8> {
        vec![id as u8]
    }

    /// Drains every chunk a pump produces into a flat list, interleaving drains
    /// with pumps so backpressure is exercised. Returns the delivered chunks.
    fn drive<I, D>(pump: &mut StreamPump<I, D>, channel: &mut TokenChannel) -> Vec<AiTokenChunk>
    where
        I: Iterator<Item = TokResult>,
        D: FnMut(u32) -> Vec<u8>,
    {
        let mut out = Vec::new();
        loop {
            let status = pump.pump(channel);
            while let Some(c) = channel.pop() {
                out.push(c);
            }
            match status {
                PumpStatus::Yielded | PumpStatus::Blocked => {}
                PumpStatus::Done | PumpStatus::Failed => break,
            }
        }
        out
    }

    #[test]
    fn pumps_tokens_in_order_with_seq_text_and_terminal() {
        let mut channel = TokenChannel::with_capacity(8);
        let source = vec![tok(10, 0), tok(11, 1), tok(12, 2)].into_iter();
        let mut pump = StreamPump::new(AiStreamHandle::new(3), 99, source, byte_detok);

        let chunks = drive(&mut pump, &mut channel);
        assert_eq!(chunks.len(), 3);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.seq, i as u32);
            assert_eq!(c.handle, AiStreamHandle::new(3));
            assert_eq!(c.request_id, 99);
        }
        assert_eq!(chunks[0].token, 10);
        assert_eq!(chunks[0].text, vec![10]);
        assert_eq!(chunks[2].token, 12);
        // Only the final chunk is terminal.
        assert!(!chunks[0].is_last && !chunks[1].is_last);
        assert!(chunks[2].is_last);
        assert!(pump.is_finished());
        assert!(channel.is_drained());
    }

    #[test]
    fn backpressure_parks_and_resumes_without_dropping() {
        // Capacity 1 forces a Blocked between every token.
        let mut channel = TokenChannel::with_capacity(1);
        let source = vec![tok(1, 0), tok(2, 1), tok(3, 2)].into_iter();
        let mut pump = StreamPump::new(AiStreamHandle::new(1), 7, source, byte_detok);

        let chunks = drive(&mut pump, &mut channel);
        let ids: Vec<u32> = chunks.iter().map(|c| c.token).collect();
        assert_eq!(ids, vec![1, 2, 3], "all tokens delivered in order");
        assert!(chunks.last().is_some_and(|c| c.is_last));

        // Observe an explicit Blocked when the channel is left full.
        let mut ch2 = TokenChannel::with_capacity(1);
        let mut p2 = StreamPump::new(
            AiStreamHandle::new(1),
            7,
            vec![tok(1, 0), tok(2, 1)].into_iter(),
            byte_detok,
        );
        assert_eq!(p2.pump(&mut ch2), PumpStatus::Yielded); // token 1 enqueued
        assert_eq!(p2.pump(&mut ch2), PumpStatus::Blocked); // full -> parked token 2
        assert_eq!(ch2.pop().map(|c| c.token), Some(1));
        assert_eq!(p2.pump(&mut ch2), PumpStatus::Done); // parked token 2 is terminal
        assert_eq!(ch2.pop().map(|c| c.token), Some(2));
    }

    #[test]
    fn empty_stream_closes_the_channel() {
        let mut channel = TokenChannel::with_capacity(4);
        let source = Vec::<TokResult>::new().into_iter();
        let mut pump = StreamPump::new(AiStreamHandle::new(2), 5, source, byte_detok);
        assert_eq!(pump.pump(&mut channel), PumpStatus::Done);
        assert!(channel.is_closed());
        assert!(channel.is_drained());
        // Further pumps stay Done.
        assert_eq!(pump.pump(&mut channel), PumpStatus::Done);
    }

    #[test]
    fn decode_error_fails_and_closes_channel() {
        let mut channel = TokenChannel::with_capacity(4);
        let err: TokResult = Err(NexaCoreError::hal(HalErrorKind::DeviceFailure, "boom"));
        let source = vec![tok(1, 0), err].into_iter();
        let mut pump = StreamPump::new(AiStreamHandle::new(9), 1, source, byte_detok);

        assert_eq!(pump.pump(&mut channel), PumpStatus::Yielded); // token 1
        assert_eq!(pump.pump(&mut channel), PumpStatus::Failed); // error
        assert!(channel.is_closed());
        assert!(pump.is_finished());
        assert!(pump.take_error().is_some());
        // The valid token before the error is still drainable.
        assert_eq!(channel.pop().map(|c| c.token), Some(1));
    }

    #[test]
    fn consumer_close_stops_the_pump() {
        let mut channel = TokenChannel::with_capacity(4);
        let source = vec![tok(1, 0), tok(2, 1), tok(3, 2)].into_iter();
        let mut pump = StreamPump::new(AiStreamHandle::new(4), 2, source, byte_detok);
        assert_eq!(pump.pump(&mut channel), PumpStatus::Yielded);
        channel.close(); // consumer cancels
        assert_eq!(pump.pump(&mut channel), PumpStatus::Done);
        assert!(pump.is_finished());
    }
}
