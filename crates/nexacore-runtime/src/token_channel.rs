//! Bounded token-streaming channel with backpressure (WS5-03.2).
//!
//! The streaming inference path produces `AiTokenChunk`s one token at a time
//! (the engine's incremental yield, WS5-03.3) and a consumer drains them over
//! the `ai_stream` IPC channel. Between the two sits this **bounded FIFO**: it
//! decouples the producer's generation rate from the consumer's drain rate and
//! enforces *backpressure* — when the buffer is full, `TokenChannel::push`
//! returns `PushError::Full` (handing the rejected chunk back, never dropping
//! it) so the producer yields instead of growing memory without bound.
//!
//! The channel also models stream termination: the chunk whose
//! `AiTokenChunk::is_last` is set *closes* the channel, after which further
//! pushes are rejected with `PushError::Closed`. A producer that aborts early
//! (cancellation, error) closes it explicitly with `TokenChannel::close`.
//!
//! This is a pure data structure: the actual scheduler yield / wakeup on a full
//! or empty channel is the caller's effect (the relay wiring, WS5-03.3). That
//! keeps the backpressure and termination logic fully deterministic and
//! host-testable. `no_std + alloc`, dep-free beyond [`nexacore_types`].

#[cfg(not(feature = "std"))]
use alloc::collections::VecDeque;
#[cfg(feature = "std")]
use std::collections::VecDeque;

use nexacore_types::ai::AiTokenChunk;

/// Why a [`TokenChannel::push`] could not accept a chunk.
///
/// Both variants hand the rejected [`AiTokenChunk`] back so the producer can
/// retry (after the consumer drains) or surface it — a chunk is never silently
/// dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The buffer is at capacity (backpressure): the producer should yield to
    /// the consumer and retry the returned chunk once space frees.
    Full(AiTokenChunk),
    /// The channel is closed — a terminal chunk was already enqueued, or
    /// [`TokenChannel::close`] was called. The returned chunk is discarded work.
    Closed(AiTokenChunk),
}

/// A bounded FIFO of [`AiTokenChunk`]s with backpressure and terminal-close.
///
/// Single-producer / single-consumer by contract: the streaming engine pushes,
/// the relay drains. Capacity is fixed at construction (at least 1).
#[derive(Debug, Clone)]
pub struct TokenChannel {
    queue: VecDeque<AiTokenChunk>,
    capacity: usize,
    closed: bool,
}

impl TokenChannel {
    /// Creates a channel holding at most `capacity` pending chunks.
    ///
    /// A `capacity` of 0 is clamped to 1 (a zero-capacity channel could never
    /// accept a chunk).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            closed: false,
        }
    }

    /// Maximum number of pending chunks the channel can hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of chunks currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// `true` if no chunks are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// `true` if the buffer is at capacity (the next push will backpressure).
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.capacity
    }

    /// `true` once the channel is closed (terminal chunk enqueued or
    /// [`TokenChannel::close`] called); no further pushes are accepted.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// `true` once the channel is closed *and* fully drained — the consumer has
    /// seen every chunk and may stop polling.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.closed && self.queue.is_empty()
    }

    /// Enqueues `chunk` at the back of the buffer.
    ///
    /// Returns `Ok(true)` if `chunk` was the terminal chunk (which closes the
    /// channel), `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// [`PushError::Full`] when the buffer is at capacity (backpressure), or
    /// [`PushError::Closed`] when the channel is already closed. The rejected
    /// chunk is returned inside the error.
    pub fn push(&mut self, chunk: AiTokenChunk) -> Result<bool, PushError> {
        if self.closed {
            return Err(PushError::Closed(chunk));
        }
        if self.queue.len() >= self.capacity {
            return Err(PushError::Full(chunk));
        }
        let last = chunk.is_last;
        self.queue.push_back(chunk);
        if last {
            self.closed = true;
        }
        Ok(last)
    }

    /// Dequeues the oldest buffered chunk (FIFO), or `None` if empty.
    pub fn pop(&mut self) -> Option<AiTokenChunk> {
        self.queue.pop_front()
    }

    /// Closes the channel without a terminal chunk (early cancel / error).
    ///
    /// Already-buffered chunks remain drainable; subsequent pushes are rejected
    /// with [`PushError::Closed`]. Idempotent.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use super::*;

    fn chunk(seq: u32, last: bool) -> AiTokenChunk {
        AiTokenChunk::new(
            nexacore_types::ai::AiStreamHandle::new(1),
            42,
            seq,
            100 + seq,
            Vec::new(),
            last,
        )
    }

    #[test]
    fn delivers_chunks_in_fifo_order() {
        let mut ch = TokenChannel::with_capacity(8);
        assert!(ch.is_empty());
        for s in 0..3 {
            assert_eq!(ch.push(chunk(s, false)), Ok(false));
        }
        assert_eq!(ch.len(), 3);
        assert_eq!(ch.pop().map(|c| c.seq), Some(0));
        assert_eq!(ch.pop().map(|c| c.seq), Some(1));
        assert_eq!(ch.pop().map(|c| c.seq), Some(2));
        assert!(ch.pop().is_none());
    }

    #[test]
    fn full_channel_backpressures_and_returns_the_chunk() {
        let mut ch = TokenChannel::with_capacity(2);
        assert_eq!(ch.push(chunk(0, false)), Ok(false));
        assert_eq!(ch.push(chunk(1, false)), Ok(false));
        assert!(ch.is_full());
        // Third push is refused with backpressure; the chunk comes back intact.
        match ch.push(chunk(2, false)) {
            Err(PushError::Full(c)) => assert_eq!(c.seq, 2),
            other => panic!("expected Full, got {other:?}"),
        }
        // Draining one frees a slot; the retried push now succeeds.
        assert_eq!(ch.pop().map(|c| c.seq), Some(0));
        assert!(!ch.is_full());
        assert_eq!(ch.push(chunk(2, false)), Ok(false));
        assert_eq!(ch.len(), 2);
    }

    #[test]
    fn terminal_chunk_closes_the_channel() {
        let mut ch = TokenChannel::with_capacity(4);
        assert_eq!(ch.push(chunk(0, false)), Ok(false));
        assert_eq!(ch.push(chunk(1, true)), Ok(true)); // terminal
        assert!(ch.is_closed());
        assert!(!ch.is_drained()); // still buffered

        // No more pushes after the terminal chunk.
        match ch.push(chunk(2, false)) {
            Err(PushError::Closed(c)) => assert_eq!(c.seq, 2),
            other => panic!("expected Closed, got {other:?}"),
        }

        assert_eq!(ch.pop().map(|c| c.seq), Some(0));
        assert_eq!(ch.pop().map(|c| c.is_last), Some(true));
        assert!(ch.is_drained());
    }

    #[test]
    fn explicit_close_rejects_further_pushes() {
        let mut ch = TokenChannel::with_capacity(4);
        assert_eq!(ch.push(chunk(0, false)), Ok(false));
        ch.close();
        assert!(ch.is_closed());
        assert!(matches!(
            ch.push(chunk(1, false)),
            Err(PushError::Closed(_))
        ));
        // Buffered chunk is still drainable.
        assert_eq!(ch.pop().map(|c| c.seq), Some(0));
        assert!(ch.is_drained());
        ch.close(); // idempotent
        assert!(ch.is_closed());
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut ch = TokenChannel::with_capacity(0);
        assert_eq!(ch.capacity(), 1);
        assert_eq!(ch.push(chunk(0, false)), Ok(false));
        assert!(ch.is_full());
    }
}
