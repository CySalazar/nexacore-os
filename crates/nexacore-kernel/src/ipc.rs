//! Inter-process communication primitives.
//!
//! ## Status
//!
//! P6.5/P6.6 scaffold. Message-passing IPC with typed envelopes and
//! capability-gated send/receive.
//!
//! ## Design rationale
//!
//! - **Typed messages.** The IPC layer carries opaque byte slices on the
//!   wire (the kernel is type-agnostic), but each message slot is
//!   tagged with a `MessageKind` discriminant for fast triage. The
//!   sender's userspace stub (in `nexacore-sdk`) handles serialization.
//! - **Capability-gated send.** A task may only send a message to a
//!   channel for which it presents a valid capability. The capability
//!   names the action (`SEND` / `RECEIVE`) and the target channel.
//! - **Bounded queues.** Each channel has a fixed-size queue. Sends to
//!   a full queue either block, fail, or evict the oldest message
//!   depending on the channel's policy. The policy is set at channel
//!   creation; it cannot be changed without destroying and recreating
//!   the channel.
//! - **TEE awareness.** A channel can be marked as TEE-bound: messages
//!   are encrypted with a key sealed to the recipient's TEE measurement.
//!   The kernel does not see the plaintext; it routes ciphertext.

#![allow(
    clippy::missing_errors_doc,
    reason = "kernel-internal IPC methods; errors mapped to syscall ABI at the boundary"
)]
#![cfg_attr(
    all(feature = "bare-metal", target_arch = "x86_64"),
    allow(
        unsafe_code,
        reason = "IPC_REGISTRY static mut singleton + addr_of_mut accessor; SAFETY documented at the fn boundary"
    )
)]

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use crate::{
    KernelError, KernelResult,
    capabilities::{
        CapabilityVerdict, KernelAction, KernelCapabilityCheck, KernelCapabilityToken,
        KernelPrincipal, KernelResource,
    },
    scheduling::TaskId,
};

// -----------------------------------------------------------------------------
// Channel identifier
// -----------------------------------------------------------------------------

/// IPC channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub u64);

// -----------------------------------------------------------------------------
// Message kind
// -----------------------------------------------------------------------------

/// Discriminant for the kind of message.
///
/// Used for fast triage; deeper deserialization is the receiver's
/// responsibility. The set is intentionally small; adding a variant
/// requires an NCIP.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Generic request expecting a reply.
    Request = 1,
    /// Reply to a previous request.
    Reply = 2,
    /// Asynchronous notification (no reply expected).
    Notification = 3,
    /// Capability passing — the message carries a capability handle.
    CapabilityHandoff = 4,
    /// Shared-memory grant.
    SharedMemoryGrant = 5,
}

// -----------------------------------------------------------------------------
// Channel policy
// -----------------------------------------------------------------------------

/// What the channel does when its queue is full on a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackpressurePolicy {
    /// The sender's send call blocks until queue space frees up.
    Block,
    /// The send call returns [`crate::KernelError::ResourceExhausted`].
    Drop,
    /// The oldest queued message is evicted to make room.
    EvictOldest,
}

/// Per-channel configuration. Set at channel creation; immutable
/// thereafter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPolicy {
    /// Maximum number of in-flight messages on this channel.
    pub queue_depth: usize,
    /// What to do on a full queue.
    pub backpressure: BackpressurePolicy,
    /// Whether the channel is TEE-bound (messages are sealed to the
    /// recipient's TEE).
    pub tee_bound: bool,
}

// -----------------------------------------------------------------------------
// Message envelope
// -----------------------------------------------------------------------------

/// Kernel-side message envelope.
///
/// The `payload` is opaque to the kernel; userspace is responsible for
/// serialization. The envelope is allocated in a kernel-private buffer
/// pool and copied out to the receiver's address space on `receive`.
///
/// **Why a copy** (versus shared memory): copy ensures the sender cannot
/// continue to modify the message after the kernel has accepted it,
/// which is necessary for the capability invariant. Shared-memory
/// regions are a separate mechanism (`MessageKind::SharedMemoryGrant`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// The sender task (filled in by the kernel; the sender cannot
    /// forge this).
    pub sender: TaskId,
    /// The channel.
    pub channel: ChannelId,
    /// The message kind.
    pub kind: MessageKind,
    /// Opaque payload. Length-limited per channel policy.
    pub payload: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Wake actions — IPC↔scheduler contract
// -----------------------------------------------------------------------------

/// What the scheduler should do after the IPC layer returns.
///
/// The IPC layer never calls into the scheduler directly. Instead, each
/// fallible operation returns a [`WakeAction`] that the *caller* (the
/// syscall handler) translates into a scheduler operation:
///
/// - [`WakeAction::None`] — nothing to do.
/// - [`WakeAction::Wake(t)`] — the syscall handler calls
///   `scheduler.enqueue(t, priority)` to re-enable a previously-blocked
///   task. Used by `send` when a `receive` waiter was parked, and by
///   `receive` when a `Block`-policy `send` was parked.
/// - [`WakeAction::Block(t)`] — the syscall handler calls
///   `scheduler.yield_current(t, BlockedOnIpc)` to park the calling
///   task. Used by `send` under `Block` backpressure on a full queue,
///   and by `receive` on an empty queue with `blocking = true`.
///
/// This decoupling keeps the registry testable in `cargo test`
/// (no scheduler global needed) and the syscall layer flexible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeAction {
    /// Nothing to do.
    None,
    /// Re-enable a task that was waiting on this channel.
    Wake(TaskId),
    /// Park the current task until a counterpart unblocks it.
    Block(TaskId),
}

// -----------------------------------------------------------------------------
// Channel — kernel-internal per-channel state
// -----------------------------------------------------------------------------

/// Per-channel state owned by the [`KernelIpcRegistry`].
///
/// Wait queues live *inside* the channel (not lazily in the scheduler)
/// for two reasons:
///
/// 1. O(1) lookup of "who is waiting on this channel?" at send/receive
///    time.
/// 2. Local cleanup on `destroy_channel`: if the channel goes away,
///    waiters are visible right here without a scheduler walk.
#[derive(Debug)]
pub struct Channel {
    /// Kernel-allocated identifier.
    pub id: ChannelId,
    /// Per-channel policy. Immutable post-creation.
    pub policy: ChannelPolicy,
    /// The task that created this channel; only they may destroy it.
    pub owner: TaskId,
    /// Principal authorised to call `IpcSend`. `None` means the channel
    /// has no send-side authentication (dev mode); the kernel accepts
    /// any sender.
    pub send_subject: Option<KernelPrincipal>,
    /// Principal authorised to call `IpcReceive`. `None` means the
    /// channel has no recv-side authentication.
    pub recv_subject: Option<KernelPrincipal>,
    /// Messages enqueued but not yet delivered. FIFO.
    pub queue: VecDeque<MessageEnvelope>,
    /// Tasks blocked on a full queue under `BackpressurePolicy::Block`.
    pub waiters_send: VecDeque<TaskId>,
    /// Tasks blocked on an empty queue with `blocking = true`.
    pub waiters_recv: VecDeque<TaskId>,
}

impl Channel {
    /// Construct an empty channel slot. Reserved for [`KernelIpcRegistry::create_channel`].
    fn new(
        id: ChannelId,
        policy: ChannelPolicy,
        owner: TaskId,
        send_subject: Option<KernelPrincipal>,
        recv_subject: Option<KernelPrincipal>,
    ) -> Self {
        Self {
            id,
            policy,
            owner,
            send_subject,
            recv_subject,
            queue: VecDeque::new(),
            waiters_send: VecDeque::new(),
            waiters_recv: VecDeque::new(),
        }
    }

    /// Current queue length.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.queue.len()
    }
}

// -----------------------------------------------------------------------------
// KernelIpcRegistry — the singleton IPC backend
// -----------------------------------------------------------------------------

/// Maximum live channels a single owner task may hold (NCIP-Kernel-Sec-026
/// §S3.2). Far above legitimate Phase-1 usage (a handful per service); bounds
/// a channel-creation flood from one principal.
pub const MAX_CHANNELS_PER_OWNER: usize = 256;

/// Hard global cap on live channels — a backstop against kernel-heap
/// exhaustion regardless of owner distribution (NCIP-Kernel-Sec-026 §S3.2).
pub const MAX_CHANNELS_TOTAL: usize = 4096;

/// Kernel-internal IPC registry. One instance per kernel; bare-metal
/// builds keep it inside a `static mut`.
///
/// Backing storage is a `BTreeMap` rather than a `HashMap`: `hashbrown`
/// (the workspace's `HashMap` source) seeds `ahash` from `getrandom`,
/// which is exactly the dependency `nexacore-crypto`'s `rng` feature was
/// gated to avoid in bare-metal builds. `BTreeMap` is `alloc`-only,
/// deterministic, and well-suited to the small number of channels Phase
/// 1 will create (tens at most).
#[derive(Debug)]
pub struct KernelIpcRegistry {
    channels: BTreeMap<u64, Channel>,
    next_id: u64,
}

impl KernelIpcRegistry {
    /// Construct an empty registry. `const fn` so a `static mut` slot
    /// can hold one without a lazy initializer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            channels: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Number of live channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Enforce the channel-creation quota (NCIP-Kernel-Sec-026 §S3.2 / R4).
    ///
    /// Re-justified for the reclaiming allocator (WS1-08.7, NCIP-Kernel-Alloc-029):
    /// the kernel heap now frees on `destroy_channel`, so this cap is no longer
    /// about a *never-freeing* heap. It is **per-owner resource governance**:
    /// every *live* (not-yet-destroyed) channel still consumes heap proportional
    /// to its queue depth, so an unbounded creation loop by one principal would
    /// still exhaust memory. A per-owner cap bounds that, and a global cap is a
    /// hard backstop independent of owner distribution. Both limits are far
    /// above any legitimate Phase-1 usage (tens of channels) yet low enough to
    /// stop a flood.
    fn enforce_channel_quota(&self, owner: TaskId) -> KernelResult<()> {
        if self.channels.len() >= MAX_CHANNELS_TOTAL {
            return Err(KernelError::ResourceExhausted);
        }
        let owned_count = self
            .channels
            .values()
            .filter(|c| c.owner.0 == owner.0)
            .count();
        if owned_count >= MAX_CHANNELS_PER_OWNER {
            return Err(KernelError::ResourceExhausted);
        }
        Ok(())
    }

    /// Borrow a channel by id, if it exists.
    #[must_use]
    pub fn channel(&self, id: ChannelId) -> Option<&Channel> {
        self.channels.get(&id.0)
    }

    /// Create a new channel.
    ///
    /// `send_token` and `recv_token` are optional. When present, the
    /// kernel verifies each token via the provided
    /// [`KernelCapabilityCheck`] and memorises the embedded
    /// `subject` for later send/recv comparison. When absent, the
    /// channel is unauthenticated on that direction (developer mode).
    ///
    /// `policy.queue_depth` has **no upper cap**: the legacy ADR-0005
    /// recommendation of `≤ 256` messages per channel existed only to bound
    /// the never-freeing `BumpHeap`, and is withdrawn now that the reclaiming
    /// `SlabHeap` backs the queue (WS1-08.7, NCIP-Kernel-Alloc-029 § S5). Depth
    /// is bounded only by available heap; per-owner resource pressure is
    /// governed by the live-channel quota (`enforce_channel_quota`).
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] when `policy.queue_depth` is
    ///   zero (a zero-depth channel would deadlock under `Block` and is
    ///   never useful).
    /// - [`KernelError::CapabilityDenied`] when a token is presented but
    ///   the capability check rejects it.
    /// - [`KernelError::ResourceExhausted`] when the registry's monotonic
    ///   id counter would overflow (~2^64 channels — practically never),
    ///   or the per-owner / global live-channel quota is reached.
    pub fn create_channel<C: KernelCapabilityCheck>(
        &mut self,
        owner: TaskId,
        policy: ChannelPolicy,
        send_token: Option<KernelCapabilityToken>,
        recv_token: Option<KernelCapabilityToken>,
        verifier: &C,
    ) -> KernelResult<ChannelId> {
        if policy.queue_depth == 0 {
            return Err(KernelError::InvalidArgument);
        }
        self.enforce_channel_quota(owner)?;

        let id_u64 = self.next_id;
        let id = ChannelId(id_u64);
        let resource = KernelResource::IpcChannel(id_u64);

        let send_subject = if let Some(tok) = send_token {
            if verifier.verify(&tok, KernelAction::IpcSend, resource)
                != CapabilityVerdict::Authorised
            {
                return Err(KernelError::CapabilityDenied);
            }
            Some(tok.subject)
        } else {
            None
        };

        let recv_subject = if let Some(tok) = recv_token {
            if verifier.verify(&tok, KernelAction::IpcRecv, resource)
                != CapabilityVerdict::Authorised
            {
                return Err(KernelError::CapabilityDenied);
            }
            Some(tok.subject)
        } else {
            None
        };

        let channel = Channel::new(id, policy, owner, send_subject, recv_subject);
        self.channels.insert(id_u64, channel);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(KernelError::ResourceExhausted)?;
        Ok(id)
    }

    /// Create a channel from signed user-space capability tokens.
    ///
    /// MB13.d entry-point used by the `IpcCreateChannel(20)` syscall when
    /// the caller supplies postcard-encoded
    /// [`nexacore_capability::CapabilityToken`] blobs. Each non-`None` slot
    /// runs full Ed25519 verification (signature + time window + TEE
    /// binding) via [`crate::capabilities::decode_and_authenticate_token`]
    /// and extracts the embedded subject as a [`KernelPrincipal`].
    ///
    /// When both slots are `None`, this delegates to
    /// [`Self::create_channel`] with the same
    /// `Ed25519CapabilityProvider` supplied by the caller — the
    /// per-IPC `verify` impl on that provider is identical O(1)
    /// shape-matching to the (now `#[cfg(test)]`-only)
    /// `StubCapabilityProvider`, so the legacy MB12 open-channel path
    /// (used by the `mb12-userprobe` boot wiring) keeps working
    /// byte-for-byte. Per the MB13.d ABI,
    /// `(send_token = None, recv_token = None)` is the explicit
    /// "no capability gating" signal.
    ///
    /// `now` is the kernel monotonic timestamp passed to
    /// `Ed25519CapabilityProvider::verify_signed_token`; on bare-metal
    /// the syscall handler sources it from
    /// `crate::bare_metal::arch::rtc_seconds`.
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] when `policy.queue_depth` is 0
    ///   or when token bytes fail to decode.
    /// - [`KernelError::CapabilityDenied`] when a presented token fails
    ///   Ed25519 / time / TEE verification, or carries the wrong
    ///   scope action / resource shape.
    /// - [`KernelError::ResourceExhausted`] when the monotonic channel-id
    ///   counter would overflow.
    pub fn create_channel_signed(
        &mut self,
        owner: TaskId,
        policy: ChannelPolicy,
        send_token_bytes: Option<&[u8]>,
        recv_token_bytes: Option<&[u8]>,
        provider: &crate::capabilities::Ed25519CapabilityProvider,
        now: u64,
    ) -> KernelResult<ChannelId> {
        if send_token_bytes.is_none() && recv_token_bytes.is_none() {
            return self.create_channel(owner, policy, None, None, provider);
        }

        if policy.queue_depth == 0 {
            return Err(KernelError::InvalidArgument);
        }
        self.enforce_channel_quota(owner)?;

        let send_subject = match send_token_bytes {
            Some(b) => Some(crate::capabilities::decode_and_authenticate_token(
                b,
                KernelAction::IpcSend,
                provider,
                now,
            )?),
            None => None,
        };
        let recv_subject = match recv_token_bytes {
            Some(b) => Some(crate::capabilities::decode_and_authenticate_token(
                b,
                KernelAction::IpcRecv,
                provider,
                now,
            )?),
            None => None,
        };

        let id_u64 = self.next_id;
        let id = ChannelId(id_u64);
        let channel = Channel::new(id, policy, owner, send_subject, recv_subject);
        self.channels.insert(id_u64, channel);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(KernelError::ResourceExhausted)?;
        Ok(id)
    }

    /// Destroy a channel. Only the channel's `owner` may do this.
    ///
    /// Pending messages are dropped. Removing the channel drops its `queue`
    /// and waiter `VecDeque`s, whose backing store is **returned to the
    /// global allocator** — with the reclaiming `SlabHeap` (WS1-08.6,
    /// NCIP-Kernel-Alloc-029) this memory is genuinely reclaimed, fixing the
    /// ADR-0005 leak where the never-freeing `BumpHeap` retained a destroyed
    /// channel's buffers until reboot.
    ///
    /// Any task currently blocked on this channel
    /// (`waiters_send`/`waiters_recv`) is left for the caller to wake — the
    /// syscall handler that issued `IpcDestroyChannel` inherits the
    /// responsibility (Phase 1 single-CPU: typically the destroyer is also the
    /// only task that could have been waiting on the channel; multi-task
    /// destroy semantics ship with MB13).
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] if no such channel exists.
    /// - [`KernelError::CapabilityDenied`] if `requester != channel.owner`.
    pub fn destroy_channel(&mut self, channel: ChannelId, requester: TaskId) -> KernelResult<()> {
        let entry = self
            .channels
            .get(&channel.0)
            .ok_or(KernelError::InvalidArgument)?;
        if entry.owner.0 != requester.0 {
            return Err(KernelError::CapabilityDenied);
        }
        self.channels.remove(&channel.0);
        Ok(())
    }

    /// Send a message on a channel.
    ///
    /// The kernel fills `envelope.sender` from `sender_task`; the
    /// caller-supplied value (if any) is overwritten. The `requester`
    /// argument is the principal claimed by the calling task — the
    /// registry compares it against `channel.send_subject` when one is
    /// set.
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] if no such channel.
    /// - [`KernelError::CapabilityDenied`] if `requester` does not match
    ///   the channel's send subject.
    /// - [`KernelError::ResourceExhausted`] under
    ///   `BackpressurePolicy::Drop` when the queue is full.
    ///
    /// On `BackpressurePolicy::Block` with a full queue, the call
    /// succeeds with [`WakeAction::Block(sender_task)`] — the syscall
    /// handler must park the sender. The envelope is **not** enqueued
    /// in this case; the handler must re-issue the send when the task
    /// wakes up.
    pub fn send(
        &mut self,
        mut envelope: MessageEnvelope,
        sender_task: TaskId,
        requester: KernelPrincipal,
    ) -> KernelResult<WakeAction> {
        let channel = self
            .channels
            .get_mut(&envelope.channel.0)
            .ok_or(KernelError::InvalidArgument)?;

        if let Some(allowed) = channel.send_subject {
            if allowed != requester {
                return Err(KernelError::CapabilityDenied);
            }
        }

        envelope.sender = sender_task;
        envelope.channel = channel.id;

        let full = channel.queue.len() >= channel.policy.queue_depth;
        if full {
            match channel.policy.backpressure {
                BackpressurePolicy::Drop => return Err(KernelError::ResourceExhausted),
                BackpressurePolicy::EvictOldest => {
                    let _ = channel.queue.pop_front();
                }
                BackpressurePolicy::Block => {
                    // Dedup: a blocked sender that is woken and re-issues the
                    // send while the queue is still full MUST NOT be enqueued
                    // twice. Without this, a spin-retry (or a self-feeding peer)
                    // grows `waiters_send` without bound and exhausts the
                    // never-freeing kernel heap (NCIP-Kernel-Sec-026 §S3.2 / R4).
                    if !channel.waiters_send.contains(&sender_task) {
                        channel.waiters_send.push_back(sender_task);
                    }
                    return Ok(WakeAction::Block(sender_task));
                }
            }
        }

        channel.queue.push_back(envelope);

        Ok(channel
            .waiters_recv
            .pop_front()
            .map_or(WakeAction::None, WakeAction::Wake))
    }

    /// Dequeue a message from a channel.
    ///
    /// Returns:
    /// - `Ok((Some(env), wake))` — a message was dequeued. `wake` is
    ///   `Wake(t)` if a `Block`-policy sender was parked on this
    ///   channel and now has space to enqueue; otherwise `None`.
    /// - `Ok((None, wake))` — the queue was empty. If `blocking` is
    ///   true, `wake` is `Block(requester_task)` and the caller must
    ///   park the task. If `blocking` is false, `wake` is `None`.
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] if no such channel.
    /// - [`KernelError::CapabilityDenied`] if `requester` does not match
    ///   the channel's recv subject.
    pub fn receive(
        &mut self,
        channel_id: ChannelId,
        requester_task: TaskId,
        requester: KernelPrincipal,
        blocking: bool,
    ) -> KernelResult<(Option<MessageEnvelope>, WakeAction)> {
        let channel = self
            .channels
            .get_mut(&channel_id.0)
            .ok_or(KernelError::InvalidArgument)?;

        if let Some(allowed) = channel.recv_subject {
            if allowed != requester {
                return Err(KernelError::CapabilityDenied);
            }
        }

        if let Some(env) = channel.queue.pop_front() {
            let wake = channel
                .waiters_send
                .pop_front()
                .map_or(WakeAction::None, WakeAction::Wake);
            return Ok((Some(env), wake));
        }

        if blocking {
            // Dedup (NCIP-Kernel-Sec-026 §S3.2 / R4): a receiver woken spuriously
            // that re-issues a blocking receive on a still-empty channel MUST
            // NOT be enqueued twice, else `waiters_recv` grows without bound and
            // exhausts the never-freeing kernel heap.
            if !channel.waiters_recv.contains(&requester_task) {
                channel.waiters_recv.push_back(requester_task);
            }
            Ok((None, WakeAction::Block(requester_task)))
        } else {
            Ok((None, WakeAction::None))
        }
    }

    /// Queue depth for a channel.
    ///
    /// # Errors
    ///
    /// - [`KernelError::InvalidArgument`] if no such channel.
    pub fn queue_depth(&self, channel: ChannelId) -> KernelResult<usize> {
        self.channels
            .get(&channel.0)
            .map(Channel::depth)
            .ok_or(KernelError::InvalidArgument)
    }
}

impl Default for KernelIpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Singleton accessor (bare-metal only)
// -----------------------------------------------------------------------------

/// Global IPC registry. Single instance per kernel.
///
/// Mirrors the `SCHEDULER` / `FRAME_ALLOC` singleton pattern from the
/// rest of the kernel: a `static mut` rather than a `Mutex<...>` because
/// Phase 1 is single-CPU and the SYSCALL entry path masks interrupts via
/// `IA32_FMASK = 0x200`. MP introduction (Phase 2) will replace this
/// with a `Mutex` or per-CPU array — tracked in ADR-0005.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
static mut IPC_REGISTRY: KernelIpcRegistry = KernelIpcRegistry::new();

/// Borrow the global IPC registry mutably.
///
/// # Safety
///
/// Caller must be in a context where no other reference to
/// `IPC_REGISTRY` is live. The SYSCALL path already provides this
/// guarantee (interrupts masked + single-CPU + no recursion).
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    clippy::mut_from_ref,
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn ipc_registry_mut() -> &'static mut KernelIpcRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of_mut!(IPC_REGISTRY);
        &mut *p
    }
}

/// Borrow the global IPC registry immutably.
///
/// # Safety
///
/// Caller must be in a context where no `&mut` to `IPC_REGISTRY` is
/// concurrently live. The SYSCALL path provides this in single-CPU
/// Phase 1; the MP transition will replace this accessor with a
/// shared lock guard per ADR-0005.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn ipc_registry() -> &'static KernelIpcRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of!(IPC_REGISTRY);
        &*p
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::capabilities::StubCapabilityProvider;

    fn principal(b: u8) -> KernelPrincipal {
        KernelPrincipal::from_bytes([b; 32])
    }

    fn open_policy(depth: usize, bp: BackpressurePolicy) -> ChannelPolicy {
        ChannelPolicy {
            queue_depth: depth,
            backpressure: bp,
            tee_bound: false,
        }
    }

    fn make_envelope(channel: ChannelId, payload: &[u8]) -> MessageEnvelope {
        MessageEnvelope {
            sender: TaskId(0),
            channel,
            kind: MessageKind::Request,
            payload: payload.to_vec(),
        }
    }

    // ---- Shape sanity --------------------------------------------------------

    #[test]
    fn message_kind_fits_in_one_byte() {
        assert_eq!(core::mem::size_of::<MessageKind>(), 1);
    }

    #[test]
    fn envelope_round_trip() {
        let e = MessageEnvelope {
            sender: TaskId(7),
            channel: ChannelId(42),
            kind: MessageKind::Request,
            payload: vec![1, 2, 3],
        };
        assert_eq!(e.sender, TaskId(7));
        assert_eq!(e.channel, ChannelId(42));
        assert_eq!(e.kind, MessageKind::Request);
        assert_eq!(e.payload, vec![1, 2, 3]);
    }

    #[test]
    fn channel_policy_carries_tee_bit() {
        let p = ChannelPolicy {
            queue_depth: 16,
            backpressure: BackpressurePolicy::Block,
            tee_bound: true,
        };
        assert!(p.tee_bound);
        assert_eq!(p.backpressure, BackpressurePolicy::Block);
    }

    // ---- KernelIpcRegistry: create / destroy --------------------------------

    #[test]
    fn create_channel_returns_monotonic_ids() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let a = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        let b = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        assert_eq!(a, ChannelId(1));
        assert_eq!(b, ChannelId(2));
        assert_eq!(r.channel_count(), 2);
    }

    #[test]
    fn create_rejects_zero_depth() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let err = r
            .create_channel(
                TaskId(1),
                open_policy(0, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap_err();
        assert_eq!(err, KernelError::InvalidArgument);
    }

    #[test]
    fn destroy_requires_owner() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let id = r
            .create_channel(
                TaskId(10),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        // Non-owner cannot destroy.
        assert_eq!(
            r.destroy_channel(id, TaskId(99)).unwrap_err(),
            KernelError::CapabilityDenied
        );
        // Owner can.
        r.destroy_channel(id, TaskId(10)).unwrap();
        assert_eq!(r.channel_count(), 0);
    }

    // ---- KernelIpcRegistry: send / receive round-trip ------------------------

    #[test]
    fn send_then_receive_round_trip() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        let env = make_envelope(ch, b"ping");
        let wake = r.send(env, TaskId(10), principal(0)).unwrap();
        assert_eq!(wake, WakeAction::None);

        let (got, wake) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert_eq!(wake, WakeAction::None);
        let env = got.expect("message delivered");
        assert_eq!(env.sender, TaskId(10));
        assert_eq!(env.channel, ch);
        assert_eq!(env.payload, b"ping");
    }

    #[test]
    fn queue_depth_above_legacy_recommendation_is_accepted() {
        // WS1-08.7 / NCIP-029 § S5: the ADR-0005 `queue_depth ≤ 256` ceiling is
        // withdrawn now that the reclaiming SlabHeap backs the queue. A channel
        // far above that bound is created and fills past 256 in-flight messages
        // without rejection.
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let depth = 1024; // 4× the legacy recommendation
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(depth, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .expect("queue_depth > 256 must be accepted");
        let in_flight = 300; // > 256, still < depth
        for i in 0..in_flight {
            let payload = [u8::try_from(i % 256).unwrap()];
            let wake = r
                .send(make_envelope(ch, &payload), TaskId(10), principal(0))
                .expect("send below queue_depth must succeed");
            assert_eq!(wake, WakeAction::None);
        }
        assert_eq!(
            r.queue_depth(ch).unwrap(),
            in_flight,
            "all {in_flight} messages (> legacy 256 cap) are queued"
        );
    }

    #[test]
    fn kernel_overwrites_sender_field() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(2, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        // Userspace claims to be TaskId(999); kernel must overwrite to actual.
        let mut env = make_envelope(ch, b"x");
        env.sender = TaskId(999);
        r.send(env, TaskId(42), principal(0)).unwrap();
        let (got, _) = r.receive(ch, TaskId(1), principal(0), false).unwrap();
        assert_eq!(got.unwrap().sender, TaskId(42));
    }

    // ---- Backpressure --------------------------------------------------------

    #[test]
    fn drop_policy_returns_resource_exhausted_when_full() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        r.send(make_envelope(ch, b"first"), TaskId(10), principal(0))
            .unwrap();
        let err = r
            .send(make_envelope(ch, b"second"), TaskId(10), principal(0))
            .unwrap_err();
        assert_eq!(err, KernelError::ResourceExhausted);
        // The original message is still there.
        let (got, _) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert_eq!(got.unwrap().payload, b"first");
    }

    #[test]
    fn evict_oldest_replaces_head_when_full() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(2, BackpressurePolicy::EvictOldest),
                None,
                None,
                &stub,
            )
            .unwrap();
        r.send(make_envelope(ch, b"a"), TaskId(10), principal(0))
            .unwrap();
        r.send(make_envelope(ch, b"b"), TaskId(10), principal(0))
            .unwrap();
        // Queue now full → "a" evicted, queue becomes [b, c].
        r.send(make_envelope(ch, b"c"), TaskId(10), principal(0))
            .unwrap();
        let (got, _) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert_eq!(got.unwrap().payload, b"b");
        let (got, _) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert_eq!(got.unwrap().payload, b"c");
    }

    #[test]
    fn block_policy_signals_block_action_when_full() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        r.send(make_envelope(ch, b"a"), TaskId(10), principal(0))
            .unwrap();
        let wake = r
            .send(make_envelope(ch, b"b"), TaskId(20), principal(0))
            .unwrap();
        assert_eq!(wake, WakeAction::Block(TaskId(20)));
        // Sender 20 must be parked in waiters_send.
        let ch_ref = r.channel(ch).unwrap();
        assert_eq!(ch_ref.waiters_send.front().copied(), Some(TaskId(20)));
    }

    // ---- Wakeup contracts ----------------------------------------------------

    #[test]
    fn receive_on_empty_blocks_when_requested() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        let (got, wake) = r.receive(ch, TaskId(11), principal(0), true).unwrap();
        assert!(got.is_none());
        assert_eq!(wake, WakeAction::Block(TaskId(11)));
        let ch_ref = r.channel(ch).unwrap();
        assert_eq!(ch_ref.waiters_recv.front().copied(), Some(TaskId(11)));
    }

    #[test]
    fn receive_on_empty_nonblocking_returns_none() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        let (got, wake) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert!(got.is_none());
        assert_eq!(wake, WakeAction::None);
    }

    #[test]
    fn send_wakes_pending_receiver() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        // Receiver parks first.
        let _ = r.receive(ch, TaskId(11), principal(0), true).unwrap();
        // Now sender arrives.
        let wake = r
            .send(make_envelope(ch, b"x"), TaskId(10), principal(0))
            .unwrap();
        assert_eq!(wake, WakeAction::Wake(TaskId(11)));
    }

    #[test]
    fn receive_wakes_pending_blocking_sender() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        r.send(make_envelope(ch, b"first"), TaskId(10), principal(0))
            .unwrap();
        let _ = r
            .send(make_envelope(ch, b"second"), TaskId(20), principal(0))
            .unwrap();
        // The sender 20 is parked; pull "first" → wake 20.
        let (got, wake) = r.receive(ch, TaskId(11), principal(0), false).unwrap();
        assert!(got.is_some());
        assert_eq!(wake, WakeAction::Wake(TaskId(20)));
    }

    // ---- Capability gating ---------------------------------------------------

    #[test]
    fn send_subject_mismatch_denies() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let send_tok = KernelCapabilityToken {
            subject: principal(42),
            action: KernelAction::IpcSend,
            resource: KernelResource::IpcChannel(1),
        };
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                Some(send_tok),
                None,
                &stub,
            )
            .unwrap();
        // Sender with wrong principal is rejected.
        let err = r
            .send(make_envelope(ch, b"x"), TaskId(99), principal(7))
            .unwrap_err();
        assert_eq!(err, KernelError::CapabilityDenied);
        // Correct principal succeeds.
        r.send(make_envelope(ch, b"y"), TaskId(99), principal(42))
            .unwrap();
    }

    #[test]
    fn recv_subject_mismatch_denies() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let recv_tok = KernelCapabilityToken {
            subject: principal(7),
            action: KernelAction::IpcRecv,
            resource: KernelResource::IpcChannel(1),
        };
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                None,
                Some(recv_tok),
                &stub,
            )
            .unwrap();
        r.send(make_envelope(ch, b"x"), TaskId(99), principal(0))
            .unwrap();
        let err = r.receive(ch, TaskId(11), principal(99), false).unwrap_err();
        assert_eq!(err, KernelError::CapabilityDenied);
        // Correct principal succeeds.
        let (got, _) = r.receive(ch, TaskId(11), principal(7), false).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn create_with_invalid_token_action_denies() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        // Caller presents an IpcRecv token in the send slot — stub rejects.
        let wrong_action = KernelCapabilityToken {
            subject: principal(1),
            action: KernelAction::IpcRecv,
            resource: KernelResource::IpcChannel(1),
        };
        let err = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Drop),
                Some(wrong_action),
                None,
                &stub,
            )
            .unwrap_err();
        assert_eq!(err, KernelError::CapabilityDenied);
    }

    // ---- queue_depth + missing channel --------------------------------------

    #[test]
    fn queue_depth_reflects_in_flight_messages() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let ch = r
            .create_channel(
                TaskId(1),
                open_policy(8, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        assert_eq!(r.queue_depth(ch).unwrap(), 0);
        r.send(make_envelope(ch, b"a"), TaskId(10), principal(0))
            .unwrap();
        r.send(make_envelope(ch, b"b"), TaskId(10), principal(0))
            .unwrap();
        assert_eq!(r.queue_depth(ch).unwrap(), 2);
    }

    #[test]
    fn operations_on_missing_channel_return_invalid_argument() {
        let mut r = KernelIpcRegistry::new();
        let missing = ChannelId(9999);
        assert_eq!(
            r.queue_depth(missing).unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            r.destroy_channel(missing, TaskId(1)).unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            r.send(make_envelope(missing, b"x"), TaskId(1), principal(0))
                .unwrap_err(),
            KernelError::InvalidArgument
        );
        assert_eq!(
            r.receive(missing, TaskId(1), principal(0), false)
                .unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    // --- NCIP-Kernel-Sec-026 §S3.2 (R4): bounded waiters + channel quota ---

    #[test]
    fn waiters_send_deduped_on_repeated_block() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let id = r
            .create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        // Fill the single slot.
        let _ = r
            .send(make_envelope(id, b"x"), TaskId(2), principal(0))
            .unwrap();
        // Queue full: a Block sender parks. Re-issue the same send three times
        // (spin-retry while still full) — the waiter MUST appear exactly once.
        for _ in 0..3 {
            let w = r
                .send(make_envelope(id, b"y"), TaskId(2), principal(0))
                .unwrap();
            assert!(matches!(w, WakeAction::Block(_)));
        }
        assert_eq!(r.channel(id).unwrap().waiters_send.len(), 1);
    }

    #[test]
    fn waiters_recv_deduped_on_repeated_block() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let id = r
            .create_channel(
                TaskId(1),
                open_policy(4, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .unwrap();
        // Empty channel: a blocking receive parks. Re-issue three times — one
        // waiter only.
        for _ in 0..3 {
            let (msg, wake) = r.receive(id, TaskId(5), principal(0), true).unwrap();
            assert!(msg.is_none());
            assert!(matches!(wake, WakeAction::Block(_)));
        }
        assert_eq!(r.channel(id).unwrap().waiters_recv.len(), 1);
    }

    #[test]
    fn channel_quota_per_owner_enforced() {
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        for _ in 0..MAX_CHANNELS_PER_OWNER {
            r.create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap();
        }
        // One more from the same owner is refused.
        assert_eq!(
            r.create_channel(
                TaskId(1),
                open_policy(1, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .unwrap_err(),
            KernelError::ResourceExhausted
        );
        // A different owner is still allowed (per-owner cap, total still low).
        assert!(
            r.create_channel(
                TaskId(2),
                open_policy(1, BackpressurePolicy::Drop),
                None,
                None,
                &stub,
            )
            .is_ok()
        );
    }

    // ---- WS1-08.8: create/destroy stress at 10^5 scale -----------------------

    #[test]
    fn stress_create_destroy_100k_channels_reclaims() {
        // 10^5 create/destroy cycles through the real registry. With each
        // channel destroyed before the next is created, the live count never
        // grows — proving the registry releases every channel (and, on the
        // bare-metal SlabHeap, its buffers) rather than accumulating them.
        // Ids must keep increasing (no reuse) and the map must return to empty.
        // The allocator-level "limited memory, no OOM" half of WS1-08.8 lives
        // in `tests/heap.rs` (the global allocator here is the host's, not
        // SlabHeap).
        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let owner = TaskId(1);
        let mut last_id = 0u64;
        for _ in 0..100_000u32 {
            let ch = r
                .create_channel(
                    owner,
                    open_policy(8, BackpressurePolicy::Drop),
                    None,
                    None,
                    &stub,
                )
                .expect("create must succeed (each prior channel was destroyed)");
            assert!(ch.0 > last_id, "channel ids strictly increase — no reuse");
            last_id = ch.0;
            // Push a few messages so the queue VecDeque actually allocates and
            // is then reclaimed on destroy.
            for _ in 0..4 {
                r.send(
                    make_envelope(ch, b"stress-payload"),
                    TaskId(10),
                    principal(0),
                )
                .expect("send below queue_depth");
            }
            r.destroy_channel(ch, owner).expect("owner may destroy");
            assert_eq!(r.channel_count(), 0, "channel fully released each cycle");
        }
        assert_eq!(r.channel_count(), 0, "no channels leaked after 100k cycles");
        assert!(last_id >= 100_000, "all 100k channels were created");
    }

    // ---- M0 socket-relay round-trip (PLAN.md TASK-05) ------------------------

    /// Host round-trip of the M0 contract: the full
    /// `NetSocket → NetConnect → NetSend → NetRecv` request/response
    /// sequence between a "kernel relay" side and a mock `nexacore-net`,
    /// carried over the REAL two-channel rendezvous (`stack` request
    /// channel + `stack_reply` reply channel) in the real
    /// [`KernelIpcRegistry`], with postcard-canonical payloads
    /// (`nexacore_types::wire`, NCIP-Serde-004).
    ///
    /// The Ring 0 relay glue itself is `target_os = "none"`-gated; this
    /// test pins down everything host-testable around it: the wire
    /// protocol, the envelope path, ordering, and that each request is
    /// answered on the OTHER channel (the rendezvous invariant the relay
    /// depends on).
    #[test]
    #[allow(clippy::too_many_lines, reason = "full 4-step protocol sequence")]
    fn m0_socket_relay_round_trip_over_two_real_channels() {
        use nexacore_types::{
            socket::{
                SocketApiAddr, SocketDomain, SocketHandle, SocketRequest, SocketResponse,
                SocketType,
            },
            wire::{decode_canonical, encode_canonical},
        };

        let mut r = KernelIpcRegistry::new();
        let stub = StubCapabilityProvider;
        let relay_task = TaskId(1); // plays the kernel relay (client side)
        let net_task = TaskId(2); // plays nexacore-net (mock service side)
        let p = principal(0);

        // The two REAL channels of the rendezvous (M0 contract § 2).
        let stack = r
            .create_channel(
                net_task,
                open_policy(8, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .expect("stack channel");
        let stack_reply = r
            .create_channel(
                net_task,
                open_policy(8, BackpressurePolicy::Block),
                None,
                None,
                &stub,
            )
            .expect("stack_reply channel");

        // One request/response exchange over the rendezvous: send the
        // encoded request on `stack`, mock-serve it, answer on
        // `stack_reply`, decode the reply on the relay side.
        let mut exchange = |req: &SocketRequest,
                            serve: &mut dyn FnMut(SocketRequest) -> SocketResponse|
         -> SocketResponse {
            // Relay → stack.
            let payload = encode_canonical(req).expect("encode request");
            let env = MessageEnvelope {
                sender: relay_task,
                channel: stack,
                kind: MessageKind::Request,
                payload,
            };
            r.send(env, relay_task, p).expect("send on stack");

            // Mock nexacore-net: drain stack, serve, reply on stack_reply.
            let (got, _) = r
                .receive(stack, net_task, p, false)
                .expect("receive on stack");
            let got = got.expect("request envelope present");
            let decoded: SocketRequest = decode_canonical(&got.payload).expect("decode request");
            let resp = serve(decoded);
            let reply_env = MessageEnvelope {
                sender: net_task,
                channel: stack_reply,
                kind: MessageKind::Reply,
                payload: encode_canonical(&resp).expect("encode response"),
            };
            r.send(reply_env, net_task, p).expect("send on stack_reply");

            // Relay side: blocking-receive the reply on the OTHER channel.
            let (reply, _) = r
                .receive(stack_reply, relay_task, p, true)
                .expect("receive on stack_reply");
            let reply = reply.expect("reply envelope present");
            decode_canonical(&reply.payload).expect("decode response")
        };

        // ── 1. NetSocket ────────────────────────────────────────────────
        let resp = exchange(
            &SocketRequest::Socket {
                domain: SocketDomain::Inet,
                sock_type: SocketType::Stream,
            },
            &mut |req| {
                assert!(matches!(
                    req,
                    SocketRequest::Socket {
                        domain: SocketDomain::Inet,
                        sock_type: SocketType::Stream,
                    }
                ));
                SocketResponse::Handle(SocketHandle(1))
            },
        );
        assert!(matches!(resp, SocketResponse::Handle(SocketHandle(1))));

        // ── 2. NetConnect (192.0.2.11:11434) ──────────────────────────
        let resp = exchange(
            &SocketRequest::Connect {
                handle: SocketHandle(1),
                addr: SocketApiAddr {
                    ip: [192, 0, 2, 11],
                    port: 11434,
                },
            },
            &mut |req| {
                let SocketRequest::Connect { handle, addr } = req else {
                    panic!("expected Connect, got {req:?}");
                };
                assert_eq!(handle, SocketHandle(1));
                assert_eq!(addr.ip, [192, 0, 2, 11]);
                assert_eq!(addr.port, 11434);
                SocketResponse::Ok(0)
            },
        );
        assert!(matches!(resp, SocketResponse::Ok(0)));

        // ── 3. NetSend (the HTTP GET) ───────────────────────────────────
        let request_bytes: &[u8] = b"GET /api/tags HTTP/1.1\r\nHost: 192.0.2.11:11434\r\n\r\n";
        let resp = exchange(
            &SocketRequest::Send {
                handle: SocketHandle(1),
                data: request_bytes.to_vec(),
                flags: 0,
            },
            &mut |req| {
                let SocketRequest::Send { handle, data, .. } = req else {
                    panic!("expected Send, got {req:?}");
                };
                assert_eq!(handle, SocketHandle(1));
                assert_eq!(data, request_bytes, "request must survive the wire");
                SocketResponse::Ok(data.len() as u64)
            },
        );
        assert!(
            matches!(resp, SocketResponse::Ok(n) if n == request_bytes.len() as u64),
            "Send must round-trip the byte count: {resp:?}"
        );

        // ── 4. NetRecv (the HTTP 200 response) ──────────────────────────
        let response_bytes: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"models\":[]}";
        let resp = exchange(
            &SocketRequest::Recv {
                handle: SocketHandle(1),
                max_len: 1024,
                flags: 0,
            },
            &mut |req| {
                let SocketRequest::Recv {
                    handle, max_len, ..
                } = req
                else {
                    panic!("expected Recv, got {req:?}");
                };
                assert_eq!(handle, SocketHandle(1));
                assert_eq!(max_len, 1024);
                SocketResponse::Data(response_bytes.to_vec())
            },
        );
        let SocketResponse::Data(bytes) = resp else {
            panic!("expected Data, got {resp:?}");
        };
        assert_eq!(bytes, response_bytes, "response must survive the wire");

        // Rendezvous invariant: both channels drained — nothing stranded.
        let (none_stack, _) = r.receive(stack, net_task, p, false).expect("stack empty");
        assert!(none_stack.is_none());
        let (none_reply, _) = r
            .receive(stack_reply, relay_task, p, false)
            .expect("stack_reply empty");
        assert!(none_reply.is_none());
    }
}
