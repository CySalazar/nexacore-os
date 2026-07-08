//! IRQ-to-IPC routing table.
//!
//! Maintains a fixed-size `[Option<IrqBinding>; MAX_IRQ_VECTORS]` that maps
//! hardware interrupt vectors to kernel IPC channels. When a hardware IRQ
//! fires, the ISR trampoline calls [`crate::irq_table::irq_notify`] which looks
//! up the binding and enqueues an 8-byte notification payload (the vector
//! number as `u64` LE) on the bound IPC channel.
//!
//! ## Design notes
//!
//! - **No `alloc`** — the entire table is a fixed-size array. This keeps the
//!   module usable in `no_std` contexts without a heap (e.g., early-boot or
//!   bare-metal test builds).
//! - **Phase 1 single-CPU**: access to the global `IRQ_TABLE` follows the
//!   same single-core, no-preemption invariant that governs `FRAME_ALLOC` and
//!   `SCHEDULER`. `// MP-SAFETY:` comments mark every access site that will
//!   need a spinlock when SMP lands (P6.4+).
//! - **Vectors 0–31** are x86_64 CPU exceptions; they cannot be bound by
//!   drivers. Only vectors `IRQ_VECTOR_DEVICE_BASE` (32) through
//!   `MAX_IRQ_VECTORS - 1` (255) are valid for [`crate::irq_table::IrqTable::bind`].

/// Total number of interrupt vectors on `x86_64`.
pub const MAX_IRQ_VECTORS: usize = 256;

/// First vector available for device IRQs. Vectors 0–31 are CPU exceptions
/// (e.g., #DE=0, #DB=1, …, #PF=14) and must never be bound by drivers.
pub const IRQ_VECTOR_DEVICE_BASE: u8 = 32;

// -----------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------

/// Errors returned by [`IrqTable`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqBindError {
    /// A binding already exists for the requested vector.
    AlreadyBound,
    /// The vector is out of the valid device range (`< IRQ_VECTOR_DEVICE_BASE`
    /// or `>= MAX_IRQ_VECTORS`).
    InvalidVector,
    /// No binding exists for the requested vector.
    NotBound,
    /// The caller does not own the binding (wrong `owner_task_id`).
    NotOwner,
    /// The table is full — no free slot exists.
    ///
    /// In the current fixed-array design this variant is unreachable in
    /// practice (one slot per vector), but it is included for API
    /// completeness and forward compatibility.
    TableFull,
}

// -----------------------------------------------------------------------
// IrqBinding
// -----------------------------------------------------------------------

/// A single IRQ-to-IPC routing entry.
///
/// Stored inside [`IrqTable`] at index `irq_vector`. The entry is
/// considered live as long as the containing `Option<IrqBinding>` is `Some`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqBinding {
    /// The hardware interrupt vector this binding covers.
    pub irq_vector: u8,
    /// Kernel-allocated IPC channel id that receives notifications.
    pub channel_id: u64,
    /// Task id of the driver process that called `IrqAttach`.
    pub owner_task_id: u64,
    /// When `true` the vector is masked: [`irq_notify`] silently drops
    /// fires without enqueuing a message. `false` by default after
    /// [`IrqTable::bind`].
    pub masked: bool,
}

// -----------------------------------------------------------------------
// IrqTable
// -----------------------------------------------------------------------

/// Fixed-size IRQ-to-IPC routing table.
///
/// One slot per vector; the index is the vector number. Slots 0–31 are
/// permanently reserved for CPU exceptions and will always be `None`.
///
/// # Example
///
/// ```
/// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqBindError, IrqTable};
///
/// let mut table = IrqTable::new();
/// assert!(table.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
///
/// table.bind(IRQ_VECTOR_DEVICE_BASE, 42, 1).unwrap();
/// let binding = table.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap();
/// assert_eq!(binding.channel_id, 42);
///
/// table.unbind(IRQ_VECTOR_DEVICE_BASE, 1).unwrap();
/// assert!(table.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
/// ```
pub struct IrqTable {
    /// One slot per vector. Index `i` corresponds to vector `i`.
    /// Vectors 0–31 are permanently `None`.
    ///
    /// `Option<IrqBinding>` is `Copy` (all fields are `Copy`), so the
    /// array can be zero-initialised with `[None; MAX_IRQ_VECTORS]`.
    bindings: [Option<IrqBinding>; MAX_IRQ_VECTORS],
}

impl IrqTable {
    /// Construct an empty table with all slots free.
    ///
    /// `const fn` so the global `IRQ_TABLE` can be initialised in a
    /// `static` without a lazy initialiser.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: [None; MAX_IRQ_VECTORS],
        }
    }

    /// Validate that `vector` is in the device-usable range.
    ///
    /// Returns `Err(InvalidVector)` for vectors below
    /// [`IRQ_VECTOR_DEVICE_BASE`] (CPU exceptions) or at or above
    /// [`MAX_IRQ_VECTORS`] (impossible on `x86_64`, but guarded for
    /// defensive programming).
    fn validate_vector(vector: u8) -> Result<usize, IrqBindError> {
        if vector < IRQ_VECTOR_DEVICE_BASE {
            return Err(IrqBindError::InvalidVector);
        }
        // vector is u8 so vector as usize < 256 == MAX_IRQ_VECTORS always.
        Ok(vector as usize)
    }

    /// Bind `irq_vector` to an IPC channel.
    ///
    /// Registers a mapping from `irq_vector` to `channel_id`, marking
    /// `owner_task_id` as the driver that owns the binding. The vector
    /// is unmasked (live) immediately after binding.
    ///
    /// # Errors
    ///
    /// - [`IrqBindError::InvalidVector`] — `irq_vector < IRQ_VECTOR_DEVICE_BASE`.
    /// - [`IrqBindError::AlreadyBound`] — a binding already exists for this vector.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqTable};
    ///
    /// let mut t = IrqTable::new();
    /// t.bind(IRQ_VECTOR_DEVICE_BASE, 7, 1).unwrap();
    /// assert_eq!(t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().channel_id, 7);
    /// ```
    pub fn bind(
        &mut self,
        irq_vector: u8,
        channel_id: u64,
        owner_task_id: u64,
    ) -> Result<(), IrqBindError> {
        let idx = Self::validate_vector(irq_vector)?;
        // Safety: idx < MAX_IRQ_VECTORS by validate_vector contract.
        #[allow(
            clippy::indexing_slicing,
            reason = "idx validated to < MAX_IRQ_VECTORS above"
        )]
        if self.bindings[idx].is_some() {
            return Err(IrqBindError::AlreadyBound);
        }
        #[allow(
            clippy::indexing_slicing,
            reason = "idx validated to < MAX_IRQ_VECTORS above"
        )]
        {
            self.bindings[idx] = Some(IrqBinding {
                irq_vector,
                channel_id,
                owner_task_id,
                masked: false,
            });
        }
        Ok(())
    }

    /// Remove the binding for `irq_vector`, verifying ownership.
    ///
    /// Only the task that created the binding (`owner_task_id`) may
    /// remove it.
    ///
    /// # Errors
    ///
    /// - [`IrqBindError::InvalidVector`] — vector out of device range.
    /// - [`IrqBindError::NotBound`] — no binding exists for this vector.
    /// - [`IrqBindError::NotOwner`] — the supplied `owner_task_id` does
    ///   not match the binding's owner.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqBindError, IrqTable};
    ///
    /// let mut t = IrqTable::new();
    /// t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 99).unwrap();
    ///
    /// // Wrong owner
    /// assert_eq!(
    ///     t.unbind(IRQ_VECTOR_DEVICE_BASE, 0),
    ///     Err(IrqBindError::NotOwner)
    /// );
    ///
    /// // Correct owner
    /// t.unbind(IRQ_VECTOR_DEVICE_BASE, 99).unwrap();
    /// assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
    /// ```
    pub fn unbind(&mut self, irq_vector: u8, owner_task_id: u64) -> Result<(), IrqBindError> {
        let idx = Self::validate_vector(irq_vector)?;
        #[allow(
            clippy::indexing_slicing,
            reason = "idx validated to < MAX_IRQ_VECTORS above"
        )]
        match &self.bindings[idx] {
            None => Err(IrqBindError::NotBound),
            Some(b) if b.owner_task_id != owner_task_id => Err(IrqBindError::NotOwner),
            Some(_) => {
                #[allow(
                    clippy::indexing_slicing,
                    reason = "idx validated to < MAX_IRQ_VECTORS above"
                )]
                {
                    self.bindings[idx] = None;
                }
                Ok(())
            }
        }
    }

    /// Look up the binding for `irq_vector`.
    ///
    /// Returns `None` for vectors that are unbound, out-of-range, or
    /// reserved (0–31). Never fails.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqTable};
    ///
    /// let mut t = IrqTable::new();
    /// assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
    /// t.bind(IRQ_VECTOR_DEVICE_BASE, 5, 1).unwrap();
    /// assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).is_some());
    /// ```
    #[must_use]
    pub fn lookup(&self, irq_vector: u8) -> Option<&IrqBinding> {
        let idx = Self::validate_vector(irq_vector).ok()?;
        #[allow(
            clippy::indexing_slicing,
            reason = "idx validated to < MAX_IRQ_VECTORS above"
        )]
        self.bindings[idx].as_ref()
    }

    /// Mask the vector: subsequent [`irq_notify`] calls for this vector
    /// will be silently dropped.
    ///
    /// No-op if the vector is unbound or already masked.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqTable};
    ///
    /// let mut t = IrqTable::new();
    /// t.bind(IRQ_VECTOR_DEVICE_BASE, 3, 1).unwrap();
    /// t.mask(IRQ_VECTOR_DEVICE_BASE);
    /// assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    /// ```
    pub fn mask(&mut self, irq_vector: u8) {
        if let Ok(idx) = Self::validate_vector(irq_vector) {
            #[allow(
                clippy::indexing_slicing,
                reason = "idx validated to < MAX_IRQ_VECTORS above"
            )]
            if let Some(ref mut b) = self.bindings[idx] {
                b.masked = true;
            }
        }
    }

    /// Unmask the vector: subsequent [`irq_notify`] calls will enqueue
    /// notifications again.
    ///
    /// No-op if the vector is unbound or already unmasked.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_kernel::irq_table::{IRQ_VECTOR_DEVICE_BASE, IrqTable};
    ///
    /// let mut t = IrqTable::new();
    /// t.bind(IRQ_VECTOR_DEVICE_BASE, 3, 1).unwrap();
    /// t.mask(IRQ_VECTOR_DEVICE_BASE);
    /// t.unmask(IRQ_VECTOR_DEVICE_BASE);
    /// assert!(!t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    /// ```
    pub fn unmask(&mut self, irq_vector: u8) {
        if let Ok(idx) = Self::validate_vector(irq_vector) {
            #[allow(
                clippy::indexing_slicing,
                reason = "idx validated to < MAX_IRQ_VECTORS above"
            )]
            if let Some(ref mut b) = self.bindings[idx] {
                b.masked = false;
            }
        }
    }
}

impl Default for IrqTable {
    /// Returns an empty [`IrqTable`]. Delegates to [`IrqTable::new`].
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------
// Kernel-global IrqTable + irq_notify (bare-metal only)
// -----------------------------------------------------------------------
//
// The global follows the same static-mut + addr_of_mut! pattern used for
// FRAME_ALLOC, SCHEDULER, IPC_REGISTRY etc. throughout the kernel.
//
// MP-SAFETY NOTE: Every access to IRQ_TABLE_GLOBAL uses a raw pointer
// dereference via `addr_of_mut!`. This is safe for single-CPU Phase 1
// builds (P6) because the BSP never enables preemption and only one
// logical CPU is running at any moment. When SMP lands (P6.4+) every
// call site that mutates the table must hold the kernel IRQ spinlock
// (`spin::Mutex<IrqTable>` or equivalent) before calling `addr_of_mut!`.

/// The kernel-global IRQ routing table.
///
/// Initialised to empty (`IrqTable::new()`) at link time; populated by
/// `irq_table::global_bind` / `irq_table::global_unbind` calls from the
/// `IrqAttach (72)` syscall handler.
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
static mut IRQ_TABLE_GLOBAL: IrqTable = IrqTable::new();

/// Register a binding in the kernel-global `IrqTable`.
///
/// Thin wrapper around [`IrqTable::bind`] that targets the global
/// singleton. Called from the `IrqAttach (72)` syscall handler after
/// the capability token is verified.
///
/// # Safety
///
/// Caller must be executing in a single-CPU, no-preemption context
/// (Phase 1 syscall path). MP-SAFETY: must acquire the IRQ spinlock
/// before calling when SMP is active (P6.4+).
///
/// # Errors
///
/// Propagates [`IrqBindError`] from the underlying [`IrqTable::bind`].
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
#[allow(
    unsafe_code,
    reason = "accesses kernel-global IRQ table; SAFETY at call site"
)]
pub unsafe fn global_bind(
    irq_vector: u8,
    channel_id: u64,
    owner_task_id: u64,
) -> Result<(), IrqBindError> {
    // SAFETY: single-CPU Phase 1; IRQ_TABLE_GLOBAL not aliased.
    // MP-SAFETY: upgrade to spinlock when SMP lands (P6.4+).
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(IRQ_TABLE_GLOBAL);
        table.bind(irq_vector, channel_id, owner_task_id)
    }
}

/// Remove a binding from the kernel-global `IrqTable`.
///
/// Thin wrapper around [`IrqTable::unbind`] that targets the global
/// singleton. Called from `tear_down_irq_attachments` on process exit.
///
/// # Safety
///
/// Same single-CPU, no-preemption invariant as [`global_bind`].
///
/// # Errors
///
/// Propagates [`IrqBindError`] from the underlying [`IrqTable::unbind`].
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
#[allow(
    unsafe_code,
    reason = "accesses kernel-global IRQ table; SAFETY at call site"
)]
pub unsafe fn global_unbind(irq_vector: u8, owner_task_id: u64) -> Result<(), IrqBindError> {
    // SAFETY: single-CPU Phase 1; IRQ_TABLE_GLOBAL not aliased.
    // MP-SAFETY: upgrade to spinlock when SMP lands (P6.4+).
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(IRQ_TABLE_GLOBAL);
        table.unbind(irq_vector, owner_task_id)
    }
}

/// Deliver an IRQ notification to the IPC channel bound to `vector`.
///
/// This function is called from the ISR trampoline path (via
/// `dispatch_fire` in `syscall_entry`). It:
///
/// 1. Looks up the [`IrqBinding`] for `vector` in the global table.
/// 2. If unbound or masked, silently drops (spurious IRQ).
/// 3. Otherwise, enqueues an 8-byte `u64`-LE payload (the vector number)
///    as a [`crate::ipc::MessageKind::Notification`] on the bound channel.
/// 4. If the channel queue is full (`EvictOldest` / `Drop` path), the
///    fire is counted as missed — the driver can detect coalesced events
///    via the separate `missed` atomic in the legacy `IrqSlot` table.
///
/// **Interrupt-context safety**: this function must not block. Any
/// backpressure that would park the calling task is structurally
/// impossible here because there is no calling *task* — the ISR
/// trampoline runs on whatever stack was interrupted. The IPC `send`
/// under `Block` policy would attempt to enqueue the caller task id
/// into `waiters_send`; we pass `TaskId(0)` (the kernel sentinel) so
/// a `Block`-policy full queue stores a sentinel and the next
/// `receive` wakes the sentinel rather than a real task — harmless but
/// visible. Future work: switch interrupt-bound channels to `Drop`
/// policy so this path is never reached.
///
/// # Safety
///
/// Must be called in a single-CPU, no-preemption context. The ISR
/// trampoline guarantees this for Phase 1. MP-SAFETY: requires the IRQ
/// spinlock when SMP is active (P6.4+).
#[cfg(all(feature = "bare-metal", target_os = "none", not(test)))]
#[allow(unsafe_code, reason = "ISR path; SAFETY comments at each site")]
pub unsafe fn irq_notify(vector: u8) {
    use crate::{
        capabilities::KernelPrincipal,
        ipc::{ChannelId, MessageEnvelope, MessageKind},
        scheduling::TaskId,
    };

    // SAFETY: single-CPU Phase 1; IRQ_TABLE_GLOBAL not aliased while
    // this function runs. MP-SAFETY: upgrade to spinlock (P6.4+).
    let binding = unsafe {
        let table = &*core::ptr::addr_of!(IRQ_TABLE_GLOBAL);
        table.lookup(vector).copied()
    };

    let Some(binding) = binding else {
        // Spurious IRQ — not bound.
        return;
    };

    if binding.masked {
        return;
    }

    // Build the 8-byte notification payload: vector as u64 LE.
    let payload_bytes = u64::from(vector).to_le_bytes();

    let envelope = MessageEnvelope {
        // Kernel is the sender (sentinel task id 0).
        sender: TaskId(0),
        channel: ChannelId(binding.channel_id),
        kind: MessageKind::Notification,
        payload: alloc::vec![
            payload_bytes[0],
            payload_bytes[1],
            payload_bytes[2],
            payload_bytes[3],
            payload_bytes[4],
            payload_bytes[5],
            payload_bytes[6],
            payload_bytes[7],
        ],
    };

    // SAFETY: IPC_REGISTRY not aliased; single-CPU ISR context.
    // MP-SAFETY: upgrade to spinlock (P6.4+).
    unsafe {
        // Ignore errors: if the channel was destroyed between the bind
        // and this fire, or the queue is full under Drop policy, the
        // fire is silently absorbed. The driver's missed-count
        // (maintained by irq_attach_handlers::note_fire in the
        // existing slot table) already tracks this.
        let _ = crate::ipc::ipc_registry_mut().send(envelope, TaskId(0), KernelPrincipal::ZERO);
    }
}

// -----------------------------------------------------------------------
// Stub for non-bare-metal / test builds
// -----------------------------------------------------------------------

/// No-op stub for host-test / non-bare-metal builds.
///
/// The real implementation is gated behind `bare-metal + target_os = none`.
/// This stub keeps call sites in `syscall_entry` compilable without
/// feature-gating every invocation.
#[cfg(not(all(feature = "bare-metal", target_os = "none", not(test))))]
pub fn irq_notify(_vector: u8) {}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Basic bind / unbind / lookup
    // ------------------------------------------------------------------

    #[test]
    fn new_table_is_empty() {
        let t = IrqTable::new();
        for v in 0u8..=255 {
            assert!(t.lookup(v).is_none(), "vector {v} should be unbound");
        }
    }

    #[test]
    fn bind_and_lookup_first_valid_vector() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 42, 1).unwrap();
        let b = t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap();
        assert_eq!(b.irq_vector, IRQ_VECTOR_DEVICE_BASE);
        assert_eq!(b.channel_id, 42);
        assert_eq!(b.owner_task_id, 1);
        assert!(!b.masked);
    }

    #[test]
    fn bind_and_lookup_last_valid_vector() {
        let mut t = IrqTable::new();
        t.bind(255, 99, 7).unwrap();
        let b = t.lookup(255).unwrap();
        assert_eq!(b.irq_vector, 255);
        assert_eq!(b.channel_id, 99);
        assert_eq!(b.owner_task_id, 7);
    }

    #[test]
    fn unbind_succeeds_with_correct_owner() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 10).unwrap();
        t.unbind(IRQ_VECTOR_DEVICE_BASE, 10).unwrap();
        assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
    }

    #[test]
    fn lookup_returns_none_after_unbind() {
        let mut t = IrqTable::new();
        t.bind(100, 5, 2).unwrap();
        t.unbind(100, 2).unwrap();
        assert!(t.lookup(100).is_none());
    }

    // ------------------------------------------------------------------
    // Bind validation: invalid vectors
    // ------------------------------------------------------------------

    #[test]
    fn bind_rejects_vector_zero() {
        let mut t = IrqTable::new();
        assert_eq!(t.bind(0, 1, 1), Err(IrqBindError::InvalidVector));
    }

    #[test]
    fn bind_rejects_vector_31() {
        let mut t = IrqTable::new();
        assert_eq!(t.bind(31, 1, 1), Err(IrqBindError::InvalidVector));
    }

    #[test]
    fn bind_accepts_vector_32() {
        let mut t = IrqTable::new();
        // IRQ_VECTOR_DEVICE_BASE == 32; this must succeed.
        assert!(t.bind(32, 1, 1).is_ok());
    }

    #[test]
    fn bind_accepts_vector_255() {
        let mut t = IrqTable::new();
        assert!(t.bind(255, 1, 1).is_ok());
    }

    // ------------------------------------------------------------------
    // Bind validation: double-bind
    // ------------------------------------------------------------------

    #[test]
    fn bind_rejects_double_bind_same_vector() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 1).unwrap();
        assert_eq!(
            t.bind(IRQ_VECTOR_DEVICE_BASE, 2, 2),
            Err(IrqBindError::AlreadyBound)
        );
    }

    #[test]
    fn rebind_after_unbind_succeeds() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 1).unwrap();
        t.unbind(IRQ_VECTOR_DEVICE_BASE, 1).unwrap();
        // Should now be free and accept a new bind.
        assert!(t.bind(IRQ_VECTOR_DEVICE_BASE, 2, 2).is_ok());
    }

    // ------------------------------------------------------------------
    // Unbind validation
    // ------------------------------------------------------------------

    #[test]
    fn unbind_rejects_not_bound() {
        let mut t = IrqTable::new();
        assert_eq!(
            t.unbind(IRQ_VECTOR_DEVICE_BASE, 1),
            Err(IrqBindError::NotBound)
        );
    }

    #[test]
    fn unbind_rejects_wrong_owner() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 99).unwrap();
        assert_eq!(
            t.unbind(IRQ_VECTOR_DEVICE_BASE, 0),
            Err(IrqBindError::NotOwner)
        );
    }

    #[test]
    fn unbind_rejects_invalid_vector() {
        let mut t = IrqTable::new();
        assert_eq!(t.unbind(0, 1), Err(IrqBindError::InvalidVector));
    }

    // ------------------------------------------------------------------
    // Lookup edge cases
    // ------------------------------------------------------------------

    #[test]
    fn lookup_unbound_vector_returns_none() {
        let t = IrqTable::new();
        assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).is_none());
    }

    #[test]
    fn lookup_cpu_exception_vector_returns_none() {
        let t = IrqTable::new();
        // Vectors 0–31 are reserved; lookup returns None regardless.
        for v in 0..IRQ_VECTOR_DEVICE_BASE {
            assert!(
                t.lookup(v).is_none(),
                "cpu exception vector {v} should be None"
            );
        }
    }

    // ------------------------------------------------------------------
    // Mask / unmask
    // ------------------------------------------------------------------

    #[test]
    fn mask_sets_masked_flag() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 3, 1).unwrap();
        assert!(!t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
        t.mask(IRQ_VECTOR_DEVICE_BASE);
        assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    }

    #[test]
    fn unmask_clears_masked_flag() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 3, 1).unwrap();
        t.mask(IRQ_VECTOR_DEVICE_BASE);
        t.unmask(IRQ_VECTOR_DEVICE_BASE);
        assert!(!t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    }

    #[test]
    fn mask_noop_on_unbound_vector() {
        let mut t = IrqTable::new();
        // Must not panic.
        t.mask(IRQ_VECTOR_DEVICE_BASE);
        t.mask(0);
    }

    #[test]
    fn unmask_noop_on_unbound_vector() {
        let mut t = IrqTable::new();
        t.unmask(IRQ_VECTOR_DEVICE_BASE);
        t.unmask(0);
    }

    #[test]
    fn double_mask_idempotent() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 1).unwrap();
        t.mask(IRQ_VECTOR_DEVICE_BASE);
        t.mask(IRQ_VECTOR_DEVICE_BASE);
        assert!(t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    }

    #[test]
    fn double_unmask_idempotent() {
        let mut t = IrqTable::new();
        t.bind(IRQ_VECTOR_DEVICE_BASE, 1, 1).unwrap();
        t.unmask(IRQ_VECTOR_DEVICE_BASE);
        t.unmask(IRQ_VECTOR_DEVICE_BASE);
        assert!(!t.lookup(IRQ_VECTOR_DEVICE_BASE).unwrap().masked);
    }

    // ------------------------------------------------------------------
    // Multiple simultaneous bindings
    // ------------------------------------------------------------------

    #[test]
    fn multiple_vectors_independent() {
        let mut t = IrqTable::new();
        t.bind(32, 100, 1).unwrap();
        t.bind(33, 200, 2).unwrap();
        t.bind(255, 300, 3).unwrap();
        assert_eq!(t.lookup(32).unwrap().channel_id, 100);
        assert_eq!(t.lookup(33).unwrap().channel_id, 200);
        assert_eq!(t.lookup(255).unwrap().channel_id, 300);
    }

    #[test]
    fn unbind_one_does_not_affect_others() {
        let mut t = IrqTable::new();
        t.bind(32, 1, 1).unwrap();
        t.bind(33, 2, 1).unwrap();
        t.unbind(32, 1).unwrap();
        assert!(t.lookup(32).is_none());
        assert!(t.lookup(33).is_some());
    }

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    #[test]
    fn irq_vector_device_base_equals_32() {
        assert_eq!(IRQ_VECTOR_DEVICE_BASE, 32u8);
    }

    #[test]
    fn max_irq_vectors_equals_256() {
        assert_eq!(MAX_IRQ_VECTORS, 256);
    }
}
