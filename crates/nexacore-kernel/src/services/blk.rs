//! Kernel-side BLK service-channel registry.
//!
//! Maintains the canonical mapping `disk_slot → ChannelId` for every
//! storage driver that has registered an `nexacore.svc.blk.<disk_slot>`
//! IPC channel per [`NCIP-Driver-NVMe-014`](../../../../ncips/ncip-driver-nvme-014.md)
//! § S4 + § S6 step 12. The future filesystem service consults
//! [`BlkChannelRegistry::lookup_disk_slot`] /
//! [`BlkChannelRegistry::lookup_channel_name`] to obtain the live
//! [`ChannelId`] without sniffing the IPC registry by string.
//!
//! ## Why a name → id table
//!
//! The kernel [`crate::ipc`] layer is name-agnostic — channels are
//! addressed by [`ChannelId`] only. User space derives a channel name
//! at creation time (the NVMe driver picks `nexacore.svc.blk.nvme0`) and
//! stores it locally; the kernel never learns about that name. For the
//! BLK layer, however, a stable cross-process resolution path is
//! required: a filesystem service spawned independently of the NVMe
//! driver must locate the channel the driver registered, and the
//! lookup MUST be capability-gated by the channel-name prefix the
//! kernel publishes in [`nexacore_types::blk::CHANNEL_NAME_PREFIX`]. This
//! registry is the kernel-side bookkeeping that supports that
//! gate.
//!
//! ## What this module does NOT do
//!
//! - It does not create IPC channels — that is still
//!   [`crate::ipc::KernelIpcRegistry::create_channel_signed`]. The
//!   driver allocates the channel first, then records the mapping
//!   here through the (future) `BlkRegister` syscall.
//! - It does not emit any MMIO or touch the page tables — every
//!   operation is a pure-state mutation of a small `Vec`.
//! - It does not implement the BLK read/write protocol — that lives
//!   in user space on both sides of the wire. The registry only
//!   answers "what channel id is `nexacore.svc.blk.nvme0`?".
//!
//! ## Phase-1 scope
//!
//! The Phase-1 driver framework caps the number of NVMe controllers
//! and namespaces at the low single digits (one controller, one
//! namespace per NCIP-014 § S6). [`MAX_BLK_CHANNELS`] therefore stays
//! at 64, which is generous enough to host every plausible Phase-1
//! storage topology plus headroom for future SATA / virtio-blk
//! drivers without committing to an unbounded allocation.

#![cfg_attr(
    all(feature = "bare-metal", target_arch = "x86_64"),
    allow(
        unsafe_code,
        reason = "BLK_REGISTRY static mut singleton + addr_of_mut accessor; SAFETY documented at the fn boundary"
    )
)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_types::blk::CHANNEL_NAME_PREFIX;

use crate::{ipc::ChannelId, scheduling::TaskId};

/// Maximum number of BLK channels the registry may hold concurrently.
///
/// Bounded for two reasons:
///
/// 1. **Capacity.** The Phase-1 driver framework caps the number of
///    NVMe controllers and namespaces at the low single digits
///    (NCIP-014 § S6). 64 is generous for every plausible Phase-1
///    storage topology (NVMe + future SATA + future virtio-blk).
/// 2. **Denial-of-service defence.** Every entry pins a `String`
///    allocation. An unbounded registry would let a compromised
///    driver loop on [`BlkChannelRegistry::register`] until the
///    kernel allocator is exhausted; capping at 64 turns that into
///    a `Err(RegistryFull)` in O(1).
pub const MAX_BLK_CHANNELS: usize = 64;

/// Maximum byte length of a disk-slot string (e.g. `"nvme0"`,
/// `"sata12"`).
///
/// Bounds the per-entry channel-name allocation and the log lines
/// downstream consumers emit for triage. 32 ASCII bytes is generous
/// for every plausible naming scheme (single-digit NVMe + multi-digit
/// SATA fits in well under 8); the cap exists to keep the failure
/// surface of [`BlkChannelRegistry::register`] explicit.
pub const MAX_DISK_SLOT_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Reason a [`BlkChannelRegistry`] call could not complete.
///
/// All variants are observable through the (future) `BlkRegister` /
/// `BlkUnregister` syscall return path; the kernel-internal handler
/// maps each variant to the appropriate `NexaCoreError` at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlkRegistryError {
    /// The supplied `disk_slot` was empty. The kernel rejects empty
    /// slots so the resulting channel name (`"nexacore.svc.blk."`) does
    /// not collide with the canonical prefix itself.
    DiskSlotEmpty,
    /// The supplied `disk_slot` exceeded [`MAX_DISK_SLOT_LEN`]
    /// bytes.
    DiskSlotTooLong,
    /// The supplied `disk_slot` contained a byte outside the allowed
    /// ASCII alphabet `[A-Za-z0-9_-]`. Restricting the slot alphabet
    /// keeps the resulting channel name safe to log and parse and
    /// closes a path where a compromised driver could embed control
    /// bytes (newline, CR, escape sequence) in the kernel boot log.
    DiskSlotInvalidChar,
    /// A registration already exists for the requested `disk_slot`.
    /// Per NCIP-014 § S4 the disk-slot half of a BLK channel name is
    /// expected to be unique — a duplicate registration is a
    /// programming error in user space.
    DiskSlotAlreadyRegistered,
    /// The registry has hit [`MAX_BLK_CHANNELS`] entries and cannot
    /// accept the new registration.
    RegistryFull,
    /// [`BlkChannelRegistry::unregister`] was called for a `disk_slot`
    /// the registry does not know.
    DiskSlotNotRegistered,
    /// The caller is not the [`TaskId`] recorded as the owner of the
    /// requested registration. Enforces the "only the producing
    /// driver may unregister its own channel" invariant; clean-up
    /// on task death goes through
    /// [`BlkChannelRegistry::clear_for_owner`].
    OwnerMismatch,
    /// Defensive sentinel for invariants the registry expects to
    /// hold but cannot statically prove (e.g. a `Vec` that should be
    /// non-empty immediately after `push`). Maps to
    /// [`crate::KernelError::Internal`] at the syscall boundary.
    /// Unreachable in well-formed code; exists so the registry
    /// never aborts the kernel.
    Internal,
}

// ---------------------------------------------------------------------------
// Registry entry
// ---------------------------------------------------------------------------

/// One BLK channel registration record.
///
/// Lifetime: created by [`BlkChannelRegistry::register`] when the
/// driver completes NCIP-014 § S6 step 12 (`IpcCreateChannel(name =
/// "nexacore.svc.blk.<diskN>", ...)`); destroyed by
/// [`BlkChannelRegistry::unregister`] on graceful driver shutdown or
/// by [`BlkChannelRegistry::clear_for_owner`] on driver task exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlkChannelEntry {
    /// The producer's disk slot, e.g. `"nvme0"`. Always ASCII; bounded
    /// by [`MAX_DISK_SLOT_LEN`]; restricted to `[A-Za-z0-9_-]`.
    pub disk_slot: String,
    /// The full channel name, i.e.
    /// [`nexacore_types::blk::CHANNEL_NAME_PREFIX`] concatenated with
    /// [`Self::disk_slot`]. Pre-built at registration time so consumer
    /// call sites do not re-allocate on every lookup.
    pub channel_name: String,
    /// The live IPC channel id the driver received from
    /// [`crate::ipc::KernelIpcRegistry::create_channel_signed`].
    pub channel_id: ChannelId,
    /// The driver task that owns the channel. Used by
    /// [`BlkChannelRegistry::unregister`] to enforce owner-only
    /// teardown and by [`BlkChannelRegistry::clear_for_owner`] to
    /// drain stale registrations on task exit.
    pub owner: TaskId,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Kernel-internal BLK channel registry. Pure-state bookkeeping; the
/// Phase-1 boot wires a single instance into the kernel-global state
/// (future work).
///
/// Storage is a [`Vec<BlkChannelEntry>`] rather than a `BTreeMap`
/// because (a) the Phase-1 cap is 64 entries, (b) every operation is
/// O(N) at most, (c) the order of [`Self::entries`] is observable
/// (insertion order until [`Self::unregister`]) which is friendlier
/// to debug-print output than the random ordering of `BTreeMap`.
#[derive(Debug, Default)]
pub struct BlkChannelRegistry {
    entries: Vec<BlkChannelEntry>,
}

impl BlkChannelRegistry {
    /// Construct an empty registry. `const fn` so a future global
    /// `static mut` slot can hold one without a lazy initialiser
    /// (mirrors the [`crate::ipc::KernelIpcRegistry::new`] pattern).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of live registrations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry holds any registration.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow the registry's entries in insertion order (until the
    /// first [`Self::unregister`] call, which reorders via
    /// `swap_remove` to keep the average remove path O(1)).
    #[must_use]
    pub fn entries(&self) -> &[BlkChannelEntry] {
        &self.entries
    }

    /// Record a new BLK channel for `disk_slot`.
    ///
    /// Returns the canonical channel name (e.g. `"nexacore.svc.blk.nvme0"`)
    /// the registry built for the new entry so the caller can echo it
    /// in the boot log without re-allocating. To inspect the rest of
    /// the new entry's fields, call [`Self::lookup_disk_slot`].
    ///
    /// # Errors
    ///
    /// - [`BlkRegistryError::DiskSlotEmpty`] if `disk_slot` is empty.
    /// - [`BlkRegistryError::DiskSlotTooLong`] if `disk_slot` exceeds
    ///   [`MAX_DISK_SLOT_LEN`] bytes.
    /// - [`BlkRegistryError::DiskSlotInvalidChar`] if `disk_slot`
    ///   contains a byte outside `[A-Za-z0-9_-]`.
    /// - [`BlkRegistryError::DiskSlotAlreadyRegistered`] if a
    ///   registration for `disk_slot` already exists.
    /// - [`BlkRegistryError::RegistryFull`] if the registry already
    ///   holds [`MAX_BLK_CHANNELS`] entries.
    pub fn register(
        &mut self,
        disk_slot: &str,
        channel_id: ChannelId,
        owner: TaskId,
    ) -> Result<&str, BlkRegistryError> {
        Self::validate_disk_slot(disk_slot)?;
        if self.entries.iter().any(|e| e.disk_slot == disk_slot) {
            return Err(BlkRegistryError::DiskSlotAlreadyRegistered);
        }
        if self.entries.len() >= MAX_BLK_CHANNELS {
            return Err(BlkRegistryError::RegistryFull);
        }
        let channel_name = Self::build_channel_name(disk_slot);
        self.entries.push(BlkChannelEntry {
            disk_slot: disk_slot.to_string(),
            channel_name,
            channel_id,
            owner,
        });
        // `Vec::push` cannot make the slice empty after a successful
        // push, so `last()` is `Some` here. `map_or` matches the
        // workspace `clippy::option_if_let_else` style; the `None`
        // arm is unreachable in well-formed code and surfaces
        // [`BlkRegistryError::Internal`] rather than panicking so the
        // registry never aborts the kernel on a clippy edge-case.
        self.entries
            .last()
            .map_or(Err(BlkRegistryError::Internal), |entry| {
                Ok(&entry.channel_name)
            })
    }

    /// Drop the registration for `disk_slot`. Only `owner` may call.
    ///
    /// Returns the removed entry on success so the caller can log
    /// the channel id it must subsequently destroy through
    /// [`crate::ipc::KernelIpcRegistry::destroy_channel`].
    ///
    /// # Errors
    ///
    /// - [`BlkRegistryError::DiskSlotNotRegistered`] if no entry
    ///   matches `disk_slot`.
    /// - [`BlkRegistryError::OwnerMismatch`] if the entry's recorded
    ///   owner differs from `owner`. The graceful owner-driven path
    ///   is the only legal `unregister` route; task-exit clean-up
    ///   goes through [`Self::clear_for_owner`].
    pub fn unregister(
        &mut self,
        disk_slot: &str,
        owner: TaskId,
    ) -> Result<BlkChannelEntry, BlkRegistryError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.disk_slot == disk_slot)
            .ok_or(BlkRegistryError::DiskSlotNotRegistered)?;
        // `position` returned `idx`, so `get(idx)` is `Some`. Use
        // `get` rather than `[idx]` because the workspace lint
        // `clippy::indexing_slicing` forbids slice indexing.
        let recorded_owner = match self.entries.get(idx) {
            Some(entry) => entry.owner,
            None => return Err(BlkRegistryError::Internal),
        };
        if recorded_owner != owner {
            return Err(BlkRegistryError::OwnerMismatch);
        }
        Ok(self.entries.swap_remove(idx))
    }

    /// Resolve a registration by raw disk slot (e.g. `"nvme0"`).
    #[must_use]
    pub fn lookup_disk_slot(&self, disk_slot: &str) -> Option<&BlkChannelEntry> {
        self.entries.iter().find(|e| e.disk_slot == disk_slot)
    }

    /// Resolve a registration by full channel name (e.g.
    /// `"nexacore.svc.blk.nvme0"`).
    ///
    /// Used by the (future) capability-gating syscall handler that
    /// receives the full channel name from user space and must
    /// constant-time defend against arbitrary inputs.
    #[must_use]
    pub fn lookup_channel_name(&self, channel_name: &str) -> Option<&BlkChannelEntry> {
        self.entries.iter().find(|e| e.channel_name == channel_name)
    }

    /// Resolve a registration by its allocated [`ChannelId`].
    ///
    /// Used by IRQ / driver-exit clean-up paths that have a
    /// `ChannelId` in hand and need to learn which disk slot it
    /// served.
    #[must_use]
    pub fn lookup_channel_id(&self, channel_id: ChannelId) -> Option<&BlkChannelEntry> {
        self.entries.iter().find(|e| e.channel_id == channel_id)
    }

    /// Drop every registration owned by `owner`. Returns the number
    /// of entries removed.
    ///
    /// Called from the kernel task-exit path (future
    /// `task_exit_handlers::tear_down_blk_channels`) so a
    /// crashed/killed driver does not leak stale registry entries.
    /// The caller is responsible for tearing down the underlying
    /// IPC channels through
    /// [`crate::ipc::KernelIpcRegistry::destroy_channel`] before /
    /// after this call; the registry only owns its bookkeeping.
    pub fn clear_for_owner(&mut self, owner: TaskId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.owner != owner);
        before - self.entries.len()
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    /// Reject empty, oversized, or non-portable disk slots.
    fn validate_disk_slot(slot: &str) -> Result<(), BlkRegistryError> {
        if slot.is_empty() {
            return Err(BlkRegistryError::DiskSlotEmpty);
        }
        if slot.len() > MAX_DISK_SLOT_LEN {
            return Err(BlkRegistryError::DiskSlotTooLong);
        }
        for &b in slot.as_bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {}
                _ => return Err(BlkRegistryError::DiskSlotInvalidChar),
            }
        }
        Ok(())
    }

    /// Compose the canonical channel name from a validated disk slot.
    fn build_channel_name(slot: &str) -> String {
        let mut s = String::with_capacity(CHANNEL_NAME_PREFIX.len() + slot.len());
        s.push_str(CHANNEL_NAME_PREFIX);
        s.push_str(slot);
        s
    }
}

// ===========================================================================
// errno mapping
// ===========================================================================

/// Map a [`BlkRegistryError`] to a POSIX-aligned errno.
///
/// The errno is consumed by the rich two-register syscall return
/// path ([`crate::syscall::SyscallReturn`]). The mapping matches
/// the vocabulary `NCIP-Driver-Framework-013` § S2.3 publishes for
/// the driver-framework syscalls so user-space tooling can reuse
/// the same triage table across `MmioMap`, `DmaMap`, `IrqAttach`,
/// and the new `BlkRegister` / `BlkUnregister` / `BlkLookup`
/// syscalls.
#[must_use]
pub const fn errno_for(err: BlkRegistryError) -> u64 {
    use crate::syscall::syscall_errno;
    match err {
        // Argument-shape violations → `EINVAL`.
        BlkRegistryError::DiskSlotEmpty
        | BlkRegistryError::DiskSlotTooLong
        | BlkRegistryError::DiskSlotInvalidChar => syscall_errno::EINVAL,
        // Disk slot already in use → `EEXIST`. Distinguishing this
        // from `EINVAL` lets user space tell "the kernel rejected
        // my disk-slot string" (programmer bug) from "another
        // driver got there first" (operational race).
        BlkRegistryError::DiskSlotAlreadyRegistered => syscall_errno::EEXIST,
        // Capacity ceiling → `ENOSPC`.
        BlkRegistryError::RegistryFull => syscall_errno::ENOSPC,
        // Lookup-failed (`unregister` path) → `ENOENT`. The
        // dedicated `BlkLookup` syscall surfaces the same code for
        // the read-only path.
        BlkRegistryError::DiskSlotNotRegistered => syscall_errno::ENOENT,
        // Caller is not the recorded owner → `EACCES`.
        BlkRegistryError::OwnerMismatch => syscall_errno::EACCES,
        // Defensive invariant — should never surface in well-formed
        // code; reported as `EIO` so the kernel does not abort and
        // user space sees a non-`EINVAL` error code that triage
        // tooling can grep for.
        BlkRegistryError::Internal => syscall_errno::EIO,
    }
}

// ===========================================================================
// Kernel-global singleton
// ===========================================================================

/// Process-global BLK channel registry, mirroring
/// [`crate::ipc::IPC_REGISTRY`].
///
/// Phase 1 is single-CPU and the SYSCALL entry path masks interrupts
/// via `IA32_FMASK`, so a `static mut` rather than a `Mutex<...>` is
/// sufficient. The MP transition (ADR-0005) will swap this for a
/// shared lock guard analogous to the planned IPC rework. The
/// `static mut` lives behind `bare-metal` + `target_arch = "x86_64"`
/// because (a) only the bare-metal build owns the SYSCALL path that
/// provides the no-aliasing invariant and (b) host tests exercise
/// [`BlkChannelRegistry`] directly without the singleton.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
static mut BLK_REGISTRY: BlkChannelRegistry = BlkChannelRegistry::new();

/// Borrow the global BLK registry mutably.
///
/// # Safety
///
/// Caller must be in a context where no other reference to
/// `BLK_REGISTRY` is live. The SYSCALL path provides this
/// invariant in single-CPU Phase 1 (interrupts masked, no
/// recursion).
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    clippy::mut_from_ref,
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn blk_registry_mut() -> &'static mut BlkChannelRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of_mut!(BLK_REGISTRY);
        &mut *p
    }
}

/// Borrow the global BLK registry immutably.
///
/// # Safety
///
/// Caller must be in a context where no `&mut` to `BLK_REGISTRY`
/// is concurrently live. Phase 1 single-CPU + interrupt-masked
/// SYSCALL provides this; MP introduction swaps the accessor for a
/// lock guard per ADR-0005.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn blk_registry() -> &'static BlkChannelRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of!(BLK_REGISTRY);
        &*p
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: u64) -> TaskId {
        TaskId(id)
    }

    fn channel(id: u64) -> ChannelId {
        ChannelId(id)
    }

    // -----------------------------------------------------------------
    // Construction & basic invariants
    // -----------------------------------------------------------------

    #[test]
    fn new_registry_is_empty() {
        let r = BlkChannelRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(r.entries().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let a = BlkChannelRegistry::new();
        let b = BlkChannelRegistry::default();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.is_empty(), b.is_empty());
    }

    #[test]
    fn max_disk_slot_len_constant_is_32() {
        // Tripwire: changing the cap silently widens the kernel boot
        // log lines and the registry's per-entry allocation.
        assert_eq!(MAX_DISK_SLOT_LEN, 32);
    }

    #[test]
    fn max_blk_channels_constant_is_64() {
        // Tripwire: changing the cap changes the registry's
        // worst-case memory footprint; documented in module docs.
        assert_eq!(MAX_BLK_CHANNELS, 64);
    }

    #[test]
    fn channel_name_prefix_constant_matches_nexacore_types() {
        // The kernel registry MUST consume the canonical prefix from
        // `nexacore-types` so a future rename does not desynchronise the
        // two crates. Asserts the import path resolves to the value
        // NCIP-014 § S4 freezes.
        assert_eq!(CHANNEL_NAME_PREFIX, "nexacore.svc.blk.");
    }

    // -----------------------------------------------------------------
    // register — happy path + validation
    // -----------------------------------------------------------------

    #[test]
    fn register_inserts_entry_with_canonical_channel_name() {
        let mut r = BlkChannelRegistry::new();
        let name = r
            .register("nvme0", channel(7), task(42))
            .expect("registration must succeed");
        assert_eq!(name, "nexacore.svc.blk.nvme0");
        let entry = r.lookup_disk_slot("nvme0").expect("entry present");
        assert_eq!(entry.disk_slot, "nvme0");
        assert_eq!(entry.channel_name, "nexacore.svc.blk.nvme0");
        assert_eq!(entry.channel_id, channel(7));
        assert_eq!(entry.owner, task(42));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn register_return_value_is_canonical_channel_name() {
        let mut r = BlkChannelRegistry::new();
        let a = r
            .register("nvme0", channel(1), task(1))
            .expect("first register");
        assert_eq!(a, "nexacore.svc.blk.nvme0");
        let b = r
            .register("sata-12", channel(2), task(1))
            .expect("second register");
        assert_eq!(b, "nexacore.svc.blk.sata-12");
    }

    #[test]
    fn register_accepts_alphanumeric_underscore_and_hyphen() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(1)).expect("nvme0");
        r.register("sata-12", channel(2), task(1)).expect("sata-12");
        r.register("virtio_blk_3", channel(3), task(1))
            .expect("virtio_blk_3");
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn register_rejects_empty_disk_slot() {
        let mut r = BlkChannelRegistry::new();
        let err = r
            .register("", channel(1), task(1))
            .expect_err("empty slot must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotEmpty);
        assert!(r.is_empty());
    }

    #[test]
    fn register_rejects_disk_slot_too_long() {
        let mut r = BlkChannelRegistry::new();
        let oversized = "a".repeat(MAX_DISK_SLOT_LEN + 1);
        let err = r
            .register(&oversized, channel(1), task(1))
            .expect_err("oversized slot must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotTooLong);
        assert!(r.is_empty());
    }

    #[test]
    fn register_accepts_disk_slot_at_max_length() {
        let mut r = BlkChannelRegistry::new();
        let exact = "a".repeat(MAX_DISK_SLOT_LEN);
        r.register(&exact, channel(1), task(1))
            .expect("exactly-max length must succeed");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_rejects_disk_slot_with_space() {
        let mut r = BlkChannelRegistry::new();
        let err = r
            .register("nvme 0", channel(1), task(1))
            .expect_err("space must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotInvalidChar);
    }

    #[test]
    fn register_rejects_disk_slot_with_dot() {
        // The dot byte is the channel-name separator, so allowing it
        // inside the slot would let a malicious driver smuggle a fake
        // suffix into the channel name.
        let mut r = BlkChannelRegistry::new();
        let err = r
            .register("nvme.0", channel(1), task(1))
            .expect_err("dot must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotInvalidChar);
    }

    #[test]
    fn register_rejects_disk_slot_with_control_byte() {
        // Newline is the most adversarial byte — embedding it in a
        // boot-log line would let a compromised driver spoof a kernel
        // log line. The validator rejects every byte outside the
        // ASCII alphabet, newline included.
        let mut r = BlkChannelRegistry::new();
        let err = r
            .register("nvme0\n", channel(1), task(1))
            .expect_err("newline must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotInvalidChar);
    }

    #[test]
    fn register_rejects_disk_slot_with_non_ascii() {
        let mut r = BlkChannelRegistry::new();
        // UTF-8 byte sequence for U+00E9 'é'. Both bytes are >= 0x80,
        // so the validator must reject the slot.
        let err = r
            .register("nvmé0", channel(1), task(1))
            .expect_err("non-ASCII must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotInvalidChar);
    }

    #[test]
    fn register_rejects_duplicate_disk_slot() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(1)).expect("first");
        let err = r
            .register("nvme0", channel(2), task(2))
            .expect_err("duplicate must be rejected");
        assert_eq!(err, BlkRegistryError::DiskSlotAlreadyRegistered);
        // The duplicate must NOT have replaced the first entry.
        let kept = r.lookup_disk_slot("nvme0").expect("first entry survived");
        assert_eq!(kept.channel_id, channel(1));
        assert_eq!(kept.owner, task(1));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_rejects_when_registry_is_full() {
        let mut r = BlkChannelRegistry::new();
        for i in 0..MAX_BLK_CHANNELS {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "i is bounded by MAX_BLK_CHANNELS = 64, fits trivially in u64/u32"
            )]
            let slot = alloc::format!("nvme{i}");
            r.register(&slot, channel(i as u64), task(1))
                .expect("fill registry");
        }
        let err = r
            .register("nvme_overflow", channel(9999), task(1))
            .expect_err("registry must be full");
        assert_eq!(err, BlkRegistryError::RegistryFull);
        assert_eq!(r.len(), MAX_BLK_CHANNELS);
    }

    // -----------------------------------------------------------------
    // unregister
    // -----------------------------------------------------------------

    #[test]
    fn unregister_drops_entry_and_returns_record() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(7), task(42)).expect("register");
        let removed = r.unregister("nvme0", task(42)).expect("unregister");
        assert_eq!(removed.disk_slot, "nvme0");
        assert_eq!(removed.channel_id, channel(7));
        assert_eq!(removed.owner, task(42));
        assert!(r.is_empty());
        assert!(r.lookup_disk_slot("nvme0").is_none());
    }

    #[test]
    fn unregister_unknown_disk_slot_returns_not_registered() {
        let mut r = BlkChannelRegistry::new();
        let err = r
            .unregister("nvme0", task(1))
            .expect_err("unregister of unknown slot must fail");
        assert_eq!(err, BlkRegistryError::DiskSlotNotRegistered);
    }

    #[test]
    fn unregister_rejects_non_owner() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(42)).expect("register");
        let err = r
            .unregister("nvme0", task(7))
            .expect_err("non-owner must be rejected");
        assert_eq!(err, BlkRegistryError::OwnerMismatch);
        // Entry MUST still be present.
        assert!(r.lookup_disk_slot("nvme0").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn re_register_after_unregister_succeeds() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(42)).expect("first");
        r.unregister("nvme0", task(42)).expect("unregister");
        let name = r
            .register("nvme0", channel(99), task(7))
            .expect("re-register with different owner+channel");
        assert_eq!(name, "nexacore.svc.blk.nvme0");
        let entry = r.lookup_disk_slot("nvme0").expect("entry present");
        assert_eq!(entry.channel_id, channel(99));
        assert_eq!(entry.owner, task(7));
        assert_eq!(r.len(), 1);
    }

    // -----------------------------------------------------------------
    // lookup
    // -----------------------------------------------------------------

    #[test]
    fn lookup_disk_slot_returns_some_for_registered_slot() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(11), task(1)).expect("register");
        let hit = r.lookup_disk_slot("nvme0").expect("lookup hit");
        assert_eq!(hit.channel_id, channel(11));
    }

    #[test]
    fn lookup_disk_slot_returns_none_for_unknown_slot() {
        let r = BlkChannelRegistry::new();
        assert!(r.lookup_disk_slot("nvme0").is_none());
    }

    #[test]
    fn lookup_channel_name_uses_fully_qualified_name() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(11), task(1)).expect("register");
        let hit = r
            .lookup_channel_name("nexacore.svc.blk.nvme0")
            .expect("lookup hit");
        assert_eq!(hit.channel_id, channel(11));
        assert_eq!(hit.disk_slot, "nvme0");
    }

    #[test]
    fn lookup_channel_name_returns_none_for_missing_prefix() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(11), task(1)).expect("register");
        // Raw slot is NOT a valid full channel name.
        assert!(r.lookup_channel_name("nvme0").is_none());
        // Wrong prefix is rejected.
        assert!(r.lookup_channel_name("nexacore.svc.net.nvme0").is_none());
    }

    #[test]
    fn lookup_channel_id_finds_entry() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(11), task(1)).expect("register");
        r.register("sata0", channel(22), task(1)).expect("register");
        let hit = r.lookup_channel_id(channel(22)).expect("lookup hit");
        assert_eq!(hit.disk_slot, "sata0");
    }

    #[test]
    fn lookup_channel_id_returns_none_for_unknown_id() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(11), task(1)).expect("register");
        assert!(r.lookup_channel_id(channel(99)).is_none());
    }

    // -----------------------------------------------------------------
    // clear_for_owner
    // -----------------------------------------------------------------

    #[test]
    fn clear_for_owner_drops_all_owner_entries() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(42)).expect("a");
        r.register("nvme1", channel(2), task(42)).expect("b");
        r.register("sata0", channel(3), task(7)).expect("c");
        let dropped = r.clear_for_owner(task(42));
        assert_eq!(dropped, 2);
        assert!(r.lookup_disk_slot("nvme0").is_none());
        assert!(r.lookup_disk_slot("nvme1").is_none());
        assert!(r.lookup_disk_slot("sata0").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_for_owner_with_no_match_returns_zero() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(7)).expect("register");
        let dropped = r.clear_for_owner(task(42));
        assert_eq!(dropped, 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_for_owner_on_empty_registry_is_noop() {
        let mut r = BlkChannelRegistry::new();
        let dropped = r.clear_for_owner(task(1));
        assert_eq!(dropped, 0);
        assert!(r.is_empty());
    }

    // -----------------------------------------------------------------
    // entries ordering
    // -----------------------------------------------------------------

    #[test]
    fn entries_preserves_insertion_order_before_unregister() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(1)).expect("a");
        r.register("nvme1", channel(2), task(1)).expect("b");
        r.register("sata0", channel(3), task(1)).expect("c");
        let slots: alloc::vec::Vec<&str> =
            r.entries().iter().map(|e| e.disk_slot.as_str()).collect();
        assert_eq!(slots, ["nvme0", "nvme1", "sata0"]);
    }

    #[test]
    fn unregister_swap_remove_does_not_corrupt_remaining_entries() {
        let mut r = BlkChannelRegistry::new();
        r.register("nvme0", channel(1), task(1)).expect("a");
        r.register("nvme1", channel(2), task(1)).expect("b");
        r.register("sata0", channel(3), task(1)).expect("c");
        r.unregister("nvme0", task(1)).expect("drop head");
        // The remaining lookups MUST still resolve to the original
        // channel ids and owners — swap_remove must not alias.
        let kept_nvme1 = r.lookup_disk_slot("nvme1").expect("nvme1 survives");
        assert_eq!(kept_nvme1.channel_id, channel(2));
        let kept_sata0 = r.lookup_disk_slot("sata0").expect("sata0 survives");
        assert_eq!(kept_sata0.channel_id, channel(3));
        assert_eq!(r.len(), 2);
    }

    // -----------------------------------------------------------------
    // errno mapping (P6.7.10-pre.3 BLK syscall boundary)
    // -----------------------------------------------------------------

    #[test]
    fn errno_for_argument_shape_violations_maps_to_einval() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(BlkRegistryError::DiskSlotEmpty),
            syscall_errno::EINVAL
        );
        assert_eq!(
            errno_for(BlkRegistryError::DiskSlotTooLong),
            syscall_errno::EINVAL
        );
        assert_eq!(
            errno_for(BlkRegistryError::DiskSlotInvalidChar),
            syscall_errno::EINVAL
        );
    }

    #[test]
    fn errno_for_duplicate_slot_maps_to_eexist() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(BlkRegistryError::DiskSlotAlreadyRegistered),
            syscall_errno::EEXIST
        );
    }

    #[test]
    fn errno_for_capacity_ceiling_maps_to_enospc() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(BlkRegistryError::RegistryFull),
            syscall_errno::ENOSPC
        );
    }

    #[test]
    fn errno_for_lookup_failed_maps_to_enoent() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(BlkRegistryError::DiskSlotNotRegistered),
            syscall_errno::ENOENT
        );
    }

    #[test]
    fn errno_for_owner_mismatch_maps_to_eacces() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(BlkRegistryError::OwnerMismatch),
            syscall_errno::EACCES
        );
    }

    #[test]
    fn errno_for_internal_invariant_maps_to_eio() {
        use crate::syscall::syscall_errno;
        // Defensive: surfaces as EIO rather than panicking the
        // kernel; user space sees a non-EINVAL code that triage
        // tooling can grep for.
        assert_eq!(errno_for(BlkRegistryError::Internal), syscall_errno::EIO);
    }

    #[test]
    fn errno_for_is_total_over_known_variants() {
        // Tripwire: every variant currently surfaceable from the
        // registry MUST have a documented errno mapping. Adding a
        // new variant to `BlkRegistryError` forces the contributor
        // to either extend this list or revisit `errno_for`'s
        // semantics.
        let variants = [
            BlkRegistryError::DiskSlotEmpty,
            BlkRegistryError::DiskSlotTooLong,
            BlkRegistryError::DiskSlotInvalidChar,
            BlkRegistryError::DiskSlotAlreadyRegistered,
            BlkRegistryError::RegistryFull,
            BlkRegistryError::DiskSlotNotRegistered,
            BlkRegistryError::OwnerMismatch,
            BlkRegistryError::Internal,
        ];
        for v in variants {
            // Either an explicit-mapping arm or the `#[non_exhaustive]`
            // catch-all would assign one of the documented errnos.
            // We assert the codomain rather than the exact map so
            // the test does not duplicate the table — `errno_for`
            // itself already pins the per-variant mapping above.
            let e = errno_for(v);
            assert!(matches!(
                e,
                crate::syscall::syscall_errno::EINVAL
                    | crate::syscall::syscall_errno::EEXIST
                    | crate::syscall::syscall_errno::ENOSPC
                    | crate::syscall::syscall_errno::ENOENT
                    | crate::syscall::syscall_errno::EACCES
                    | crate::syscall::syscall_errno::EIO
            ));
        }
    }
}
