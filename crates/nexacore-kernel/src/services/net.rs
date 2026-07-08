//! Kernel-side NET service-channel registry.
//!
//! Maintains the canonical mapping `interface_name → (ChannelId,
//! EventChannelId)` for every NIC driver that has registered an
//! `nexacore.svc.net.<iface>` command channel and the accompanying
//! `nexacore.svc.net.<iface>.evt` event channel per the NET driver NCIP
//! (NCIP-Driver-Net-015) § S2. The future network stack service
//! consults [`NetChannelRegistry::lookup_interface`] /
//! [`NetChannelRegistry::lookup_channel_name`] to obtain the live
//! [`ChannelId`] without sniffing the IPC registry by string.
//!
//! ## Why two channels per interface
//!
//! Each NIC driver exposes exactly two IPC channels per network
//! interface (per `nexacore_types::net_channel` module):
//!
//! 1. **Command channel** (`nexacore.svc.net.<iface>`): carries
//!    `NetRequest` → `NetResponse` round-trips from the network
//!    stack to the driver.
//! 2. **Event channel** (`nexacore.svc.net.<iface>.evt`): carries
//!    unsolicited `NetEvent` messages (received frames, link-state
//!    changes, MAC changes) from the driver to the network stack.
//!
//! Both channel IDs are recorded here at registration time so
//! the network stack can subscribe to both without a second lookup.
//!
//! ## Why a name → id table
//!
//! The kernel [`crate::ipc`] layer is name-agnostic — channels are
//! addressed by [`ChannelId`] only. User space derives a channel name
//! at creation time (the NIC driver picks `nexacore.svc.net.eth0`) and
//! stores it locally; the kernel never learns about that name. For
//! the NET layer, however, a stable cross-process resolution path is
//! required: a network stack service spawned independently of the
//! NIC driver must locate the channels the driver registered, and
//! the lookup MUST be capability-gated by the channel-name prefix
//! the kernel publishes in
//! [`nexacore_types::net_channel::NET_CHANNEL_PREFIX`]. This registry
//! is the kernel-side bookkeeping that supports that gate.
//!
//! ## What this module does NOT do
//!
//! - It does not create IPC channels — that is still
//!   [`crate::ipc::KernelIpcRegistry::create_channel_signed`]. The
//!   driver allocates the channels first, then records the mapping
//!   here through the `NetRegister` syscall.
//! - It does not emit any MMIO or touch the page tables — every
//!   operation is a pure-state mutation of a small `Vec`.
//! - It does not implement the NET send/receive protocol — that
//!   lives in user space on both sides of the wire. The registry
//!   only answers "what channel ids are `nexacore.svc.net.eth0` and
//!   `nexacore.svc.net.eth0.evt`?".
//!
//! ## Phase-1 scope
//!
//! The Phase-1 driver framework caps the number of simultaneous NIC
//! registrations at [`MAX_NET_CHANNELS`] (16), which is generous for
//! every plausible Phase-1 network topology (one or two virtual NICs,
//! one physical NIC, a loopback tap) without committing to an
//! unbounded allocation. The limit is a denial-of-service defence:
//! a compromised driver looping on
//! [`NetChannelRegistry::register`] will get `RegistryFull` in
//! O(1) rather than exhausting the kernel allocator.

#![cfg_attr(
    all(feature = "bare-metal", target_arch = "x86_64"),
    allow(
        unsafe_code,
        reason = "NET_REGISTRY static mut singleton + addr_of_mut accessor; SAFETY documented at the fn boundary"
    )
)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use nexacore_types::net_channel::NET_CHANNEL_PREFIX;

use crate::{ipc::ChannelId, scheduling::TaskId};

/// Maximum number of NET channel pairs the registry may hold
/// concurrently.
///
/// Bounded for two reasons:
///
/// 1. **Capacity.** The Phase-1 driver framework uses at most a
///    handful of virtual NICs (virtio-net, loopback tap). 16 covers
///    any foreseeable Phase-1 + early Phase-2 topology.
/// 2. **Denial-of-service defence.** Every entry pins two `String`
///    allocations (command channel name + event channel name). An
///    unbounded registry would let a compromised driver loop on
///    [`NetChannelRegistry::register`] until the kernel allocator
///    is exhausted; capping at 16 turns that into a
///    `Err(RegistryFull)` in O(1).
pub const MAX_NET_CHANNELS: usize = 16;

/// Maximum byte length of a network interface name string
/// (e.g. `"eth0"`, `"virtio0"`, `"lo"`).
///
/// Linux allows up to `IFNAMSIZ - 1 = 15` bytes. We match that
/// limit so kernel-side tooling and Linux-originated interface
/// names agree on the constraint. 16 bytes also keeps the per-entry
/// channel-name allocation bounded and the boot-log lines short.
pub const MAX_INTERFACE_NAME_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Reason a [`NetChannelRegistry`] call could not complete.
///
/// All variants are observable through the `NetRegister` /
/// `NetUnregister` syscall return path; the kernel-internal handler
/// maps each variant to the appropriate POSIX errno at the boundary
/// via [`errno_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetRegistryError {
    /// The supplied `interface_name` was empty. The kernel rejects
    /// empty names so the resulting channel name
    /// (`"nexacore.svc.net."`) does not collide with the canonical
    /// prefix itself.
    InterfaceNameEmpty,
    /// The supplied `interface_name` exceeded
    /// [`MAX_INTERFACE_NAME_LEN`] bytes.
    InterfaceNameTooLong,
    /// The supplied `interface_name` contained a byte outside the
    /// allowed ASCII alphabet `[A-Za-z0-9_-]`. Restricting the
    /// name alphabet keeps the resulting channel name safe to log
    /// and parse and closes a path where a compromised driver could
    /// embed control bytes (newline, CR, escape sequence) in the
    /// kernel boot log.
    InterfaceNameInvalidChar,
    /// A registration already exists for the requested
    /// `interface_name`. Per the driver NCIP the interface-name
    /// half of a NET channel name is expected to be unique — a
    /// duplicate registration is a programming error in user space.
    InterfaceAlreadyRegistered,
    /// The registry has hit [`MAX_NET_CHANNELS`] entries and cannot
    /// accept the new registration.
    RegistryFull,
    /// [`NetChannelRegistry::unregister`] or
    /// [`NetChannelRegistry::update_link_state`] was called for an
    /// `interface_name` the registry does not know.
    InterfaceNotRegistered,
    /// The caller is not the [`TaskId`] recorded as the owner of the
    /// requested registration. Enforces the "only the producing
    /// driver may unregister its own channel" invariant; clean-up
    /// on task death goes through
    /// [`NetChannelRegistry::clear_for_owner`].
    OwnerMismatch,
    /// Defensive sentinel for invariants the registry expects to
    /// hold but cannot statically prove (e.g. a `Vec` that should
    /// be non-empty immediately after `push`). Maps to
    /// [`crate::KernelError::Internal`] at the syscall boundary.
    /// Unreachable in well-formed code; exists so the registry
    /// never aborts the kernel.
    Internal,
}

// ---------------------------------------------------------------------------
// Registry entry
// ---------------------------------------------------------------------------

/// One NET channel pair registration record.
///
/// Lifetime: created by [`NetChannelRegistry::register`] when the
/// NIC driver completes NCIP-Driver-Net-015 § S2 channel setup
/// (`IpcCreateChannel(name = "nexacore.svc.net.<iface>", ...)` and
/// `IpcCreateChannel(name = "nexacore.svc.net.<iface>.evt", ...)`);
/// destroyed by [`NetChannelRegistry::unregister`] on graceful
/// driver shutdown or by [`NetChannelRegistry::clear_for_owner`]
/// on driver task exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetChannelEntry {
    /// The interface name, e.g. `"eth0"`. Always ASCII; bounded by
    /// [`MAX_INTERFACE_NAME_LEN`]; restricted to `[A-Za-z0-9_-]`.
    pub interface_name: String,
    /// The full command channel name, i.e.
    /// [`nexacore_types::net_channel::NET_CHANNEL_PREFIX`] concatenated
    /// with [`Self::interface_name`]. Pre-built at registration time
    /// so consumer call sites do not re-allocate on every lookup.
    /// Example: `"nexacore.svc.net.eth0"`.
    pub channel_name: String,
    /// The live IPC channel id the driver received from
    /// [`crate::ipc::KernelIpcRegistry::create_channel_signed`] for
    /// the **command** channel.
    pub channel_id: ChannelId,
    /// The live IPC channel id the driver received from
    /// [`crate::ipc::KernelIpcRegistry::create_channel_signed`] for
    /// the **event** channel (`nexacore.svc.net.<iface>.evt`).
    pub event_channel_id: ChannelId,
    /// The 6-byte MAC address of the interface in network byte
    /// order, as reported by the driver at registration time.
    pub mac: [u8; 6],
    /// Current link state: `true` means the link is up. Updated
    /// by the driver via `NetLinkStateUpdate` (syscall) /
    /// [`NetChannelRegistry::update_link_state`].
    pub link_up: bool,
    /// The driver task that owns the channel pair. Used by
    /// [`NetChannelRegistry::unregister`] to enforce owner-only
    /// teardown and by [`NetChannelRegistry::clear_for_owner`] to
    /// drain stale registrations on task exit.
    pub owner: TaskId,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Kernel-internal NET channel registry. Pure-state bookkeeping;
/// the Phase-1 boot wires a single instance into the kernel-global
/// state (future work).
///
/// Storage is a [`Vec<NetChannelEntry>`] rather than a `BTreeMap`
/// because (a) the Phase-1 cap is 16 entries, (b) every operation
/// is O(N) at most, (c) the order of [`Self::entries`] is
/// observable (insertion order until [`Self::unregister`]) which is
/// friendlier to debug-print output than the random ordering of
/// `BTreeMap`.
///
/// # Example
///
/// ```rust
/// # use nexacore_kernel::services::net::{NetChannelRegistry, MAX_NET_CHANNELS};
/// # use nexacore_kernel::ipc::ChannelId;
/// # use nexacore_kernel::scheduling::TaskId;
/// let mut registry = NetChannelRegistry::new();
/// assert!(registry.is_empty());
/// assert_eq!(registry.len(), 0);
/// let name = registry
///     .register(
///         "eth0",
///         ChannelId(1),
///         ChannelId(2),
///         [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF],
///         TaskId(42),
///     )
///     .expect("registration must succeed");
/// assert_eq!(name, "nexacore.svc.net.eth0");
/// assert_eq!(registry.len(), 1);
/// ```
#[derive(Debug, Default)]
pub struct NetChannelRegistry {
    entries: Vec<NetChannelEntry>,
}

impl NetChannelRegistry {
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
    pub fn entries(&self) -> &[NetChannelEntry] {
        &self.entries
    }

    /// Record a new NET channel pair for `interface_name`.
    ///
    /// Returns the canonical command channel name (e.g.
    /// `"nexacore.svc.net.eth0"`) the registry built for the new
    /// entry so the caller can echo it in the boot log without
    /// re-allocating. To inspect the rest of the new entry's
    /// fields, call [`Self::lookup_interface`].
    ///
    /// # Errors
    ///
    /// - [`NetRegistryError::InterfaceNameEmpty`] if
    ///   `interface_name` is empty.
    /// - [`NetRegistryError::InterfaceNameTooLong`] if
    ///   `interface_name` exceeds [`MAX_INTERFACE_NAME_LEN`] bytes.
    /// - [`NetRegistryError::InterfaceNameInvalidChar`] if
    ///   `interface_name` contains a byte outside `[A-Za-z0-9_-]`.
    /// - [`NetRegistryError::InterfaceAlreadyRegistered`] if a
    ///   registration for `interface_name` already exists.
    /// - [`NetRegistryError::RegistryFull`] if the registry already
    ///   holds [`MAX_NET_CHANNELS`] entries.
    pub fn register(
        &mut self,
        interface_name: &str,
        channel_id: ChannelId,
        event_channel_id: ChannelId,
        mac: [u8; 6],
        owner: TaskId,
    ) -> Result<&str, NetRegistryError> {
        Self::validate_interface_name(interface_name)?;
        if self
            .entries
            .iter()
            .any(|e| e.interface_name == interface_name)
        {
            return Err(NetRegistryError::InterfaceAlreadyRegistered);
        }
        if self.entries.len() >= MAX_NET_CHANNELS {
            return Err(NetRegistryError::RegistryFull);
        }
        let channel_name = Self::build_channel_name(interface_name);
        self.entries.push(NetChannelEntry {
            interface_name: interface_name.to_string(),
            channel_name,
            channel_id,
            event_channel_id,
            mac,
            link_up: false,
            owner,
        });
        // `Vec::push` cannot make the slice empty after a successful
        // push, so `last()` is `Some` here. `map_or` matches the
        // workspace `clippy::option_if_let_else` style; the `None`
        // arm is unreachable in well-formed code and surfaces
        // [`NetRegistryError::Internal`] rather than panicking so
        // the registry never aborts the kernel on a clippy edge-case.
        self.entries
            .last()
            .map_or(Err(NetRegistryError::Internal), |entry| {
                Ok(&entry.channel_name)
            })
    }

    /// Drop the registration for `interface_name`. Only `owner` may
    /// call.
    ///
    /// Returns the removed entry on success so the caller can log
    /// the channel ids it must subsequently destroy through
    /// [`crate::ipc::KernelIpcRegistry::destroy_channel`].
    ///
    /// # Errors
    ///
    /// - [`NetRegistryError::InterfaceNotRegistered`] if no entry
    ///   matches `interface_name`.
    /// - [`NetRegistryError::OwnerMismatch`] if the entry's recorded
    ///   owner differs from `owner`. The graceful owner-driven path
    ///   is the only legal `unregister` route; task-exit clean-up
    ///   goes through [`Self::clear_for_owner`].
    pub fn unregister(
        &mut self,
        interface_name: &str,
        owner: TaskId,
    ) -> Result<NetChannelEntry, NetRegistryError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.interface_name == interface_name)
            .ok_or(NetRegistryError::InterfaceNotRegistered)?;
        // `position` returned `idx`, so `get(idx)` is `Some`. Use
        // `get` rather than `[idx]` because the workspace lint
        // `clippy::indexing_slicing` forbids slice indexing.
        let recorded_owner = match self.entries.get(idx) {
            Some(entry) => entry.owner,
            None => return Err(NetRegistryError::Internal),
        };
        if recorded_owner != owner {
            return Err(NetRegistryError::OwnerMismatch);
        }
        Ok(self.entries.swap_remove(idx))
    }

    /// Resolve a registration by raw interface name (e.g. `"eth0"`).
    #[must_use]
    pub fn lookup_interface(&self, interface_name: &str) -> Option<&NetChannelEntry> {
        self.entries
            .iter()
            .find(|e| e.interface_name == interface_name)
    }

    /// Resolve a registration by full command channel name (e.g.
    /// `"nexacore.svc.net.eth0"`).
    ///
    /// Used by the (future) capability-gating syscall handler that
    /// receives the full channel name from user space and must
    /// defend against arbitrary inputs.
    #[must_use]
    pub fn lookup_channel_name(&self, channel_name: &str) -> Option<&NetChannelEntry> {
        self.entries.iter().find(|e| e.channel_name == channel_name)
    }

    /// Resolve a registration by its command [`ChannelId`].
    ///
    /// Used by IRQ / driver-exit clean-up paths that have a
    /// `ChannelId` in hand and need to learn which interface it
    /// served. Matches against [`NetChannelEntry::channel_id`]
    /// (the command channel); to match the event channel, iterate
    /// [`Self::entries`] directly.
    #[must_use]
    pub fn lookup_channel_id(&self, channel_id: ChannelId) -> Option<&NetChannelEntry> {
        self.entries.iter().find(|e| e.channel_id == channel_id)
    }

    /// Drop every registration owned by `owner`. Returns the number
    /// of entries removed.
    ///
    /// Called from the kernel task-exit path so a crashed/killed
    /// driver does not leak stale registry entries. The caller is
    /// responsible for tearing down the underlying IPC channels
    /// through
    /// [`crate::ipc::KernelIpcRegistry::destroy_channel`] before /
    /// after this call; the registry only owns its bookkeeping.
    pub fn clear_for_owner(&mut self, owner: TaskId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.owner != owner);
        before - self.entries.len()
    }

    /// Update the link state for a registered interface.
    ///
    /// Called by the NIC driver (via the future `NetLinkUpdate`
    /// syscall) when the physical link state changes. The updated
    /// `link_up` value is immediately visible to subsequent
    /// [`Self::lookup_interface`] calls.
    ///
    /// # Errors
    ///
    /// - [`NetRegistryError::InterfaceNotRegistered`] if no entry
    ///   matches `interface_name`.
    pub fn update_link_state(
        &mut self,
        interface_name: &str,
        up: bool,
    ) -> Result<(), NetRegistryError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.interface_name == interface_name)
            .ok_or(NetRegistryError::InterfaceNotRegistered)?;
        entry.link_up = up;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    /// Reject empty, oversized, or non-portable interface names.
    fn validate_interface_name(name: &str) -> Result<(), NetRegistryError> {
        if name.is_empty() {
            return Err(NetRegistryError::InterfaceNameEmpty);
        }
        if name.len() > MAX_INTERFACE_NAME_LEN {
            return Err(NetRegistryError::InterfaceNameTooLong);
        }
        for &b in name.as_bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {}
                _ => return Err(NetRegistryError::InterfaceNameInvalidChar),
            }
        }
        Ok(())
    }

    /// Compose the canonical command channel name from a validated
    /// interface name.
    fn build_channel_name(iface: &str) -> String {
        let mut s = String::with_capacity(NET_CHANNEL_PREFIX.len() + iface.len());
        s.push_str(NET_CHANNEL_PREFIX);
        s.push_str(iface);
        s
    }
}

// ===========================================================================
// errno mapping
// ===========================================================================

/// Map a [`NetRegistryError`] to a POSIX-aligned errno.
///
/// The errno is consumed by the rich two-register syscall return
/// path ([`crate::syscall::SyscallReturn`]). The mapping matches
/// the vocabulary `NCIP-Driver-Net-015` § S2.3 publishes for the
/// NET registry syscalls so user-space tooling can reuse the same
/// triage table across `NetRegister`, `NetUnregister`, and
/// `NetLookup`.
#[must_use]
pub const fn errno_for(err: NetRegistryError) -> u64 {
    use crate::syscall::syscall_errno;
    match err {
        // Argument-shape violations → `EINVAL`.
        NetRegistryError::InterfaceNameEmpty
        | NetRegistryError::InterfaceNameTooLong
        | NetRegistryError::InterfaceNameInvalidChar => syscall_errno::EINVAL,
        // Interface name already in use → `EEXIST`. Distinguishing
        // this from `EINVAL` lets user space tell "the kernel
        // rejected my interface name string" (programmer bug) from
        // "another driver got there first" (operational race).
        NetRegistryError::InterfaceAlreadyRegistered => syscall_errno::EEXIST,
        // Capacity ceiling → `ENOSPC`.
        NetRegistryError::RegistryFull => syscall_errno::ENOSPC,
        // Lookup-failed (`unregister` / `update_link_state` path) →
        // `ENOENT`. The dedicated `NetLookup` syscall surfaces the
        // same code for the read-only path.
        NetRegistryError::InterfaceNotRegistered => syscall_errno::ENOENT,
        // Caller is not the recorded owner → `EACCES`.
        NetRegistryError::OwnerMismatch => syscall_errno::EACCES,
        // Defensive invariant — should never surface in well-formed
        // code; reported as `EIO` so the kernel does not abort and
        // user space sees a non-`EINVAL` error code that triage
        // tooling can grep for.
        NetRegistryError::Internal => syscall_errno::EIO,
    }
}

// ===========================================================================
// Kernel-global singleton
// ===========================================================================

/// Process-global NET channel registry, mirroring
/// [`crate::ipc::IPC_REGISTRY`] and the BLK registry pattern.
///
/// Phase 1 is single-CPU and the SYSCALL entry path masks interrupts
/// via `IA32_FMASK`, so a `static mut` rather than a `Mutex<...>` is
/// sufficient. The MP transition (ADR-0005) will swap this for a
/// shared lock guard analogous to the planned IPC rework. The
/// `static mut` lives behind `bare-metal` + `target_arch = "x86_64"`
/// because (a) only the bare-metal build owns the SYSCALL path that
/// provides the no-aliasing invariant and (b) host tests exercise
/// [`NetChannelRegistry`] directly without the singleton.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
static mut NET_REGISTRY: NetChannelRegistry = NetChannelRegistry::new();

/// Borrow the global NET registry mutably.
///
/// # Safety
///
/// Caller must be in a context where no other reference to
/// `NET_REGISTRY` is live. The SYSCALL path provides this
/// invariant in single-CPU Phase 1 (interrupts masked, no
/// recursion).
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    clippy::mut_from_ref,
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn net_registry_mut() -> &'static mut NetChannelRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of_mut!(NET_REGISTRY);
        &mut *p
    }
}

/// Borrow the global NET registry immutably.
///
/// # Safety
///
/// Caller must be in a context where no `&mut` to `NET_REGISTRY`
/// is concurrently live. Phase 1 single-CPU + interrupt-masked
/// SYSCALL provides this; MP introduction swaps the accessor for a
/// lock guard per ADR-0005.
#[cfg(all(feature = "bare-metal", target_arch = "x86_64"))]
#[allow(
    static_mut_refs,
    reason = "single-CPU kernel singleton; SAFETY documented at the call site"
)]
pub unsafe fn net_registry() -> &'static NetChannelRegistry {
    // SAFETY: caller invariant — see fn doc.
    unsafe {
        let p = core::ptr::addr_of!(NET_REGISTRY);
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

    /// Constant MAC address used in tests.
    const MAC_A: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
    /// A second MAC address for tests that need two distinct MACs.
    const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

    // -----------------------------------------------------------------
    // Construction & basic invariants
    // -----------------------------------------------------------------

    #[test]
    fn new_registry_is_empty() {
        let r = NetChannelRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(r.entries().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let a = NetChannelRegistry::new();
        let b = NetChannelRegistry::default();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.is_empty(), b.is_empty());
    }

    #[test]
    fn max_interface_name_len_constant_is_16() {
        // Tripwire: changing the cap silently widens the kernel boot
        // log lines and the registry's per-entry allocation.
        assert_eq!(MAX_INTERFACE_NAME_LEN, 16);
    }

    #[test]
    fn max_net_channels_constant_is_16() {
        // Tripwire: changing the cap changes the registry's
        // worst-case memory footprint; documented in module docs.
        assert_eq!(MAX_NET_CHANNELS, 16);
    }

    #[test]
    fn net_channel_prefix_constant_matches_nexacore_types() {
        // The kernel registry MUST consume the canonical prefix from
        // `nexacore-types` so a future rename does not desynchronise the
        // two crates. Asserts the import path resolves to the value
        // the NET driver NCIP freezes.
        assert_eq!(NET_CHANNEL_PREFIX, "nexacore.svc.net.");
    }

    // -----------------------------------------------------------------
    // register — happy path + validation
    // -----------------------------------------------------------------

    #[test]
    fn register_inserts_entry_with_canonical_channel_name() {
        let mut r = NetChannelRegistry::new();
        let name = r
            .register("eth0", channel(7), channel(8), MAC_A, task(42))
            .expect("registration must succeed");
        assert_eq!(name, "nexacore.svc.net.eth0");
        let entry = r.lookup_interface("eth0").expect("entry present");
        assert_eq!(entry.interface_name, "eth0");
        assert_eq!(entry.channel_name, "nexacore.svc.net.eth0");
        assert_eq!(entry.channel_id, channel(7));
        assert_eq!(entry.event_channel_id, channel(8));
        assert_eq!(entry.mac, MAC_A);
        assert!(!entry.link_up, "initial link state must be down");
        assert_eq!(entry.owner, task(42));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn register_return_value_is_canonical_channel_name() {
        let mut r = NetChannelRegistry::new();
        let a = r
            .register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("first register");
        assert_eq!(a, "nexacore.svc.net.eth0");
        let b = r
            .register("virtio-0", channel(3), channel(4), MAC_B, task(1))
            .expect("second register");
        assert_eq!(b, "nexacore.svc.net.virtio-0");
    }

    #[test]
    fn register_accepts_alphanumeric_underscore_and_hyphen() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("eth0");
        r.register("virtio-0", channel(3), channel(4), MAC_B, task(1))
            .expect("virtio-0");
        r.register("tap_lo", channel(5), channel(6), MAC_A, task(1))
            .expect("tap_lo");
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn register_rejects_empty_interface_name() {
        let mut r = NetChannelRegistry::new();
        let err = r
            .register("", channel(1), channel(2), MAC_A, task(1))
            .expect_err("empty name must be rejected");
        assert_eq!(err, NetRegistryError::InterfaceNameEmpty);
        assert!(r.is_empty());
    }

    #[test]
    fn register_rejects_interface_name_too_long() {
        let mut r = NetChannelRegistry::new();
        // MAX_INTERFACE_NAME_LEN + 1 bytes — one over the limit.
        let oversized = "a".repeat(MAX_INTERFACE_NAME_LEN + 1);
        let err = r
            .register(&oversized, channel(1), channel(2), MAC_A, task(1))
            .expect_err("oversized name must be rejected");
        assert_eq!(err, NetRegistryError::InterfaceNameTooLong);
        assert!(r.is_empty());
    }

    #[test]
    fn register_accepts_interface_name_at_max_length() {
        let mut r = NetChannelRegistry::new();
        let exact = "a".repeat(MAX_INTERFACE_NAME_LEN);
        r.register(&exact, channel(1), channel(2), MAC_A, task(1))
            .expect("exactly-max length must succeed");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_rejects_interface_name_with_invalid_char() {
        let cases: &[&str] = &[
            "eth 0",  // space
            "eth.0",  // dot (channel-name separator)
            "eth0\n", // newline (log-injection)
            "eth@0",  // at-sign
            "eth/0",  // slash
        ];
        for name in cases {
            let mut r = NetChannelRegistry::new();
            let err = r
                .register(name, channel(1), channel(2), MAC_A, task(1))
                .expect_err("invalid char must be rejected");
            assert_eq!(
                err,
                NetRegistryError::InterfaceNameInvalidChar,
                "expected InterfaceNameInvalidChar for {name:?}"
            );
        }
    }

    #[test]
    fn register_rejects_duplicate_interface() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("first");
        let err = r
            .register("eth0", channel(3), channel(4), MAC_B, task(2))
            .expect_err("duplicate must be rejected");
        assert_eq!(err, NetRegistryError::InterfaceAlreadyRegistered);
        // The duplicate must NOT have replaced the first entry.
        let kept = r.lookup_interface("eth0").expect("first entry survived");
        assert_eq!(kept.channel_id, channel(1));
        assert_eq!(kept.owner, task(1));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_rejects_when_registry_is_full() {
        let mut r = NetChannelRegistry::new();
        for i in 0..MAX_NET_CHANNELS {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "i is bounded by MAX_NET_CHANNELS = 16, fits trivially in u64"
            )]
            let iface = alloc::format!("eth{i}");
            r.register(
                &iface,
                channel(i as u64 * 2),
                channel(i as u64 * 2 + 1),
                MAC_A,
                task(1),
            )
            .expect("fill registry");
        }
        let err = r
            .register("eth_overflow", channel(9998), channel(9999), MAC_B, task(1))
            .expect_err("registry must be full");
        assert_eq!(err, NetRegistryError::RegistryFull);
        assert_eq!(r.len(), MAX_NET_CHANNELS);
    }

    // -----------------------------------------------------------------
    // unregister
    // -----------------------------------------------------------------

    #[test]
    fn unregister_drops_entry_and_returns_record() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(7), channel(8), MAC_A, task(42))
            .expect("register");
        let removed = r.unregister("eth0", task(42)).expect("unregister");
        assert_eq!(removed.interface_name, "eth0");
        assert_eq!(removed.channel_id, channel(7));
        assert_eq!(removed.event_channel_id, channel(8));
        assert_eq!(removed.mac, MAC_A);
        assert_eq!(removed.owner, task(42));
        assert!(r.is_empty());
        assert!(r.lookup_interface("eth0").is_none());
    }

    #[test]
    fn unregister_unknown_interface_returns_not_registered() {
        let mut r = NetChannelRegistry::new();
        let err = r
            .unregister("eth0", task(1))
            .expect_err("unregister of unknown interface must fail");
        assert_eq!(err, NetRegistryError::InterfaceNotRegistered);
    }

    #[test]
    fn unregister_rejects_non_owner() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(42))
            .expect("register");
        let err = r
            .unregister("eth0", task(7))
            .expect_err("non-owner must be rejected");
        assert_eq!(err, NetRegistryError::OwnerMismatch);
        // Entry MUST still be present.
        assert!(r.lookup_interface("eth0").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn re_register_after_unregister_succeeds() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(42))
            .expect("first");
        r.unregister("eth0", task(42)).expect("unregister");
        let name = r
            .register("eth0", channel(99), channel(100), MAC_B, task(7))
            .expect("re-register with different owner+channels");
        assert_eq!(name, "nexacore.svc.net.eth0");
        let entry = r.lookup_interface("eth0").expect("entry present");
        assert_eq!(entry.channel_id, channel(99));
        assert_eq!(entry.event_channel_id, channel(100));
        assert_eq!(entry.mac, MAC_B);
        assert_eq!(entry.owner, task(7));
        assert_eq!(r.len(), 1);
    }

    // -----------------------------------------------------------------
    // lookup
    // -----------------------------------------------------------------

    #[test]
    fn lookup_interface_returns_some_for_registered() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(11), channel(12), MAC_A, task(1))
            .expect("register");
        let hit = r.lookup_interface("eth0").expect("lookup hit");
        assert_eq!(hit.channel_id, channel(11));
    }

    #[test]
    fn lookup_interface_returns_none_for_unknown() {
        let r = NetChannelRegistry::new();
        assert!(r.lookup_interface("eth0").is_none());
    }

    #[test]
    fn lookup_channel_name_uses_fully_qualified_name() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(11), channel(12), MAC_A, task(1))
            .expect("register");
        let hit = r
            .lookup_channel_name("nexacore.svc.net.eth0")
            .expect("lookup hit");
        assert_eq!(hit.channel_id, channel(11));
        assert_eq!(hit.interface_name, "eth0");
    }

    #[test]
    fn lookup_channel_name_returns_none_for_missing_prefix() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(11), channel(12), MAC_A, task(1))
            .expect("register");
        // Raw interface name is NOT a valid full channel name.
        assert!(r.lookup_channel_name("eth0").is_none());
        // Wrong prefix is rejected.
        assert!(r.lookup_channel_name("nexacore.svc.blk.eth0").is_none());
    }

    #[test]
    fn lookup_channel_id_finds_entry() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(11), channel(12), MAC_A, task(1))
            .expect("register");
        r.register("eth1", channel(22), channel(23), MAC_B, task(1))
            .expect("register");
        let hit = r.lookup_channel_id(channel(22)).expect("lookup hit");
        assert_eq!(hit.interface_name, "eth1");
    }

    #[test]
    fn lookup_channel_id_returns_none_for_unknown_id() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(11), channel(12), MAC_A, task(1))
            .expect("register");
        assert!(r.lookup_channel_id(channel(99)).is_none());
    }

    // -----------------------------------------------------------------
    // clear_for_owner
    // -----------------------------------------------------------------

    #[test]
    fn clear_for_owner_drops_all_owner_entries() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(42))
            .expect("a");
        r.register("eth1", channel(3), channel(4), MAC_A, task(42))
            .expect("b");
        r.register("eth2", channel(5), channel(6), MAC_B, task(7))
            .expect("c");
        let dropped = r.clear_for_owner(task(42));
        assert_eq!(dropped, 2);
        assert!(r.lookup_interface("eth0").is_none());
        assert!(r.lookup_interface("eth1").is_none());
        assert!(r.lookup_interface("eth2").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_for_owner_with_no_match_returns_zero() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(7))
            .expect("register");
        let dropped = r.clear_for_owner(task(42));
        assert_eq!(dropped, 0);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn clear_for_owner_on_empty_registry_is_noop() {
        let mut r = NetChannelRegistry::new();
        let dropped = r.clear_for_owner(task(1));
        assert_eq!(dropped, 0);
        assert!(r.is_empty());
    }

    // -----------------------------------------------------------------
    // update_link_state
    // -----------------------------------------------------------------

    #[test]
    fn update_link_state_changes_flag() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("register");
        // Initial state is down.
        assert!(!r.lookup_interface("eth0").expect("present").link_up);
        r.update_link_state("eth0", true).expect("update to up");
        assert!(r.lookup_interface("eth0").expect("present").link_up);
        r.update_link_state("eth0", false).expect("update to down");
        assert!(!r.lookup_interface("eth0").expect("present").link_up);
    }

    #[test]
    fn update_link_state_unknown_interface_returns_error() {
        let mut r = NetChannelRegistry::new();
        let err = r
            .update_link_state("eth0", true)
            .expect_err("unknown interface must fail");
        assert_eq!(err, NetRegistryError::InterfaceNotRegistered);
    }

    // -----------------------------------------------------------------
    // entries ordering
    // -----------------------------------------------------------------

    #[test]
    fn entries_preserves_insertion_order_before_unregister() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("a");
        r.register("eth1", channel(3), channel(4), MAC_A, task(1))
            .expect("b");
        r.register("eth2", channel(5), channel(6), MAC_B, task(1))
            .expect("c");
        let names: alloc::vec::Vec<&str> = r
            .entries()
            .iter()
            .map(|e| e.interface_name.as_str())
            .collect();
        assert_eq!(names, ["eth0", "eth1", "eth2"]);
    }

    #[test]
    fn unregister_swap_remove_does_not_corrupt_remaining_entries() {
        let mut r = NetChannelRegistry::new();
        r.register("eth0", channel(1), channel(2), MAC_A, task(1))
            .expect("a");
        r.register("eth1", channel(3), channel(4), MAC_A, task(1))
            .expect("b");
        r.register("eth2", channel(5), channel(6), MAC_B, task(1))
            .expect("c");
        r.unregister("eth0", task(1)).expect("drop head");
        // The remaining lookups MUST still resolve to the original
        // channel ids — swap_remove must not alias.
        let kept_eth1 = r.lookup_interface("eth1").expect("eth1 survives");
        assert_eq!(kept_eth1.channel_id, channel(3));
        let kept_eth2 = r.lookup_interface("eth2").expect("eth2 survives");
        assert_eq!(kept_eth2.channel_id, channel(5));
        assert_eq!(r.len(), 2);
    }

    // -----------------------------------------------------------------
    // errno mapping
    // -----------------------------------------------------------------

    #[test]
    fn errno_for_argument_shape_violations_maps_to_einval() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(NetRegistryError::InterfaceNameEmpty),
            syscall_errno::EINVAL
        );
        assert_eq!(
            errno_for(NetRegistryError::InterfaceNameTooLong),
            syscall_errno::EINVAL
        );
        assert_eq!(
            errno_for(NetRegistryError::InterfaceNameInvalidChar),
            syscall_errno::EINVAL
        );
    }

    #[test]
    fn errno_for_duplicate_interface_maps_to_eexist() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(NetRegistryError::InterfaceAlreadyRegistered),
            syscall_errno::EEXIST
        );
    }

    #[test]
    fn errno_for_capacity_ceiling_maps_to_enospc() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(NetRegistryError::RegistryFull),
            syscall_errno::ENOSPC
        );
    }

    #[test]
    fn errno_for_interface_not_registered_maps_to_enoent() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(NetRegistryError::InterfaceNotRegistered),
            syscall_errno::ENOENT
        );
    }

    #[test]
    fn errno_for_owner_mismatch_maps_to_eacces() {
        use crate::syscall::syscall_errno;
        assert_eq!(
            errno_for(NetRegistryError::OwnerMismatch),
            syscall_errno::EACCES
        );
    }

    #[test]
    fn errno_for_internal_invariant_maps_to_eio() {
        use crate::syscall::syscall_errno;
        assert_eq!(errno_for(NetRegistryError::Internal), syscall_errno::EIO);
    }

    #[test]
    fn errno_for_is_total_over_known_variants() {
        // Tripwire: every variant currently surfaceable from the
        // registry MUST have a documented errno mapping. Adding a
        // new variant to `NetRegistryError` forces the contributor
        // to either extend this list or revisit `errno_for`'s
        // semantics.
        let variants = [
            NetRegistryError::InterfaceNameEmpty,
            NetRegistryError::InterfaceNameTooLong,
            NetRegistryError::InterfaceNameInvalidChar,
            NetRegistryError::InterfaceAlreadyRegistered,
            NetRegistryError::RegistryFull,
            NetRegistryError::InterfaceNotRegistered,
            NetRegistryError::OwnerMismatch,
            NetRegistryError::Internal,
        ];
        for v in variants {
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
