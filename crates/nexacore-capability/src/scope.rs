//! Typed scope vocabulary: action × resource × time × caveats.
//!
//! A [`Scope`] is the authority granted by a capability token. It is
//! deliberately **typed end-to-end** — no `String` stuffed with a
//! free-form action name, no `Vec<u8>` resource opaque blob — so that
//! the compiler catches whole categories of policy bugs (e.g.,
//! comparing a [`Resource::Network`] against a [`Resource::Filesystem`]
//! cannot accidentally succeed).
//!
//! # Invariants
//!
//! * Two scopes are **comparable** iff their [`Action`] discriminants
//!   match AND their [`Resource`] discriminants match.
//! * Subset (`a ⊆ b`) is a partial order: it requires both Actions to
//!   match exactly, the resource pattern of `a` to be at least as
//!   specific as `b`, the time window of `a` to be contained in `b`'s,
//!   and every caveat in `b` to be ALSO present in `a`.
//! * Time is in seconds since the Unix epoch (`u64`). The clock source
//!   is provided by the caller — see `nexacore-hal::clock` (P6).

use alloc::{string::String, vec::Vec};

use nexacore_types::identity::{AgentId, ModelId, NodeId};
use serde::{Deserialize, Serialize};

// =============================================================================
// Action
// =============================================================================

/// The action a capability authorises.
///
/// `#[non_exhaustive]` so adding new action kinds is backwards-
/// compatible. Pattern-match sites in downstream code should always
/// include a `_ =>` arm.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Action {
    /// Read data from a resource.
    Read,
    /// Write or update data on a resource.
    Write,
    /// Append data to a resource (does not overwrite).
    Append,
    /// Execute a resource (binary, model, etc.).
    Execute,
    /// Delete a resource.
    Delete,
    /// Open an outgoing connection.
    Connect,
    /// Accept incoming connections.
    Listen,
    /// Run inference against a model.
    ModelInfer,
    /// Load a model into memory.
    ModelLoad,
    /// Spawn a child agent.
    AgentSpawn,
    /// Send a message to another agent.
    AgentSend,
    /// Enqueue a message on a kernel IPC channel (MB13.c). The matching
    /// resource is [`Resource::IpcChannel`]; the kernel `IpcSend`
    /// syscall consults a capability with this action.
    IpcSend,
    /// Dequeue a message from a kernel IPC channel (MB13.c). The
    /// matching resource is [`Resource::IpcChannel`]; the kernel
    /// `IpcReceive` syscall consults a capability with this action.
    IpcRecv,
    /// Map an MMIO region into the caller's address space
    /// (`NCIP-Driver-Framework-013` § S2). The matching resource is
    /// [`Resource::MmioRegion`]; the kernel `MmioMap` syscall
    /// (`SyscallNo = 70`) checks bounds against the token's region.
    MmioMap,
    /// Install a DMA window for device-initiated transfers
    /// (`NCIP-Driver-Framework-013` § S3). The matching resource is
    /// [`Resource::DmaWindow`]; the kernel `DmaMap` syscall
    /// (`SyscallNo = 71`) creates an IOMMU domain entry.
    DmaMap,
    /// Attach an interrupt line to a per-driver IPC channel
    /// (`NCIP-Driver-Framework-013` § S4). The matching resource is
    /// [`Resource::IrqLine`]; the kernel `IrqAttach` syscall
    /// (`SyscallNo = 72`) rejects shared IOAPIC lines (`EBUSY`).
    IrqAttach,
    /// Read a PCI configuration register
    /// (`NCIP-Driver-Framework-013` § S1). Reserved for diagnostics
    /// and bring-up sequences; the matching resource is
    /// [`Resource::PciDevice`].
    PciConfigRead,
    /// Write a PCI configuration register (e.g. command/status,
    /// BAR program, MSI-X enable; `NCIP-Driver-Framework-013` § S1).
    /// The matching resource is [`Resource::PciDevice`].
    PciConfigWrite,
    /// Load a signed driver image (`NCIP-Driver-Framework-013` § S5).
    /// The matching resource is [`Resource::Any`] (driver loading is
    /// a system-wide privilege held by a small set of issuers); the
    /// kernel `DriverLoad` syscall (`SyscallNo = 73`) atomically
    /// verifies BLAKE3(image) + Ed25519 signature against
    /// `KNOWN_ISSUERS`.
    DriverLoad,
    /// Unload a previously loaded driver
    /// (`NCIP-Driver-Framework-013` § S5). The matching resource is
    /// [`Resource::Any`]; tearing down IOMMU domains, MMIO mappings,
    /// and IRQ attachments is fully kernel-mediated.
    DriverUnload,
    /// Issue a kernel-mediated TEE probe instruction (TDCALL on Intel
    /// TDX, MSR write on AMD SEV-SNP; `NCIP-Driver-TEE-016` § S5/S6).
    /// The matching resource is [`Resource::Any`]; held only by the
    /// TEE driver. Routed through `SyscallNo = 74` (TDCALL) and
    /// `SyscallNo = 75` (MSR).
    TeeProbe,
    /// Map the GOP framebuffer (or a sub-window of it) into a Ring-3
    /// compositor's address space (TASK-18 / DE-C1, ADR-0040). The
    /// matching resource is [`Resource::Framebuffer`]; the kernel
    /// `DisplayMap` syscall (`SyscallNo = 79`) maps the framebuffer
    /// physical pages with NX + WRITABLE + USER + uncached flags. Held
    /// only by the display compositor (least privilege — distinct from
    /// [`Action::MmioMap`] so a compositor cannot map arbitrary device
    /// MMIO).
    DisplayMap,
}

// =============================================================================
// Resource
// =============================================================================

/// The target of an [`Action`].
///
/// Patterns match a single resource at a time; wildcard semantics live
/// inside each variant (e.g., a `Filesystem` path may end with `/*`).
/// We keep the variants small and well-typed; expanding to a richer
/// pattern grammar is a Phase 2+ decision behind an NCIP.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Resource {
    /// Any resource (the implicit-deny ceiling). Use sparingly — every
    /// occurrence is an audit-flagged "broad capability".
    Any,
    /// A filesystem path. Wildcard suffix `/**` matches any descendant.
    Filesystem(String),
    /// A network endpoint, formatted as `host:port` (IPv4/v6 or DNS
    /// name). Port `0` matches any port; host `*` matches any host.
    Network(String),
    /// A specific model identified by content hash.
    Model(ModelId),
    /// A specific agent.
    Agent(AgentId),
    /// A specific node.
    Node(NodeId),
    /// A kernel IPC channel identified by its kernel-allocated id
    /// (MB13.c). Paired with [`Action::IpcSend`] / [`Action::IpcRecv`].
    /// Channel ids are opaque; equality is the only meaningful relation.
    IpcChannel(u64),
    /// A PCI device identified by its segment/bus/device/function tuple
    /// (`NCIP-Driver-Framework-013` § S1). Subset semantics: byte-exact
    /// equality. Paired with [`Action::PciConfigRead`] /
    /// [`Action::PciConfigWrite`].
    PciDevice {
        /// `PCIe` segment (0 on systems without segments).
        segment: u16,
        /// PCI bus number `0..=255`.
        bus: u8,
        /// PCI device number `0..=31`.
        device: u8,
        /// PCI function number `0..=7`.
        function: u8,
    },
    /// A physical MMIO region (`NCIP-Driver-Framework-013` § S2). The
    /// region is half-open `[phys_base, phys_base + len)`. Subset
    /// semantics: range-contained (child range MUST lie entirely inside
    /// parent range). Paired with [`Action::MmioMap`].
    MmioRegion {
        /// Page-aligned physical base address.
        phys_base: u64,
        /// Length in bytes; MUST be a multiple of 4 KiB.
        len: u64,
    },
    /// An IOMMU-translated DMA window (`NCIP-Driver-Framework-013` § S3).
    /// Half-open `[iova_base, iova_base + len)`. Subset semantics:
    /// range-contained. Paired with [`Action::DmaMap`].
    DmaWindow {
        /// Page-aligned IO virtual address base.
        iova_base: u64,
        /// Length in bytes; MUST be a multiple of 4 KiB.
        len: u64,
    },
    /// An interrupt line (`NCIP-Driver-Framework-013` § S4). For IOAPIC
    /// pin-based interrupts this is the global system interrupt (GSI);
    /// for MSI/MSI-X it is the allocated vector. Subset semantics:
    /// byte-exact equality. Paired with [`Action::IrqAttach`].
    IrqLine(u16),
    /// The GOP framebuffer physical region (TASK-18 / DE-C1, ADR-0040).
    /// Half-open `[phys_base, phys_base + len)`. Subset semantics:
    /// range-contained (child range MUST lie entirely inside parent) —
    /// so a token scoped to the whole framebuffer authorises a
    /// `DisplayMap` of any page-aligned sub-window. Paired with
    /// [`Action::DisplayMap`].
    Framebuffer {
        /// Page-aligned physical base address of the framebuffer.
        phys_base: u64,
        /// Length in bytes; MUST be a multiple of 4 KiB.
        len: u64,
    },
}

impl Resource {
    /// Returns `true` iff `self` is at least as specific as `other`.
    ///
    /// "More specific" means every concrete resource that satisfies
    /// `self` also satisfies `other`. Wildcards in `other` may bind a
    /// concrete value in `self` (so `Filesystem("/data/x")` is more
    /// specific than `Filesystem("/data/**")`), but not vice versa.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            // `Any` is the universal set — anything is a subset of `Any`.
            // The `(Self::Any, _)` case where `_` is concrete is handled
            // by the catch-all wildcard arm at the bottom (returns false).
            (_, Self::Any) => true,
            (Self::Filesystem(a), Self::Filesystem(b)) => path_is_subset(a, b),
            (Self::Network(a), Self::Network(b)) => endpoint_is_subset(a, b),
            (Self::Model(a), Self::Model(b)) => a == b,
            (Self::Agent(a), Self::Agent(b)) => a == b,
            (Self::Node(a), Self::Node(b)) => a == b,
            // IPC channels are opaque kernel ids: subset == equality.
            // There is no wildcard for channels in MB13.c; an upstream
            // grant for a different channel id never authorises another.
            (Self::IpcChannel(a), Self::IpcChannel(b)) => a == b,
            // PCI BDF tuples: byte-exact equality (NCIP-013 § S1).
            (Self::PciDevice { .. }, Self::PciDevice { .. }) => self == other,
            // MMIO regions and DMA windows: child range MUST lie
            // entirely inside parent. Half-open semantics: end = base +
            // len computed in u128 to avoid u64 wrap-around when the
            // caller asks about the last page of the address space.
            // Cross-discriminant pairs `(MmioRegion, DmaWindow)` do
            // NOT match these arms — the `|` alternation between two
            // same-discriminant tuples is type-narrowed by the compiler.
            (
                Self::MmioRegion {
                    phys_base: a_base,
                    len: a_len,
                },
                Self::MmioRegion {
                    phys_base: b_base,
                    len: b_len,
                },
            )
            | (
                Self::DmaWindow {
                    iova_base: a_base,
                    len: a_len,
                },
                Self::DmaWindow {
                    iova_base: b_base,
                    len: b_len,
                },
            )
            | (
                Self::Framebuffer {
                    phys_base: a_base,
                    len: a_len,
                },
                Self::Framebuffer {
                    phys_base: b_base,
                    len: b_len,
                },
            ) => range_is_subset(*a_base, *a_len, *b_base, *b_len),
            // IRQ lines: byte-exact equality. NCIP-013 § S4 forbids
            // shared-line fan-out — a token for line N never authorises N+1.
            (Self::IrqLine(a), Self::IrqLine(b)) => a == b,
            // Cross-discriminant + (Any, concrete) → not a subset.
            _ => false,
        }
    }
}

// Half-open range containment with u128 widening so the upper bound
// arithmetic never wraps. Empty `len == 0` ranges are treated as a
// degenerate subset of any containing parent at the same base.
fn range_is_subset(child_base: u64, child_len: u64, parent_base: u64, parent_len: u64) -> bool {
    let child_end = u128::from(child_base) + u128::from(child_len);
    let parent_end = u128::from(parent_base) + u128::from(parent_len);
    child_base >= parent_base && child_end <= parent_end
}

// Filesystem path subset semantics:
// * Pattern ending in `/**` matches any path with that prefix.
// * Otherwise exact match.
//
// `a is_subset_of b` iff every concrete path matching `a` also matches `b`.
// Implementation kept minimal — the goal is to be obviously-correct, not
// fast. A future revision can add globbing.
//
// `option_if_let_else` is allowed because the nested `if let` reads
// closer to the spec ("if b ends with /**, then …") than an
// `Option::map_or_else` chain would.
#[allow(clippy::option_if_let_else)]
fn path_is_subset(a: &str, b: &str) -> bool {
    if let Some(b_prefix) = b.strip_suffix("/**") {
        // `b` matches any descendant of `b_prefix`. `a` is a subset iff
        // it's the same wildcard at a deeper level OR a concrete path
        // beneath `b_prefix`.
        if let Some(a_prefix) = a.strip_suffix("/**") {
            a_prefix == b_prefix || a_prefix.starts_with(&alloc::format!("{b_prefix}/"))
        } else {
            a == b_prefix || a.starts_with(&alloc::format!("{b_prefix}/"))
        }
    } else {
        // No wildcard in `b` -> exact match required.
        a == b
    }
}

// Network endpoint subset semantics:
// * `host:port` where host can be `*` and port can be `0` (= any).
// * `a is_subset_of b` iff host and port both match.
fn endpoint_is_subset(a: &str, b: &str) -> bool {
    let Some((a_host, a_port)) = a.rsplit_once(':') else {
        return false;
    };
    let Some((b_host, b_port)) = b.rsplit_once(':') else {
        return false;
    };
    let host_ok = b_host == "*" || a_host == b_host;
    let port_ok = b_port == "0" || a_port == b_port;
    host_ok && port_ok
}

// =============================================================================
// TimeWindow
// =============================================================================

/// A half-open `[not_before, not_after)` time window in seconds since
/// the Unix epoch.
///
/// Validity is checked against a caller-supplied "now" — this crate
/// intentionally does NOT call `SystemTime::now()` because it is
/// `no_std` and because the project policy mandates a monotonic
/// attestable clock.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive lower bound.
    pub not_before: u64,
    /// Exclusive upper bound.
    pub not_after: u64,
}

impl TimeWindow {
    /// Construct a window. `not_before` must be `<= not_after`; the
    /// constructor returns `None` otherwise.
    #[must_use]
    pub const fn new(not_before: u64, not_after: u64) -> Option<Self> {
        if not_before <= not_after {
            Some(Self {
                not_before,
                not_after,
            })
        } else {
            None
        }
    }

    /// Returns `true` iff `now` falls within `[not_before, not_after)`.
    #[must_use]
    pub const fn contains(&self, now: u64) -> bool {
        now >= self.not_before && now < self.not_after
    }

    /// Returns `true` iff this window is contained in `other`.
    #[must_use]
    pub const fn is_subset_of(&self, other: &Self) -> bool {
        self.not_before >= other.not_before && self.not_after <= other.not_after
    }

    /// Returns the duration of the window in seconds (`not_after -
    /// not_before`).
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        self.not_after - self.not_before
    }
}

// =============================================================================
// Caveat
// =============================================================================

/// A monotonic restriction applied during attenuation.
///
/// Caveats can ONLY restrict — never broaden. Every caveat appended in
/// the attenuation chain is checked against the original parent scope
/// at verification time; if any caveat does not hold, the capability
/// is rejected.
///
/// The variants here cover the common cases. The escape hatch
/// [`Caveat::Custom`] carries an opaque tag; downstream verifiers map
/// the tag to a domain-specific predicate via
/// [`crate::attenuation::CaveatPredicate`].
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Caveat {
    /// Tighten the time window (`not_after = min(not_after, t)`).
    ExpiresAt(u64),
    /// Tighten the time window (`not_before = max(not_before, t)`).
    NotBefore(u64),
    /// Restrict to a specific node (caller MUST be running on `node`).
    BoundToNode(NodeId),
    /// Restrict to a specific session.
    BoundToSession([u8; 16]),
    /// Domain-specific tag. The tag MUST be ASCII; the verifier looks
    /// it up in its [`crate::attenuation::CaveatPredicate`] table.
    Custom {
        /// ASCII tag identifying the predicate.
        tag: String,
        /// Opaque payload bytes interpreted by the predicate.
        payload: Vec<u8>,
    },
}

// =============================================================================
// Scope
// =============================================================================

/// The authority a capability grants: an action over a resource within
/// a time window, restricted by zero or more caveats.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Scope {
    /// The authorised action.
    pub action: Action,
    /// The resource the action applies to.
    pub resource: Resource,
    /// The time window during which the capability is valid.
    pub window: TimeWindow,
    /// Restrictions applied along the attenuation chain. Order is
    /// preserved for canonical encoding determinism.
    pub caveats: Vec<Caveat>,
}

impl Scope {
    /// Returns `true` iff `self` is at least as restrictive as `other`.
    ///
    /// Concretely, every (action, resource, time, caveat) request that
    /// satisfies `self` also satisfies `other`. This is the invariant
    /// that [`crate::attenuation::attenuate`] preserves.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        // Action must match exactly — no widening (e.g., Read does not
        // imply Write, even though "less" would be a misleading word).
        if self.action != other.action {
            return false;
        }
        if !self.resource.is_subset_of(&other.resource) {
            return false;
        }
        if !self.window.is_subset_of(&other.window) {
            return false;
        }
        // Every caveat in the parent must also be in the child. The
        // child may add MORE caveats (further restrictions) — that's
        // permitted.
        other.caveats.iter().all(|c| self.caveats.contains(c))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    fn id32(b: u8) -> NodeId {
        NodeId::from_attestation_hash([b; 32])
    }

    // ---- TimeWindow ---------------------------------------------------------

    #[test]
    fn timewindow_contains() {
        let w = TimeWindow::new(100, 200).unwrap();
        assert!(!w.contains(99));
        assert!(w.contains(100));
        assert!(w.contains(199));
        assert!(!w.contains(200)); // exclusive upper
    }

    #[test]
    fn timewindow_subset() {
        let parent = TimeWindow::new(100, 200).unwrap();
        let child = TimeWindow::new(120, 180).unwrap();
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn timewindow_rejects_inverted() {
        assert!(TimeWindow::new(200, 100).is_none());
    }

    #[test]
    fn timewindow_zero_duration_is_legal() {
        // Edge case: not_before == not_after means an empty (but valid)
        // window. `contains` returns false for every `now`.
        let w = TimeWindow::new(100, 100).unwrap();
        assert!(!w.contains(100));
        assert_eq!(w.duration_secs(), 0);
    }

    // ---- Resource subset ----------------------------------------------------

    #[test]
    fn resource_filesystem_exact_match() {
        let a = Resource::Filesystem("/data/x".to_string());
        let b = Resource::Filesystem("/data/x".to_string());
        assert!(a.is_subset_of(&b));
    }

    #[test]
    fn resource_filesystem_glob_subset() {
        let concrete = Resource::Filesystem("/data/x/y".to_string());
        let pattern = Resource::Filesystem("/data/**".to_string());
        assert!(concrete.is_subset_of(&pattern));
        assert!(!pattern.is_subset_of(&concrete));
    }

    #[test]
    fn resource_filesystem_glob_to_glob() {
        let inner = Resource::Filesystem("/data/x/**".to_string());
        let outer = Resource::Filesystem("/data/**".to_string());
        assert!(inner.is_subset_of(&outer));
        assert!(!outer.is_subset_of(&inner));
    }

    #[test]
    fn resource_filesystem_disjoint_paths() {
        let a = Resource::Filesystem("/data/x".to_string());
        let b = Resource::Filesystem("/etc/y".to_string());
        assert!(!a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    #[test]
    fn resource_network_exact() {
        let a = Resource::Network("api.example.com:443".to_string());
        let b = Resource::Network("api.example.com:443".to_string());
        assert!(a.is_subset_of(&b));
    }

    #[test]
    fn resource_network_host_wildcard() {
        let a = Resource::Network("api.example.com:443".to_string());
        let b = Resource::Network("*:443".to_string());
        assert!(a.is_subset_of(&b));
        assert!(!b.is_subset_of(&a));
    }

    #[test]
    fn resource_network_port_wildcard() {
        let a = Resource::Network("api.example.com:443".to_string());
        let b = Resource::Network("api.example.com:0".to_string());
        assert!(a.is_subset_of(&b));
    }

    #[test]
    fn resource_any_is_supremum() {
        let concrete = Resource::Filesystem("/x".to_string());
        assert!(concrete.is_subset_of(&Resource::Any));
        assert!(!Resource::Any.is_subset_of(&concrete));
    }

    #[test]
    fn resource_cross_kind_never_subset() {
        let f = Resource::Filesystem("/x".to_string());
        let n = Resource::Network("h:1".to_string());
        assert!(!f.is_subset_of(&n));
        assert!(!n.is_subset_of(&f));
    }

    #[test]
    fn resource_node_match_by_id() {
        assert!(Resource::Node(id32(1)).is_subset_of(&Resource::Node(id32(1))));
        assert!(!Resource::Node(id32(1)).is_subset_of(&Resource::Node(id32(2))));
    }

    // ---- Scope subset -------------------------------------------------------

    #[test]
    fn scope_subset_same_action_and_window() {
        let parent = Scope {
            action: Action::Read,
            resource: Resource::Filesystem("/data/**".to_string()),
            window: TimeWindow::new(100, 200).unwrap(),
            caveats: vec![],
        };
        let child = Scope {
            action: Action::Read,
            resource: Resource::Filesystem("/data/x".to_string()),
            window: TimeWindow::new(120, 180).unwrap(),
            caveats: vec![],
        };
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_action_mismatch_never_subset() {
        let read = Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(0, u64::MAX).unwrap(),
            caveats: vec![],
        };
        let write = Scope {
            action: Action::Write,
            resource: Resource::Any,
            window: TimeWindow::new(0, u64::MAX).unwrap(),
            caveats: vec![],
        };
        assert!(!read.is_subset_of(&write));
        assert!(!write.is_subset_of(&read));
    }

    #[test]
    fn resource_ipc_channel_subset_is_equality() {
        // Channel ids are opaque kernel handles — subset == equality.
        let ch_a = Resource::IpcChannel(7);
        let ch_b = Resource::IpcChannel(7);
        let ch_c = Resource::IpcChannel(8);
        assert!(ch_a.is_subset_of(&ch_b));
        assert!(!ch_a.is_subset_of(&ch_c));
        assert!(!ch_c.is_subset_of(&ch_a));
    }

    #[test]
    fn resource_ipc_channel_is_subset_of_any() {
        // Every concrete resource is a subset of `Any`; the IPC channel
        // variant is no exception. This matters because attenuation may
        // narrow `Any` down to a specific channel.
        let concrete = Resource::IpcChannel(42);
        assert!(concrete.is_subset_of(&Resource::Any));
        assert!(!Resource::Any.is_subset_of(&concrete));
    }

    #[test]
    fn resource_ipc_channel_disjoint_from_filesystem() {
        // Cross-kind comparisons never satisfy the subset relation, so a
        // filesystem capability can never accidentally authorise an IPC
        // operation and vice versa.
        let ch = Resource::IpcChannel(1);
        let fs = Resource::Filesystem("/dev/null".to_string());
        assert!(!ch.is_subset_of(&fs));
        assert!(!fs.is_subset_of(&ch));
    }

    #[test]
    fn action_ipc_send_recv_are_distinct() {
        // Sanity check that the two MB13.c additions are not aliased by
        // the derive(PartialEq) — protects against an accidental copy of
        // a variant.
        assert_ne!(Action::IpcSend, Action::IpcRecv);
        assert_ne!(Action::IpcSend, Action::AgentSend);
    }

    #[test]
    fn scope_ipc_send_subset_requires_matching_action_and_channel() {
        let parent = Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(1),
            window: TimeWindow::new(0, 100).unwrap(),
            caveats: vec![],
        };
        let same = Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(1),
            window: TimeWindow::new(10, 90).unwrap(),
            caveats: vec![],
        };
        let other_action = Scope {
            action: Action::IpcRecv,
            resource: Resource::IpcChannel(1),
            window: TimeWindow::new(10, 90).unwrap(),
            caveats: vec![],
        };
        let other_channel = Scope {
            action: Action::IpcSend,
            resource: Resource::IpcChannel(2),
            window: TimeWindow::new(10, 90).unwrap(),
            caveats: vec![],
        };
        assert!(same.is_subset_of(&parent));
        assert!(!other_action.is_subset_of(&parent));
        assert!(!other_channel.is_subset_of(&parent));
    }

    // ---- NCIP-013 driver framework: PCI / MMIO / DMA / IRQ ------------------

    fn pci(seg: u16, bus: u8, dev: u8, func: u8) -> Resource {
        Resource::PciDevice {
            segment: seg,
            bus,
            device: dev,
            function: func,
        }
    }

    #[test]
    fn resource_pci_device_byte_exact_subset() {
        let a = pci(0, 0x01, 0x00, 0);
        let b = pci(0, 0x01, 0x00, 0);
        let c = pci(0, 0x01, 0x00, 1);
        assert!(a.is_subset_of(&b));
        assert!(!a.is_subset_of(&c));
        assert!(!c.is_subset_of(&a));
    }

    #[test]
    fn resource_pci_device_subset_of_any() {
        let dev = pci(0, 0x00, 0x1F, 0x03);
        assert!(dev.is_subset_of(&Resource::Any));
        assert!(!Resource::Any.is_subset_of(&dev));
    }

    #[test]
    fn resource_mmio_region_range_contained() {
        let parent = Resource::MmioRegion {
            phys_base: 0xFEBC_0000,
            len: 0x0001_0000,
        };
        let child = Resource::MmioRegion {
            phys_base: 0xFEBC_2000,
            len: 0x0000_2000,
        };
        let outside = Resource::MmioRegion {
            phys_base: 0xFEBC_F000,
            len: 0x0000_2000,
        };
        assert!(child.is_subset_of(&parent));
        assert!(!outside.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn resource_mmio_region_upper_bound_no_wrap() {
        // A range that touches the last byte of the u64 address space
        // MUST NOT wrap; we use u128 widening inside `range_is_subset`.
        let parent = Resource::MmioRegion {
            phys_base: u64::MAX - 0xFFF,
            len: 0x1000,
        };
        // `parent` is `Copy`-eligible (only u64 + u64 fields), but the
        // outer `Resource` enum is not `Copy`; we deliberately rebuild
        // the child range so the test exercises distinct values rather
        // than reference equality.
        let child = Resource::MmioRegion {
            phys_base: u64::MAX - 0xFFF,
            len: 0x1000,
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn resource_dma_window_range_contained() {
        let parent = Resource::DmaWindow {
            iova_base: 0x1_0000_0000,
            len: 0x4000,
        };
        let child = Resource::DmaWindow {
            iova_base: 0x1_0000_1000,
            len: 0x1000,
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn resource_irq_line_byte_exact_subset() {
        assert!(Resource::IrqLine(33).is_subset_of(&Resource::IrqLine(33)));
        assert!(!Resource::IrqLine(33).is_subset_of(&Resource::IrqLine(34)));
        assert!(!Resource::IrqLine(34).is_subset_of(&Resource::IrqLine(33)));
    }

    #[test]
    fn driver_framework_actions_are_distinct() {
        // Sanity check: each Action discriminant from NCIP-013/016 stands
        // alone — protects against an accidental copy-paste duplicate.
        let actions = [
            Action::MmioMap,
            Action::DmaMap,
            Action::IrqAttach,
            Action::PciConfigRead,
            Action::PciConfigWrite,
            Action::DriverLoad,
            Action::DriverUnload,
            Action::TeeProbe,
        ];
        for (i, a) in actions.iter().enumerate() {
            for (j, b) in actions.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn scope_mmio_map_subset_matches_action_and_region() {
        let parent = Scope {
            action: Action::MmioMap,
            resource: Resource::MmioRegion {
                phys_base: 0xFEBC_0000,
                len: 0x0001_0000,
            },
            window: TimeWindow::new(0, 1000).unwrap(),
            caveats: vec![],
        };
        let child = Scope {
            action: Action::MmioMap,
            resource: Resource::MmioRegion {
                phys_base: 0xFEBC_4000,
                len: 0x0000_1000,
            },
            window: TimeWindow::new(0, 1000).unwrap(),
            caveats: vec![],
        };
        let wrong_action = Scope {
            action: Action::DmaMap,
            resource: child.resource.clone(),
            window: child.window,
            caveats: vec![],
        };
        assert!(child.is_subset_of(&parent));
        assert!(!wrong_action.is_subset_of(&parent));
    }

    #[test]
    fn scope_display_map_subset_matches_framebuffer_subwindow() {
        // TASK-18 / ADR-0040: a token scoped to the whole framebuffer
        // authorises a DisplayMap of any page-aligned sub-window, but not a
        // window that runs past the framebuffer end, nor a different action.
        let parent = Scope {
            action: Action::DisplayMap,
            resource: Resource::Framebuffer {
                phys_base: 0x3840_0000_0000,
                len: 0x0080_0000, // 8 MiB framebuffer
            },
            window: TimeWindow::new(0, 1000).unwrap(),
            caveats: vec![],
        };
        let child_subwindow = Scope {
            action: Action::DisplayMap,
            resource: Resource::Framebuffer {
                phys_base: 0x3840_0000_1000,
                len: 0x0000_2000,
            },
            window: TimeWindow::new(0, 1000).unwrap(),
            caveats: vec![],
        };
        let child_overruns = Scope {
            action: Action::DisplayMap,
            resource: Resource::Framebuffer {
                phys_base: 0x3840_0000_0000,
                len: 0x0080_1000, // 4 KiB past the parent end
            },
            window: TimeWindow::new(0, 1000).unwrap(),
            caveats: vec![],
        };
        let wrong_action = Scope {
            action: Action::MmioMap,
            resource: child_subwindow.resource.clone(),
            window: child_subwindow.window,
            caveats: vec![],
        };
        assert!(child_subwindow.is_subset_of(&parent));
        assert!(!child_overruns.is_subset_of(&parent));
        assert!(!wrong_action.is_subset_of(&parent));
    }

    #[test]
    fn scope_child_must_carry_parent_caveats() {
        let parent_caveat = Caveat::BoundToNode(id32(1));
        let parent = Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(0, 100).unwrap(),
            caveats: vec![parent_caveat.clone()],
        };
        let child_missing = Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(0, 100).unwrap(),
            caveats: vec![],
        };
        assert!(!child_missing.is_subset_of(&parent));

        let child_ok = Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(0, 100).unwrap(),
            caveats: vec![parent_caveat],
        };
        assert!(child_ok.is_subset_of(&parent));
    }
}
