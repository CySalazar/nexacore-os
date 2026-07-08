//! Multi-namespace validation and mapping.
//!
//! Enumerates every active NSID the controller reported in the
//! `Identify(ActiveNsList)` response, runs per-namespace validation
//! (sector-size compatibility, non-zero size), and stores the result
//! in a fixed-capacity map keyed by NSID. The map enforces namespace
//! isolation: each NSID owns its own validated metadata, and the
//! driver can query whether a given NSID is admitted before issuing
//! IO commands against it.
//!
//! ## Phase-1 scope
//!
//! Phase-1 admits only namespaces whose active LBA format uses
//! 4 KiB sectors (`LBADS = 12`) per NCIP-Driver-NVMe-014 § S6
//! step 10. Namespaces with other sector sizes are recorded as
//! rejected (with the observed LBADS) so the driver can log the
//! rejection without silently ignoring the namespace.
//!
//! The map capacity is bounded by [`MAX_NAMESPACE_SLOTS`] (16) —
//! generous for Phase-1 single-controller bring-up and small enough
//! to live on the stack without heap allocation.

use crate::identify::{
    ActiveNsListView, IDENTIFY_RESPONSE_BYTES, IdentifyError, IdentifyNamespace,
};

/// Maximum number of validated namespace slots the map holds.
///
/// Phase-1 targets single-controller bring-up with 1–2 namespaces;
/// 16 slots accommodate multi-namespace NVMe controllers without
/// heap allocation. A controller reporting more than 16 active
/// namespaces will have the excess silently truncated (the map
/// records how many were seen vs. how many fit).
pub const MAX_NAMESPACE_SLOTS: usize = 16;

/// Validated metadata for a single NVMe namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceDescriptor {
    nsid: u32,
    nsze: u64,
    ncap: u64,
    lbads: u8,
    byte_size: u64,
}

impl NamespaceDescriptor {
    /// Construct a descriptor from pre-validated fields.
    ///
    /// The caller is responsible for ensuring the fields are
    /// consistent (e.g. `byte_size == nsze << lbads`). This
    /// constructor is used by the live image bring-up where the
    /// Identify Namespace response has already been validated.
    #[must_use]
    pub const fn from_validated(
        nsid: u32,
        nsze: u64,
        ncap: u64,
        lbads: u8,
        byte_size: u64,
    ) -> Self {
        Self {
            nsid,
            nsze,
            ncap,
            lbads,
            byte_size,
        }
    }

    /// The namespace identifier.
    #[must_use]
    pub const fn nsid(&self) -> u32 {
        self.nsid
    }

    /// Namespace Size in sectors (NSZE field).
    #[must_use]
    pub const fn nsze(&self) -> u64 {
        self.nsze
    }

    /// Namespace Capacity in sectors (NCAP field).
    #[must_use]
    pub const fn ncap(&self) -> u64 {
        self.ncap
    }

    /// LBA Data Size as `log2(sector_size_in_bytes)`.
    #[must_use]
    pub const fn lbads(&self) -> u8 {
        self.lbads
    }

    /// Total byte capacity (`NSZE << LBADS`).
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.byte_size
    }
}

/// Reason a namespace was rejected during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// The Identify Namespace response page was undersized.
    PageTooSmall,
    /// `LBADS != 12` — sector size is not 4 KiB.
    UnsupportedLbads {
        /// The actual `LBADS` value the namespace reported.
        observed: u8,
    },
    /// `NSZE == 0` — the namespace has zero capacity.
    ZeroSize,
}

/// Entry in the namespace map: either a validated descriptor or a
/// rejection record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceEntry {
    /// The namespace passed all validation checks.
    Valid(NamespaceDescriptor),
    /// The namespace was rejected for the stated reason.
    Rejected {
        /// The NSID that was rejected.
        nsid: u32,
        /// Why it was rejected.
        reason: RejectReason,
    },
}

impl NamespaceEntry {
    /// Returns the NSID regardless of validation outcome.
    #[must_use]
    pub const fn nsid(&self) -> u32 {
        match self {
            Self::Valid(d) => d.nsid,
            Self::Rejected { nsid, .. } => *nsid,
        }
    }

    /// Returns `true` if the namespace passed validation.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

/// Errors [`NamespaceMap::build`] can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceMapError {
    /// The Active Namespace List response page was undersized.
    NsListPageTooSmall,
    /// The controller reported zero active namespaces.
    NoActiveNamespaces,
}

/// Fixed-capacity map of validated NVMe namespaces.
///
/// Built from the `Identify(ActiveNsList)` response page and a
/// closure that resolves each NSID to its 4 KiB Identify Namespace
/// response page. The map records up to [`MAX_NAMESPACE_SLOTS`]
/// entries (valid or rejected); excess NSIDs are counted but not
/// stored.
#[derive(Debug)]
pub struct NamespaceMap {
    entries: [Option<NamespaceEntry>; MAX_NAMESPACE_SLOTS],
    len: usize,
    total_active: usize,
    valid_count: usize,
}

impl NamespaceMap {
    /// Build the map from raw Identify response pages.
    ///
    /// `ns_list_page` is the 4 KiB `Identify(ActiveNsList)` response.
    /// `resolve_ns_page` is called for each active NSID with the NSID
    /// as argument; it must return the 4 KiB `Identify(Namespace)`
    /// response page for that NSID, or `None` if the page could not
    /// be fetched (in which case the namespace is skipped entirely —
    /// not recorded as rejected, because the failure is transport-level
    /// rather than namespace-level).
    ///
    /// # Errors
    ///
    /// - [`NamespaceMapError::NsListPageTooSmall`] if `ns_list_page`
    ///   is shorter than 4 KiB.
    /// - [`NamespaceMapError::NoActiveNamespaces`] if the controller
    ///   reports zero active NSIDs.
    pub fn build<F>(ns_list_page: &[u8], mut resolve_ns_page: F) -> Result<Self, NamespaceMapError>
    where
        F: FnMut(u32) -> Option<[u8; IDENTIFY_RESPONSE_BYTES]>,
    {
        let ns_list = ActiveNsListView::new(ns_list_page)
            .map_err(|_| NamespaceMapError::NsListPageTooSmall)?;

        let mut entries = [None; MAX_NAMESPACE_SLOTS];
        let mut len = 0;
        let mut total_active = 0;
        let mut valid_count = 0;

        for nsid in ns_list.iter_nsids() {
            total_active += 1;

            if len >= MAX_NAMESPACE_SLOTS {
                continue;
            }

            let Some(ns_page) = resolve_ns_page(nsid) else {
                continue;
            };

            let entry = validate_namespace(nsid, &ns_page);
            if entry.is_valid() {
                valid_count += 1;
            }
            if let Some(slot) = entries.get_mut(len) {
                *slot = Some(entry);
            }
            len += 1;
        }

        if total_active == 0 {
            return Err(NamespaceMapError::NoActiveNamespaces);
        }

        Ok(Self {
            entries,
            len,
            total_active,
            valid_count,
        })
    }

    /// Number of entries stored (valid + rejected, up to
    /// [`MAX_NAMESPACE_SLOTS`]).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the map contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total active NSIDs the controller reported (may exceed
    /// [`MAX_NAMESPACE_SLOTS`]).
    #[must_use]
    pub const fn total_active(&self) -> usize {
        self.total_active
    }

    /// Number of namespaces that passed validation.
    #[must_use]
    pub const fn valid_count(&self) -> usize {
        self.valid_count
    }

    /// Look up a namespace entry by NSID. Returns `None` if the
    /// NSID was not enumerated or was truncated.
    #[must_use]
    pub fn get(&self, nsid: u32) -> Option<&NamespaceEntry> {
        self.entries
            .iter()
            .take(self.len)
            .flatten()
            .find(|e| e.nsid() == nsid)
    }

    /// Returns the first valid namespace descriptor, or `None` if
    /// no namespace passed validation.
    #[must_use]
    pub fn first_valid(&self) -> Option<&NamespaceDescriptor> {
        self.entries
            .iter()
            .take(self.len)
            .flatten()
            .find_map(|e| match e {
                NamespaceEntry::Valid(d) => Some(d),
                NamespaceEntry::Rejected { .. } => None,
            })
    }

    /// Iterate over all stored entries (valid and rejected).
    pub fn iter(&self) -> impl Iterator<Item = &NamespaceEntry> {
        self.entries.iter().take(self.len).flatten()
    }

    /// Returns `true` if the given NSID is admitted (passed
    /// validation and is present in the map).
    #[must_use]
    pub fn is_admitted(&self, nsid: u32) -> bool {
        self.get(nsid)
            .is_some_and(|e| matches!(e, NamespaceEntry::Valid(_)))
    }
}

/// Validate a single namespace against Phase-1 requirements.
fn validate_namespace(nsid: u32, ns_page: &[u8]) -> NamespaceEntry {
    let ns_view = match IdentifyNamespace::new(ns_page) {
        Ok(v) => v,
        Err(IdentifyError::PageTooSmall) => {
            return NamespaceEntry::Rejected {
                nsid,
                reason: RejectReason::PageTooSmall,
            };
        }
        Err(IdentifyError::UnsupportedLbads { observed }) => {
            return NamespaceEntry::Rejected {
                nsid,
                reason: RejectReason::UnsupportedLbads { observed },
            };
        }
    };

    if ns_view.nsze() == 0 {
        return NamespaceEntry::Rejected {
            nsid,
            reason: RejectReason::ZeroSize,
        };
    }

    match ns_view.validated_byte_size() {
        Ok(byte_size) => NamespaceEntry::Valid(NamespaceDescriptor {
            nsid,
            nsze: ns_view.nsze(),
            ncap: ns_view.ncap(),
            lbads: ns_view.lbads(),
            byte_size,
        }),
        Err(IdentifyError::UnsupportedLbads { observed }) => NamespaceEntry::Rejected {
            nsid,
            reason: RejectReason::UnsupportedLbads { observed },
        },
        Err(IdentifyError::PageTooSmall) => NamespaceEntry::Rejected {
            nsid,
            reason: RejectReason::PageTooSmall,
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "host tests pre-allocate fixed 4 KiB pages and write canonical NVMe field offsets in-place"
)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::identify::{IdentifyNamespace, PHASE_1_REQUIRED_LBADS};

    fn zero_page() -> [u8; IDENTIFY_RESPONSE_BYTES] {
        [0u8; IDENTIFY_RESPONSE_BYTES]
    }

    fn ns_list_with_nsids(nsids: &[u32]) -> [u8; IDENTIFY_RESPONSE_BYTES] {
        let mut page = zero_page();
        for (i, &nsid) in nsids.iter().enumerate() {
            let off = i * 4;
            page[off..off + 4].copy_from_slice(&nsid.to_le_bytes());
        }
        page
    }

    fn valid_ns_page(nsze: u64, ncap: u64) -> [u8; IDENTIFY_RESPONSE_BYTES] {
        let mut page = zero_page();
        page[..8].copy_from_slice(&nsze.to_le_bytes());
        page[8..16].copy_from_slice(&ncap.to_le_bytes());
        page[IdentifyNamespace::FLBAS_OFFSET] = 0;
        page[IdentifyNamespace::LBAF_BASE_OFFSET + 2] = PHASE_1_REQUIRED_LBADS;
        page
    }

    fn ns_page_with_lbads(nsze: u64, lbads: u8) -> [u8; IDENTIFY_RESPONSE_BYTES] {
        let mut page = zero_page();
        page[..8].copy_from_slice(&nsze.to_le_bytes());
        page[8..16].copy_from_slice(&nsze.to_le_bytes());
        page[IdentifyNamespace::FLBAS_OFFSET] = 0;
        page[IdentifyNamespace::LBAF_BASE_OFFSET + 2] = lbads;
        page
    }

    // -------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------

    #[test]
    fn max_namespace_slots_is_16() {
        assert_eq!(MAX_NAMESPACE_SLOTS, 16);
    }

    // -------------------------------------------------------------------
    // NamespaceDescriptor accessors
    // -------------------------------------------------------------------

    #[test]
    fn descriptor_accessors_return_stored_values() {
        let d = NamespaceDescriptor {
            nsid: 1,
            nsze: 1024,
            ncap: 2048,
            lbads: 12,
            byte_size: 1024 * 4096,
        };
        assert_eq!(d.nsid(), 1);
        assert_eq!(d.nsze(), 1024);
        assert_eq!(d.ncap(), 2048);
        assert_eq!(d.lbads(), 12);
        assert_eq!(d.byte_size(), 1024 * 4096);
    }

    // -------------------------------------------------------------------
    // NamespaceEntry
    // -------------------------------------------------------------------

    #[test]
    fn entry_nsid_returns_nsid_for_valid_and_rejected() {
        let valid = NamespaceEntry::Valid(NamespaceDescriptor {
            nsid: 1,
            nsze: 100,
            ncap: 100,
            lbads: 12,
            byte_size: 100 * 4096,
        });
        let rejected = NamespaceEntry::Rejected {
            nsid: 2,
            reason: RejectReason::ZeroSize,
        };
        assert_eq!(valid.nsid(), 1);
        assert_eq!(rejected.nsid(), 2);
    }

    #[test]
    fn entry_is_valid_distinguishes_valid_from_rejected() {
        let valid = NamespaceEntry::Valid(NamespaceDescriptor {
            nsid: 1,
            nsze: 100,
            ncap: 100,
            lbads: 12,
            byte_size: 100 * 4096,
        });
        let rejected = NamespaceEntry::Rejected {
            nsid: 2,
            reason: RejectReason::ZeroSize,
        };
        assert!(valid.is_valid());
        assert!(!rejected.is_valid());
    }

    // -------------------------------------------------------------------
    // NamespaceMap::build — happy paths
    // -------------------------------------------------------------------

    #[test]
    fn build_single_valid_namespace() {
        let ns_list = ns_list_with_nsids(&[1]);
        let ns1_page = valid_ns_page(1024, 1024);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            assert_eq!(nsid, 1);
            Some(ns1_page)
        })
        .unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(map.total_active(), 1);
        assert_eq!(map.valid_count(), 1);
        assert!(!map.is_empty());
        assert!(map.is_admitted(1));

        let desc = map.first_valid().unwrap();
        assert_eq!(desc.nsid(), 1);
        assert_eq!(desc.nsze(), 1024);
        assert_eq!(desc.byte_size(), 1024 * 4096);
    }

    #[test]
    fn build_multiple_valid_namespaces() {
        let ns_list = ns_list_with_nsids(&[1, 2, 3]);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            let nsze = u64::from(nsid) * 512;
            Some(valid_ns_page(nsze, nsze))
        })
        .unwrap();

        assert_eq!(map.len(), 3);
        assert_eq!(map.total_active(), 3);
        assert_eq!(map.valid_count(), 3);

        for nsid in 1..=3 {
            assert!(map.is_admitted(nsid));
            let entry = map.get(nsid).unwrap();
            let NamespaceEntry::Valid(d) = entry else {
                panic!("expected Valid for NSID {nsid}");
            };
            assert_eq!(d.nsze(), u64::from(nsid) * 512);
        }

        assert_eq!(map.first_valid().unwrap().nsid(), 1);
    }

    // -------------------------------------------------------------------
    // NamespaceMap::build — mixed valid + rejected
    // -------------------------------------------------------------------

    #[test]
    fn build_mixed_valid_and_rejected_namespaces() {
        let ns_list = ns_list_with_nsids(&[1, 2, 3]);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            match nsid {
                1 => Some(valid_ns_page(1024, 1024)),
                2 => Some(ns_page_with_lbads(1024, 9)), // 512-byte sectors → rejected
                3 => Some(valid_ns_page(2048, 2048)),
                _ => None,
            }
        })
        .unwrap();

        assert_eq!(map.len(), 3);
        assert_eq!(map.valid_count(), 2);
        assert!(map.is_admitted(1));
        assert!(!map.is_admitted(2));
        assert!(map.is_admitted(3));

        let entry2 = map.get(2).unwrap();
        assert_eq!(
            *entry2,
            NamespaceEntry::Rejected {
                nsid: 2,
                reason: RejectReason::UnsupportedLbads { observed: 9 }
            }
        );

        assert_eq!(map.first_valid().unwrap().nsid(), 1);
    }

    #[test]
    fn build_namespace_with_zero_size_is_rejected() {
        let ns_list = ns_list_with_nsids(&[1]);
        let map = NamespaceMap::build(&ns_list, |_| {
            Some(valid_ns_page(0, 0)) // NSZE = 0
        })
        .unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(map.valid_count(), 0);
        assert!(!map.is_admitted(1));

        let entry = map.get(1).unwrap();
        assert_eq!(
            *entry,
            NamespaceEntry::Rejected {
                nsid: 1,
                reason: RejectReason::ZeroSize,
            }
        );
        assert!(map.first_valid().is_none());
    }

    // -------------------------------------------------------------------
    // NamespaceMap::build — error paths
    // -------------------------------------------------------------------

    #[test]
    fn build_rejects_undersized_ns_list_page() {
        let small = vec![0u8; IDENTIFY_RESPONSE_BYTES - 1];
        let result = NamespaceMap::build(&small, |_| None);
        assert!(matches!(result, Err(NamespaceMapError::NsListPageTooSmall)));
    }

    #[test]
    fn build_rejects_empty_ns_list() {
        let empty = zero_page();
        let result = NamespaceMap::build(&empty, |_| None);
        assert!(matches!(result, Err(NamespaceMapError::NoActiveNamespaces)));
    }

    // -------------------------------------------------------------------
    // NamespaceMap::build — capacity overflow
    // -------------------------------------------------------------------

    #[test]
    fn build_truncates_at_max_namespace_slots() {
        let mut nsids = [0u32; 20];
        for (i, slot) in nsids.iter_mut().enumerate() {
            *slot = u32::try_from(i).expect("20 fits u32") + 1;
        }
        let ns_list = ns_list_with_nsids(&nsids);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            Some(valid_ns_page(u64::from(nsid) * 100, u64::from(nsid) * 100))
        })
        .unwrap();

        assert_eq!(map.len(), MAX_NAMESPACE_SLOTS);
        assert_eq!(map.total_active(), 20);
        assert_eq!(map.valid_count(), MAX_NAMESPACE_SLOTS);

        // First 16 are stored.
        for nsid in 1..=16 {
            assert!(map.is_admitted(nsid));
        }
        // 17–20 are truncated.
        for nsid in 17..=20 {
            assert!(!map.is_admitted(nsid));
        }
    }

    // -------------------------------------------------------------------
    // NamespaceMap::build — resolve_ns_page returns None
    // -------------------------------------------------------------------

    #[test]
    fn build_skips_namespaces_with_unresolvable_page() {
        let ns_list = ns_list_with_nsids(&[1, 2, 3]);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            if nsid == 2 {
                None // transport failure
            } else {
                Some(valid_ns_page(1024, 1024))
            }
        })
        .unwrap();

        assert_eq!(map.len(), 2); // 1 and 3 stored; 2 skipped
        assert_eq!(map.total_active(), 3);
        assert_eq!(map.valid_count(), 2);
        assert!(map.is_admitted(1));
        assert!(!map.is_admitted(2)); // not in map
        assert!(map.is_admitted(3));
    }

    // -------------------------------------------------------------------
    // NamespaceMap — isolation
    // -------------------------------------------------------------------

    #[test]
    fn namespace_isolation_each_nsid_has_independent_metadata() {
        let ns_list = ns_list_with_nsids(&[1, 2]);
        let map = NamespaceMap::build(&ns_list, |nsid| match nsid {
            1 => Some(valid_ns_page(1000, 1000)),
            2 => Some(valid_ns_page(2000, 2000)),
            _ => None,
        })
        .unwrap();

        let NamespaceEntry::Valid(d1) = map.get(1).unwrap() else {
            panic!("expected valid")
        };
        let NamespaceEntry::Valid(d2) = map.get(2).unwrap() else {
            panic!("expected valid")
        };

        assert_ne!(d1.nsze(), d2.nsze());
        assert_eq!(d1.nsze(), 1000);
        assert_eq!(d2.nsze(), 2000);
        assert_eq!(d1.byte_size(), 1000 * 4096);
        assert_eq!(d2.byte_size(), 2000 * 4096);
    }

    // -------------------------------------------------------------------
    // NamespaceMap — iterator
    // -------------------------------------------------------------------

    #[test]
    fn iter_yields_all_stored_entries() {
        let ns_list = ns_list_with_nsids(&[5, 10]);
        let map = NamespaceMap::build(&ns_list, |nsid| {
            Some(valid_ns_page(u64::from(nsid) * 100, u64::from(nsid) * 100))
        })
        .unwrap();

        let nsids: alloc::vec::Vec<u32> = map.iter().map(NamespaceEntry::nsid).collect();
        assert_eq!(nsids, alloc::vec![5, 10]);
    }

    // -------------------------------------------------------------------
    // RejectReason taxonomy
    // -------------------------------------------------------------------

    #[test]
    fn reject_reason_variants_are_distinguishable() {
        let a = RejectReason::PageTooSmall;
        let b = RejectReason::UnsupportedLbads { observed: 9 };
        let c = RejectReason::ZeroSize;
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    // -------------------------------------------------------------------
    // NamespaceMapError taxonomy
    // -------------------------------------------------------------------

    #[test]
    fn namespace_map_error_variants_are_distinguishable() {
        let a = NamespaceMapError::NsListPageTooSmall;
        let b = NamespaceMapError::NoActiveNamespaces;
        assert_ne!(a, b);
    }

    // -------------------------------------------------------------------
    // validate_namespace — undersized page
    // -------------------------------------------------------------------

    #[test]
    fn validate_namespace_rejects_undersized_page() {
        let small = [0u8; IDENTIFY_RESPONSE_BYTES - 1];
        let entry = validate_namespace(1, &small);
        assert_eq!(
            entry,
            NamespaceEntry::Rejected {
                nsid: 1,
                reason: RejectReason::PageTooSmall,
            }
        );
    }
}
