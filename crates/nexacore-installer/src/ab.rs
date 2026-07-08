//! A/B (seamless) update partitioning and slot state (WS11-05.1/.2).
//!
//! A NexaCore system installs onto **two** root slots that share one ESP: an
//! update is written to the inactive slot while the active slot keeps running,
//! then the bootloader is pointed at the new slot on next boot. If the new slot
//! fails to boot successfully within its allotted tries, the bootloader rolls
//! back to the previous slot.
//!
//! - WS11-05.1 defines the A/B partition scheme ([`Slot`], [`ab_root_partition`]).
//! - WS11-05.2 tracks the active/inactive slot with the Android-style
//!   `boot_control` model ([`AbState`]): each slot carries a priority, a
//!   remaining-tries counter, and a successful-boot flag; the bootloader picks
//!   the highest-priority *bootable* slot, decrements tries on each attempt, and
//!   marks a slot unbootable once its tries are exhausted without success.
//!
//! Pure state — no I/O. `no_std + alloc`.

use alloc::string::ToString;

use crate::gpt::{Guid, Partition};

/// Maximum slot priority (Android `boot_control` uses a 4-bit field).
pub const MAX_PRIORITY: u8 = 15;
/// Maximum boot tries granted to a freshly installed slot (3-bit field).
pub const MAX_TRIES: u8 = 7;

/// One of the two update slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Slot A.
    A,
    /// Slot B.
    B,
}

impl Slot {
    /// The other slot.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    /// The array index of this slot (`A` = 0, `B` = 1).
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    /// The conventional root partition label for this slot.
    #[must_use]
    pub fn root_name(self) -> &'static str {
        match self {
            Self::A => "nexacore-root-a",
            Self::B => "nexacore-root-b",
        }
    }

    /// A stable unique partition GUID for this slot's root.
    #[must_use]
    pub fn root_unique_guid(self) -> Guid {
        // Distinct, deterministic per-slot unique GUIDs (the installer may
        // override with random ones; these keep the scheme self-describing).
        match self {
            Self::A => Guid::from_fields(0x0A0A_0A0A, 0, 0, [0xA; 8]),
            Self::B => Guid::from_fields(0x0B0B_0B0B, 0, 0, [0xB; 8]),
        }
    }
}

/// Build the root [`Partition`] for `slot` spanning `first_lba..=last_lba`
/// (WS11-05.1). Both slots share the `NEXACORE_ROOT` type GUID and differ by
/// unique GUID and label.
#[must_use]
pub fn ab_root_partition(slot: Slot, first_lba: u64, last_lba: u64) -> Partition {
    Partition {
        type_guid: Guid::NEXACORE_ROOT,
        unique_guid: slot.root_unique_guid(),
        first_lba,
        last_lba,
        attributes: 0,
        name: slot.root_name().to_string(),
    }
}

/// The `boot_control` metadata for one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotInfo {
    /// Boot priority (higher wins; 0 = never boot).
    pub priority: u8,
    /// Remaining boot attempts before the slot is considered failed.
    pub tries_remaining: u8,
    /// Whether the slot has booted successfully at least once.
    pub successful: bool,
}

impl SlotInfo {
    /// A slot the bootloader may attempt: either proven good, or still has
    /// tries left, and not explicitly disabled (priority 0).
    #[must_use]
    pub fn is_bootable(self) -> bool {
        self.priority > 0 && (self.successful || self.tries_remaining > 0)
    }
}

/// The persisted A/B slot state (the "boot control block").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbState {
    slots: [SlotInfo; 2],
}

impl Default for AbState {
    fn default() -> Self {
        Self::new()
    }
}

impl AbState {
    /// A fresh install: slot A is the committed active slot, slot B is empty.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: [
                SlotInfo {
                    priority: MAX_PRIORITY,
                    tries_remaining: 0,
                    successful: true,
                },
                SlotInfo {
                    priority: 0,
                    tries_remaining: 0,
                    successful: false,
                },
            ],
        }
    }

    /// The metadata for `slot`.
    #[must_use]
    pub fn slot(self, slot: Slot) -> SlotInfo {
        let [a, b] = self.slots;
        match slot {
            Slot::A => a,
            Slot::B => b,
        }
    }

    fn slot_mut(&mut self, slot: Slot) -> &mut SlotInfo {
        let [a, b] = &mut self.slots;
        match slot {
            Slot::A => a,
            Slot::B => b,
        }
    }

    /// The slot the bootloader would boot now: the highest-priority bootable
    /// slot (ties resolve to A). `None` if neither slot is bootable.
    #[must_use]
    pub fn boot_slot(self) -> Option<Slot> {
        let (a, b) = (self.slot(Slot::A), self.slot(Slot::B));
        match (a.is_bootable(), b.is_bootable()) {
            (true, true) => {
                if b.priority > a.priority {
                    Some(Slot::B)
                } else {
                    Some(Slot::A)
                }
            }
            (true, false) => Some(Slot::A),
            (false, true) => Some(Slot::B),
            (false, false) => None,
        }
    }

    /// The slot an update should be written to: the inactive one.
    #[must_use]
    pub fn target_slot(self) -> Slot {
        self.boot_slot().unwrap_or(Slot::A).other()
    }

    /// Begin writing an update into `target`: mark it not-bootable while the
    /// write is in progress so a crash mid-flash cannot boot a partial slot.
    pub fn begin_update(&mut self, target: Slot) {
        *self.slot_mut(target) = SlotInfo {
            priority: 0,
            tries_remaining: 0,
            successful: false,
        };
    }

    /// Finish an update to `target`: make it the preferred boot slot with a full
    /// tries budget, and lower the previously active slot's priority so it stays
    /// available only as a rollback.
    pub fn finish_update(&mut self, target: Slot) {
        let previous = target.other();
        let prev_priority = self.slot(previous).priority.min(MAX_PRIORITY - 1);
        self.slot_mut(previous).priority = prev_priority;
        *self.slot_mut(target) = SlotInfo {
            priority: MAX_PRIORITY,
            tries_remaining: MAX_TRIES,
            successful: false,
        };
    }

    /// Record a boot attempt of `slot`: if it is not yet proven successful,
    /// consume one try. Once the tries reach zero the slot is no longer bootable
    /// ([`SlotInfo::is_bootable`]) — its priority is left intact so the state
    /// still records it as the *intended* slot ([`Self::is_rolling_back`]) — so
    /// the next boot falls back to the other slot.
    pub fn record_boot(&mut self, slot: Slot) {
        let info = self.slot_mut(slot);
        if info.successful {
            return;
        }
        info.tries_remaining = info.tries_remaining.saturating_sub(1);
    }

    /// Mark `slot` as having booted successfully: it is committed and no longer
    /// consumes tries.
    pub fn mark_successful(&mut self, slot: Slot) {
        let info = self.slot_mut(slot);
        info.successful = true;
        info.tries_remaining = 0;
        info.priority = MAX_PRIORITY;
    }

    /// Whether the highest-priority slot is unbootable so booting falls back to
    /// the other slot (a rollback is in effect).
    #[must_use]
    pub fn is_rolling_back(self) -> bool {
        let top = if self.slot(Slot::B).priority > self.slot(Slot::A).priority {
            Slot::B
        } else {
            Slot::A
        };
        self.boot_slot().is_some_and(|boot| boot != top)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_gives_distinct_ab_root_partitions() {
        let a = ab_root_partition(Slot::A, 100, 200);
        let b = ab_root_partition(Slot::B, 201, 300);
        assert_eq!(a.type_guid, Guid::NEXACORE_ROOT);
        assert_eq!(b.type_guid, Guid::NEXACORE_ROOT);
        assert_ne!(a.unique_guid, b.unique_guid);
        assert_eq!(a.name, "nexacore-root-a");
        assert_eq!(b.name, "nexacore-root-b");
        assert_eq!(Slot::A.other(), Slot::B);
    }

    #[test]
    fn fresh_state_boots_slot_a() {
        let st = AbState::new();
        assert_eq!(st.boot_slot(), Some(Slot::A));
        assert_eq!(st.target_slot(), Slot::B);
        assert!(st.slot(Slot::A).is_bootable());
        assert!(!st.slot(Slot::B).is_bootable());
    }

    #[test]
    fn update_flow_switches_to_new_slot_on_success() {
        let mut st = AbState::new();
        let target = st.target_slot(); // B
        st.begin_update(target);
        assert!(!st.slot(target).is_bootable()); // not bootable mid-flash
        st.finish_update(target);
        // The new slot is now preferred.
        assert_eq!(st.boot_slot(), Some(Slot::B));
        assert!(!st.is_rolling_back());
        // First boot of B consumes a try, then it is marked successful.
        st.record_boot(Slot::B);
        assert_eq!(st.slot(Slot::B).tries_remaining, MAX_TRIES - 1);
        st.mark_successful(Slot::B);
        assert!(st.slot(Slot::B).successful);
        assert_eq!(st.boot_slot(), Some(Slot::B));
    }

    #[test]
    fn failed_update_rolls_back_to_previous_slot() {
        let mut st = AbState::new();
        let target = st.target_slot(); // B
        st.begin_update(target);
        st.finish_update(target);
        assert_eq!(st.boot_slot(), Some(Slot::B));
        // B never succeeds; exhaust all its tries.
        for _ in 0..MAX_TRIES {
            st.record_boot(Slot::B);
        }
        assert!(!st.slot(Slot::B).is_bootable());
        // Boot falls back to A (rollback).
        assert_eq!(st.boot_slot(), Some(Slot::A));
        assert!(st.is_rolling_back());
    }

    #[test]
    fn successful_slot_does_not_consume_tries() {
        let mut st = AbState::new();
        // A is already successful; recording boots must not disable it.
        for _ in 0..10 {
            st.record_boot(Slot::A);
        }
        assert!(st.slot(Slot::A).successful);
        assert_eq!(st.boot_slot(), Some(Slot::A));
    }
}
