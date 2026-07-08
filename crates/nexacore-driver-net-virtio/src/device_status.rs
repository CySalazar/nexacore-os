//! `device_status` byte constants from virtio 1.0 § 2.1.
//!
//! The Common Configuration structure exposes a single `device_status`
//! byte (offset `0x14` per virtio 1.0 § 4.1.4.3, table "Common configuration
//! structure layout") that the driver writes to advance the device through
//! the initialization phases. Each phase is represented by an OR-able bit;
//! the driver MUST write back a status equal to **all previously set bits
//! OR-ed with the next bit**.
//!
//! Sequence per `NCIP-Driver-Net-015` § S4.1 (which collapses virtio 1.0 § 3
//! into seven steps for the M1 deliverable):
//!
//! 1. Write [`RESET`] (`0x00`), poll the status until it reads back `0x00`.
//! 2. Write [`ACKNOWLEDGE`] (`0x01`).
//! 3. Write [`ACKNOWLEDGE`] `|` [`DRIVER`] (`0x03`).
//! 4. Negotiate features, then write
//!    [`ACKNOWLEDGE`] `|` [`DRIVER`] `|` [`FEATURES_OK`] (`0x0B`).
//! 5. Re-read; if [`FEATURES_OK`] is not still set, the device has rejected
//!    the negotiated feature subset — abort with [`FAILED`] (`0x80`).
//! 6. Set up virtqueues, post RX buffers.
//! 7. Write
//!    [`ACKNOWLEDGE`] `|` [`DRIVER`] `|` [`FEATURES_OK`] `|` [`DRIVER_OK`]
//!    (`0x0F`). Device is now operational.

/// Status `0x00`: the driver has just reset the device. The device clears
/// its internal state on a write of `RESET` to `device_status`.
pub const RESET: u8 = 0x00;

/// Status bit 0 (`0x01`): the driver has noticed the device.
pub const ACKNOWLEDGE: u8 = 0x01;

/// Status bit 1 (`0x02`): the driver knows how to drive the device.
pub const DRIVER: u8 = 0x02;

/// Status bit 2 (`0x04`): the driver is set up and ready to drive the
/// device. Set AFTER virtqueues are configured.
pub const DRIVER_OK: u8 = 0x04;

/// Status bit 3 (`0x08`): the driver has acknowledged all the features it
/// understands, and feature negotiation is complete.
pub const FEATURES_OK: u8 = 0x08;

/// Status bit 6 (`0x40`): the device has experienced an error from which
/// it cannot recover (set by the device, not the driver).
pub const DEVICE_NEEDS_RESET: u8 = 0x40;

/// Status bit 7 (`0x80`): something went wrong in the guest, and it has
/// given up on the device. Setting this bit instructs the device to abort.
pub const FAILED: u8 = 0x80;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_is_zero() {
        // Writing `0x00` to device_status triggers the device reset path;
        // any other value here would silently break NCIP-015 § S4.1 step 2.
        assert_eq!(RESET, 0x00);
    }

    #[test]
    fn status_bits_are_disjoint() {
        // Each phase advances by OR-ing the next bit. Overlapping bits
        // would conflate phases and corrupt the bring-up state machine.
        let bits = [
            ACKNOWLEDGE,
            DRIVER,
            DRIVER_OK,
            FEATURES_OK,
            DEVICE_NEEDS_RESET,
            FAILED,
        ];
        for (i, a) in bits.iter().enumerate() {
            for b in bits.iter().skip(i + 1) {
                assert_eq!(
                    a & b,
                    0,
                    "device_status bits overlap: 0x{a:02X} & 0x{b:02X}"
                );
            }
        }
    }

    #[test]
    fn fully_initialised_status_matches_spec() {
        // virtio 1.0 § 3.1.1 step 7: final status before the device is
        // considered live is the OR of ACKNOWLEDGE | DRIVER | FEATURES_OK
        // | DRIVER_OK == 0x0F.
        let live = ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK;
        assert_eq!(live, 0x0F);
    }
}
