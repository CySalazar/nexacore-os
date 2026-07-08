//! PHY management (MDIC) and link-status decoding (WS2-03.7, host side).
//!
//! Link-up is observable through two host-testable layers:
//!
//! 1. The device **`STATUS` register** ([`crate::controller_regs::STATUS_OFFSET`])
//!    reflects the internal PHY's link state into its `LU` / `FD` / speed bits —
//!    the fast path the driver re-reads on every `LSC` interrupt.
//!    [`LinkStatus::from_csr_status`] decodes it.
//! 2. The **PHY status register** (MII register 1, IEEE 802.3 clause 22) read
//!    over the `MDIC` MDIO interface — the authoritative PHY-side view used at
//!    bring-up before `STATUS.LU` is trustworthy. [`mdic_read_command`] composes
//!    the MDIO read transaction; [`mdic_ready`] / [`mdic_error`] / [`mdic_data`]
//!    parse the completion; [`mii_status_link_up`] decodes the result.
//!
//! Issuing the MMIO write to `MDIC` and polling for completion is rig-side; the
//! bit layouts encoded/decoded here are pure and host-tested.

use crate::controller_regs::{STATUS_FD_BIT, STATUS_LU_BIT, STATUS_SPEED_MASK, STATUS_SPEED_SHIFT};

// MDIC bit layout (Intel 82574L datasheet § 10.5.4 "MDI Control Register"):
//   bits 15:0   DATA   — read result / write payload
//   bits 20:16  REGADD — PHY register address (5 bits)
//   bits 25:21  PHYADD — PHY address (5 bits)
//   bits 27:26  OP     — 0b01 = write, 0b10 = read
//   bit  28     R      — Ready (hardware sets it on completion)
//   bit  30     E      — Error

/// MDIC opcode for a PHY register read (bits 27:26 = `0b10`).
const MDIC_OP_READ: u32 = 0b10 << 26;

/// `MDIC.R` (Ready) — bit 28. Hardware sets it when the transaction completes.
pub const MDIC_READY_BIT: u32 = 1 << 28;

/// `MDIC.E` (Error) — bit 30. Hardware sets it if the transaction failed.
pub const MDIC_ERROR_BIT: u32 = 1 << 30;

/// Compose an `MDIC` value that requests a read of PHY register `reg` on PHY
/// address `phy`.
///
/// Write the result to [`crate::controller_regs::MDIC_OFFSET`], then poll until
/// [`mdic_ready`] returns `true` and read back with [`mdic_data`]. `phy` and
/// `reg` are masked to their 5-bit fields.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::phy::{MII_STATUS_REG, mdic_read_command};
///
/// // Read the PHY status register (reg 1) on PHY address 1.
/// let cmd = mdic_read_command(1, MII_STATUS_REG);
/// assert_eq!((cmd >> 16) & 0x1F, u32::from(MII_STATUS_REG)); // REGADD
/// assert_eq!((cmd >> 21) & 0x1F, 1); // PHYADD
/// assert_eq!((cmd >> 26) & 0b11, 0b10); // OP = read
/// ```
#[must_use]
pub fn mdic_read_command(phy: u8, reg: u8) -> u32 {
    let phy = (u32::from(phy) & 0x1F) << 21;
    let reg = (u32::from(reg) & 0x1F) << 16;
    MDIC_OP_READ | phy | reg
}

/// `true` once the `MDIC` transaction has completed (the `R` bit is set).
#[must_use]
pub const fn mdic_ready(mdic: u32) -> bool {
    mdic & MDIC_READY_BIT != 0
}

/// `true` if the `MDIC` transaction reported an error (the `E` bit is set).
#[must_use]
pub const fn mdic_error(mdic: u32) -> bool {
    mdic & MDIC_ERROR_BIT != 0
}

/// Extract the 16-bit PHY register value from a completed `MDIC` read.
#[must_use]
pub fn mdic_data(mdic: u32) -> u16 {
    let [lo, hi, _, _] = mdic.to_le_bytes();
    u16::from_le_bytes([lo, hi])
}

/// MII register 1 — PHY Status Register (IEEE 802.3 clause 22).
pub const MII_STATUS_REG: u8 = 1;

/// `MII_STATUS.Link Status` — bit 2. Reads 1 while the link is up.
pub const MII_STATUS_LINK_UP_BIT: u16 = 1 << 2;

/// `MII_STATUS.Auto-Negotiation Complete` — bit 5.
pub const MII_STATUS_ANEG_COMPLETE_BIT: u16 = 1 << 5;

/// Decode link-up from a PHY Status Register ([`MII_STATUS_REG`]) value.
#[must_use]
pub const fn mii_status_link_up(mii_status: u16) -> bool {
    mii_status & MII_STATUS_LINK_UP_BIT != 0
}

/// `true` once the PHY has completed auto-negotiation.
#[must_use]
pub const fn mii_status_aneg_complete(mii_status: u16) -> bool {
    mii_status & MII_STATUS_ANEG_COMPLETE_BIT != 0
}

/// Negotiated link speed decoded from the device `STATUS` register speed field
/// (bits 7:6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSpeed {
    /// 10 Mb/s (`STATUS` speed field `0b00`).
    Mb10,
    /// 100 Mb/s (`STATUS` speed field `0b01`).
    Mb100,
    /// 1000 Mb/s (`STATUS` speed field `0b10` or `0b11`).
    Mb1000,
}

/// Decoded link state from the device `STATUS` register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// `true` when `STATUS.LU` (link up) is set.
    pub up: bool,
    /// `true` when `STATUS.FD` (full duplex) is set.
    pub full_duplex: bool,
    /// Negotiated speed (only meaningful when [`LinkStatus::up`] is `true`).
    pub speed: LinkSpeed,
}

impl LinkStatus {
    /// Decode a device `STATUS` register value
    /// ([`crate::controller_regs::STATUS_OFFSET`], offset `0x0008`).
    ///
    /// Bit 0 = `FD`, bit 1 = `LU`, bits 7:6 = speed.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::phy::{LinkSpeed, LinkStatus};
    ///
    /// // LU | FD | speed=0b10 (1 Gb/s): bit1 | bit0 | (0b10 << 6) = 0x83.
    /// let link = LinkStatus::from_csr_status(0x0000_0083);
    /// assert!(link.up && link.full_duplex);
    /// assert_eq!(link.speed, LinkSpeed::Mb1000);
    /// // Link down.
    /// assert!(!LinkStatus::from_csr_status(0).up);
    /// ```
    #[must_use]
    pub const fn from_csr_status(status: u32) -> Self {
        let speed = match (status >> STATUS_SPEED_SHIFT) & STATUS_SPEED_MASK {
            0b00 => LinkSpeed::Mb10,
            0b01 => LinkSpeed::Mb100,
            _ => LinkSpeed::Mb1000,
        };
        Self {
            up: status & STATUS_LU_BIT != 0,
            full_duplex: status & STATUS_FD_BIT != 0,
            speed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdic_read_command_places_fields_correctly() {
        let cmd = mdic_read_command(2, MII_STATUS_REG);
        assert_eq!((cmd >> 16) & 0x1F, u32::from(MII_STATUS_REG), "REGADD");
        assert_eq!((cmd >> 21) & 0x1F, 2, "PHYADD");
        assert_eq!((cmd >> 26) & 0b11, 0b10, "OP must be read");
        // A freshly composed command is neither ready nor errored.
        assert!(!mdic_ready(cmd));
        assert!(!mdic_error(cmd));
    }

    #[test]
    fn mdic_read_command_masks_oversized_addresses() {
        // 0xFF is wider than the 5-bit PHY/REG fields → must mask to 0x1F.
        let cmd = mdic_read_command(0xFF, 0xFF);
        assert_eq!((cmd >> 21) & 0x1F, 0x1F);
        assert_eq!((cmd >> 16) & 0x1F, 0x1F);
        // No stray bits leak into OP/Ready/Error.
        assert_eq!((cmd >> 26) & 0b11, 0b10);
        assert!(!mdic_ready(cmd) && !mdic_error(cmd));
    }

    #[test]
    fn mdic_completion_parsing() {
        // Hardware writes back DATA in bits 15:0 and sets R.
        let done = MDIC_READY_BIT | 0x0000_1234;
        assert!(mdic_ready(done));
        assert!(!mdic_error(done));
        assert_eq!(mdic_data(done), 0x1234);
        // Error completion.
        let err = MDIC_READY_BIT | MDIC_ERROR_BIT;
        assert!(mdic_ready(err) && mdic_error(err));
    }

    #[test]
    fn mii_status_link_and_aneg_bits() {
        assert!(mii_status_link_up(MII_STATUS_LINK_UP_BIT));
        assert!(!mii_status_link_up(0));
        assert!(mii_status_aneg_complete(MII_STATUS_ANEG_COMPLETE_BIT));
        assert!(!mii_status_aneg_complete(MII_STATUS_LINK_UP_BIT));
    }

    #[test]
    fn link_status_decodes_up_duplex_and_speed() {
        // LU | FD | speed=0b10 → up, full duplex, 1 Gb/s.
        let link = LinkStatus::from_csr_status(STATUS_LU_BIT | STATUS_FD_BIT | (0b10 << 6));
        assert_eq!(
            link,
            LinkStatus {
                up: true,
                full_duplex: true,
                speed: LinkSpeed::Mb1000,
            }
        );
    }

    #[test]
    fn link_status_decodes_down_and_half_duplex_speeds() {
        let down = LinkStatus::from_csr_status(0);
        assert!(!down.up && !down.full_duplex);
        assert_eq!(down.speed, LinkSpeed::Mb10);
        // LU only, speed=0b01 (100 Mb/s), half duplex.
        let hundred = LinkStatus::from_csr_status(STATUS_LU_BIT | (0b01 << 6));
        assert!(hundred.up && !hundred.full_duplex);
        assert_eq!(hundred.speed, LinkSpeed::Mb100);
    }
}
