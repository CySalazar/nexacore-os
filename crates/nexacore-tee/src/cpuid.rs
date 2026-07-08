//! CPU-vendor detection for TEE backend routing (WS10-02.9).
//!
//! `select_tee_backend` ([`crate::select`]) must route to the Intel TDX or AMD
//! SEV-SNP backend depending on the host CPU.  The vendor comes from CPUID leaf
//! 0, whose `EBX‖EDX‖ECX` spell a 12-byte vendor string (`"GenuineIntel"`,
//! `"AuthenticAMD"`).  Decoding that string into a [`CpuVendor`] is pure and
//! host-testable; executing the `cpuid` instruction is `x86_64`-only and
//! unsafe, so `CpuVendor::detect` is gated to that target.

/// The CPU vendor relevant to TEE selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    /// `GenuineIntel` — eligible for Intel TDX.
    Intel,
    /// `AuthenticAMD` — eligible for AMD SEV-SNP.
    Amd,
    /// Any other / unrecognised vendor.
    Other,
}

impl CpuVendor {
    /// Decode a 12-byte CPUID vendor string in display order
    /// (e.g. `b"GenuineIntel"`).
    #[must_use]
    pub fn from_vendor_string(vendor: &[u8; 12]) -> Self {
        match vendor {
            b"GenuineIntel" => Self::Intel,
            b"AuthenticAMD" => Self::Amd,
            _ => Self::Other,
        }
    }

    /// Detect the running CPU's vendor via CPUID leaf 0 (`x86_64` only).
    ///
    /// The 12 vendor bytes are returned by leaf 0 as `EBX`, then `EDX`, then
    /// `ECX` (little-endian within each register).
    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn detect() -> Self {
        // SAFETY: CPUID leaf 0 is always available on x86_64 and has no
        // side effects; we only read the vendor-string registers.
        #[allow(unsafe_code)]
        let leaf = unsafe { core::arch::x86_64::__cpuid(0) };
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
        Self::from_vendor_string(&vendor)
    }
}

#[cfg(test)]
#[allow(clippy::missing_docs_in_private_items)]
mod tests {
    use super::*;

    #[test]
    fn recognises_intel() {
        assert_eq!(
            CpuVendor::from_vendor_string(b"GenuineIntel"),
            CpuVendor::Intel
        );
    }

    #[test]
    fn recognises_amd() {
        assert_eq!(
            CpuVendor::from_vendor_string(b"AuthenticAMD"),
            CpuVendor::Amd
        );
    }

    #[test]
    fn unknown_vendor_is_other() {
        assert_eq!(
            CpuVendor::from_vendor_string(b"SomeOtherCpu"),
            CpuVendor::Other
        );
    }
}
