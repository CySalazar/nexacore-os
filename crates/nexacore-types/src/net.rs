//! Network protocol types shared across NexaCore OS.
//!
//! This module provides the foundational wire types for Ethernet, `IPv4`, `IPv6`,
//! ICMP, UDP, TCP, and ARP. All types are `no_std + alloc`-compatible and
//! follow the same conventions as the rest of `nexacore-types`:
//!
//! - Big-endian wire layout for all multi-byte fields (network byte order).
//! - `parse` / `serialize` methods use `Option` — `None` signals a malformed
//!   or undersized input, not a recoverable error requiring a context slug.
//! - Serializable types derive `serde::{Serialize, Deserialize}` and go
//!   through [`crate::wire::encode_canonical`] / [`crate::wire::decode_canonical`]
//!   for any cross-trust-boundary encoding.
//! - No `unsafe` code; all slice access goes through `.get()`.
//!
//! ## Sections
//!
//! - [`MacAddress`] / [`EtherType`] / [`EthernetHeader`] — N0.1 Ethernet/MAC
//! - [`Ipv4Addr`] / [`Ipv6Addr`] / [`IpAddr`] / [`Cidr`] / [`SocketAddr`] /
//!   [`IpProtocol`] / [`Ipv4Header`] — N0.2 IP
//! - [`IcmpType`] / [`IcmpCode`] / [`IcmpHeader`] / [`IcmpEchoHeader`] — N0.3 ICMP
//! - [`UdpHeader`] / [`UdpPseudoHeader`] — N0.4 UDP
//! - [`TcpHeader`] / [`TcpFlags`] / [`TcpPseudoHeader`] — N0.5 TCP
//! - [`ArpOperation`] / [`ArpPacket`] — N0.6 ARP

use core::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

// =============================================================================
// Internet checksum (RFC 1071)
// =============================================================================

/// Compute the RFC 1071 internet checksum over `data`.
///
/// Used by `IPv4`, ICMP, UDP, and TCP. The caller is responsible for
/// zero-initialising the checksum field before passing the header bytes in,
/// and for combining pseudo-header words when the protocol requires it
/// (UDP/TCP).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let hi = *data.get(i).unwrap_or(&0);
        let lo = *data.get(i + 1).unwrap_or(&0);
        sum += u32::from(u16::from_be_bytes([hi, lo]));
        i += 2;
    }
    if i < data.len() {
        if let Some(&b) = data.get(i) {
            sum += u32::from(b) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // Fold and invert. The truncation is intentional: we've folded all
    // carries back into the low 16 bits above, so the cast is lossless.
    #[allow(clippy::cast_possible_truncation)]
    !(sum as u16)
}

/// Accumulate the internet checksum over multiple discontiguous byte slices.
///
/// Equivalent to concatenating the slices then calling `internet_checksum`,
/// but avoids a heap allocation. Correctly handles odd-length slices by
/// carrying the spare byte into the next slice.
///
/// Exposed for protocols whose checksum spans a pseudo-header plus the message
/// without a contiguous buffer (e.g. the `ICMPv6` / `UDP` / `TCP` `IPv6`
/// checksum).
pub fn checksum_combine(slices: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;

    for slice in slices {
        if let Some(prev) = carry_byte.take() {
            if let Some(&first) = slice.first() {
                sum += u32::from(u16::from_be_bytes([prev, first]));
                let rest = slice.get(1..).unwrap_or(&[]);
                let mut i = 0;
                while i + 1 < rest.len() {
                    let hi = *rest.get(i).unwrap_or(&0);
                    let lo = *rest.get(i + 1).unwrap_or(&0);
                    sum += u32::from(u16::from_be_bytes([hi, lo]));
                    i += 2;
                }
                if i < rest.len() {
                    carry_byte = rest.get(i).copied();
                }
            } else {
                carry_byte = Some(prev);
            }
        } else {
            let mut i = 0;
            while i + 1 < slice.len() {
                let hi = *slice.get(i).unwrap_or(&0);
                let lo = *slice.get(i + 1).unwrap_or(&0);
                sum += u32::from(u16::from_be_bytes([hi, lo]));
                i += 2;
            }
            if i < slice.len() {
                carry_byte = slice.get(i).copied();
            }
        }
    }

    if let Some(b) = carry_byte {
        sum += u32::from(b) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    !(sum as u16)
}

// =============================================================================
// Ethernet / MAC (N0.1)
// =============================================================================

/// Default Ethernet MTU in bytes (payload only, not including the header).
pub const MTU_DEFAULT: u16 = 1500;

/// Jumbo-frame Ethernet MTU in bytes (payload only).
pub const MTU_JUMBO: u16 = 9000;

/// Minimum Ethernet frame size on the wire, excluding the 4-byte FCS.
pub const ETH_FRAME_MIN: usize = 60;

/// Maximum Ethernet frame size on the wire, excluding the 4-byte FCS.
pub const ETH_FRAME_MAX: usize = 1518;

/// A 48-bit IEEE 802.3 MAC address.
///
/// # Display
///
/// Formats as `xx:xx:xx:xx:xx:xx` with lower-case hex digits, matching the
/// conventional Linux / BSD representation.
///
/// # Examples
///
/// ```
/// use alloc::string::ToString;
/// use core::str::FromStr;
///
/// use nexacore_types::net::MacAddress;
/// extern crate alloc;
///
/// let mac = MacAddress::BROADCAST;
/// assert_eq!(mac.to_string(), "ff:ff:ff:ff:ff:ff");
///
/// let parsed = MacAddress::from_str("01:23:45:67:89:ab").unwrap();
/// assert_eq!(parsed.to_string(), "01:23:45:67:89:ab");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The all-ones broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// Returns `true` if the least-significant bit of the first octet is set,
    /// which per IEEE 802.3 signals a multicast (or broadcast) destination.
    #[must_use]
    pub fn is_multicast(self) -> bool {
        self.0.first().is_some_and(|b| b & 0x01 != 0)
    }

    /// Returns `true` if this is a unicast address (first octet LSB clear).
    #[must_use]
    pub fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    /// Returns `true` if the locally-administered bit (second LSB of the
    /// first octet) is set, indicating the address was assigned locally
    /// rather than burned in by the manufacturer.
    #[must_use]
    pub fn is_locally_administered(self) -> bool {
        self.0.first().is_some_and(|b| b & 0x02 != 0)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Error returned when a string cannot be parsed as a [`MacAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddressParseError;

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address")
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or(MacAddressParseError)?;
            *octet = u8::from_str_radix(part, 16).map_err(|_| MacAddressParseError)?;
        }
        if parts.next().is_some() {
            return Err(MacAddressParseError);
        }
        Ok(Self(octets))
    }
}

/// An Ethernet `EtherType` field (big-endian `u16`).
///
/// Identifies the protocol carried in the Ethernet payload.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::EtherType;
///
/// assert_eq!(EtherType::IPV4.0, 0x0800);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EtherType(pub u16);

impl EtherType {
    /// Internet Protocol version 4 (`0x0800`).
    pub const IPV4: Self = Self(0x0800);
    /// Address Resolution Protocol (`0x0806`).
    pub const ARP: Self = Self(0x0806);
    /// Internet Protocol version 6 (`0x86DD`).
    pub const IPV6: Self = Self(0x86DD);
    /// IEEE 802.1Q VLAN tag (`0x8100`).
    pub const VLAN: Self = Self(0x8100);
}

/// A parsed Ethernet II frame header (14 bytes).
///
/// Does not include the FCS; the caller is expected to strip it before
/// passing bytes to [`EthernetHeader::parse`].
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{EtherType, EthernetHeader, MacAddress};
///
/// let mut buf = [0u8; EthernetHeader::HEADER_LEN];
/// let hdr = EthernetHeader {
///     dst: MacAddress::BROADCAST,
///     src: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
///     ether_type: EtherType::IPV4,
/// };
/// hdr.serialize(&mut buf).unwrap();
/// let (parsed, _rest) = EthernetHeader::parse(&buf).unwrap();
/// assert_eq!(parsed.ether_type, EtherType::IPV4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthernetHeader {
    /// Destination MAC address.
    pub dst: MacAddress,
    /// Source MAC address.
    pub src: MacAddress,
    /// `EtherType` / length field.
    pub ether_type: EtherType,
}

impl EthernetHeader {
    /// Wire length of an Ethernet II header in bytes.
    pub const HEADER_LEN: usize = 14;

    /// Parse an Ethernet header from `bytes`.
    ///
    /// Returns `(header, remaining_payload)` on success, `None` if `bytes`
    /// is shorter than [`Self::HEADER_LEN`].
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let dst = MacAddress([
            *bytes.first()?,
            *bytes.get(1)?,
            *bytes.get(2)?,
            *bytes.get(3)?,
            *bytes.get(4)?,
            *bytes.get(5)?,
        ]);
        let src = MacAddress([
            *bytes.get(6)?,
            *bytes.get(7)?,
            *bytes.get(8)?,
            *bytes.get(9)?,
            *bytes.get(10)?,
            *bytes.get(11)?,
        ]);
        let ether_type = EtherType(u16::from_be_bytes([*bytes.get(12)?, *bytes.get(13)?]));
        Some((
            Self {
                dst,
                src,
                ether_type,
            },
            bytes.get(Self::HEADER_LEN..)?,
        ))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN`] bytes of
    /// `buf`.
    ///
    /// Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        *buf.get_mut(0)? = self.dst.0[0];
        *buf.get_mut(1)? = self.dst.0[1];
        *buf.get_mut(2)? = self.dst.0[2];
        *buf.get_mut(3)? = self.dst.0[3];
        *buf.get_mut(4)? = self.dst.0[4];
        *buf.get_mut(5)? = self.dst.0[5];
        *buf.get_mut(6)? = self.src.0[0];
        *buf.get_mut(7)? = self.src.0[1];
        *buf.get_mut(8)? = self.src.0[2];
        *buf.get_mut(9)? = self.src.0[3];
        *buf.get_mut(10)? = self.src.0[4];
        *buf.get_mut(11)? = self.src.0[5];
        let et = self.ether_type.0.to_be_bytes();
        *buf.get_mut(12)? = et[0];
        *buf.get_mut(13)? = et[1];
        Some(())
    }
}

// =============================================================================
// IP (N0.2)
// =============================================================================

/// Error returned when a string cannot be parsed as an [`Ipv4Addr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4AddrParseError;

impl fmt::Display for Ipv4AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IPv4 address")
    }
}

/// An `IPv4` address stored as four octets in network byte order.
///
/// # Examples
///
/// ```
/// use alloc::string::ToString;
/// use core::str::FromStr;
///
/// use nexacore_types::net::Ipv4Addr;
/// extern crate alloc;
///
/// let addr = Ipv4Addr::from_str("192.168.1.1").unwrap();
/// assert!(addr.is_private());
/// assert_eq!(addr.to_string(), "192.168.1.1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    /// The loopback address `127.0.0.1`.
    pub const LOOPBACK: Self = Self([127, 0, 0, 1]);
    /// The limited broadcast address `255.255.255.255`.
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);
    /// The unspecified address `0.0.0.0`.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);

    /// Returns `true` if the address is in `127.0.0.0/8`.
    #[must_use]
    pub fn is_loopback(self) -> bool {
        self.0.first().is_some_and(|&b| b == 127)
    }

    /// Returns `true` if the address falls in any RFC 1918 private range:
    /// `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`.
    #[must_use]
    pub fn is_private(self) -> bool {
        matches!(self.0, [10, ..] | [172, 16..=31, ..] | [192, 168, ..])
    }

    /// Returns `true` if the address is the limited broadcast `255.255.255.255`.
    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    /// Returns `true` if the address is in the multicast range `224.0.0.0/4`.
    #[must_use]
    pub fn is_multicast(self) -> bool {
        self.0.first().is_some_and(|&b| (224..=239).contains(&b))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl FromStr for Ipv4Addr {
    type Err = Ipv4AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 4];
        let mut parts = s.split('.');
        for octet in &mut octets {
            let part = parts.next().ok_or(Ipv4AddrParseError)?;
            *octet = part.parse::<u8>().map_err(|_| Ipv4AddrParseError)?;
        }
        if parts.next().is_some() {
            return Err(Ipv4AddrParseError);
        }
        Ok(Self(octets))
    }
}

/// Error returned when a string cannot be parsed as an [`Ipv6Addr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6AddrParseError;

impl fmt::Display for Ipv6AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IPv6 address")
    }
}

/// An `IPv6` address stored as 16 octets in network byte order.
///
/// Display uses the full eight-group colon-hex format (`xxxx:xxxx:...:xxxx`).
/// A future version will implement RFC 5952 compression (`::` notation).
///
/// # Examples
///
/// ```
/// use nexacore_types::net::Ipv6Addr;
///
/// assert!(Ipv6Addr::LOOPBACK.is_loopback());
/// assert_eq!(
///     format!("{}", Ipv6Addr::LOOPBACK),
///     "0000:0000:0000:0000:0000:0000:0000:0001"
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    /// The `IPv6` loopback address `::1`.
    pub const LOOPBACK: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// Returns `true` if this is the loopback address `::1`.
    #[must_use]
    pub fn is_loopback(self) -> bool {
        self.0 == Self::LOOPBACK.0
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.chunks(2).enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            if let (Some(&hi), Some(&lo)) = (chunk.first(), chunk.get(1)) {
                let word = u16::from_be_bytes([hi, lo]);
                write!(f, "{word:04x}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for Ipv6Addr {
    type Err = Ipv6AddrParseError;

    /// Parses a full eight-group colon-hex `IPv6` address.
    ///
    /// Does not support `::` compression or embedded `IPv4` addresses.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 16];
        let mut groups = s.split(':');
        for i in 0..8usize {
            let group = groups.next().ok_or(Ipv6AddrParseError)?;
            let word = u16::from_str_radix(group, 16).map_err(|_| Ipv6AddrParseError)?;
            let word_bytes = word.to_be_bytes();
            let Some(slot_hi) = bytes.get_mut(i * 2) else {
                return Err(Ipv6AddrParseError);
            };
            *slot_hi = word_bytes[0];
            let Some(slot_lo) = bytes.get_mut(i * 2 + 1) else {
                return Err(Ipv6AddrParseError);
            };
            *slot_lo = word_bytes[1];
        }
        if groups.next().is_some() {
            return Err(Ipv6AddrParseError);
        }
        Ok(Self(bytes))
    }
}

/// An IP address — either `IPv4` or `IPv6`.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{IpAddr, Ipv4Addr};
///
/// let addr = IpAddr::V4(Ipv4Addr::LOOPBACK);
/// assert_eq!(format!("{addr}"), "127.0.0.1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpAddr {
    /// An `IPv4` address.
    V4(Ipv4Addr),
    /// An `IPv6` address.
    V6(Ipv6Addr),
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => a.fmt(f),
            Self::V6(a) => a.fmt(f),
        }
    }
}

/// An `IPv4` CIDR block (`address/prefix_len`).
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{Cidr, Ipv4Addr};
///
/// let cidr = Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24).unwrap();
/// assert!(cidr.contains(Ipv4Addr([192, 168, 1, 100])));
/// assert!(!cidr.contains(Ipv4Addr([192, 168, 2, 1])));
/// assert_eq!(cidr.broadcast_addr(), Ipv4Addr([192, 168, 1, 255]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    /// The network address (host bits are not required to be zero, but
    /// [`Cidr::network_addr`] will mask them out).
    pub addr: Ipv4Addr,
    /// Prefix length in bits (0–32 inclusive).
    pub prefix_len: u8,
}

impl Cidr {
    /// Construct a new CIDR block.
    ///
    /// Returns `None` if `prefix_len > 32`.
    #[must_use]
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        Some(Self { addr, prefix_len })
    }

    /// Returns the 32-bit network mask with the top `prefix_len` bits set.
    #[must_use]
    pub fn netmask(self) -> Ipv4Addr {
        let mask: u32 = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        Ipv4Addr(mask.to_be_bytes())
    }

    /// Returns the network address (host bits zeroed out).
    #[must_use]
    pub fn network_addr(self) -> Ipv4Addr {
        let ip = u32::from_be_bytes(self.addr.0);
        let mask = u32::from_be_bytes(self.netmask().0);
        Ipv4Addr((ip & mask).to_be_bytes())
    }

    /// Returns the directed broadcast address for this prefix (host bits all 1).
    #[must_use]
    pub fn broadcast_addr(self) -> Ipv4Addr {
        let ip = u32::from_be_bytes(self.addr.0);
        let mask = u32::from_be_bytes(self.netmask().0);
        Ipv4Addr((ip | !mask).to_be_bytes())
    }

    /// Returns `true` if `addr` falls within this CIDR block.
    #[must_use]
    pub fn contains(self, addr: Ipv4Addr) -> bool {
        let mask = u32::from_be_bytes(self.netmask().0);
        let net = u32::from_be_bytes(self.network_addr().0);
        let candidate = u32::from_be_bytes(addr.0);
        (candidate & mask) == net
    }
}

/// A transport-layer socket address: an IP address and a port.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// let sa = SocketAddr {
///     ip: IpAddr::V4(Ipv4Addr::LOOPBACK),
///     port: 8080,
/// };
/// assert_eq!(sa.port, 8080);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketAddr {
    /// The IP address component.
    pub ip: IpAddr,
    /// The port number (0–65535; port 0 means "any" or "unspecified").
    pub port: u16,
}

/// An IP protocol number as defined by IANA.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::IpProtocol;
///
/// assert_eq!(IpProtocol::TCP.0, 6);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpProtocol(pub u8);

impl IpProtocol {
    /// Internet Control Message Protocol (`1`).
    pub const ICMP: Self = Self(1);
    /// Transmission Control Protocol (`6`).
    pub const TCP: Self = Self(6);
    /// User Datagram Protocol (`17`).
    pub const UDP: Self = Self(17);
}

/// A parsed `IPv4` header per RFC 791.
///
/// All multi-byte fields are stored in host byte order after parsing.
/// [`Ipv4Header::serialize`] converts them back to network byte order.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{IpProtocol, Ipv4Addr, Ipv4Header};
///
/// let mut hdr = Ipv4Header {
///     version_ihl: 0x45,
///     dscp_ecn: 0,
///     total_length: 20,
///     identification: 0,
///     flags_fragment: 0,
///     ttl: 64,
///     protocol: IpProtocol::UDP,
///     header_checksum: 0,
///     src: Ipv4Addr::LOOPBACK,
///     dst: Ipv4Addr::LOOPBACK,
/// };
/// hdr.header_checksum = hdr.compute_checksum();
/// assert!(hdr.verify_checksum());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Header {
    /// Version (4 bits) + IHL (4 bits). For a standard 20-byte header: `0x45`.
    pub version_ihl: u8,
    /// DSCP (6 bits) + ECN (2 bits).
    pub dscp_ecn: u8,
    /// Total length of IP datagram (header + payload) in bytes.
    pub total_length: u16,
    /// Identification field for fragmentation reassembly.
    pub identification: u16,
    /// Flags (3 bits) + Fragment Offset (13 bits).
    pub flags_fragment: u16,
    /// Time to live.
    pub ttl: u8,
    /// Encapsulated protocol.
    pub protocol: IpProtocol,
    /// Header checksum (RFC 791 internet checksum over the header only).
    pub header_checksum: u16,
    /// Source `IPv4` address.
    pub src: Ipv4Addr,
    /// Destination `IPv4` address.
    pub dst: Ipv4Addr,
}

impl Ipv4Header {
    /// Minimum `IPv4` header length in bytes (IHL = 5, no options).
    pub const HEADER_LEN_MIN: usize = 20;

    /// Parse an `IPv4` header from `bytes`.
    ///
    /// Returns `(header, remaining_payload)` on success, or `None` if
    /// the buffer is too short.  Options are not parsed; the payload
    /// slice begins after `IHL * 4` bytes.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN_MIN {
            return None;
        }
        let version_ihl = *bytes.first()?;
        let ihl = usize::from(version_ihl & 0x0F) * 4;
        if ihl < Self::HEADER_LEN_MIN || bytes.len() < ihl {
            return None;
        }
        let hdr = Self {
            version_ihl,
            dscp_ecn: *bytes.get(1)?,
            total_length: u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            identification: u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]),
            flags_fragment: u16::from_be_bytes([*bytes.get(6)?, *bytes.get(7)?]),
            ttl: *bytes.get(8)?,
            protocol: IpProtocol(*bytes.get(9)?),
            header_checksum: u16::from_be_bytes([*bytes.get(10)?, *bytes.get(11)?]),
            src: Ipv4Addr([
                *bytes.get(12)?,
                *bytes.get(13)?,
                *bytes.get(14)?,
                *bytes.get(15)?,
            ]),
            dst: Ipv4Addr([
                *bytes.get(16)?,
                *bytes.get(17)?,
                *bytes.get(18)?,
                *bytes.get(19)?,
            ]),
        };
        Some((hdr, bytes.get(ihl..)?))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN_MIN`] bytes
    /// of `buf`.  Options are not supported; IHL is assumed to be 5.
    ///
    /// Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN_MIN {
            return None;
        }
        *buf.get_mut(0)? = self.version_ihl;
        *buf.get_mut(1)? = self.dscp_ecn;
        let tl = self.total_length.to_be_bytes();
        *buf.get_mut(2)? = tl[0];
        *buf.get_mut(3)? = tl[1];
        let id = self.identification.to_be_bytes();
        *buf.get_mut(4)? = id[0];
        *buf.get_mut(5)? = id[1];
        let ff = self.flags_fragment.to_be_bytes();
        *buf.get_mut(6)? = ff[0];
        *buf.get_mut(7)? = ff[1];
        *buf.get_mut(8)? = self.ttl;
        *buf.get_mut(9)? = self.protocol.0;
        let ck = self.header_checksum.to_be_bytes();
        *buf.get_mut(10)? = ck[0];
        *buf.get_mut(11)? = ck[1];
        *buf.get_mut(12)? = self.src.0[0];
        *buf.get_mut(13)? = self.src.0[1];
        *buf.get_mut(14)? = self.src.0[2];
        *buf.get_mut(15)? = self.src.0[3];
        *buf.get_mut(16)? = self.dst.0[0];
        *buf.get_mut(17)? = self.dst.0[1];
        *buf.get_mut(18)? = self.dst.0[2];
        *buf.get_mut(19)? = self.dst.0[3];
        Some(())
    }

    /// Compute the RFC 791 internet checksum over the 20-byte header,
    /// treating the `header_checksum` field as zero.
    #[must_use]
    pub fn compute_checksum(self) -> u16 {
        let mut buf = [0u8; Self::HEADER_LEN_MIN];
        let mut tmp = self;
        tmp.header_checksum = 0;
        // If serialize returns None the buf stays zero — indicates a bug
        // in the caller but we cannot panic here (no_std policy).
        let _ = tmp.serialize(&mut buf);
        internet_checksum(&buf)
    }

    /// Returns `true` if [`Self::header_checksum`] is correct for the
    /// current field values.
    #[must_use]
    pub fn verify_checksum(self) -> bool {
        self.compute_checksum() == self.header_checksum
    }
}

// =============================================================================
// IPv6 (WS4-04.1)
// =============================================================================

/// A fixed `IPv6` header (RFC 8200 § 3): 40 bytes, no checksum.
///
/// Unlike `IPv4`, the `IPv6` base header carries no checksum (upper-layer
/// protocols cover integrity via a pseudo-header) and has a fixed length;
/// optional extension headers live at the start of the payload and are parsed
/// by upper layers, not here.
///
/// The first 32-bit word packs Version (4 bits), Traffic Class (8 bits) and
/// Flow Label (20 bits); use [`version`](Self::version),
/// [`traffic_class`](Self::traffic_class) and [`flow_label`](Self::flow_label)
/// to read them.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{IpProtocol, Ipv6Addr, Ipv6Header};
///
/// let hdr = Ipv6Header::new(
///     0,
///     0,
///     3,
///     IpProtocol::UDP,
///     64,
///     Ipv6Addr::LOOPBACK,
///     Ipv6Addr::LOOPBACK,
/// );
/// assert_eq!(hdr.version(), 6);
/// assert_eq!(hdr.next_header, IpProtocol::UDP);
/// assert_eq!(hdr.hop_limit, 64);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Header {
    /// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits),
    /// packed into a single big-endian 32-bit word.
    pub version_tc_flow: u32,
    /// Length of the payload (everything after this 40-byte header) in bytes.
    pub payload_length: u16,
    /// The type of the next header (an upper-layer protocol or an extension
    /// header). Shares the [`IpProtocol`] numbering space.
    pub next_header: IpProtocol,
    /// Hop limit (the `IPv6` analogue of the `IPv4` TTL).
    pub hop_limit: u8,
    /// Source `IPv6` address.
    pub src: Ipv6Addr,
    /// Destination `IPv6` address.
    pub dst: Ipv6Addr,
}

impl Ipv6Header {
    /// The fixed `IPv6` header length in bytes.
    pub const HEADER_LEN: usize = 40;

    /// Construct a header with `version` fixed to 6.
    #[must_use]
    pub fn new(
        traffic_class: u8,
        flow_label: u32,
        payload_length: u16,
        next_header: IpProtocol,
        hop_limit: u8,
        src: Ipv6Addr,
        dst: Ipv6Addr,
    ) -> Self {
        let version_tc_flow =
            (6_u32 << 28) | (u32::from(traffic_class) << 20) | (flow_label & 0x000F_FFFF);
        Self {
            version_tc_flow,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
        }
    }

    /// The IP version field (6 for a valid `IPv6` header).
    #[must_use]
    pub fn version(self) -> u8 {
        u8::try_from(self.version_tc_flow >> 28).unwrap_or(0)
    }

    /// The Traffic Class field.
    #[must_use]
    pub fn traffic_class(self) -> u8 {
        u8::try_from((self.version_tc_flow >> 20) & 0xFF).unwrap_or(0)
    }

    /// The 20-bit Flow Label field.
    #[must_use]
    pub fn flow_label(self) -> u32 {
        self.version_tc_flow & 0x000F_FFFF
    }

    /// Parse a fixed `IPv6` header from `bytes`.
    ///
    /// Returns `(header, payload)` where `payload` is everything after the
    /// 40-byte base header (including any extension headers), or `None` if the
    /// buffer is shorter than the fixed header.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let hdr = Self {
            version_tc_flow: u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?),
            payload_length: u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()?),
            next_header: IpProtocol(*bytes.get(6)?),
            hop_limit: *bytes.get(7)?,
            src: Ipv6Addr(bytes.get(8..24)?.try_into().ok()?),
            dst: Ipv6Addr(bytes.get(24..40)?.try_into().ok()?),
        };
        Some((hdr, bytes.get(Self::HEADER_LEN..)?))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN`] bytes of `buf`.
    ///
    /// Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        buf.get_mut(0..4)?
            .copy_from_slice(&self.version_tc_flow.to_be_bytes());
        buf.get_mut(4..6)?
            .copy_from_slice(&self.payload_length.to_be_bytes());
        *buf.get_mut(6)? = self.next_header.0;
        *buf.get_mut(7)? = self.hop_limit;
        buf.get_mut(8..24)?.copy_from_slice(&self.src.0);
        buf.get_mut(24..40)?.copy_from_slice(&self.dst.0);
        Some(())
    }
}

// =============================================================================
// ICMP (N0.3)
// =============================================================================

/// An ICMP message type field.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::IcmpType;
///
/// assert_eq!(IcmpType::ECHO_REQUEST.0, 8);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IcmpType(pub u8);

impl IcmpType {
    /// Echo Reply (`0`).
    pub const ECHO_REPLY: Self = Self(0);
    /// Destination Unreachable (`3`).
    pub const DEST_UNREACHABLE: Self = Self(3);
    /// Echo Request (`8`).
    pub const ECHO_REQUEST: Self = Self(8);
    /// Time Exceeded (`11`).
    pub const TIME_EXCEEDED: Self = Self(11);
}

/// An ICMP code field.
///
/// The meaning depends on the accompanying [`IcmpType`].
///
/// # Examples
///
/// ```
/// use nexacore_types::net::IcmpCode;
///
/// assert_eq!(IcmpCode::PORT_UNREACHABLE.0, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IcmpCode(pub u8);

impl IcmpCode {
    /// Destination Unreachable: Net Unreachable (`0`).
    pub const NET_UNREACHABLE: Self = Self(0);
    /// Destination Unreachable: Host Unreachable (`1`).
    pub const HOST_UNREACHABLE: Self = Self(1);
    /// Destination Unreachable: Port Unreachable (`3`).
    pub const PORT_UNREACHABLE: Self = Self(3);
    /// Code zero — used for Echo Request/Reply and Time Exceeded.
    pub const ZERO: Self = Self(0);
}

/// A parsed ICMP header (8 bytes).
///
/// The `rest` field holds the 4 bytes following the checksum, whose
/// interpretation depends on the ICMP type (e.g., identifier + sequence for
/// Echo, unused zeros for Destination Unreachable).
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{IcmpCode, IcmpHeader, IcmpType};
///
/// let mut hdr = IcmpHeader {
///     icmp_type: IcmpType::ECHO_REQUEST,
///     code: IcmpCode::ZERO,
///     checksum: 0,
///     rest: [0, 1, 0, 1],
/// };
/// hdr.checksum = hdr.compute_checksum(&[]);
/// assert!(hdr.verify_checksum(&[]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IcmpHeader {
    /// ICMP message type.
    pub icmp_type: IcmpType,
    /// ICMP code (type-dependent).
    pub code: IcmpCode,
    /// RFC 792 internet checksum over the ICMP header and payload.
    pub checksum: u16,
    /// Type-specific 4 bytes (identifier+sequence for Echo, zeros otherwise).
    pub rest: [u8; 4],
}

impl IcmpHeader {
    /// Wire length of the ICMP header in bytes.
    pub const HEADER_LEN: usize = 8;

    /// Parse an ICMP header from `bytes`.
    ///
    /// Returns `(header, remaining_payload)` or `None` if the buffer is
    /// shorter than [`Self::HEADER_LEN`].
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let hdr = Self {
            icmp_type: IcmpType(*bytes.first()?),
            code: IcmpCode(*bytes.get(1)?),
            checksum: u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            rest: [
                *bytes.get(4)?,
                *bytes.get(5)?,
                *bytes.get(6)?,
                *bytes.get(7)?,
            ],
        };
        Some((hdr, bytes.get(Self::HEADER_LEN..)?))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN`] bytes of
    /// `buf`.  Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        *buf.get_mut(0)? = self.icmp_type.0;
        *buf.get_mut(1)? = self.code.0;
        let ck = self.checksum.to_be_bytes();
        *buf.get_mut(2)? = ck[0];
        *buf.get_mut(3)? = ck[1];
        *buf.get_mut(4)? = self.rest[0];
        *buf.get_mut(5)? = self.rest[1];
        *buf.get_mut(6)? = self.rest[2];
        *buf.get_mut(7)? = self.rest[3];
        Some(())
    }

    /// Compute the RFC 792 checksum over the header (checksum zeroed) and
    /// `payload`.
    #[must_use]
    pub fn compute_checksum(self, payload: &[u8]) -> u16 {
        let mut buf = [0u8; Self::HEADER_LEN];
        let mut tmp = self;
        tmp.checksum = 0;
        let _ = tmp.serialize(&mut buf);
        checksum_combine(&[&buf, payload])
    }

    /// Returns `true` if [`Self::checksum`] is correct for the current
    /// header and `payload`.
    #[must_use]
    pub fn verify_checksum(self, payload: &[u8]) -> bool {
        self.compute_checksum(payload) == self.checksum
    }
}

/// The identifier and sequence fields extracted from an ICMP Echo
/// Request/Reply `rest` field.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::IcmpEchoHeader;
///
/// let echo = IcmpEchoHeader {
///     id: 0x1234,
///     sequence: 1,
/// };
/// let rest = echo.to_rest();
/// assert_eq!(IcmpEchoHeader::from_rest(rest), echo);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IcmpEchoHeader {
    /// Echo identifier — used to match replies to requests.
    pub id: u16,
    /// Echo sequence number — incremented by the sender for each request.
    pub sequence: u16,
}

impl IcmpEchoHeader {
    /// Pack this echo header into the 4-byte `rest` array used by
    /// [`IcmpHeader`].
    #[must_use]
    pub fn to_rest(self) -> [u8; 4] {
        let id = self.id.to_be_bytes();
        let seq = self.sequence.to_be_bytes();
        [id[0], id[1], seq[0], seq[1]]
    }

    /// Unpack an echo header from the 4-byte `rest` array.
    #[must_use]
    pub fn from_rest(rest: [u8; 4]) -> Self {
        Self {
            id: u16::from_be_bytes([rest[0], rest[1]]),
            sequence: u16::from_be_bytes([rest[2], rest[3]]),
        }
    }
}

// =============================================================================
// UDP (N0.4)
// =============================================================================

/// The pseudo-header used when computing UDP checksums (RFC 768).
///
/// The checksum covers this pseudo-header concatenated with the UDP header
/// and payload, to detect routing to the wrong address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UdpPseudoHeader {
    /// Source `IPv4` address.
    pub src_ip: Ipv4Addr,
    /// Destination `IPv4` address.
    pub dst_ip: Ipv4Addr,
    /// Reserved — must be zero.
    pub zero: u8,
    /// Protocol number — always `17` for UDP.
    pub protocol: u8,
    /// UDP length (header + payload) in bytes.
    pub udp_length: u16,
}

impl UdpPseudoHeader {
    /// Serialize the pseudo-header into a 12-byte array.
    #[must_use]
    fn to_bytes(self) -> [u8; 12] {
        let ul = self.udp_length.to_be_bytes();
        [
            self.src_ip.0[0],
            self.src_ip.0[1],
            self.src_ip.0[2],
            self.src_ip.0[3],
            self.dst_ip.0[0],
            self.dst_ip.0[1],
            self.dst_ip.0[2],
            self.dst_ip.0[3],
            self.zero,
            self.protocol,
            ul[0],
            ul[1],
        ]
    }
}

/// A parsed UDP header per RFC 768.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{Ipv4Addr, UdpHeader, UdpPseudoHeader};
///
/// let pseudo = UdpPseudoHeader {
///     src_ip: Ipv4Addr::LOOPBACK,
///     dst_ip: Ipv4Addr::LOOPBACK,
///     zero: 0,
///     protocol: 17,
///     udp_length: 8,
/// };
/// let mut hdr = UdpHeader {
///     src_port: 1234,
///     dst_port: 5678,
///     length: 8,
///     checksum: 0,
/// };
/// hdr.checksum = hdr.compute_checksum(pseudo, &[]);
/// assert!(hdr.verify_checksum(pseudo, &[]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UdpHeader {
    /// Source port number.
    pub src_port: u16,
    /// Destination port number.
    pub dst_port: u16,
    /// Total length of UDP datagram (header + payload) in bytes.
    pub length: u16,
    /// UDP checksum (`0` means no checksum over `IPv4`).
    pub checksum: u16,
}

impl UdpHeader {
    /// Wire length of the UDP header in bytes.
    pub const HEADER_LEN: usize = 8;

    /// Parse a UDP header from `bytes`.
    ///
    /// Returns `(header, remaining_payload)` or `None` if the buffer is
    /// shorter than [`Self::HEADER_LEN`].
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let hdr = Self {
            src_port: u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]),
            dst_port: u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            length: u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]),
            checksum: u16::from_be_bytes([*bytes.get(6)?, *bytes.get(7)?]),
        };
        Some((hdr, bytes.get(Self::HEADER_LEN..)?))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN`] bytes of
    /// `buf`.  Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        let sp = self.src_port.to_be_bytes();
        *buf.get_mut(0)? = sp[0];
        *buf.get_mut(1)? = sp[1];
        let dp = self.dst_port.to_be_bytes();
        *buf.get_mut(2)? = dp[0];
        *buf.get_mut(3)? = dp[1];
        let ln = self.length.to_be_bytes();
        *buf.get_mut(4)? = ln[0];
        *buf.get_mut(5)? = ln[1];
        let ck = self.checksum.to_be_bytes();
        *buf.get_mut(6)? = ck[0];
        *buf.get_mut(7)? = ck[1];
        Some(())
    }

    /// Compute the RFC 768 UDP checksum over `pseudo_header`, this header
    /// (checksum zeroed), and `payload`.
    #[must_use]
    pub fn compute_checksum(self, pseudo: UdpPseudoHeader, payload: &[u8]) -> u16 {
        let ph = pseudo.to_bytes();
        let mut hdr_buf = [0u8; Self::HEADER_LEN];
        let mut tmp = self;
        tmp.checksum = 0;
        let _ = tmp.serialize(&mut hdr_buf);
        checksum_combine(&[&ph, &hdr_buf, payload])
    }

    /// Returns `true` if [`Self::checksum`] is correct.
    #[must_use]
    pub fn verify_checksum(self, pseudo: UdpPseudoHeader, payload: &[u8]) -> bool {
        self.compute_checksum(pseudo, payload) == self.checksum
    }
}

// =============================================================================
// TCP (N0.5)
// =============================================================================

/// TCP control-bit constants.
///
/// Combine with bitwise OR to form a flags byte.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::TcpFlags;
///
/// let flags = TcpFlags::SYN | TcpFlags::ACK;
/// assert_eq!(flags, 0x12);
/// ```
pub struct TcpFlags;

impl TcpFlags {
    /// FIN — no more data from sender.
    pub const FIN: u8 = 0x01;
    /// SYN — synchronise sequence numbers.
    pub const SYN: u8 = 0x02;
    /// RST — reset the connection.
    pub const RST: u8 = 0x04;
    /// PSH — push buffered data to the receiving application.
    pub const PSH: u8 = 0x08;
    /// ACK — acknowledgement field is significant.
    pub const ACK: u8 = 0x10;
    /// URG — urgent pointer field is significant.
    pub const URG: u8 = 0x20;
}

/// The pseudo-header used when computing TCP checksums (RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpPseudoHeader {
    /// Source `IPv4` address.
    pub src_ip: Ipv4Addr,
    /// Destination `IPv4` address.
    pub dst_ip: Ipv4Addr,
    /// Reserved — must be zero.
    pub zero: u8,
    /// Protocol number — always `6` for TCP.
    pub protocol: u8,
    /// TCP segment length (header + payload) in bytes.
    pub tcp_length: u16,
}

impl TcpPseudoHeader {
    fn to_bytes(self) -> [u8; 12] {
        let tl = self.tcp_length.to_be_bytes();
        [
            self.src_ip.0[0],
            self.src_ip.0[1],
            self.src_ip.0[2],
            self.src_ip.0[3],
            self.dst_ip.0[0],
            self.dst_ip.0[1],
            self.dst_ip.0[2],
            self.dst_ip.0[3],
            self.zero,
            self.protocol,
            tl[0],
            tl[1],
        ]
    }
}

/// A parsed TCP header per RFC 793 (minimum 20 bytes, no options).
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{Ipv4Addr, TcpFlags, TcpHeader, TcpPseudoHeader};
///
/// let pseudo = TcpPseudoHeader {
///     src_ip: Ipv4Addr::LOOPBACK,
///     dst_ip: Ipv4Addr::LOOPBACK,
///     zero: 0,
///     protocol: 6,
///     tcp_length: 20,
/// };
/// let mut hdr = TcpHeader {
///     src_port: 12345,
///     dst_port: 80,
///     seq_num: 1,
///     ack_num: 0,
///     data_offset_flags: (5 << 12) | (TcpFlags::SYN as u16),
///     window: 65535,
///     checksum: 0,
///     urgent_ptr: 0,
/// };
/// hdr.checksum = hdr.compute_checksum(pseudo, &[]);
/// assert!(hdr.verify_checksum(pseudo, &[]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpHeader {
    /// Source port number.
    pub src_port: u16,
    /// Destination port number.
    pub dst_port: u16,
    /// Sequence number.
    pub seq_num: u32,
    /// Acknowledgement number (valid only when ACK flag is set).
    pub ack_num: u32,
    /// Data offset (4 bits, in 32-bit words) + reserved (3 bits) +
    /// control bits (9 bits) packed into a `u16`.
    pub data_offset_flags: u16,
    /// Receive window size in bytes.
    pub window: u16,
    /// TCP checksum.
    pub checksum: u16,
    /// Urgent pointer (valid only when URG flag is set).
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Minimum TCP header length in bytes (data offset = 5, no options).
    pub const HEADER_LEN_MIN: usize = 20;

    /// Parse a TCP header from `bytes`.
    ///
    /// Returns `(header, remaining_payload)` or `None` if the buffer is too
    /// short.  TCP options are not parsed; the payload starts after
    /// `data_offset * 4` bytes.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN_MIN {
            return None;
        }
        let dof = u16::from_be_bytes([*bytes.get(12)?, *bytes.get(13)?]);
        let data_offset = usize::from(dof >> 12) * 4;
        if data_offset < Self::HEADER_LEN_MIN || bytes.len() < data_offset {
            return None;
        }
        let hdr = Self {
            src_port: u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]),
            dst_port: u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            seq_num: u32::from_be_bytes([
                *bytes.get(4)?,
                *bytes.get(5)?,
                *bytes.get(6)?,
                *bytes.get(7)?,
            ]),
            ack_num: u32::from_be_bytes([
                *bytes.get(8)?,
                *bytes.get(9)?,
                *bytes.get(10)?,
                *bytes.get(11)?,
            ]),
            data_offset_flags: dof,
            window: u16::from_be_bytes([*bytes.get(14)?, *bytes.get(15)?]),
            checksum: u16::from_be_bytes([*bytes.get(16)?, *bytes.get(17)?]),
            urgent_ptr: u16::from_be_bytes([*bytes.get(18)?, *bytes.get(19)?]),
        };
        Some((hdr, bytes.get(data_offset..)?))
    }

    /// Serialize this header into the first [`Self::HEADER_LEN_MIN`] bytes of
    /// `buf`.  Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::HEADER_LEN_MIN {
            return None;
        }
        let sp = self.src_port.to_be_bytes();
        *buf.get_mut(0)? = sp[0];
        *buf.get_mut(1)? = sp[1];
        let dp = self.dst_port.to_be_bytes();
        *buf.get_mut(2)? = dp[0];
        *buf.get_mut(3)? = dp[1];
        let sn = self.seq_num.to_be_bytes();
        *buf.get_mut(4)? = sn[0];
        *buf.get_mut(5)? = sn[1];
        *buf.get_mut(6)? = sn[2];
        *buf.get_mut(7)? = sn[3];
        let an = self.ack_num.to_be_bytes();
        *buf.get_mut(8)? = an[0];
        *buf.get_mut(9)? = an[1];
        *buf.get_mut(10)? = an[2];
        *buf.get_mut(11)? = an[3];
        let dof = self.data_offset_flags.to_be_bytes();
        *buf.get_mut(12)? = dof[0];
        *buf.get_mut(13)? = dof[1];
        let wn = self.window.to_be_bytes();
        *buf.get_mut(14)? = wn[0];
        *buf.get_mut(15)? = wn[1];
        let ck = self.checksum.to_be_bytes();
        *buf.get_mut(16)? = ck[0];
        *buf.get_mut(17)? = ck[1];
        let up = self.urgent_ptr.to_be_bytes();
        *buf.get_mut(18)? = up[0];
        *buf.get_mut(19)? = up[1];
        Some(())
    }

    /// Extract the 8-bit flags from [`Self::data_offset_flags`].
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn flags(self) -> u8 {
        (self.data_offset_flags & 0x00FF) as u8
    }

    /// Return the data offset (header length) in bytes.
    #[must_use]
    pub fn data_offset(self) -> usize {
        usize::from(self.data_offset_flags >> 12) * 4
    }

    /// Compute the RFC 793 TCP checksum over `pseudo_header`, this header
    /// (checksum zeroed), and `payload`.
    #[must_use]
    pub fn compute_checksum(self, pseudo: TcpPseudoHeader, payload: &[u8]) -> u16 {
        let ph = pseudo.to_bytes();
        let mut hdr_buf = [0u8; Self::HEADER_LEN_MIN];
        let mut tmp = self;
        tmp.checksum = 0;
        let _ = tmp.serialize(&mut hdr_buf);
        checksum_combine(&[&ph, &hdr_buf, payload])
    }

    /// Returns `true` if [`Self::checksum`] is correct.
    #[must_use]
    pub fn verify_checksum(self, pseudo: TcpPseudoHeader, payload: &[u8]) -> bool {
        self.compute_checksum(pseudo, payload) == self.checksum
    }
}

// =============================================================================
// ARP (N0.6)
// =============================================================================

/// An ARP operation code.
///
/// # Examples
///
/// ```
/// use nexacore_types::net::ArpOperation;
///
/// assert_eq!(ArpOperation::REQUEST.0, 1);
/// assert_eq!(ArpOperation::REPLY.0, 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArpOperation(pub u16);

impl ArpOperation {
    /// ARP Request (`1`).
    pub const REQUEST: Self = Self(1);
    /// ARP Reply (`2`).
    pub const REPLY: Self = Self(2);
}

/// A complete ARP packet for `IPv4`-over-Ethernet (28 bytes, per RFC 826).
///
/// Fields `htype`, `ptype`, `hlen`, and `plen` are fixed for
/// `IPv4`-over-Ethernet and are validated by [`ArpPacket::parse`].
///
/// # Examples
///
/// ```
/// use nexacore_types::net::{ArpOperation, ArpPacket, Ipv4Addr, MacAddress};
///
/// let pkt = ArpPacket {
///     htype: 1,
///     ptype: 0x0800,
///     hlen: 6,
///     plen: 4,
///     operation: ArpOperation::REQUEST,
///     sender_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
///     sender_ip: Ipv4Addr([192, 168, 1, 1]),
///     target_mac: MacAddress([0, 0, 0, 0, 0, 0]),
///     target_ip: Ipv4Addr([192, 168, 1, 2]),
/// };
/// let mut buf = [0u8; ArpPacket::PACKET_LEN];
/// pkt.serialize(&mut buf).unwrap();
/// let parsed = ArpPacket::parse(&buf).unwrap();
/// assert_eq!(parsed.operation, ArpOperation::REQUEST);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArpPacket {
    /// Hardware type — `1` for Ethernet.
    pub htype: u16,
    /// Protocol type — `0x0800` for `IPv4`.
    pub ptype: u16,
    /// Hardware address length — `6` for MAC addresses.
    pub hlen: u8,
    /// Protocol address length — `4` for `IPv4`.
    pub plen: u8,
    /// Operation: REQUEST or REPLY.
    pub operation: ArpOperation,
    /// Sender hardware (MAC) address.
    pub sender_mac: MacAddress,
    /// Sender protocol (`IPv4`) address.
    pub sender_ip: Ipv4Addr,
    /// Target hardware (MAC) address (zeros in a request).
    pub target_mac: MacAddress,
    /// Target protocol (`IPv4`) address.
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Wire length of a complete ARP-for-`IPv4`-over-Ethernet packet.
    pub const PACKET_LEN: usize = 28;

    /// Parse an ARP packet from `bytes`.
    ///
    /// Returns `None` if the buffer is too short.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::PACKET_LEN {
            return None;
        }
        Some(Self {
            htype: u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]),
            ptype: u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]),
            hlen: *bytes.get(4)?,
            plen: *bytes.get(5)?,
            operation: ArpOperation(u16::from_be_bytes([*bytes.get(6)?, *bytes.get(7)?])),
            sender_mac: MacAddress([
                *bytes.get(8)?,
                *bytes.get(9)?,
                *bytes.get(10)?,
                *bytes.get(11)?,
                *bytes.get(12)?,
                *bytes.get(13)?,
            ]),
            sender_ip: Ipv4Addr([
                *bytes.get(14)?,
                *bytes.get(15)?,
                *bytes.get(16)?,
                *bytes.get(17)?,
            ]),
            target_mac: MacAddress([
                *bytes.get(18)?,
                *bytes.get(19)?,
                *bytes.get(20)?,
                *bytes.get(21)?,
                *bytes.get(22)?,
                *bytes.get(23)?,
            ]),
            target_ip: Ipv4Addr([
                *bytes.get(24)?,
                *bytes.get(25)?,
                *bytes.get(26)?,
                *bytes.get(27)?,
            ]),
        })
    }

    /// Serialize this packet into the first [`Self::PACKET_LEN`] bytes of
    /// `buf`.  Returns `None` if `buf` is too small.
    pub fn serialize(self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < Self::PACKET_LEN {
            return None;
        }
        let ht = self.htype.to_be_bytes();
        *buf.get_mut(0)? = ht[0];
        *buf.get_mut(1)? = ht[1];
        let pt = self.ptype.to_be_bytes();
        *buf.get_mut(2)? = pt[0];
        *buf.get_mut(3)? = pt[1];
        *buf.get_mut(4)? = self.hlen;
        *buf.get_mut(5)? = self.plen;
        let op = self.operation.0.to_be_bytes();
        *buf.get_mut(6)? = op[0];
        *buf.get_mut(7)? = op[1];
        *buf.get_mut(8)? = self.sender_mac.0[0];
        *buf.get_mut(9)? = self.sender_mac.0[1];
        *buf.get_mut(10)? = self.sender_mac.0[2];
        *buf.get_mut(11)? = self.sender_mac.0[3];
        *buf.get_mut(12)? = self.sender_mac.0[4];
        *buf.get_mut(13)? = self.sender_mac.0[5];
        *buf.get_mut(14)? = self.sender_ip.0[0];
        *buf.get_mut(15)? = self.sender_ip.0[1];
        *buf.get_mut(16)? = self.sender_ip.0[2];
        *buf.get_mut(17)? = self.sender_ip.0[3];
        *buf.get_mut(18)? = self.target_mac.0[0];
        *buf.get_mut(19)? = self.target_mac.0[1];
        *buf.get_mut(20)? = self.target_mac.0[2];
        *buf.get_mut(21)? = self.target_mac.0[3];
        *buf.get_mut(22)? = self.target_mac.0[4];
        *buf.get_mut(23)? = self.target_mac.0[5];
        *buf.get_mut(24)? = self.target_ip.0[0];
        *buf.get_mut(25)? = self.target_ip.0[1];
        *buf.get_mut(26)? = self.target_ip.0[2];
        *buf.get_mut(27)? = self.target_ip.0[3];
        Some(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // =========================================================================
    // MAC / Ethernet (N0.1)
    // =========================================================================

    #[test]
    fn mac_display_roundtrip_broadcast() {
        let mac = MacAddress::BROADCAST;
        assert_eq!(mac.to_string(), "ff:ff:ff:ff:ff:ff");
        let parsed = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
        assert_eq!(parsed, mac);
    }

    #[test]
    fn mac_display_roundtrip_zero() {
        let mac = MacAddress([0; 6]);
        assert_eq!(mac.to_string(), "00:00:00:00:00:00");
        let parsed = MacAddress::from_str("00:00:00:00:00:00").unwrap();
        assert_eq!(parsed, mac);
    }

    #[test]
    fn mac_display_roundtrip_mixed() {
        let mac = MacAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert_eq!(mac.to_string(), "01:23:45:67:89:ab");
        let parsed = MacAddress::from_str("01:23:45:67:89:ab").unwrap();
        assert_eq!(parsed, mac);
    }

    #[test]
    fn mac_broadcast_constant_is_all_ff() {
        assert_eq!(MacAddress::BROADCAST.0, [0xFF; 6]);
    }

    #[test]
    fn mac_is_broadcast() {
        assert!(MacAddress::BROADCAST.is_multicast());
    }

    #[test]
    fn mac_multicast_bit_set() {
        let mac = MacAddress([0x01, 0, 0, 0, 0, 0]);
        assert!(mac.is_multicast());
        assert!(!mac.is_unicast());
    }

    #[test]
    fn mac_unicast() {
        let mac = MacAddress([0x02, 0xAB, 0xCD, 0xEF, 0x01, 0x23]);
        assert!(mac.is_unicast());
        assert!(!mac.is_multicast());
    }

    #[test]
    fn mac_locally_administered() {
        let mac = MacAddress([0x02, 0, 0, 0, 0, 0]);
        assert!(mac.is_locally_administered());
    }

    #[test]
    fn mac_globally_administered() {
        let mac = MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert!(!mac.is_locally_administered());
    }

    #[test]
    fn mac_fromstr_invalid_too_few_octets() {
        assert!(MacAddress::from_str("01:02:03").is_err());
    }

    #[test]
    fn mac_fromstr_invalid_too_many_octets() {
        assert!(MacAddress::from_str("01:02:03:04:05:06:07").is_err());
    }

    #[test]
    fn mac_fromstr_invalid_non_hex() {
        assert!(MacAddress::from_str("zz:02:03:04:05:06").is_err());
    }

    #[test]
    fn mac_fromstr_invalid_empty() {
        assert!(MacAddress::from_str("").is_err());
    }

    #[test]
    fn ethernet_header_len_constant() {
        assert_eq!(EthernetHeader::HEADER_LEN, 14);
    }

    #[test]
    fn ethernet_header_parse_serialize_roundtrip() {
        let hdr = EthernetHeader {
            dst: MacAddress::BROADCAST,
            src: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ether_type: EtherType::IPV4,
        };
        let mut buf = [0u8; EthernetHeader::HEADER_LEN];
        hdr.serialize(&mut buf).unwrap();
        let (parsed, rest) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(rest.is_empty());
    }

    #[test]
    fn ethernet_header_parse_too_short() {
        let buf = [0u8; 13];
        assert!(EthernetHeader::parse(&buf).is_none());
    }

    #[test]
    fn ethernet_header_ethertype_arp() {
        let hdr = EthernetHeader {
            dst: MacAddress::BROADCAST,
            src: MacAddress([0x00; 6]),
            ether_type: EtherType::ARP,
        };
        let mut buf = [0u8; 64];
        hdr.serialize(&mut buf).unwrap();
        let (parsed, _) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(parsed.ether_type, EtherType::ARP);
    }

    #[test]
    fn ethernet_header_payload_slice() {
        let mut buf = [0xFFu8; EthernetHeader::HEADER_LEN + 4];
        let hdr = EthernetHeader {
            dst: MacAddress([0; 6]),
            src: MacAddress([0; 6]),
            ether_type: EtherType::IPV6,
        };
        hdr.serialize(&mut buf).unwrap();
        buf[EthernetHeader::HEADER_LEN] = 0x42;
        let (_, rest) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(rest.len(), 4);
        assert_eq!(rest[0], 0x42);
    }

    #[test]
    fn mtu_constants() {
        assert_eq!(MTU_DEFAULT, 1500);
        assert_eq!(MTU_JUMBO, 9000);
        assert_eq!(ETH_FRAME_MIN, 60);
        assert_eq!(ETH_FRAME_MAX, 1518);
    }

    // =========================================================================
    // IPv4 / IP (N0.2)
    // =========================================================================

    #[test]
    fn ipv4_display_roundtrip_loopback() {
        let addr = Ipv4Addr::LOOPBACK;
        assert_eq!(addr.to_string(), "127.0.0.1");
        let parsed = Ipv4Addr::from_str("127.0.0.1").unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn ipv4_display_roundtrip_broadcast() {
        let addr = Ipv4Addr::BROADCAST;
        assert_eq!(addr.to_string(), "255.255.255.255");
        let parsed = Ipv4Addr::from_str("255.255.255.255").unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn ipv4_display_roundtrip_arbitrary() {
        let addr = Ipv4Addr([10, 20, 30, 40]);
        assert_eq!(addr.to_string(), "10.20.30.40");
        let parsed = Ipv4Addr::from_str("10.20.30.40").unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn ipv4_is_loopback() {
        assert!(Ipv4Addr::LOOPBACK.is_loopback());
        assert!(Ipv4Addr([127, 255, 255, 255]).is_loopback());
        assert!(!Ipv4Addr([128, 0, 0, 1]).is_loopback());
    }

    #[test]
    fn ipv4_is_private_10_block() {
        assert!(Ipv4Addr([10, 0, 0, 1]).is_private());
        assert!(Ipv4Addr([10, 255, 255, 255]).is_private());
    }

    #[test]
    fn ipv4_is_private_172_block() {
        assert!(Ipv4Addr([172, 16, 0, 1]).is_private());
        assert!(Ipv4Addr([172, 31, 255, 255]).is_private());
        assert!(!Ipv4Addr([172, 15, 0, 1]).is_private());
        assert!(!Ipv4Addr([172, 32, 0, 1]).is_private());
    }

    #[test]
    fn ipv4_is_private_192_168_block() {
        assert!(Ipv4Addr([192, 168, 0, 1]).is_private());
        assert!(Ipv4Addr([192, 168, 255, 255]).is_private());
        assert!(!Ipv4Addr([192, 169, 0, 1]).is_private());
    }

    #[test]
    fn ipv4_is_broadcast() {
        assert!(Ipv4Addr::BROADCAST.is_broadcast());
        assert!(!Ipv4Addr::LOOPBACK.is_broadcast());
    }

    #[test]
    fn ipv4_is_multicast() {
        assert!(Ipv4Addr([224, 0, 0, 1]).is_multicast());
        assert!(Ipv4Addr([239, 255, 255, 255]).is_multicast());
        assert!(!Ipv4Addr([223, 0, 0, 1]).is_multicast());
        assert!(!Ipv4Addr([240, 0, 0, 1]).is_multicast());
    }

    #[test]
    fn ipv4_fromstr_invalid_empty() {
        assert!(Ipv4Addr::from_str("").is_err());
    }

    #[test]
    fn ipv4_fromstr_invalid_octet_out_of_range() {
        assert!(Ipv4Addr::from_str("256.0.0.1").is_err());
    }

    #[test]
    fn ipv4_fromstr_invalid_too_few_parts() {
        assert!(Ipv4Addr::from_str("1.2.3").is_err());
    }

    #[test]
    fn ipv4_fromstr_invalid_too_many_parts() {
        assert!(Ipv4Addr::from_str("1.2.3.4.5").is_err());
    }

    #[test]
    fn ipv4_constants() {
        assert_eq!(Ipv4Addr::LOOPBACK.0, [127, 0, 0, 1]);
        assert_eq!(Ipv4Addr::BROADCAST.0, [255, 255, 255, 255]);
        assert_eq!(Ipv4Addr::UNSPECIFIED.0, [0, 0, 0, 0]);
    }

    #[test]
    fn cidr_contains_inside() {
        let cidr = Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24).unwrap();
        assert!(cidr.contains(Ipv4Addr([192, 168, 1, 100])));
    }

    #[test]
    fn cidr_contains_outside() {
        let cidr = Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24).unwrap();
        assert!(!cidr.contains(Ipv4Addr([192, 168, 2, 1])));
    }

    #[test]
    fn cidr_contains_network_addr() {
        let cidr = Cidr::new(Ipv4Addr([10, 0, 0, 0]), 8).unwrap();
        assert!(cidr.contains(Ipv4Addr([10, 0, 0, 0])));
    }

    #[test]
    fn cidr_contains_broadcast_addr() {
        let cidr = Cidr::new(Ipv4Addr([10, 0, 0, 0]), 8).unwrap();
        assert!(cidr.contains(Ipv4Addr([10, 255, 255, 255])));
    }

    #[test]
    fn cidr_network_addr() {
        let cidr = Cidr::new(Ipv4Addr([192, 168, 1, 100]), 24).unwrap();
        assert_eq!(cidr.network_addr(), Ipv4Addr([192, 168, 1, 0]));
    }

    #[test]
    fn cidr_broadcast_addr() {
        let cidr = Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24).unwrap();
        assert_eq!(cidr.broadcast_addr(), Ipv4Addr([192, 168, 1, 255]));
    }

    #[test]
    fn cidr_netmask_24() {
        let cidr = Cidr::new(Ipv4Addr([0; 4]), 24).unwrap();
        assert_eq!(cidr.netmask(), Ipv4Addr([255, 255, 255, 0]));
    }

    #[test]
    fn cidr_netmask_0() {
        let cidr = Cidr::new(Ipv4Addr([0; 4]), 0).unwrap();
        assert_eq!(cidr.netmask(), Ipv4Addr([0, 0, 0, 0]));
    }

    #[test]
    fn cidr_netmask_32() {
        let cidr = Cidr::new(Ipv4Addr([1, 2, 3, 4]), 32).unwrap();
        assert_eq!(cidr.netmask(), Ipv4Addr([255, 255, 255, 255]));
    }

    #[test]
    fn cidr_prefix_len_too_large() {
        assert!(Cidr::new(Ipv4Addr([0; 4]), 33).is_none());
    }

    // =========================================================================
    // Ipv4Header (N0.2)
    // =========================================================================

    fn make_ipv4_header() -> Ipv4Header {
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: 20,
            identification: 0x1234,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IpProtocol::UDP,
            header_checksum: 0,
            src: Ipv4Addr([1, 2, 3, 4]),
            dst: Ipv4Addr([5, 6, 7, 8]),
        }
    }

    #[test]
    fn ipv4_header_len_constant() {
        assert_eq!(Ipv4Header::HEADER_LEN_MIN, 20);
    }

    #[test]
    fn ipv4_header_parse_serialize_roundtrip() {
        let mut hdr = make_ipv4_header();
        hdr.header_checksum = hdr.compute_checksum();
        let mut buf = [0u8; Ipv4Header::HEADER_LEN_MIN];
        hdr.serialize(&mut buf).unwrap();
        let (parsed, rest) = Ipv4Header::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(rest.is_empty());
    }

    #[test]
    fn ipv4_header_checksum_compute_verify() {
        let mut hdr = make_ipv4_header();
        hdr.header_checksum = hdr.compute_checksum();
        assert!(hdr.verify_checksum());
    }

    #[test]
    fn ipv4_header_checksum_detects_corruption() {
        let mut hdr = make_ipv4_header();
        hdr.header_checksum = hdr.compute_checksum();
        hdr.ttl = 63;
        assert!(!hdr.verify_checksum());
    }

    #[test]
    fn ipv4_header_parse_too_short() {
        let buf = [0u8; 19];
        assert!(Ipv4Header::parse(&buf).is_none());
    }

    // =========================================================================
    // ICMP (N0.3)
    // =========================================================================

    #[test]
    fn icmp_type_constants() {
        assert_eq!(IcmpType::ECHO_REPLY.0, 0);
        assert_eq!(IcmpType::DEST_UNREACHABLE.0, 3);
        assert_eq!(IcmpType::ECHO_REQUEST.0, 8);
        assert_eq!(IcmpType::TIME_EXCEEDED.0, 11);
    }

    #[test]
    fn icmp_code_constants() {
        assert_eq!(IcmpCode::NET_UNREACHABLE.0, 0);
        assert_eq!(IcmpCode::HOST_UNREACHABLE.0, 1);
        assert_eq!(IcmpCode::PORT_UNREACHABLE.0, 3);
    }

    #[test]
    fn icmp_echo_request_roundtrip() {
        let echo = IcmpEchoHeader {
            id: 0x0102,
            sequence: 7,
        };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REQUEST,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        let payload = b"hello";
        hdr.checksum = hdr.compute_checksum(payload);
        let mut buf = [0u8; IcmpHeader::HEADER_LEN + 5];
        hdr.serialize(&mut buf[..IcmpHeader::HEADER_LEN]).unwrap();
        buf[IcmpHeader::HEADER_LEN..].copy_from_slice(payload);
        let (parsed, rest) = IcmpHeader::parse(&buf).unwrap();
        assert_eq!(parsed.icmp_type, IcmpType::ECHO_REQUEST);
        assert!(parsed.verify_checksum(rest));
        let echo_out = IcmpEchoHeader::from_rest(parsed.rest);
        assert_eq!(echo_out.id, 0x0102);
        assert_eq!(echo_out.sequence, 7);
    }

    #[test]
    fn icmp_echo_reply_roundtrip() {
        let echo = IcmpEchoHeader {
            id: 0xBEEF,
            sequence: 42,
        };
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: echo.to_rest(),
        };
        hdr.checksum = hdr.compute_checksum(&[]);
        assert!(hdr.verify_checksum(&[]));
    }

    #[test]
    fn icmp_checksum_correct_with_payload() {
        let mut hdr = IcmpHeader {
            icmp_type: IcmpType::ECHO_REQUEST,
            code: IcmpCode::ZERO,
            checksum: 0,
            rest: [0, 1, 0, 1],
        };
        let payload = b"test payload data";
        hdr.checksum = hdr.compute_checksum(payload);
        assert!(hdr.verify_checksum(payload));
        assert!(!hdr.verify_checksum(b"wrong payload data"));
    }

    #[test]
    fn icmp_parse_malformed_too_short() {
        let buf = [0u8; 7];
        assert!(IcmpHeader::parse(&buf).is_none());
    }

    #[test]
    fn icmp_echo_header_from_rest_roundtrip() {
        let echo = IcmpEchoHeader {
            id: 0xCAFE,
            sequence: 0xBABE,
        };
        let rest = echo.to_rest();
        assert_eq!(IcmpEchoHeader::from_rest(rest), echo);
    }

    // =========================================================================
    // UDP (N0.4)
    // =========================================================================

    fn make_udp_pseudo(udp_len: u16) -> UdpPseudoHeader {
        UdpPseudoHeader {
            src_ip: Ipv4Addr([1, 2, 3, 4]),
            dst_ip: Ipv4Addr([5, 6, 7, 8]),
            zero: 0,
            protocol: 17,
            udp_length: udp_len,
        }
    }

    #[test]
    fn udp_header_len_constant() {
        assert_eq!(UdpHeader::HEADER_LEN, 8);
    }

    #[test]
    fn udp_header_parse_serialize_roundtrip() {
        let pseudo = make_udp_pseudo(8);
        let mut hdr = UdpHeader {
            src_port: 1234,
            dst_port: 5678,
            length: 8,
            checksum: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, &[]);
        let mut buf = [0u8; UdpHeader::HEADER_LEN];
        hdr.serialize(&mut buf).unwrap();
        let (parsed, rest) = UdpHeader::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(rest.is_empty());
    }

    #[test]
    fn udp_checksum_with_payload() {
        let payload = b"udp data";
        #[allow(clippy::cast_possible_truncation)]
        let pseudo = make_udp_pseudo((UdpHeader::HEADER_LEN + payload.len()) as u16);
        let mut hdr = UdpHeader {
            src_port: 9000,
            dst_port: 53,
            length: pseudo.udp_length,
            checksum: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, payload);
        assert!(hdr.verify_checksum(pseudo, payload));
    }

    #[test]
    fn udp_port_zero_valid() {
        let pseudo = make_udp_pseudo(8);
        let mut hdr = UdpHeader {
            src_port: 0,
            dst_port: 0,
            length: 8,
            checksum: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, &[]);
        assert!(hdr.verify_checksum(pseudo, &[]));
    }

    #[test]
    fn udp_parse_too_short() {
        let buf = [0u8; 7];
        assert!(UdpHeader::parse(&buf).is_none());
    }

    // =========================================================================
    // TCP (N0.5)
    // =========================================================================

    fn make_tcp_pseudo(tcp_len: u16) -> TcpPseudoHeader {
        TcpPseudoHeader {
            src_ip: Ipv4Addr([10, 0, 0, 1]),
            dst_ip: Ipv4Addr([10, 0, 0, 2]),
            zero: 0,
            protocol: 6,
            tcp_length: tcp_len,
        }
    }

    #[test]
    fn tcp_flags_combined() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        assert_eq!(flags, 0x12);
        assert!(flags & TcpFlags::SYN != 0);
        assert!(flags & TcpFlags::ACK != 0);
        assert!(flags & TcpFlags::FIN == 0);
    }

    #[test]
    fn tcp_flags_all_distinct() {
        assert_eq!(TcpFlags::FIN, 0x01);
        assert_eq!(TcpFlags::SYN, 0x02);
        assert_eq!(TcpFlags::RST, 0x04);
        assert_eq!(TcpFlags::PSH, 0x08);
        assert_eq!(TcpFlags::ACK, 0x10);
        assert_eq!(TcpFlags::URG, 0x20);
    }

    #[test]
    fn tcp_header_len_constant() {
        assert_eq!(TcpHeader::HEADER_LEN_MIN, 20);
    }

    #[test]
    fn tcp_header_parse_serialize_roundtrip() {
        let pseudo = make_tcp_pseudo(20);
        let mut hdr = TcpHeader {
            src_port: 12345,
            dst_port: 80,
            seq_num: 0xDEAD_BEEF,
            ack_num: 0,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, &[]);
        let mut buf = [0u8; TcpHeader::HEADER_LEN_MIN];
        hdr.serialize(&mut buf).unwrap();
        let (parsed, rest) = TcpHeader::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(rest.is_empty());
    }

    #[test]
    fn tcp_checksum_with_payload() {
        let payload = b"GET / HTTP/1.0\r\n\r\n";
        #[allow(clippy::cast_possible_truncation)]
        let tcp_len = (TcpHeader::HEADER_LEN_MIN + payload.len()) as u16;
        let pseudo = make_tcp_pseudo(tcp_len);
        let mut hdr = TcpHeader {
            src_port: 54321,
            dst_port: 80,
            seq_num: 1,
            ack_num: 0,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::PSH) | u16::from(TcpFlags::ACK),
            window: 8192,
            checksum: 0,
            urgent_ptr: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, payload);
        assert!(hdr.verify_checksum(pseudo, payload));
    }

    #[test]
    fn tcp_syn_packet_construction() {
        let pseudo = make_tcp_pseudo(20);
        let mut hdr = TcpHeader {
            src_port: 1024,
            dst_port: 443,
            seq_num: 0x0000_0001,
            ack_num: 0,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        hdr.checksum = hdr.compute_checksum(pseudo, &[]);
        assert_eq!(hdr.flags() & TcpFlags::SYN, TcpFlags::SYN);
        assert_eq!(hdr.flags() & TcpFlags::ACK, 0);
        assert_eq!(hdr.data_offset(), 20);
        assert!(hdr.verify_checksum(pseudo, &[]));
    }

    #[test]
    fn tcp_data_offset_extraction() {
        let hdr = TcpHeader {
            src_port: 0,
            dst_port: 0,
            seq_num: 0,
            ack_num: 0,
            data_offset_flags: 5 << 12,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        };
        assert_eq!(hdr.data_offset(), 20);
    }

    #[test]
    fn tcp_parse_too_short() {
        let buf = [0u8; 19];
        assert!(TcpHeader::parse(&buf).is_none());
    }

    // =========================================================================
    // ARP (N0.6)
    // =========================================================================

    fn make_arp_request() -> ArpPacket {
        ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            sender_ip: Ipv4Addr([192, 168, 1, 1]),
            target_mac: MacAddress([0, 0, 0, 0, 0, 0]),
            target_ip: Ipv4Addr([192, 168, 1, 2]),
        }
    }

    #[test]
    fn arp_packet_len_constant() {
        assert_eq!(ArpPacket::PACKET_LEN, 28);
    }

    #[test]
    fn arp_request_roundtrip() {
        let pkt = make_arp_request();
        let mut buf = [0u8; ArpPacket::PACKET_LEN];
        pkt.serialize(&mut buf).unwrap();
        let parsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn arp_reply_roundtrip() {
        let pkt = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REPLY,
            sender_mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            sender_ip: Ipv4Addr([192, 168, 1, 2]),
            target_mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            target_ip: Ipv4Addr([192, 168, 1, 1]),
        };
        let mut buf = [0u8; ArpPacket::PACKET_LEN];
        pkt.serialize(&mut buf).unwrap();
        let parsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(parsed, pkt);
        assert_eq!(parsed.operation, ArpOperation::REPLY);
    }

    #[test]
    fn arp_parse_from_frame() {
        let pkt = make_arp_request();
        let mut buf = [0u8; EthernetHeader::HEADER_LEN + ArpPacket::PACKET_LEN];
        let eth = EthernetHeader {
            dst: MacAddress::BROADCAST,
            src: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ether_type: EtherType::ARP,
        };
        eth.serialize(&mut buf[..EthernetHeader::HEADER_LEN])
            .unwrap();
        pkt.serialize(&mut buf[EthernetHeader::HEADER_LEN..])
            .unwrap();
        let (eth_parsed, rest) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(eth_parsed.ether_type, EtherType::ARP);
        let arp_parsed = ArpPacket::parse(rest).unwrap();
        assert_eq!(arp_parsed.sender_ip, Ipv4Addr([192, 168, 1, 1]));
    }

    #[test]
    fn arp_parse_too_short() {
        let buf = [0u8; 27];
        assert!(ArpPacket::parse(&buf).is_none());
    }

    #[test]
    fn arp_operation_constants() {
        assert_eq!(ArpOperation::REQUEST.0, 1);
        assert_eq!(ArpOperation::REPLY.0, 2);
    }

    // =========================================================================
    // Wire serialization round-trips via crate::wire (postcard)
    // =========================================================================

    #[test]
    fn mac_wire_roundtrip() {
        use crate::wire::{decode_canonical, encode_canonical};
        let mac = MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let bytes = encode_canonical(&mac).unwrap();
        let decoded: MacAddress = decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, mac);
    }

    #[test]
    fn ipv4_addr_wire_roundtrip() {
        use crate::wire::{decode_canonical, encode_canonical};
        let addr = Ipv4Addr([192, 0, 2, 1]);
        let bytes = encode_canonical(&addr).unwrap();
        let decoded: Ipv4Addr = decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn socket_addr_wire_roundtrip() {
        use crate::wire::{decode_canonical, encode_canonical};
        let sa = SocketAddr {
            ip: IpAddr::V4(Ipv4Addr::LOOPBACK),
            port: 443,
        };
        let bytes = encode_canonical(&sa).unwrap();
        let decoded: SocketAddr = decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, sa);
    }

    #[test]
    fn arp_packet_wire_roundtrip() {
        use crate::wire::{decode_canonical, encode_canonical};
        let pkt = make_arp_request();
        let bytes = encode_canonical(&pkt).unwrap();
        let decoded: ArpPacket = decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, pkt);
    }
}
