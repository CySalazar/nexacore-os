//! USB Video Class (UVC) descriptor parser (WS2-14.1).
//!
//! Walks a configuration-descriptor blob and extracts the UVC class-specific
//! (`CS_INTERFACE`) descriptors of the VideoControl and VideoStreaming
//! interfaces: the VC header (UVC version) and the VS format/frame descriptors
//! that tell the driver which pixel formats and resolutions the camera offers.
//! The enclosing standard interface descriptor's subclass (VideoControl = 1,
//! VideoStreaming = 2) is tracked so the overlapping subtype numbers are
//! disambiguated.
//!
//! All reads are bounds-checked over the untrusted device blob — a malformed
//! descriptor is skipped, never over-read. Format/frame negotiation
//! (PROBE/COMMIT) is WS2-14.2; isochronous capture is WS2-14.3.

#![allow(
    clippy::doc_markdown,
    reason = "UVC spec terms (VideoControl/VideoStreaming/bcdUVC) read better unquoted"
)]

use alloc::vec::Vec;

/// `bDescriptorType` for a standard interface descriptor.
const DT_INTERFACE: u8 = 0x04;
/// `bDescriptorType` for a class-specific interface descriptor.
const DT_CS_INTERFACE: u8 = 0x24;
/// USB Video device class code (`bInterfaceClass`).
const CLASS_VIDEO: u8 = 0x0E;
/// VideoControl subclass.
const SUBCLASS_VC: u8 = 0x01;
/// VideoStreaming subclass.
const SUBCLASS_VS: u8 = 0x02;

// VideoControl subtypes.
const VC_HEADER: u8 = 0x01;
// VideoStreaming subtypes.
const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
const VS_FRAME_UNCOMPRESSED: u8 = 0x05;
const VS_FORMAT_MJPEG: u8 = 0x06;
const VS_FRAME_MJPEG: u8 = 0x07;

/// A pixel-format family a VS format descriptor declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    /// Uncompressed (e.g. YUY2 / NV12).
    Uncompressed,
    /// Motion-JPEG.
    Mjpeg,
}

/// A VideoStreaming format descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UvcFormat {
    /// The format family.
    pub kind: FormatKind,
    /// `bFormatIndex` (1-based; referenced by frame descriptors and PROBE).
    pub format_index: u8,
    /// `bNumFrameDescriptors` — how many frame descriptors follow.
    pub num_frames: u8,
    /// `bDefaultFrameIndex`.
    pub default_frame_index: u8,
}

/// A VideoStreaming frame descriptor (one resolution of a format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UvcFrame {
    /// `bFrameIndex` (1-based).
    pub frame_index: u8,
    /// Frame width in pixels.
    pub width: u16,
    /// Frame height in pixels.
    pub height: u16,
    /// `dwDefaultFrameInterval` in 100-ns units.
    pub default_interval_100ns: u32,
}

impl UvcFrame {
    /// The default frame rate in whole frames per second (0 if unspecified).
    #[must_use]
    #[allow(clippy::integer_division, reason = "fps = 10^7 / interval, truncated")]
    pub fn default_fps(&self) -> u32 {
        if self.default_interval_100ns == 0 {
            0
        } else {
            10_000_000 / self.default_interval_100ns
        }
    }
}

/// A decoded UVC class-specific descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvcDescriptor {
    /// The VideoControl header (`bcdUVC` version).
    VcHeader {
        /// `bcdUVC` — the UVC specification version (BCD).
        uvc_version: u16,
    },
    /// A VideoStreaming format.
    Format(UvcFormat),
    /// A VideoStreaming frame.
    Frame(UvcFrame),
}

fn u16_at(block: &[u8], off: usize) -> Option<u16> {
    let b = block.get(off..off + 2)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn u32_at(block: &[u8], off: usize) -> Option<u32> {
    let b = block.get(off..off + 4)?;
    Some(u32::from_le_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

/// The current interface context during the walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    VideoControl,
    VideoStreaming,
    Other,
}

/// Interpret one `CS_INTERFACE` descriptor `block` in the given `context`.
fn parse_cs(context: Context, block: &[u8]) -> Option<UvcDescriptor> {
    let subtype = *block.get(2)?;
    match context {
        Context::VideoControl if subtype == VC_HEADER => Some(UvcDescriptor::VcHeader {
            uvc_version: u16_at(block, 3)?,
        }),
        Context::VideoStreaming => match subtype {
            VS_FORMAT_UNCOMPRESSED | VS_FORMAT_MJPEG => Some(UvcDescriptor::Format(UvcFormat {
                kind: if subtype == VS_FORMAT_MJPEG {
                    FormatKind::Mjpeg
                } else {
                    FormatKind::Uncompressed
                },
                format_index: *block.get(3)?,
                num_frames: *block.get(4)?,
                // Uncompressed carries a 16-byte GUID + bpp before the default
                // index (offset 22); MJPEG has it at offset 6.
                default_frame_index: if subtype == VS_FORMAT_MJPEG {
                    *block.get(6)?
                } else {
                    *block.get(22)?
                },
            })),
            VS_FRAME_UNCOMPRESSED | VS_FRAME_MJPEG => Some(UvcDescriptor::Frame(UvcFrame {
                frame_index: *block.get(3)?,
                width: u16_at(block, 5)?,
                height: u16_at(block, 7)?,
                default_interval_100ns: u32_at(block, 21)?,
            })),
            _ => None,
        },
        _ => None,
    }
}

/// Extract the UVC class-specific descriptors from a configuration blob
/// (WS2-14.1).
#[must_use]
pub fn parse_uvc_descriptors(data: &[u8]) -> Vec<UvcDescriptor> {
    let mut out = Vec::new();
    let mut context = Context::Other;
    let mut i = 0usize;
    while let Some(&length) = data.get(i) {
        let len = length as usize;
        if len < 2 {
            break; // zero/one-byte descriptor is malformed — stop
        }
        let Some(block) = data.get(i..i + len) else {
            break; // declared length runs past the blob
        };
        match block.get(1).copied() {
            Some(DT_INTERFACE) => {
                // Track the VideoControl / VideoStreaming context.
                context = if block.get(5).copied() == Some(CLASS_VIDEO) {
                    match block.get(6).copied() {
                        Some(SUBCLASS_VC) => Context::VideoControl,
                        Some(SUBCLASS_VS) => Context::VideoStreaming,
                        _ => Context::Other,
                    }
                } else {
                    Context::Other
                };
            }
            Some(DT_CS_INTERFACE) => {
                if let Some(desc) = parse_cs(context, block) {
                    out.push(desc);
                }
            }
            _ => {}
        }
        i += len;
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A VideoControl interface (subclass 1) + a `VC_HEADER` (UVC 1.10).
    fn vc_interface() -> [u8; 9 + 13] {
        let mut d = [0u8; 22];
        // Standard interface descriptor (9 bytes).
        d[0] = 9;
        d[1] = DT_INTERFACE;
        d[5] = CLASS_VIDEO;
        d[6] = SUBCLASS_VC;
        // VC_HEADER (13 bytes): len, CS_INTERFACE, subtype=1, bcdUVC=0x0110.
        d[9] = 13;
        d[10] = DT_CS_INTERFACE;
        d[11] = VC_HEADER;
        d[12] = 0x10;
        d[13] = 0x01;
        d
    }

    #[test]
    fn parses_vc_header_version() {
        let descs = parse_uvc_descriptors(&vc_interface());
        assert_eq!(
            descs,
            [UvcDescriptor::VcHeader {
                uvc_version: 0x0110
            }]
        );
    }

    #[test]
    fn parses_mjpeg_format_and_frame() {
        let mut d = Vec::new();
        // Standard VideoStreaming interface descriptor.
        d.extend_from_slice(&[9, DT_INTERFACE, 0, 0, 1, CLASS_VIDEO, SUBCLASS_VS, 0, 0]);
        // VS_FORMAT_MJPEG (subtype 6): index 1, 1 frame, default frame 1.
        // Layout: len, CS_IF, subtype, bFormatIndex, bNumFrame, bmFlags,
        // bDefaultFrameIndex, ...
        d.extend_from_slice(&[11, DT_CS_INTERFACE, VS_FORMAT_MJPEG, 1, 1, 0, 1, 0, 0, 0, 0]);
        // VS_FRAME_MJPEG (subtype 7): index 1, 1280x720, 30 fps.
        // dwDefaultFrameInterval @ offset 21 = 333333 (100ns) → 30 fps.
        let mut frame = [0u8; 30];
        frame[0] = 30;
        frame[1] = DT_CS_INTERFACE;
        frame[2] = VS_FRAME_MJPEG;
        frame[3] = 1; // bFrameIndex
        frame[5..7].copy_from_slice(&1280u16.to_le_bytes()); // wWidth
        frame[7..9].copy_from_slice(&720u16.to_le_bytes()); // wHeight
        frame[21..25].copy_from_slice(&333_333u32.to_le_bytes());
        d.extend_from_slice(&frame);

        let descs = parse_uvc_descriptors(&d);
        assert_eq!(descs.len(), 2);
        assert_eq!(
            descs[0],
            UvcDescriptor::Format(UvcFormat {
                kind: FormatKind::Mjpeg,
                format_index: 1,
                num_frames: 1,
                default_frame_index: 1,
            })
        );
        let UvcDescriptor::Frame(f) = descs[1] else {
            panic!("expected a frame descriptor");
        };
        assert_eq!((f.width, f.height), (1280, 720));
        assert_eq!(f.default_fps(), 30);
    }

    #[test]
    fn subtype_one_outside_videocontrol_is_not_a_vc_header() {
        // A VideoStreaming subtype-1 (VS_INPUT_HEADER) must NOT be read as a
        // VC header — context disambiguation.
        let d = [
            9,
            DT_INTERFACE,
            0,
            0,
            1,
            CLASS_VIDEO,
            SUBCLASS_VS,
            0,
            0, // VS interface
            13,
            DT_CS_INTERFACE,
            VC_HEADER,
            0x10,
            0x01,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(parse_uvc_descriptors(&d).is_empty());
    }

    #[test]
    fn truncated_descriptor_is_skipped_not_overread() {
        // Declares length 30 but only a few bytes follow.
        let d = [
            9,
            DT_INTERFACE,
            0,
            0,
            1,
            CLASS_VIDEO,
            SUBCLASS_VS,
            0,
            0,
            30,
            DT_CS_INTERFACE,
            VS_FRAME_MJPEG,
        ];
        assert!(parse_uvc_descriptors(&d).is_empty());
    }
}
