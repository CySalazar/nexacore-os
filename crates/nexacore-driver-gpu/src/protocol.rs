//! virtio-gpu control-queue protocol (VIRTIO 1.x § 5.7).
//!
//! All structures are little-endian on the wire. The serializers build the
//! exact byte sequence the guest places in a control-queue descriptor; the
//! parsers read the device's response header and `OK_DISPLAY_INFO` payload.

use alloc::vec::Vec;

/// Size of `virtio_gpu_ctrl_hdr` in bytes.
pub const CTRL_HDR_LEN: usize = 24;

/// Maximum number of scanouts a virtio-gpu device exposes
/// (`VIRTIO_GPU_MAX_SCANOUTS`).
pub const MAX_SCANOUTS: usize = 16;

/// `virtio_gpu_ctrl_hdr::flags` bit requesting a fence for this command.
pub const FLAG_FENCE: u32 = 1 << 0;

/// Control- and cursor-queue command / response type codes
/// (`virtio_gpu_ctrl_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CtrlType {
    // --- 2D control commands ---
    /// Enumerate scanouts and their preferred modes.
    GetDisplayInfo = 0x0100,
    /// Allocate a 2D host resource.
    ResourceCreate2d = 0x0101,
    /// Release a host resource.
    ResourceUnref = 0x0102,
    /// Set a resource as a scanout's framebuffer.
    SetScanout = 0x0103,
    /// Flush a resource region to the screen.
    ResourceFlush = 0x0104,
    /// Copy guest backing pixels into a host resource.
    TransferToHost2d = 0x0105,
    /// Attach guest backing pages to a resource.
    ResourceAttachBacking = 0x0106,
    /// Detach guest backing pages from a resource.
    ResourceDetachBacking = 0x0107,
    // --- 3D (virgl/venus) commands ---
    /// Create a 3D rendering context.
    CtxCreate = 0x0200,
    /// Destroy a 3D rendering context.
    CtxDestroy = 0x0201,
    /// Submit a 3D command stream.
    Submit3d = 0x0207,
    // --- cursor-queue commands ---
    /// Define / update the hardware cursor image.
    UpdateCursor = 0x0300,
    /// Move the hardware cursor.
    MoveCursor = 0x0301,
    // --- responses ---
    /// Success, no payload.
    RespOkNoData = 0x1100,
    /// Success, `virtio_gpu_resp_display_info` payload follows.
    RespOkDisplayInfo = 0x1101,
    /// Generic device error.
    RespErrUnspec = 0x1200,
}

impl CtrlType {
    /// Map a raw little-endian type code to a known [`CtrlType`].
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0x0100 => Self::GetDisplayInfo,
            0x0101 => Self::ResourceCreate2d,
            0x0102 => Self::ResourceUnref,
            0x0103 => Self::SetScanout,
            0x0104 => Self::ResourceFlush,
            0x0105 => Self::TransferToHost2d,
            0x0106 => Self::ResourceAttachBacking,
            0x0107 => Self::ResourceDetachBacking,
            0x0200 => Self::CtxCreate,
            0x0201 => Self::CtxDestroy,
            0x0207 => Self::Submit3d,
            0x0300 => Self::UpdateCursor,
            0x0301 => Self::MoveCursor,
            0x1100 => Self::RespOkNoData,
            0x1101 => Self::RespOkDisplayInfo,
            0x1200 => Self::RespErrUnspec,
            _ => return None,
        })
    }
}

/// virtio-gpu 2D pixel formats (`virtio_gpu_formats`).
///
/// The `Unorm` suffix is part of each format's canonical spec name
/// (`VIRTIO_GPU_FORMAT_*_UNORM`), so the shared postfix is intentional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
#[repr(u32)]
pub enum GpuFormat {
    /// 32-bit BGRA.
    B8G8R8A8Unorm = 1,
    /// 32-bit BGRX (no alpha).
    B8G8R8X8Unorm = 2,
    /// 32-bit ARGB.
    A8R8G8B8Unorm = 3,
    /// 32-bit RGBA.
    R8G8B8A8Unorm = 67,
    /// 32-bit RGBX (no alpha).
    R8G8B8X8Unorm = 134,
}

/// A `virtio_gpu_rect` (x, y, width, height), 16 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    /// X offset.
    pub x: u32,
    /// Y offset.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Rect {
    /// A rectangle at the origin of the given size.
    #[must_use]
    pub fn sized(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    fn extend_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.x.to_le_bytes());
        out.extend_from_slice(&self.y.to_le_bytes());
        out.extend_from_slice(&self.width.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
    }
}

/// A `virtio_gpu_mem_entry`: one guest backing page run (addr, length), 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemEntry {
    /// Guest physical address of the backing run.
    pub addr: u64,
    /// Length of the run in bytes.
    pub length: u32,
}

/// The 24-byte `virtio_gpu_ctrl_hdr` prefixing every command and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlHeader {
    /// Command / response type.
    pub cmd_type: u32,
    /// Flags (e.g. [`FLAG_FENCE`]).
    pub flags: u32,
    /// Fence id, valid when [`FLAG_FENCE`] is set.
    pub fence_id: u64,
    /// 3D context id (0 for 2D commands).
    pub ctx_id: u32,
}

impl CtrlHeader {
    /// A 2D command header (no fence, no context).
    #[must_use]
    pub fn command(cmd_type: CtrlType) -> Self {
        Self {
            cmd_type: cmd_type as u32,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
        }
    }

    /// A 3D command header bound to context `ctx_id`.
    #[must_use]
    pub fn context(cmd_type: CtrlType, ctx_id: u32) -> Self {
        Self {
            cmd_type: cmd_type as u32,
            flags: 0,
            fence_id: 0,
            ctx_id,
        }
    }

    /// Append the 24-byte header to `out`.
    fn extend_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.cmd_type.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.fence_id.to_le_bytes());
        out.extend_from_slice(&self.ctx_id.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // ring_idx (u8) + 3 padding bytes.
    }

    /// Serialize the 24-byte header.
    #[must_use]
    pub fn to_bytes(self) -> [u8; CTRL_HDR_LEN] {
        let mut v = Vec::with_capacity(CTRL_HDR_LEN);
        self.extend_into(&mut v);
        let mut b = [0u8; CTRL_HDR_LEN];
        b.copy_from_slice(&v);
        b
    }
}

fn header(out: &mut Vec<u8>, cmd: CtrlType) {
    CtrlHeader::command(cmd).extend_into(out);
}

/// Build `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` (header only).
#[must_use]
pub fn build_get_display_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN);
    header(&mut out, CtrlType::GetDisplayInfo);
    out
}

/// Build `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D`.
#[must_use]
pub fn build_resource_create_2d(
    resource_id: u32,
    format: GpuFormat,
    width: u32,
    height: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 16);
    header(&mut out, CtrlType::ResourceCreate2d);
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&(format as u32).to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out
}

/// Build `VIRTIO_GPU_CMD_RESOURCE_UNREF`.
#[must_use]
pub fn build_resource_unref(resource_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 8);
    header(&mut out, CtrlType::ResourceUnref);
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // padding
    out
}

/// Build `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING` for the given backing runs.
#[must_use]
pub fn build_attach_backing(resource_id: u32, entries: &[MemEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 8 + entries.len() * 16);
    header(&mut out, CtrlType::ResourceAttachBacking);
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.addr.to_le_bytes());
        out.extend_from_slice(&e.length.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // padding
    }
    out
}

/// Build `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D`.
#[must_use]
pub fn build_transfer_to_host_2d(resource_id: u32, rect: Rect, offset: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 32);
    header(&mut out, CtrlType::TransferToHost2d);
    rect.extend_into(&mut out);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // padding
    out
}

/// Build `VIRTIO_GPU_CMD_SET_SCANOUT`.
#[must_use]
pub fn build_set_scanout(scanout_id: u32, resource_id: u32, rect: Rect) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 24);
    header(&mut out, CtrlType::SetScanout);
    rect.extend_into(&mut out);
    out.extend_from_slice(&scanout_id.to_le_bytes());
    out.extend_from_slice(&resource_id.to_le_bytes());
    out
}

/// Build `VIRTIO_GPU_CMD_RESOURCE_FLUSH`.
#[must_use]
pub fn build_resource_flush(resource_id: u32, rect: Rect) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 24);
    header(&mut out, CtrlType::ResourceFlush);
    rect.extend_into(&mut out);
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // padding
    out
}

/// Read the response type code from a device response buffer (first u32 of the
/// control header). Returns `None` if the buffer is shorter than the header.
#[must_use]
pub fn parse_ctrl_type(resp: &[u8]) -> Option<CtrlType> {
    let b: [u8; 4] = resp.get(0..4)?.try_into().ok()?;
    CtrlType::from_u32(u32::from_le_bytes(b))
}

/// One scanout entry parsed from a `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedScanout {
    /// Preferred rectangle (position + size) for the scanout.
    pub rect: Rect,
    /// Whether the scanout is enabled (connected).
    pub enabled: bool,
}

/// Parse a `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` response into its scanout array.
///
/// Returns `None` if the response type is not `OK_DISPLAY_INFO` or the buffer
/// is too short for all [`MAX_SCANOUTS`] entries.
#[must_use]
pub fn parse_display_info(resp: &[u8]) -> Option<Vec<ParsedScanout>> {
    if parse_ctrl_type(resp)? != CtrlType::RespOkDisplayInfo {
        return None;
    }
    let mut out = Vec::with_capacity(MAX_SCANOUTS);
    for i in 0..MAX_SCANOUTS {
        // Each pmode is 24 bytes: rect(16) + enabled(4) + flags(4).
        let base = CTRL_HDR_LEN + i * 24;
        let x = read_u32(resp, base)?;
        let y = read_u32(resp, base + 4)?;
        let width = read_u32(resp, base + 8)?;
        let height = read_u32(resp, base + 12)?;
        let enabled = read_u32(resp, base + 16)? != 0;
        out.push(ParsedScanout {
            rect: Rect {
                x,
                y,
                width,
                height,
            },
            enabled,
        });
    }
    Some(out)
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = buf.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Build a `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` response (test/loopback helper):
/// a control header followed by [`MAX_SCANOUTS`] pmode entries.
#[cfg(test)]
pub(crate) fn build_display_info_resp(scanouts: &[ParsedScanout]) -> Vec<u8> {
    let mut out = Vec::new();
    CtrlHeader::command(CtrlType::RespOkDisplayInfo).extend_into(&mut out);
    for i in 0..MAX_SCANOUTS {
        let s = scanouts.get(i).copied().unwrap_or_else(|| ParsedScanout {
            rect: Rect::default(),
            enabled: false,
        });
        s.rect.extend_into(&mut out);
        out.extend_from_slice(&u32::from(s.enabled).to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // flags
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_header_is_24_bytes_le() {
        let cmd = build_get_display_info();
        assert_eq!(cmd.len(), CTRL_HDR_LEN);
        assert_eq!(&cmd[0..4], &(CtrlType::GetDisplayInfo as u32).to_le_bytes());
        // flags, fence_id, ctx_id, padding all zero.
        assert_eq!(&cmd[4..24], &[0u8; 20]);
    }

    #[test]
    fn resource_create_2d_layout() {
        let cmd = build_resource_create_2d(7, GpuFormat::B8G8R8A8Unorm, 1920, 1080);
        assert_eq!(cmd.len(), CTRL_HDR_LEN + 16);
        assert_eq!(read_u32(&cmd, 0), Some(CtrlType::ResourceCreate2d as u32));
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), Some(7)); // resource_id
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 4), Some(1)); // format B8G8R8A8
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 8), Some(1920));
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 12), Some(1080));
    }

    #[test]
    fn attach_backing_serializes_entries() {
        let entries = [
            MemEntry {
                addr: 0x1000,
                length: 4096,
            },
            MemEntry {
                addr: 0x8000,
                length: 8192,
            },
        ];
        let cmd = build_attach_backing(3, &entries);
        assert_eq!(cmd.len(), CTRL_HDR_LEN + 8 + 2 * 16);
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), Some(3)); // resource_id
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 4), Some(2)); // nr_entries
        // First entry addr (u64 LE).
        let a: [u8; 8] = cmd[CTRL_HDR_LEN + 8..CTRL_HDR_LEN + 16].try_into().unwrap();
        assert_eq!(u64::from_le_bytes(a), 0x1000);
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 16), Some(4096));
    }

    #[test]
    fn transfer_and_scanout_and_flush_lengths() {
        let r = Rect::sized(640, 480);
        assert_eq!(build_transfer_to_host_2d(1, r, 0).len(), CTRL_HDR_LEN + 32);
        assert_eq!(build_set_scanout(0, 1, r).len(), CTRL_HDR_LEN + 24);
        assert_eq!(build_resource_flush(1, r).len(), CTRL_HDR_LEN + 24);
    }

    #[test]
    fn display_info_round_trip() {
        let scanouts = [
            ParsedScanout {
                rect: Rect::sized(2560, 1440),
                enabled: true,
            },
            ParsedScanout {
                rect: Rect::sized(1920, 1080),
                enabled: true,
            },
        ];
        let resp = build_display_info_resp(&scanouts);
        assert_eq!(parse_ctrl_type(&resp), Some(CtrlType::RespOkDisplayInfo));
        let parsed = parse_display_info(&resp).expect("parse");
        assert_eq!(parsed.len(), MAX_SCANOUTS);
        assert_eq!(parsed[0].rect, Rect::sized(2560, 1440));
        assert!(parsed[0].enabled);
        assert!(parsed[1].enabled);
        assert!(!parsed[2].enabled); // unconfigured scanouts are disabled.
    }

    #[test]
    fn parse_rejects_wrong_response_type() {
        let mut out = Vec::new();
        CtrlHeader::command(CtrlType::RespOkNoData).extend_into(&mut out);
        assert!(parse_display_info(&out).is_none());
    }
}
