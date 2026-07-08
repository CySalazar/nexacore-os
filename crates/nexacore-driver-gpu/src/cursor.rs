//! virtio-gpu cursor-queue commands (VIRTIO 1.x § 5.7.7).
//!
//! The cursor queue is separate from the control queue so cursor motion never
//! stalls behind framebuffer updates. `UPDATE_CURSOR` defines the cursor image
//! (a resource) and hotspot; `MOVE_CURSOR` repositions it. Both ride the same
//! 56-byte `virtio_gpu_update_cursor` structure.

use alloc::vec::Vec;

use crate::protocol::{CTRL_HDR_LEN, CtrlHeader, CtrlType};

/// A `virtio_gpu_cursor_pos`: the target scanout and position, 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CursorPos {
    /// Target scanout index.
    pub scanout_id: u32,
    /// X position in pixels.
    pub x: u32,
    /// Y position in pixels.
    pub y: u32,
}

impl CursorPos {
    fn extend_into(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.scanout_id.to_le_bytes());
        out.extend_from_slice(&self.x.to_le_bytes());
        out.extend_from_slice(&self.y.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // padding
    }
}

/// Total serialized length of a cursor command.
pub const CURSOR_CMD_LEN: usize = CTRL_HDR_LEN + 16 + 16;

/// Build `VIRTIO_GPU_CMD_UPDATE_CURSOR`: define the cursor image (`resource_id`)
/// and hotspot (`hot_x`, `hot_y`) at `pos`.
#[must_use]
pub fn build_update_cursor(pos: CursorPos, resource_id: u32, hot_x: u32, hot_y: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURSOR_CMD_LEN);
    out.extend_from_slice(&CtrlHeader::command(CtrlType::UpdateCursor).to_bytes());
    pos.extend_into(&mut out);
    out.extend_from_slice(&resource_id.to_le_bytes());
    out.extend_from_slice(&hot_x.to_le_bytes());
    out.extend_from_slice(&hot_y.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // padding
    out
}

/// Build `VIRTIO_GPU_CMD_MOVE_CURSOR`: reposition the existing cursor to `pos`.
/// The resource / hotspot fields are zero (ignored by the device for a move).
#[must_use]
pub fn build_move_cursor(pos: CursorPos) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURSOR_CMD_LEN);
    out.extend_from_slice(&CtrlHeader::command(CtrlType::MoveCursor).to_bytes());
    pos.extend_into(&mut out);
    out.extend_from_slice(&[0u8; 16]); // resource_id + hot_x + hot_y + padding
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn update_cursor_layout() {
        let pos = CursorPos {
            scanout_id: 1,
            x: 100,
            y: 200,
        };
        let cmd = build_update_cursor(pos, 42, 4, 8);
        assert_eq!(cmd.len(), CURSOR_CMD_LEN);
        assert_eq!(read_u32(&cmd, 0), CtrlType::UpdateCursor as u32);
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), 1); // scanout_id
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 4), 100); // x
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 8), 200); // y
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 16), 42); // resource_id
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 20), 4); // hot_x
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 24), 8); // hot_y
    }

    #[test]
    fn move_cursor_has_zero_image_fields() {
        let pos = CursorPos {
            scanout_id: 0,
            x: 5,
            y: 6,
        };
        let cmd = build_move_cursor(pos);
        assert_eq!(cmd.len(), CURSOR_CMD_LEN);
        assert_eq!(read_u32(&cmd, 0), CtrlType::MoveCursor as u32);
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 4), 5); // x
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN + 16), 0); // resource_id ignored
    }
}
