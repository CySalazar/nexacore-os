//! virtio-gpu 3D (virgl/venus) context commands (VIRTIO 1.x § 5.7, 3D subset).
//!
//! These commands ride the control queue but carry a non-zero `ctx_id` in the
//! header. `CTX_CREATE` opens a rendering context; `SUBMIT_3D` hands the host a
//! virgl/venus command stream. The byte layout is host-tested here; issuing the
//! stream against a real virglrenderer host is rig-side.

use alloc::vec::Vec;

use crate::protocol::{CTRL_HDR_LEN, CtrlHeader, CtrlType};

/// Length of the fixed `debug_name` field in `virtio_gpu_ctx_create`.
pub const CTX_DEBUG_NAME_LEN: usize = 64;

/// Build `VIRTIO_GPU_CMD_CTX_CREATE` for context `ctx_id`.
///
/// `debug_name` is truncated to [`CTX_DEBUG_NAME_LEN`] bytes and zero-padded.
#[must_use]
pub fn build_ctx_create(ctx_id: u32, debug_name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 8 + CTX_DEBUG_NAME_LEN);
    out.extend_from_slice(&CtrlHeader::context(CtrlType::CtxCreate, ctx_id).to_bytes());

    let name_bytes = debug_name.as_bytes();
    let nlen = name_bytes.len().min(CTX_DEBUG_NAME_LEN);
    out.extend_from_slice(&(nlen as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // context_init (0 = default capset)

    let mut name = [0u8; CTX_DEBUG_NAME_LEN];
    for (dst, src) in name.iter_mut().zip(name_bytes.iter()) {
        *dst = *src;
    }
    out.extend_from_slice(&name);
    out
}

/// Build `VIRTIO_GPU_CMD_SUBMIT_3D` for context `ctx_id`, carrying `commands`
/// (a virgl/venus command stream).
#[must_use]
pub fn build_submit_3d(ctx_id: u32, commands: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CTRL_HDR_LEN + 8 + commands.len());
    out.extend_from_slice(&CtrlHeader::context(CtrlType::Submit3d, ctx_id).to_bytes());
    out.extend_from_slice(&(commands.len() as u32).to_le_bytes()); // size
    out.extend_from_slice(&0u32.to_le_bytes()); // padding
    out.extend_from_slice(commands);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn ctx_create_carries_ctx_id_and_name() {
        let cmd = build_ctx_create(5, "render");
        assert_eq!(cmd.len(), CTRL_HDR_LEN + 8 + CTX_DEBUG_NAME_LEN);
        assert_eq!(read_u32(&cmd, 0), CtrlType::CtxCreate as u32);
        assert_eq!(read_u32(&cmd, 16), 5); // ctx_id in header
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), 6); // nlen == "render".len()
        assert_eq!(&cmd[CTRL_HDR_LEN + 8..CTRL_HDR_LEN + 14], b"render");
    }

    #[test]
    fn ctx_create_truncates_long_name() {
        let long = "x".repeat(200);
        let cmd = build_ctx_create(1, &long);
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), CTX_DEBUG_NAME_LEN as u32);
        assert_eq!(cmd.len(), CTRL_HDR_LEN + 8 + CTX_DEBUG_NAME_LEN);
    }

    #[test]
    fn submit_3d_embeds_stream_and_size() {
        let stream = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        let cmd = build_submit_3d(9, &stream);
        assert_eq!(cmd.len(), CTRL_HDR_LEN + 8 + stream.len());
        assert_eq!(read_u32(&cmd, 0), CtrlType::Submit3d as u32);
        assert_eq!(read_u32(&cmd, 16), 9); // ctx_id
        assert_eq!(read_u32(&cmd, CTRL_HDR_LEN), stream.len() as u32);
        assert_eq!(&cmd[CTRL_HDR_LEN + 8..], &stream);
    }
}
