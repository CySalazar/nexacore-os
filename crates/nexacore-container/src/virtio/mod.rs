//! Virtio device backends — the **only** host↔guest I/O path for an
//! `NexaCoreContainer`.
//!
//! See `NCIP-Container-006` § 3 ("virtio device backing and capability
//! binding"). Every virtio device exposed to the guest is backed by a
//! host-side NexaCore userspace service that enforces capability scope on
//! each request. The guest sees a generic virtio device; the host
//! side translates each guest request to a capability check + an
//! NexaCore primitive call.
//!
//! | Device | Host backing | Capability required |
//! |---|---|---|
//! | `virtio-fs`      | `nexacore-fs` | `fs:read:<path>` / `fs:write:<path>` |
//! | `virtio-net`     | NexaCore network stack | `net:outbound:<host>:<port>` / `net:inbound:<port>` |
//! | `virtio-vsock`   | NexaCore IPC bridge | `ipc:channel:<id>` |
//! | `virtio-gpu`     | NexaCore tensor HAL | `gpu:shared` / `gpu:exclusive:<id>` |
//! | `virtio-rng`     | Kernel `getrandom` | (always granted) |
//!
//! Status: each submodule defines the host-side **trait** plus a
//! capability-bound functional backend (`CapabilityVirtio*` / `HostEntropyRng`
//! / `ProfileVirtioGpu`) that enforces the container's capabilities fail-closed
//! and is host-tested. The original `StubVirtio*` types are retained for the
//! trait-shape smoke tests. The shared split-virtqueue mechanism lives in
//! [`queue`]. Live device transports (sockets, host FS, tensor-HAL GPU) are
//! wired on the rig.

pub mod fs;
pub mod gpu;
pub mod net;
pub mod queue;
pub mod rng;
pub mod vsock;

pub use fs::{CapabilityVirtioFs, VirtioFsBackend};
pub use gpu::{ProfileVirtioGpu, VirtioGpuBackend};
pub use net::{CapabilityVirtioNet, VirtioNetBackend};
pub use queue::{DescriptorChain, Segment, SplitQueue};
pub use rng::{EntropySource, HostEntropyRng, VirtioRngBackend};
pub use vsock::{CapabilityVirtioVsock, VirtioVsockBackend};
