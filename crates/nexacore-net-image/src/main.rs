//! Bare-metal network stack service binary for NexaCore OS.
//!
//! This binary is the `nexacore-net` service image that the NexaCore OS kernel spawns
//! after boot to run the userspace TCP/IP stack. It executes as a `no_std +
//! no_main` ELF on `x86_64-unknown-none`, compiled against the `nexacore-net`
//! library in its `no_std` mode.
//!
//! ## Architecture
//!
//! ```text
//! _start()
//!     bump allocator initialised from a static 512 KiB heap
//!     IpcCreateChannel("nexacore.svc.net.stack")        -> stack_channel
//!     IpcCreateChannel("nexacore.svc.net.stack.reply")  -> stack_reply_channel
//!     NetRegister("stack", stack_channel)           (kernel relay sends here)
//!     NetRegister("stack_reply", stack_reply_channel)(kernel relay receives here)
//!     NetLookup("virtio0")                          -> (cmd_ch, evt_ch)
//!     add_interface(eth0, 192.0.2.50/24, 52:54:00:12:34:56, mtu=1500)
//!     run_forever:
//!         IpcTryReceive(evt_ch)        -> NetEvent::FrameReceivedInline -> handle_frame
//!             SendFrame outputs        -> NetRequest::SendFrameInline -> IpcSend(cmd_ch)
//!         IpcTryReceive(stack_channel) -> SocketRequest -> handle_socket_request
//!             SocketResponse           -> IpcSend(stack_reply_channel)
//! ```
//!
//! ## Two-channel rendezvous
//!
//! A kernel IPC channel has a single queue and a single blocked-receiver slot.
//! The kernel socket-syscall relay therefore SENDS each `SocketRequest` on the
//! `"stack"` channel (which this service receives on) and RECEIVES the
//! `SocketResponse` on a dedicated `"stack_reply"` channel (which this service
//! sends on). Replying on `"stack"` would make the service pop its own reply
//! and deadlock the relay.
//!
//! ## Static configuration (M0 / the test VM / ruling #6)
//!
//! | Field   | Value                              |
//! |---------|------------------------------------|
//! | IP      | `192.0.2.50`                     |
//! | Subnet  | `/24` (192.0.2.0/24)             |
//! | MAC     | `52:54:00:12:34:56` (virtio net0)  |
//! | MTU     | 1500                               |
//! | Gateway | none (target `.11` is on-subnet)   |
//!
//! ## Global allocator
//!
//! A bump allocator backed by a 512 KiB static buffer provides heap support.
//! It never frees individual blocks; acceptable because the process lifetime
//! equals the OS lifetime for a core service.
//!
//! ## Syscall layer
//!
//! Minimal inline-asm wrappers for the syscalls this binary actually needs.
//! `nexacore-usys` is deliberately NOT linked for the same `getrandom`-on-none
//! reason as `nexacore-shell-image`. The stubs follow the System V AMD64 ABI.

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use core::panic::PanicInfo;

use nexacore_net::{
    dhcp::{DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DhcpClient, DhcpLease, DhcpResult},
    dns::DnsResolver,
    ifconfig::{InterfaceInfo, NetConfigRequest, NetConfigResponse},
    ip::build_ipv4_packet,
    service::{NetworkService, ServiceOutput},
    udp::build_udp_packet,
};
use nexacore_types::{
    net::{EtherType, EthernetHeader, IpProtocol, Ipv4Addr, MacAddress, UdpHeader},
    net_channel::{NetEvent, NetRequest},
    socket::{SocketRequest, SocketResponse},
};

// =============================================================================
// Global allocator — two-class FREEING slab backed by static arenas
// =============================================================================
//
// The TCP service loop allocates short-lived `Vec<u8>`s on every relayed socket
// op — most importantly a `vec![0u8; max_len]` recv buffer (≤ 512 B, the AI
// client's CHUNK_CAP) PLUS a postcard `encode_canonical` response Vec — on
// EVERY `NetRecv`. The AI runtime polls `NetRecv` thousands of times during a
// multi-second model inference (RemoteGpu `/api/generate`), so a non-freeing
// bump allocator leaked ~600 B/recv and exhausted the 512 KiB heap in ~870
// recvs → this image OOM-panicked and DIED mid-request, so the late response
// segment was never ingested/ACKed and the connection hung (TASK-24, 2026-06-08).
// This is the IDENTICAL OOM the virtio-net driver image hit + fixed; nexacore-net
// never received the fix.
//
// This FREEING allocator reclaims every dropped block. Two size classes
// (64 B, 4096 B) cover all nexacore-net service allocations (ACK/encode Vecs → small;
// the 512 B recv buffer and ≤ AI_MAX_PAYLOAD frames → large) with O(1) alloc/free
// and no fragmentation; each uses an intrusive LIFO free list (free block's
// first word = next free address) plus a lazy bump cursor. Blocks are 16-byte
// aligned (`repr(align(16))` arena), satisfying every allocation's alignment
// (≤ 8). align > 16 or size > 4096 returns null (neither occurs — the relay is
// synchronous one-op-at-a-time and payloads are ≤ AI_MAX_PAYLOAD = 4096).
//
// SAFETY invariant: every static below is mutated only through `SlabAllocator`;
// the image is single-threaded (one Ring-3 task on one CPU).

/// Slab block size for the small class, in bytes.
const SMALL_BLK: usize = 64;
/// Slab block size for the large class, in bytes.
const LARGE_BLK: usize = 4096;
/// Small-class block count (64 B × 2048 = 128 KiB).
const SMALL_COUNT: usize = 2048;
/// Large-class block count (4096 B × 96 = 384 KiB).
const LARGE_COUNT: usize = 96;

/// 16-byte-aligned static arena so every block offset is 16-aligned.
#[repr(align(16))]
struct Arena<const N: usize>([u8; N]);

// SAFETY: mutated only through `SlabAllocator`; single-threaded.
static mut SMALL_ARENA: Arena<{ SMALL_BLK * SMALL_COUNT }> = Arena([0u8; SMALL_BLK * SMALL_COUNT]);
// SAFETY: mutated only through `SlabAllocator`; single-threaded.
static mut LARGE_ARENA: Arena<{ LARGE_BLK * LARGE_COUNT }> = Arena([0u8; LARGE_BLK * LARGE_COUNT]);

/// Free-list head per class: address of the first free block, `0` = empty.
static mut SMALL_FREE: usize = 0;
static mut LARGE_FREE: usize = 0;
/// Bump cursor per class: index of the next never-handed-out block.
static mut SMALL_NEXT: usize = 0;
static mut LARGE_NEXT: usize = 0;

/// Two-class FREEING slab allocator (see the section comment above).
struct SlabAllocator;

impl SlabAllocator {
    /// Pop a block of the class identified by its statics. Null if exhausted.
    ///
    /// # Safety
    ///
    /// The pointers must reference this image's class statics; single-threaded.
    unsafe fn class_alloc(
        free_head_ptr: *mut usize,
        next_ptr: *mut usize,
        arena_base: *mut u8,
        blk: usize,
        count: usize,
    ) -> *mut u8 {
        // SAFETY: single-threaded; pointers are to our own statics.
        unsafe {
            let head = free_head_ptr.read();
            if head != 0 {
                let next_free = (head as *const usize).read();
                free_head_ptr.write(next_free);
                return head as *mut u8;
            }
            let idx = next_ptr.read();
            if idx < count {
                next_ptr.write(idx + 1);
                return arena_base.add(idx * blk);
            }
            core::ptr::null_mut()
        }
    }

    /// Push a freed block onto the class free list.
    ///
    /// # Safety
    ///
    /// `ptr` was returned by `class_alloc` for the same class; single-threaded.
    unsafe fn class_free(free_head_ptr: *mut usize, ptr: *mut u8) {
        // SAFETY: single-threaded; `ptr` is a live block ≥ 8 bytes.
        unsafe {
            let head = free_head_ptr.read();
            (ptr as *mut usize).write(head);
            free_head_ptr.write(ptr as usize);
        }
    }
}

// SAFETY: `SlabAllocator` is a ZST; all mutable state lives in the `static mut`
// class globals above; single-threaded bare-metal target.
unsafe impl core::alloc::GlobalAlloc for SlabAllocator {
    /// Allocate from the smallest fitting class (null on exhaustion / align>16
    /// / size>LARGE_BLK).
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `layout.align()` is a power of two.
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        let size = layout.size();
        // SAFETY: addresses of our own class statics; single-threaded.
        unsafe {
            if size <= SMALL_BLK {
                Self::class_alloc(
                    core::ptr::addr_of_mut!(SMALL_FREE),
                    core::ptr::addr_of_mut!(SMALL_NEXT),
                    core::ptr::addr_of_mut!(SMALL_ARENA).cast::<u8>(),
                    SMALL_BLK,
                    SMALL_COUNT,
                )
            } else if size <= LARGE_BLK {
                Self::class_alloc(
                    core::ptr::addr_of_mut!(LARGE_FREE),
                    core::ptr::addr_of_mut!(LARGE_NEXT),
                    core::ptr::addr_of_mut!(LARGE_ARENA).cast::<u8>(),
                    LARGE_BLK,
                    LARGE_COUNT,
                )
            } else {
                core::ptr::null_mut()
            }
        }
    }

    /// Return a block to its class free list (O(1)).
    ///
    /// # Safety
    ///
    /// Per `GlobalAlloc` contract: `ptr`/`layout` match a prior `alloc`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        if ptr.is_null() {
            return;
        }
        let size = layout.size();
        // SAFETY: ptr came from the matching class in `alloc`; single-threaded.
        unsafe {
            if size <= SMALL_BLK {
                Self::class_free(core::ptr::addr_of_mut!(SMALL_FREE), ptr);
            } else if size <= LARGE_BLK {
                Self::class_free(core::ptr::addr_of_mut!(LARGE_FREE), ptr);
            }
        }
    }
}

/// Global allocator instance.
#[global_allocator]
static ALLOCATOR: SlabAllocator = SlabAllocator;

// =============================================================================
// Minimal syscall wrappers (System V AMD64 ABI)
// =============================================================================
//
// Constants mirror `nexacore_kernel::syscall::SyscallNumber`.

/// `IpcCreateChannel (20)` — create an **anonymous** IPC channel.
///
/// The kernel IPC layer is name-agnostic: `IpcCreateChannel` takes
/// `(queue_depth, backpressure, tee_bound, send_token_ptr, recv_token_ptr,
/// lens)` and returns a numeric channel id (or `SYSCALL_ERROR` in `rax`).
/// Human-readable names are bound separately via `NetRegister`.
const SYS_IPC_CREATE_CHANNEL: u64 = 20;

/// Backpressure policy `Block` (0) for `IpcCreateChannel` — a full queue parks
/// the sender until space frees. Must match `parse_backpressure` in the kernel
/// (`0 => Block, 1 => Drop, 2 => EvictOldest`).
const IPC_BACKPRESSURE_BLOCK: u64 = 0;

/// `tee_bound = false` for the channel policy (no TEE sealing for M0).
const IPC_TEE_BOUND_OFF: u64 = 0;

/// Queue depth for the socket-API channels. 16 slots comfortably absorb a
/// burst of relayed `SocketRequest`/`SocketResponse` messages before the
/// `Block` policy parks the sender.
const IPC_QUEUE_DEPTH: u64 = 16;

/// `IpcSend (22)` — send a message on a channel.
const SYS_IPC_SEND: u64 = 22;

/// `IpcTryReceive (24)` — non-blocking receive from a channel.
///
/// Returns `rax = u64::MAX` (the kernel `SYSCALL_ERROR` sentinel) when the
/// channel queue is empty, otherwise the number of bytes copied.
const SYS_IPC_TRY_RECEIVE: u64 = 24;

/// `NetRegister (100)` — register an IPC channel in the net channel registry.
const SYS_NET_REGISTER: u64 = 100;

/// `NetLookup (102)` — look up a net channel by interface name.
const SYS_NET_LOOKUP: u64 = 102;

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;

/// `SYSCALL_ERROR` sentinel returned in `rax` by single-register syscalls
/// (`IpcCreateChannel`, `IpcSend`, `IpcTryReceive`) on validation failure.
const SYSCALL_ERROR: u64 = u64::MAX;

/// `MessageKind::Request` (1) — a request expecting a reply. Used for frames
/// sent to the NIC driver's command channel (`NetRequest::SendFrameInline`).
/// Must match `nexacore_kernel::ipc::MessageKind::Request = 1`.
const IPC_KIND_REQUEST: u64 = 1;

/// `MessageKind::Reply` (2) — a reply to a prior request. Used for the
/// `SocketResponse` sent back on the `stack.reply` channel.
/// Must match `nexacore_kernel::ipc::MessageKind::Reply = 2`.
const IPC_KIND_REPLY: u64 = 2;

/// `TaskYield (12)` — voluntarily yield the CPU to the next runnable task.
///
/// Called on idle service-loop iterations so the cooperative scheduler rotates
/// to other Ring-3 processes (the NIC driver, the client). Without this, a
/// busy-poll loop monopolises the CPU and starves every other user task.
const SYS_TASK_YIELD: u64 = 12;
/// `TimeMonotonicNanos (50)` — monotonic clock in nanoseconds (rax).
const SYS_TIME_MONOTONIC_NANOS: u64 = 50;

/// `WriteConsole (60)` — write a byte slice to the kernel console (COM1).
///
/// Used for boot-time diagnostics so the service's progress is observable on
/// the serial log. ABI: `(ptr, len, 0, 0, 0, 0) -> bytes_written`.
const SYS_WRITE_CONSOLE: u64 = 60;

/// Issue a two-register-return syscall (`rax` = value, `rdx` = errno / second).
///
/// Follows the NexaCore OS kernel ABI: `rax` carries the syscall number on entry
/// and the primary return on exit; `rdx` carries argument `a2` on entry and the
/// secondary return (errno, or a paired value) on exit.
///
/// # Safety
///
/// The caller must ensure `number` is a valid syscall, pointer arguments are
/// valid for the duration of the call, and scalar arguments satisfy each
/// syscall's documented constraints.
#[inline(always)]
unsafe fn syscall2(
    number: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: `syscall` is the canonical Ring 3 -> Ring 0 transition. The
    // kernel's nexacore_syscall_entry SHUFFLES the argument registers
    // (rdi/rsi/rdx/r10/r8/r9) into SysV C-ABI order and does NOT restore them,
    // so each must be marked clobbered (`inout … => _`); otherwise the compiler
    // may keep a live value in one across the syscall and read garbage back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => rax,
            inout("rdi") a0 => _,
            inout("rsi") a1 => _,
            inlateout("rdx") a2 => rdx,
            inout("r10") a3 => _,
            inout("r8")  a4 => _,
            inout("r9")  a5 => _,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx)
}

/// Yield the CPU to the next runnable task. Issues `TaskYield (12)`.
fn sys_task_yield() {
    // SAFETY: TaskYield takes no arguments. Issued through the generic
    // 6-argument stub ON PURPOSE: the kernel syscall entry SHUFFLES the
    // argument registers (rdi/rsi/rdx/r10/r8/r9) and returns a value pair
    // in rax/rdx WITHOUT restoring any of them, so a minimal `asm!` that
    // clobbers only rcx/r11 lets the compiler keep live values (e.g. the
    // NEXT syscall's arguments) in registers the kernel destroys.
    // Hardware-observed as a boot-timing heisenbug (TASK-13: corrupted
    // input_len -> spurious EINVAL after one ENOENT retry); the generic
    // stub declares the full clobber set.
    let _ = unsafe { syscall2(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Monotonic clock in nanoseconds via `TimeMonotonicNanos (50)`.
fn sys_time_monotonic_nanos() -> u64 {
    // SAFETY: takes no pointer args; returns the nanosecond count in rax.
    let (rax, _) = unsafe { syscall2(SYS_TIME_MONOTONIC_NANOS, 0, 0, 0, 0, 0, 0) };
    rax
}

/// Write a diagnostic string to the kernel console (COM1 serial).
///
/// Best-effort: the return value is ignored. Used only for boot-time progress
/// markers so the service is observable on the serial log.
fn sys_write(msg: &str) {
    let bytes = msg.as_bytes();
    // SAFETY: bytes is a valid slice for the duration of the syscall.
    let _ = unsafe {
        syscall2(
            SYS_WRITE_CONSOLE,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
}

/// Terminate the calling process with exit `code`. Issues `TaskExit (11)`.
fn sys_exit(code: u32) -> ! {
    // SAFETY: TaskExit takes a u32 exit code in rdi and never returns.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

/// Create an **anonymous** IPC channel. Returns the channel id, or `u64::MAX`
/// (the [`SYSCALL_ERROR`] sentinel) on failure.
///
/// The kernel IPC layer is name-agnostic. ABI (per `ipc_create_channel` in the
/// kernel): `(queue_depth, backpressure, tee_bound, 0, 0, 0) -> rax` where `rax`
/// is the new channel id or `SYSCALL_ERROR` on an invalid backpressure code.
/// `backpressure` is fixed to [`IPC_BACKPRESSURE_BLOCK`] and `tee_bound` to
/// [`IPC_TEE_BOUND_OFF`] for the socket-API channels. Human-readable names are
/// bound separately via [`sys_net_register`].
fn sys_ipc_create_channel(queue_depth: u64) -> u64 {
    // SAFETY: IpcCreateChannel takes only scalar arguments (no pointers); the
    // channel id (or the SYSCALL_ERROR sentinel) is returned in rax, rdx unused.
    let (rax, _rdx) = unsafe {
        syscall2(
            SYS_IPC_CREATE_CHANNEL,
            queue_depth,
            IPC_BACKPRESSURE_BLOCK,
            IPC_TEE_BOUND_OFF,
            0,
            0,
            0,
        )
    };
    rax
}

/// Send a message on a channel (fire-and-forget). Returns `true` on success.
///
/// ABI (per `ipc_send` in the kernel): `(channel_id, kind, payload_ptr,
/// payload_len, 0, 0) -> rax` where `rax == 0` on success or `SYSCALL_ERROR`
/// on validation failure. `kind` is a `MessageKind` discriminant
/// ([`IPC_KIND_REQUEST`] / [`IPC_KIND_REPLY`]); omitting it (the previous bug)
/// shifted every argument and always yielded `SYSCALL_ERROR`.
fn sys_ipc_send(channel_id: u64, kind: u64, data: &[u8]) -> bool {
    // SAFETY: data is valid for the duration of the syscall.
    let (rax, _rdx) = unsafe {
        syscall2(
            SYS_IPC_SEND,
            channel_id,
            kind,
            data.as_ptr() as u64,
            data.len() as u64,
            0,
            0,
        )
    };
    rax != SYSCALL_ERROR
}

/// Non-blocking receive from a channel.
///
/// Writes up to `buf.len()` bytes into `buf` and returns `Some(n)` with the
/// number of bytes copied, or `None` when the queue is empty (the kernel
/// returns the `SYSCALL_ERROR` sentinel `u64::MAX`).
fn sys_ipc_try_receive(channel_id: u64, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: buf is a valid writable slice; the kernel writes at most
    // buf.len() bytes. IpcTryReceive is non-blocking and does not park.
    let (rax, _rdx) = unsafe {
        syscall2(
            SYS_IPC_TRY_RECEIVE,
            channel_id,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        )
    };
    if rax == u64::MAX {
        None
    } else {
        Some(rax as usize)
    }
}

/// Register an IPC channel pair in the net channel registry.
///
/// ABI (per `net_register` in the kernel): `(iface_ptr, iface_len, channel_id,
/// event_channel_id, mac_ptr, mac_len) -> (rax=0, rdx=errno)`. For the
/// socket-API pseudo-interfaces (`"stack"` / `"stack_reply"`) there is no event
/// channel and no MAC, so those arguments are zero. Returns `true` on success.
fn sys_net_register(iface_name: &str, channel_id: u64, event_channel_id: u64) -> bool {
    let name_bytes = iface_name.as_bytes();
    // SAFETY: name_bytes is valid for the duration of the syscall.
    let (_rax, rdx) = unsafe {
        syscall2(
            SYS_NET_REGISTER,
            name_bytes.as_ptr() as u64,
            name_bytes.len() as u64,
            channel_id,
            event_channel_id,
            0,
            0,
        )
    };
    rdx == 0
}

/// Look up a net channel pair by interface name.
///
/// ABI (per `net_lookup` in the kernel): `(iface_ptr, iface_len, 0,0,0,0) ->
/// (rax=command_channel_id, rdx=event_channel_id)` on success, or `rax =
/// u64::MAX` on a miss. Returns `Some((cmd, evt))` or `None`.
fn sys_net_lookup(iface_name: &str) -> Option<(u64, u64)> {
    let name_bytes = iface_name.as_bytes();
    // SAFETY: name_bytes is valid for the duration of the syscall.
    let (rax, rdx) = unsafe {
        syscall2(
            SYS_NET_LOOKUP,
            name_bytes.as_ptr() as u64,
            name_bytes.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    // A miss is signalled by the kernel as `rax == u64::MAX` (the SYSCALL_ERROR
    // sentinel). Also treat `rax == 0` as a miss defensively: a valid command-
    // channel id is never 0, so a 0 here can only be a malformed/legacy error
    // return — never a real interface — and must not be cached as a driver.
    if rax == u64::MAX || rax == 0 {
        None
    } else {
        Some((rax, rdx))
    }
}

// =============================================================================
// Wire encoding helpers
// =============================================================================

/// Encode `value` into `buf` via the canonical workspace wire format and return
/// the written byte slice.
///
/// Wraps [`nexacore_types::wire::encode_canonical`] (the single workspace audit
/// point for serialization per `NCIP-Serde-004`), copying the result into the
/// caller's scratch buffer so the returned slice can go straight to a syscall.
/// Returns `None` if the buffer is too small (4096 B always suffices given
/// `MAX_PAYLOAD = 4096`).
fn encode_into<'buf, T: serde::Serialize>(value: &T, buf: &'buf mut [u8]) -> Option<&'buf [u8]> {
    let encoded = nexacore_types::wire::encode_canonical(value).ok()?;
    let dst = buf.get_mut(..encoded.len())?;
    dst.copy_from_slice(&encoded);
    Some(dst)
}

/// Decode `bytes` into `T` via the canonical workspace wire format.
///
/// Wraps [`nexacore_types::wire::decode_canonical`]. Returns `None` on a
/// deserialisation error (malformed message, trailing bytes).
fn decode_from<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    nexacore_types::wire::decode_canonical(bytes).ok()
}

// =============================================================================
// Panic handler
// =============================================================================

/// Panic handler — terminate the task with a non-zero code.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    sys_exit(1)
}

// =============================================================================
// DHCP boot-time exchange helpers
// =============================================================================

/// Number of DISCOVER attempts before giving up and falling back to static.
const DHCP_MAX_ATTEMPTS: usize = 3;

/// Real-time window (nanoseconds) to wait for a DHCP reply per attempt, via the
/// monotonic clock. The server can lag the ACK by ~1 s (duplicate-address
/// detection / ARP probe of the offered IP) — far longer than an
/// iteration-counted window survived (TASK-25: the old 3000-iter loop expired
/// in ~84 ms, before the ACK, so the client kept re-DISCOVERing and the server
/// kept re-OFFERing instead of ACKing). 5 s comfortably covers the server's DAD
/// + ACK for a single DISCOVER→OFFER→REQUEST.
const DHCP_ATTEMPT_TIMEOUT_NS: u64 = 5_000_000_000;

/// Port 68 as a `u16` — the DHCP client destination port used to recognise
/// inbound DHCP replies in the raw frame stream.
const DHCP_CLIENT_PORT_U16: u16 = DHCP_CLIENT_PORT;

/// IPv4 broadcast address `255.255.255.255`.
const BROADCAST_IP: Ipv4Addr = Ipv4Addr([255, 255, 255, 255]);

/// IPv4 "all-zeros" source address `0.0.0.0` used in DHCP DISCOVER/REQUEST
/// before a lease has been obtained (RFC 2131 §4.1.1).
const UNSPECIFIED_IP: Ipv4Addr = Ipv4Addr([0, 0, 0, 0]);

/// Ethernet broadcast MAC address `ff:ff:ff:ff:ff:ff`.
const BROADCAST_MAC: MacAddress = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

/// Build a complete Ethernet/IPv4/UDP frame carrying `dhcp_payload`.
///
/// For DHCP DISCOVER and REQUEST the frame is broadcast:
/// - Ethernet dst  = `ff:ff:ff:ff:ff:ff`
/// - IP src/dst    = `0.0.0.0` → `255.255.255.255`
/// - UDP src/dst   = port 68 → port 67
///
/// For DNS queries and DHCP unicast the caller supplies non-broadcast
/// `src_ip`, `dst_ip`, and `dst_mac`.
///
/// The function constructs: `EthernetHdr(14) | IPv4Hdr(20) | UdpHdr(8) | payload`.
/// Checksum computation is delegated to `build_udp_packet` (UDP) and
/// `build_ipv4_packet` (IP) — neither panics.
///
/// # Security
///
/// All lengths are computed from the actual slices; no attacker-controlled
/// length is trusted.
fn build_udp_eth_frame(
    src_mac: MacAddress,
    dst_mac: MacAddress,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    // UDP datagram (header + payload) with correct checksum.
    let udp = build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload);
    // IPv4 packet wrapping the UDP datagram, TTL=64, DF set.
    let ip = build_ipv4_packet(src_ip, dst_ip, IpProtocol::UDP, 64, 0, &udp);
    // Ethernet frame prepended.
    let eth_hdr = EthernetHeader {
        dst: dst_mac,
        src: src_mac,
        ether_type: EtherType::IPV4,
    };
    let total = EthernetHeader::HEADER_LEN + ip.len();
    let mut frame = alloc::vec![0u8; total];
    // Serialize is infallible when buf >= HEADER_LEN (14 bytes), which it is.
    eth_hdr.serialize(
        frame
            .get_mut(..EthernetHeader::HEADER_LEN)
            .unwrap_or(&mut []),
    );
    if let Some(slot) = frame.get_mut(EthernetHeader::HEADER_LEN..) {
        slot.copy_from_slice(&ip);
    }
    frame
}

/// Extract the UDP payload from a raw Ethernet frame if it is an IPv4/UDP
/// datagram addressed to `dst_port`.
///
/// Returns `Some(payload_bytes)` on a matching, well-formed frame, or `None`
/// if the frame is not IPv4/UDP, the checksum fails, or the destination port
/// does not match.  All parsing is bounds-checked — a hostile/malformed frame
/// produces `None` and is silently discarded.
fn extract_udp_payload(frame: &[u8], dst_port: u16) -> Option<alloc::vec::Vec<u8>> {
    // Parse Ethernet header.
    let (eth_hdr, eth_payload) = EthernetHeader::parse(frame)?;
    if eth_hdr.ether_type != EtherType::IPV4 {
        return None;
    }
    // Parse IPv4 header — `parse_ipv4_packet` verifies the IP checksum.
    let (ip_hdr, ip_payload) = nexacore_net::ip::parse_ipv4_packet(eth_payload)?;
    if ip_hdr.protocol != IpProtocol::UDP {
        return None;
    }
    // Parse UDP header.
    let (udp_hdr, udp_payload) = UdpHeader::parse(ip_payload)?;
    if udp_hdr.dst_port != dst_port {
        return None;
    }
    Some(udp_payload.to_vec())
}

/// Run the boot-time DHCP exchange on `eth0`.
///
/// Sends a DHCP DISCOVER as a broadcast frame on the NIC driver command
/// channel.  Polls the driver event channel for replies, feeding each
/// well-formed UDP:68 datagram to `DhcpClient::handle_message`.  On a
/// `DhcpResult::SendRequest` the REQUEST is transmitted; on
/// `DhcpResult::Bound` the lease is returned.
///
/// The exchange is retried up to [`DHCP_MAX_ATTEMPTS`] times (one DISCOVER
/// per attempt), each with a real-time window of [`DHCP_ATTEMPT_TIMEOUT_NS`].
/// A `DhcpResult::Rejected` (NAK) restarts from Init.  All inputs are
/// untrusted; malformed frames are discarded via [`extract_udp_payload`].
///
/// Returns `Some(DhcpLease)` on success, or `None` when all attempts are
/// exhausted (the caller applies the static fallback).
///
/// # Arguments
///
/// * `driver_cmd`  — NIC driver command channel (TX path).
/// * `driver_evt`  — NIC driver event channel (RX path).
/// * `our_mac`     — Hardware MAC address of the interface.
/// * `xid`         — Transaction ID (caller-supplied; should be a pseudo-random
///                   `u32` seeded from e.g. the MAC bytes for uniqueness).
#[inline(never)]
fn run_dhcp(driver_cmd: u64, driver_evt: u64, our_mac: MacAddress, xid: u32) -> Option<DhcpLease> {
    let mut client = DhcpClient::new(our_mac.0, xid);
    let mut rx_buf = [0u8; 4096];
    let mut tx_buf = [0u8; 4096];

    'attempt: for attempt in 0..DHCP_MAX_ATTEMPTS {
        // --- Build and send DISCOVER ---
        let discover_payload = client.build_discover();
        let discover_frame = build_udp_eth_frame(
            our_mac,
            BROADCAST_MAC,
            UNSPECIFIED_IP,
            BROADCAST_IP,
            DHCP_CLIENT_PORT_U16,
            DHCP_SERVER_PORT,
            &discover_payload,
        );
        // Encode as NetRequest::SendFrameInline and send to the NIC driver.
        let req = NetRequest::SendFrameInline {
            bytes: discover_frame,
        };
        if let Some(encoded) = encode_into(&req, &mut tx_buf) {
            let _ = sys_ipc_send(driver_cmd, IPC_KIND_REQUEST, encoded);
        }

        // Log after each attempt so the serial shows progress.
        if attempt == 0 {
            sys_write("[nexacore-net] dhcp: discover sent\n");
        } else {
            sys_write("[nexacore-net] dhcp: retrying discover\n");
        }

        // --- Poll for OFFER then ACK (TIME-based window) ---
        //
        // The DHCP server can delay the ACK by ~1 s (duplicate-address
        // detection / ARP probe of the offered IP) — far longer than an
        // iteration-counted window survived (TASK-25: the old 3000-iter window
        // expired in ~84 ms, before the ACK). A monotonic-clock window
        // guarantees a real multi-second wait regardless of poll speed.
        let attempt_start = sys_time_monotonic_nanos();
        while sys_time_monotonic_nanos().wrapping_sub(attempt_start) < DHCP_ATTEMPT_TIMEOUT_NS {
            if let Some(n) = sys_ipc_try_receive(driver_evt, &mut rx_buf) {
                // Decode the NetEvent wrapper.
                if let Some(event) = decode_from::<NetEvent>(rx_buf.get(..n).unwrap_or(&[])) {
                    let raw_frame = match event {
                        NetEvent::FrameReceivedInline { bytes } => bytes,
                        _ => {
                            sys_task_yield();
                            continue;
                        }
                    };

                    // Extract the UDP:68 payload, discarding anything else.
                    if let Some(dhcp_payload) =
                        extract_udp_payload(&raw_frame, DHCP_CLIENT_PORT_U16)
                    {
                        // `now` is a poll-count approximation (ms not available
                        // at boot) — sufficient for `obtained_at` bookkeeping.
                        // `now` in ms for the client's lease bookkeeping.
                        let now_approx = sys_time_monotonic_nanos() / 1_000_000;

                        match client.handle_message(&dhcp_payload, now_approx) {
                            DhcpResult::SendRequest(req_payload) => {
                                // Log the offer (parse yiaddr from payload for display).
                                sys_write(
                                    "[nexacore-net] dhcp: offer received — sending request\n",
                                );

                                // RFC 2131: REQUEST sent as broadcast.
                                let req_frame = build_udp_eth_frame(
                                    our_mac,
                                    BROADCAST_MAC,
                                    UNSPECIFIED_IP,
                                    BROADCAST_IP,
                                    DHCP_CLIENT_PORT_U16,
                                    DHCP_SERVER_PORT,
                                    &req_payload,
                                );
                                let net_req = NetRequest::SendFrameInline { bytes: req_frame };
                                if let Some(enc) = encode_into(&net_req, &mut tx_buf) {
                                    let _ = sys_ipc_send(driver_cmd, IPC_KIND_REQUEST, enc);
                                }
                                sys_write("[nexacore-net] dhcp: request sent\n");
                            }

                            DhcpResult::Bound(lease) => {
                                // Log the lease details on a single line.
                                log_dhcp_bound(&lease);
                                return Some(lease);
                            }

                            DhcpResult::Rejected => {
                                // NAK received — reset and retry from the top.
                                sys_write("[nexacore-net] dhcp: nak received — restarting\n");
                                // Re-create a fresh client in Init state.
                                client = DhcpClient::new(our_mac.0, xid);
                                continue 'attempt;
                            }

                            // Ignored / wrong XID: keep polling.
                            DhcpResult::SendDiscover(_) | DhcpResult::Ignored => {}
                        }
                    }
                }
            } else {
                // No frame available; yield to let the NIC driver run.
                sys_task_yield();
            }
        }
        // Timeout for this attempt; retry.
        sys_write("[nexacore-net] dhcp: attempt timed out\n");
        // Reset state machine before retrying.
        client = DhcpClient::new(our_mac.0, xid);
    }

    None
}

/// Log the DHCP BOUND event with IP, gateway, DNS, and lease duration.
///
/// Uses serial writes split across multiple calls to avoid a 4096 B large
/// format buffer — each formatted segment stays within the `SMALL_BLK` (64 B)
/// slab class.
fn log_dhcp_bound(lease: &DhcpLease) {
    sys_write("[nexacore-net] dhcp: BOUND ip=");
    log_ipv4(lease.client_ip);
    sys_write(" gw=");
    match lease.gateway {
        Some(gw) => log_ipv4(gw),
        None => sys_write("(none)"),
    }
    sys_write(" dns=");
    match lease.dns_servers.first() {
        Some(dns) => log_ipv4(*dns),
        None => sys_write("(none)"),
    }
    sys_write(" lease=");
    log_u32(lease.lease_time_secs);
    sys_write("s\n");
}

/// Write an IPv4 address as "a.b.c.d" to the serial console.
fn log_ipv4(ip: Ipv4Addr) {
    let [a, b, c, d] = ip.0;
    log_u8(a);
    sys_write(".");
    log_u8(b);
    sys_write(".");
    log_u8(c);
    sys_write(".");
    log_u8(d);
}

/// Write an unsigned 8-bit decimal integer to the serial console.
fn log_u8(v: u8) {
    // Maximum 3 decimal digits for a u8 (255).
    let mut digits = [0u8; 3];
    let mut n = v;
    let mut len = 0usize;
    if n == 0 {
        sys_write("0");
        return;
    }
    while n > 0 {
        // digits is length 3 which is exactly enough for u8::MAX (255).
        if let Some(slot) = digits.get_mut(len) {
            *slot = b'0' + n % 10;
        }
        n /= 10;
        len += 1;
    }
    // Write digits in reverse order (most-significant first).
    for i in (0..len).rev() {
        if let Some(&d) = digits.get(i) {
            // SAFETY: `d` is always in `b'0'..=b'9'` — valid UTF-8.
            let s = core::str::from_utf8(core::slice::from_ref(&d)).unwrap_or("?");
            sys_write(s);
        }
    }
}

/// Write a `u32` in decimal to the serial console.
fn log_u32(v: u32) {
    // Maximum 10 decimal digits for u32::MAX.
    let mut digits = [0u8; 10];
    let mut n = v;
    let mut len = 0usize;
    if n == 0 {
        sys_write("0");
        return;
    }
    while n > 0 {
        if let Some(slot) = digits.get_mut(len) {
            *slot = b'0' + (n % 10) as u8;
        }
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        if let Some(&d) = digits.get(i) {
            // SAFETY: `d` is always in `b'0'..=b'9'` — valid UTF-8.
            let s = core::str::from_utf8(core::slice::from_ref(&d)).unwrap_or("?");
            sys_write(s);
        }
    }
}

// Subnet-mask → CIDR-prefix conversion now lives in the host-tested
// `nexacore_net::netcfg::mask_to_prefix_len` and is applied via
// `netcfg::apply_lease` in the boot path above (WS4-02.3).

// =============================================================================
// DNS boot-time check helpers
// =============================================================================

/// Real-time window (nanoseconds) to wait for a DNS reply, via the monotonic
/// clock. A recursive lookup (the resolver chasing `one.one.one.one`) can take
/// 10-100+ ms — far longer than an iteration-counted window survived
/// (TASK-25: the old 500-iter ≈ 14 ms loop expired before the reply). 3 s is
/// generous for a single A-record query.
const DNS_TIMEOUT_NS: u64 = 3_000_000_000;

/// DNS server UDP port 53.
const DNS_PORT: u16 = 53;

/// Perform a one-shot DNS A-record lookup at boot time (the `nslookup` check).
///
/// Builds a query with [`DnsResolver::build_query`], wraps it as a unicast
/// UDP frame to `dns_server`, sends it via the NIC driver command channel, then
/// polls the event channel for a UDP:53? No — for a *UDP port `dns_reply_port`*
/// (ephemeral) response.  Because we are not running the full socket stack yet
/// and the DNS server responds to the source port of our outgoing query (which
/// is a fixed ephemeral port here), we instead look for any inbound UDP
/// datagram whose source port is 53 and whose payload parses as a DNS response.
///
/// On success, logs `[nexacore-net] dns: <name> -> <a.b.c.d>`.
/// On timeout, logs `[nexacore-net] dns: <name> unresolved` — non-fatal.
///
/// # Arguments
///
/// * `driver_cmd`  — NIC driver command channel (TX path).
/// * `driver_evt`  — NIC driver event channel (RX path).
/// * `our_mac`     — Local MAC address.
/// * `our_ip`      — Leased (or static) source IP.
/// * `dns_server`  — DNS server IP from the DHCP lease (or default).
/// * `name`        — Hostname to resolve (e.g. `"one.one.one.one"`).
#[inline(never)]
fn dns_check(
    driver_cmd: u64,
    driver_evt: u64,
    our_mac: MacAddress,
    our_ip: Ipv4Addr,
    dns_server: Ipv4Addr,
    name: &str,
) {
    let mut resolver = DnsResolver::new(alloc::vec![dns_server]);
    let (_query_id, query_bytes) = resolver.build_query(name);

    // Use a fixed ephemeral source port for the DNS query.  We are not
    // yet running the full socket stack, so there is no port-allocation API
    // available — 49153 is safe because it is in the ephemeral range and
    // not currently bound.
    const DNS_SRC_PORT: u16 = 49_153;

    // Resolve the DNS server MAC.  At this point ARP is not running (we
    // are before the service loop), so we send to the Ethernet broadcast
    // and rely on the reply flowing back normally.  In practice the server
    // is always on the same LAN segment (192.0.2.x) and the NIC driver
    // delivers the reply to us regardless of destination MAC because
    // our interface is `promiscuous-enough` at boot.  If the DNS server
    // MAC is known (via a prior ARP during DHCP) this is strictly correct.
    // We choose broadcast here as the safe universal option.
    let dns_frame = build_udp_eth_frame(
        our_mac,
        BROADCAST_MAC, // ARP not resolved; broadcast is safe on /24 LAN.
        our_ip,
        dns_server,
        DNS_SRC_PORT,
        DNS_PORT,
        &query_bytes,
    );

    let net_req = NetRequest::SendFrameInline { bytes: dns_frame };
    let mut tx_buf = [0u8; 4096];
    if let Some(enc) = encode_into(&net_req, &mut tx_buf) {
        let _ = sys_ipc_send(driver_cmd, IPC_KIND_REQUEST, enc);
    }

    // Poll for the DNS response.  We look for any inbound UDP frame whose
    // UDP source port is 53 (the DNS server is always the sender).
    let mut rx_buf = [0u8; 4096];
    // Time-based window: a recursive DNS lookup can take 10-100+ ms, far longer
    // than an iteration-counted loop survived (TASK-25).
    let dns_start = sys_time_monotonic_nanos();
    while sys_time_monotonic_nanos().wrapping_sub(dns_start) < DNS_TIMEOUT_NS {
        if let Some(n) = sys_ipc_try_receive(driver_evt, &mut rx_buf) {
            if let Some(NetEvent::FrameReceivedInline { bytes }) =
                decode_from::<NetEvent>(rx_buf.get(..n).unwrap_or(&[]))
            {
                // Look for UDP frames where the *source* port is 53.
                if let Some(udp_payload) = extract_udp_src_port(&bytes, DNS_PORT) {
                    match resolver.handle_response(&udp_payload) {
                        Ok(addrs) => {
                            // Log the first resolved address.
                            sys_write("[nexacore-net] dns: ");
                            sys_write(name);
                            sys_write(" -> ");
                            if let Some(addr) = addrs.first() {
                                log_ipv4(*addr);
                            }
                            sys_write("\n");
                            return;
                        }
                        Err(_) => {
                            // Malformed or NXDOMAIN — keep polling.
                        }
                    }
                }
            }
        } else {
            sys_task_yield();
        }
    }

    // Timeout — non-fatal.
    sys_write("[nexacore-net] dns: ");
    sys_write(name);
    sys_write(" unresolved\n");
}

/// Extract the UDP payload from a raw Ethernet frame where the UDP **source**
/// port matches `src_port` (used to identify DNS replies where src port = 53).
///
/// All parsing is bounds-checked; a malformed frame returns `None`.
fn extract_udp_src_port(frame: &[u8], src_port: u16) -> Option<alloc::vec::Vec<u8>> {
    let (eth_hdr, eth_payload) = EthernetHeader::parse(frame)?;
    if eth_hdr.ether_type != EtherType::IPV4 {
        return None;
    }
    let (ip_hdr, ip_payload) = nexacore_net::ip::parse_ipv4_packet(eth_payload)?;
    if ip_hdr.protocol != IpProtocol::UDP {
        return None;
    }
    let (udp_hdr, udp_payload) = UdpHeader::parse(ip_payload)?;
    if udp_hdr.src_port != src_port {
        return None;
    }
    Some(udp_payload.to_vec())
}

// =============================================================================
// ELF entry point
// =============================================================================

/// ELF entry point for the nexacore-net network stack service.
///
/// Called by the kernel's `spawn_from_elf` after loading the ELF into Ring 3.
/// Performs one-time setup, then runs the service event loop indefinitely.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_write("[nexacore-net] service starting\n");

    // Step 1: create the two anonymous socket-API IPC channels (two-channel
    // rendezvous). They are bound to names in Step 2 via NetRegister — the
    // kernel IPC layer itself is name-agnostic.
    let stack_channel = sys_ipc_create_channel(IPC_QUEUE_DEPTH);
    if stack_channel == SYSCALL_ERROR {
        sys_write("[nexacore-net] FATAL: create stack channel failed\n");
        sys_exit(1);
    }
    let stack_reply_channel = sys_ipc_create_channel(IPC_QUEUE_DEPTH);
    if stack_reply_channel == SYSCALL_ERROR {
        sys_write("[nexacore-net] FATAL: create stack.reply channel failed\n");
        sys_exit(1);
    }

    // Step 2: bind the two channels to their well-known names in the net
    // channel registry. Neither has an event channel or MAC, so those
    // arguments are zero (net_register skips the owner check when evt == 0).
    if !sys_net_register("stack", stack_channel, 0) {
        sys_write("[nexacore-net] FATAL: register stack failed\n");
        sys_exit(2);
    }
    if !sys_net_register("stack_reply", stack_reply_channel, 0) {
        sys_write("[nexacore-net] FATAL: register stack_reply failed\n");
        sys_exit(2);
    }
    sys_write("[nexacore-net] socket-API channels registered (stack + stack.reply)\n");

    // Step 1b: create + register the network-configuration channels
    // (NCIP N6.1). Registered here, BEFORE DHCP runs below, so `ifconfig` and
    // other config clients can resolve the channel immediately at boot even
    // while a lease is still in flight — only the *interface list* is
    // legitimately empty during that window, never the channel lookup itself.
    let config_channel = sys_ipc_create_channel(IPC_QUEUE_DEPTH);
    if config_channel == SYSCALL_ERROR {
        sys_write("[nexacore-net] FATAL: create config channel failed\n");
        sys_exit(1);
    }
    let config_reply_channel = sys_ipc_create_channel(IPC_QUEUE_DEPTH);
    if config_reply_channel == SYSCALL_ERROR {
        sys_write("[nexacore-net] FATAL: create config.reply channel failed\n");
        sys_exit(1);
    }
    if !sys_net_register("config", config_channel, 0) {
        sys_write("[nexacore-net] FATAL: register config failed\n");
        sys_exit(2);
    }
    if !sys_net_register("config_reply", config_reply_channel, 0) {
        sys_write("[nexacore-net] FATAL: register config_reply failed\n");
        sys_exit(2);
    }
    sys_write("[nexacore-net] config channels registered (config + config.reply)\n");

    // Step 3: try to locate the virtio-net driver's command + event channels.
    // This is a single NON-BLOCKING attempt: the service must NOT deadlock when
    // the NIC driver has not registered yet (or is absent). It enters the
    // service loop immediately so socket calls that need no NIC (e.g.
    // `NetSocket`) are answered, and re-attempts the `virtio0` lookup lazily
    // from inside `run_forever` until the driver appears.
    let driver = sys_net_lookup("virtio0");
    if driver.is_some() {
        sys_write("[nexacore-net] virtio0 present at startup\n");
    } else {
        sys_write("[nexacore-net] virtio0 not yet registered; will retry in service loop\n");
    }

    // Step 4: acquire an IPv4 address via DHCP, falling back to the M0 static
    // config (192.0.2.50/24) if no lease is obtained.
    //
    // MAC address: 52:54:00:12:34:56 (virtio-net0 on VM103, ruling #6).
    let our_mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    // XID: a pseudo-random u32 derived from the MAC bytes so that concurrent
    // boots on different VMs choose different transaction IDs without a PRNG.
    let xid: u32 = u32::from_be_bytes([
        our_mac.0[2] ^ 0xA5,
        our_mac.0[3] ^ 0x13,
        our_mac.0[4] ^ 0xE1,
        our_mac.0[5] ^ 0xC0,
    ]);

    let mut svc = NetworkService::new();

    // Attempt DHCP only when the NIC driver is already registered at startup.
    // If it is not up yet, fall straight through to static — the driver-
    // discovery loop in `run_forever` will activate the NIC later, but we
    // cannot DHCP without a driver.
    // DHCP-first address acquisition. A successful lease is applied via the
    // host-tested `netcfg::apply_lease` (mask→CIDR, default route, DNS seed);
    // any failure path self-assigns an RFC 3927 link-local address via
    // `netcfg::link_local_config` — the previous hard-coded lab address
    // `192.0.2.50` is no longer used at boot (WS4-02.3/.6).
    let (iface, dns_server_for_check) = if let Some((driver_cmd, driver_evt)) = driver {
        match run_dhcp(driver_cmd, driver_evt, our_mac, xid) {
            Some(lease) => {
                let applied = nexacore_net::netcfg::apply_lease(&lease, "eth0", our_mac, 1500);
                let first_dns = applied
                    .dns_servers
                    .first()
                    .copied()
                    .unwrap_or(Ipv4Addr([1, 1, 1, 1]));
                svc.dns = DnsResolver::new(applied.dns_servers.clone());
                if let Some(route) = applied.default_route.clone() {
                    svc.routing.add_route(route);
                }
                (applied.interface, first_dns)
            }
            None => {
                // DHCP exhausted — RFC 3927 link-local self-assignment.
                sys_write("[nexacore-net] dhcp: no lease — RFC 3927 link-local fallback\n");
                svc.dns = DnsResolver::new(nexacore_net::netcfg::default_dns_servers());
                (
                    nexacore_net::netcfg::link_local_config("eth0", our_mac, 1500),
                    Ipv4Addr([1, 1, 1, 1]),
                )
            }
        }
    } else {
        // NIC not yet up — skip DHCP, use a link-local address for now.
        sys_write("[nexacore-net] dhcp: no driver at boot — RFC 3927 link-local fallback\n");
        svc.dns = DnsResolver::new(nexacore_net::netcfg::default_dns_servers());
        (
            nexacore_net::netcfg::link_local_config("eth0", our_mac, 1500),
            Ipv4Addr([1, 1, 1, 1]),
        )
    };

    svc.add_interface(iface.clone());
    sys_write("[nexacore-net] interface up; entering service loop\n");

    // Step 4b: boot-time DNS verification ("nslookup" acceptance check).
    // Non-fatal: a failure does not prevent the service from starting.
    if let Some((driver_cmd, driver_evt)) = driver {
        dns_check(
            driver_cmd,
            driver_evt,
            our_mac,
            iface.ip,
            dns_server_for_check,
            "one.one.one.one",
        );
    }

    // Step 5: run the event loop forever.
    run_forever(
        &mut svc,
        stack_channel,
        stack_reply_channel,
        config_channel,
        config_reply_channel,
        driver,
    )
}

/// The network service event loop.
///
/// Non-blocking round-robin over three sources:
///
/// 1. **Driver event channel** — `NetEvent::FrameReceivedInline` frames are
///    handed to [`NetworkService::handle_frame`]; resulting `SendFrame` outputs
///    go back to the driver command channel as `NetRequest::SendFrameInline`.
/// 2. **Socket-API channel** — `SocketRequest`s are dispatched to
///    [`NetworkService::handle_socket_request`]; the `SocketResponse` is sent on
///    the dedicated reply channel.
/// 3. **Network-config channel** — `NetConfigRequest`s (NCIP N6.1, e.g. the
///    shell's `ifconfig` command) are dispatched to [`handle_net_config`]; the
///    `NetConfigResponse` is sent on the dedicated config-reply channel.
/// 4. **Timer tick** — every ~1000 iterations [`NetworkService::tick`] drives
///    ARP expiry and TCP retransmit timeouts (poll-count approximation, M0).
///
/// Never returns; the process lifetime equals the OS lifetime.
fn run_forever(
    svc: &mut NetworkService,
    stack_channel: u64,
    stack_reply_channel: u64,
    config_channel: u64,
    config_reply_channel: u64,
    mut driver: Option<(u64, u64)>,
) -> ! {
    // Stack scratch buffers; 4096 B = kernel IPC MAX_PAYLOAD.
    let mut rx_buf = [0u8; 4096];
    let mut tx_buf = [0u8; 4096];

    let mut poll_count: u64 = 0;
    let mut now_ms: u64 = 0;

    // FU3: when a TCP `Connect` reply is deferred (held until the handshake
    // reaches ESTABLISHED), this holds the fake-clock deadline (ms) after which
    // the still-parked caller is failed with `TimedOut` rather than hanging the
    // boot forever. `None` means no deferred reply is outstanding. The deferred
    // `Ok`/`Error` normally arrives from `handle_frame` long before this fires.
    const CONNECT_TIMEOUT_MS: u64 = 30_000;
    let mut connect_deadline_ms: Option<u64> = None;

    loop {
        // Track whether this iteration consumed a message; if not, yield the
        // CPU so the cooperative scheduler can run the NIC driver and client.
        let mut did_work = false;

        // 0. Lazy driver discovery. If the NIC driver was not registered at
        // startup, re-attempt the `virtio0` lookup periodically. This keeps the
        // socket API responsive (sockets that need no NIC work immediately)
        // while transparently picking the driver up once it registers.
        if driver.is_none() && poll_count % 1_000 == 0 {
            if let Some(pair) = sys_net_lookup("virtio0") {
                sys_write("[nexacore-net] virtio0 registered; NIC datapath active\n");
                driver = Some(pair);
            }
        }

        // 1. Driver event channel — received frames (only once the driver is up).
        if let Some((driver_cmd_channel, driver_evt_channel)) = driver {
            if let Some(n) = sys_ipc_try_receive(driver_evt_channel, &mut rx_buf) {
                did_work = true;
                if let Some(event) = decode_from::<NetEvent>(&rx_buf[..n]) {
                    match event {
                        NetEvent::FrameReceivedInline { bytes } => {
                            let outputs = svc.handle_frame(0, &bytes, now_ms);
                            // A SYN-ACK processed here releases the deferred
                            // Connect reply (FU3) onto `stack_reply`; clear the
                            // timeout when that happens.
                            let replies = forward_outputs(
                                outputs,
                                driver_cmd_channel,
                                stack_reply_channel,
                                &mut tx_buf,
                            );
                            if replies > 0 {
                                connect_deadline_ms = None;
                            }
                        }
                        NetEvent::LinkStateChange { .. } | NetEvent::MacChanged { .. } => {
                            // Link/MAC change handling deferred to a later sprint.
                        }
                        // Non-exhaustive: ignore future variants in M0.
                        _ => {}
                    }
                }
            }
        }

        // 2. Socket-API channel — userspace SocketRequests (always serviced).
        if let Some(n) = sys_ipc_try_receive(stack_channel, &mut rx_buf) {
            did_work = true;
            if let Some(request) = decode_from::<SocketRequest>(&rx_buf[..n]) {
                let response = svc.handle_socket_request(request);
                // FU3: a `Pending` response means the reply is DEFERRED (a TCP
                // Connect awaiting ESTABLISHED). Do NOT answer now — the relay
                // caller stays parked until `handle_frame`/`tick` emits the real
                // Ok/Error. Arm the timeout so a never-completing handshake can
                // not hang the caller indefinitely.
                if matches!(response, SocketResponse::Pending) {
                    connect_deadline_ms = Some(now_ms.wrapping_add(CONNECT_TIMEOUT_MS));
                } else if let Some(encoded) = encode_into(&response, &mut tx_buf) {
                    // Reply on the dedicated reply channel — NOT "stack", which
                    // this service receives on (replying there would make it pop
                    // its own reply and deadlock the kernel relay).
                    let _ = sys_ipc_send(stack_reply_channel, IPC_KIND_REPLY, encoded);
                }
                // Drain any frames the request produced (e.g. a Connect's SYN,
                // or an ARP request to resolve the next hop) and forward them to
                // the NIC driver. `handle_socket_request` returns only a
                // SocketResponse, so these would otherwise be stranded.
                let pending = svc.take_pending_tx();
                if let Some((driver_cmd_channel, _)) = driver {
                    let _ = forward_outputs(
                        pending,
                        driver_cmd_channel,
                        stack_reply_channel,
                        &mut tx_buf,
                    );
                }
            }
        }

        // 3. Network-config channel — privileged clients (e.g. the shell's
        // `ifconfig` command) querying live interface state (NCIP N6.1).
        if let Some(n) = sys_ipc_try_receive(config_channel, &mut rx_buf) {
            did_work = true;
            if let Some(request) = decode_from::<NetConfigRequest>(&rx_buf[..n]) {
                let response = handle_net_config(svc, driver.is_some(), &request);
                if let Some(encoded) = encode_into(&response, &mut tx_buf) {
                    let _ = sys_ipc_send(config_reply_channel, IPC_KIND_REPLY, encoded);
                }
            }
        }

        // 4. Periodic timer tick. Outgoing frames (retransmits, ARP) are only
        // forwarded when the driver is up; otherwise they are dropped (the TCP
        // state machine will retransmit once the NIC datapath is active).
        poll_count = poll_count.wrapping_add(1);
        if poll_count % 1_000 == 0 {
            now_ms = now_ms.wrapping_add(1);
            let tick_outs = svc.tick(now_ms);
            if let Some((driver_cmd_channel, _)) = driver {
                let replies = forward_outputs(
                    tick_outs,
                    driver_cmd_channel,
                    stack_reply_channel,
                    &mut tx_buf,
                );
                if replies > 0 {
                    connect_deadline_ms = None;
                }
            }

            // FU3 backstop: fail a deferred Connect that never established so
            // the parked caller does not hang the boot forever.
            if let Some(deadline) = connect_deadline_ms {
                if now_ms >= deadline {
                    let timeout = SocketResponse::Error(nexacore_types::socket::NetError::TimedOut);
                    if let Some(encoded) = encode_into(&timeout, &mut tx_buf) {
                        let _ = sys_ipc_send(stack_reply_channel, IPC_KIND_REPLY, encoded);
                    }
                    connect_deadline_ms = None;
                }
            }
        }

        // 4. Cooperative fairness: if neither channel had a message this
        // iteration, yield so the driver / client / shell are not starved by
        // this busy-poll loop under the cooperative scheduler.
        if !did_work {
            sys_task_yield();
        }
    }
}

/// Dispatch [`ServiceOutput`] items produced by `handle_frame` / `tick`:
///
/// - [`ServiceOutput::SendFrame`] → the NIC driver command channel as a
///   [`NetRequest::SendFrameInline`].
/// - [`ServiceOutput::SocketResponse`] → the userspace reply channel
///   (`stack_reply`). This is the **deferred** reply path: FU3 holds a TCP
///   `Connect` reply back until the handshake reaches `ESTABLISHED`, at which
///   point `handle_frame` emits the real `Ok`/`Error` here.
///
/// Returns the number of socket replies forwarded, so the caller can clear its
/// "deferred reply outstanding" bookkeeping.
fn forward_outputs(
    outputs: alloc::vec::Vec<ServiceOutput>,
    driver_cmd_channel: u64,
    stack_reply_channel: u64,
    tx_buf: &mut [u8],
) -> usize {
    let mut replies_sent = 0;
    for output in outputs {
        match output {
            ServiceOutput::SendFrame { data, .. } => {
                let req = NetRequest::SendFrameInline { bytes: data };
                if let Some(encoded) = encode_into(&req, tx_buf) {
                    let _ = sys_ipc_send(driver_cmd_channel, IPC_KIND_REQUEST, encoded);
                }
            }
            ServiceOutput::SocketResponse(resp) => {
                if let Some(encoded) = encode_into(&resp, tx_buf) {
                    let _ = sys_ipc_send(stack_reply_channel, IPC_KIND_REPLY, encoded);
                }
                replies_sent += 1;
            }
        }
    }
    replies_sent
}

// =============================================================================
// Network configuration service (NCIP N6.1)
// =============================================================================

/// Answer a [`NetConfigRequest`] from `svc`'s live interface/routing state.
///
/// `link_up` reflects whether the NIC driver is currently registered
/// (`driver.is_some()` in the caller) — M0 has exactly one physical link, so
/// this single flag stands in for a per-interface carrier state until a real
/// link-state event path exists.
///
/// Mutating requests (`SetAddress`, `SetGateway`, `SetDns`, `BringUp`,
/// `BringDown`) are out of M0 scope: the interface's real state is driven
/// entirely by DHCP / link bring-up today, not by admin override, so they
/// reply with an explicit "not supported" error rather than silently
/// pretending to apply a change that has no effect.
fn handle_net_config(
    svc: &NetworkService,
    link_up: bool,
    request: &NetConfigRequest,
) -> NetConfigResponse {
    match request {
        NetConfigRequest::ListInterfaces => NetConfigResponse::Interfaces(
            svc.interfaces
                .iter()
                .enumerate()
                .map(|(i, cfg)| to_interface_info(svc, i, cfg, link_up))
                .collect(),
        ),
        NetConfigRequest::GetInterface { name } => svc
            .interfaces
            .iter()
            .enumerate()
            .find(|(_, cfg)| &cfg.name == name)
            .map_or_else(
                || NetConfigResponse::Error(alloc::string::String::from("interface not found")),
                |(i, cfg)| NetConfigResponse::Interface(to_interface_info(svc, i, cfg, link_up)),
            ),
        NetConfigRequest::SetAddress { .. }
        | NetConfigRequest::SetGateway { .. }
        | NetConfigRequest::SetDns { .. }
        | NetConfigRequest::BringUp { .. }
        | NetConfigRequest::BringDown { .. } => {
            NetConfigResponse::Error(alloc::string::String::from("not supported in M0"))
        }
        // `NetConfigRequest` is `#[non_exhaustive]`; reject variants this
        // build does not yet model rather than silently mismatching.
        #[allow(unreachable_patterns, reason = "forward-compat with future non_exhaustive variants")]
        _ => NetConfigResponse::Error(alloc::string::String::from("not supported in M0")),
    }
}

/// Build the real [`InterfaceInfo`] for `interfaces[idx]`, combining the
/// live [`NetworkService`] state with `link_up` (driver-presence flag) and
/// this interface's cumulative traffic counters
/// ([`NetworkService::counters`]).
///
/// `speed_mbps` is always `0`: the virtio-net driver exposes no link-speed
/// register, so there is no real value to report — `0` (meaning "unknown"
/// per the field's own doc comment) is honest, not a placeholder pretending
/// to be real data. Likewise `rx_errors`/`tx_errors` are always `0`: no
/// error counters are tracked anywhere in the stack yet.
fn to_interface_info(
    svc: &NetworkService,
    idx: usize,
    cfg: &nexacore_net::ip::InterfaceConfig,
    link_up: bool,
) -> InterfaceInfo {
    let gateway = svc
        .routing
        .lookup(Ipv4Addr([0, 0, 0, 0]))
        .and_then(|route| route.gateway);
    let counters = svc.counters(idx);
    InterfaceInfo {
        name: cfg.name.clone(),
        mac: cfg.mac,
        ip: Some(cfg.ip),
        netmask: Some(cfg.netmask),
        gateway,
        link_up,
        speed_mbps: 0,
        rx_bytes: counters.rx_bytes,
        tx_bytes: counters.tx_bytes,
        rx_packets: counters.rx_frames,
        tx_packets: counters.tx_frames,
        rx_errors: 0,
        tx_errors: 0,
    }
}
