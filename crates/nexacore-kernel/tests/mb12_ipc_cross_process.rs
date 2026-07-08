//! Host-mode integration tests for MB12 cross-process IPC.
//!
//! These tests run on the host (non-x86_64 OK) and exercise the
//! cross-module wiring that the per-module unit tests in `ipc.rs`,
//! `capabilities.rs`, `process.rs`, and `userprobe_mb12.rs` cannot
//! verify in isolation:
//!
//! - Two synthetic processes (built via the same `Arena` + `PageMapper`
//!   pattern used by `mb11_userspace.rs`) exchange a payload through a
//!   single `KernelIpcRegistry`.
//! - Capability subject mismatch is rejected at the registry boundary,
//!   exactly as the kernel's `IpcSend` / `IpcReceive` syscall handlers
//!   would surface to userspace as `SYSCALL_ERROR`.
//! - The `BackpressurePolicy::Block` flow returns `WakeAction::Block`
//!   on the sender and `WakeAction::Wake(sender)` on the unblocking
//!   receive, matching the syscall retry-loop contract.
//! - Both userprobe ELFs (sender + receiver) parse, expose the correct
//!   entry, and carry the syscall pattern the boot wiring assumes.
//!
//! The bare-metal `iretq` trampoline + first-dispatch via the
//! scheduler is exercised by the `mb12-userprobe` QEMU smoke
//! (manual run); these host tests cover everything that does not
//! require Ring 3 hardware semantics.

#![cfg(feature = "bare-metal")]
#![allow(
    unsafe_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items,
    clippy::uninlined_format_args,
    clippy::doc_markdown,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal
)]

use nexacore_kernel::{
    bare_metal::{
        address_space::AddressSpace,
        elf_loader::{Elf64, PF_R, PF_W, PF_X},
        paging::PageMapper,
        userprobe_mb12::{USERPROBE_RECEIVER_ELF, USERPROBE_SENDER_ELF},
    },
    capabilities::{
        Ed25519CapabilityProvider, KernelAction, KernelCapabilityToken, KernelPrincipal,
        KernelResource,
    },
    ipc::{
        BackpressurePolicy, ChannelId, ChannelPolicy, KernelIpcRegistry, MessageEnvelope,
        MessageKind, WakeAction,
    },
    memory::{BitmapFrameAllocator, PhysAddr},
    scheduling::TaskId,
};

// =============================================================================
// Synthetic boot environment (mirrors tests/mb11_userspace.rs)
// =============================================================================

const ARENA_PHYS_BASE: u64 = 0x0100_0000;
const ARENA_FRAMES: u64 = 64;
const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;

struct Arena {
    ptr: *mut u8,
    layout: core::alloc::Layout,
}

impl Arena {
    fn new() -> Self {
        let layout = core::alloc::Layout::from_size_align(ARENA_SIZE, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Self { ptr, layout }
    }

    fn phys_offset(&self) -> u64 {
        self.ptr as u64 - ARENA_PHYS_BASE
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

fn make_alloc() -> BitmapFrameAllocator<1> {
    let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(ARENA_PHYS_BASE));
    alloc.mark_range_free(PhysAddr(ARENA_PHYS_BASE), ARENA_SIZE as u64);
    alloc
}

fn principal(b: u8) -> KernelPrincipal {
    KernelPrincipal::from_bytes([b; 32])
}

fn make_envelope(channel: ChannelId, payload: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        sender: TaskId(0),
        channel,
        kind: MessageKind::Notification,
        payload: payload.to_vec(),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn both_userprobe_elfs_load_into_separate_address_spaces() {
    // Build a synthetic boot PML4 and parse both ELFs against two
    // distinct address spaces — the same shape `spawn_userprobe_mb12`
    // would produce on bare-metal.
    let arena = Arena::new();
    let phys_offset = arena.phys_offset();
    let boot_cr3 = PhysAddr(ARENA_PHYS_BASE);
    let mut alloc = make_alloc();
    alloc.mark_range_used(boot_cr3, 4096);

    let mapper = PageMapper::new(phys_offset, boot_cr3);

    let sender_as = AddressSpace::new_with_kernel_half(boot_cr3, &mapper, &mut alloc)
        .expect("sender address space");
    let receiver_as = AddressSpace::new_with_kernel_half(boot_cr3, &mapper, &mut alloc)
        .expect("receiver address space");
    assert_ne!(
        sender_as.pml4_phys.0, receiver_as.pml4_phys.0,
        "the two processes must own distinct PML4 frames"
    );

    let sender_elf = Elf64::parse(USERPROBE_SENDER_ELF).expect("sender ELF parses");
    let receiver_elf = Elf64::parse(USERPROBE_RECEIVER_ELF).expect("receiver ELF parses");
    assert_eq!(sender_elf.entry_point(), receiver_elf.entry_point());
    assert_eq!(sender_elf.entry_point(), 0x4000_0000);

    // Sender segment: R+X, 59 bytes.
    let s = sender_elf.load_segments().next().unwrap().unwrap();
    assert_eq!(s.mem_size, 59);
    assert_eq!(s.flags, PF_R | PF_X);

    // Receiver segment: R+W+X (writable BSS buf inline), mem_size > file_size.
    let r = receiver_elf.load_segments().next().unwrap().unwrap();
    assert_eq!(r.file_data.len(), 77);
    assert_eq!(r.mem_size, 141);
    assert_eq!(r.flags, PF_R | PF_W | PF_X);

    // Don't actually map the ELF into the AS here — that would require
    // the full bare-metal page-table layout. The unit tests in
    // `userprobe_mb12.rs` already verify the ELF byte pattern; this
    // test guarantees the two ELFs *coexist* in a multi-AS arena.
    let _ = (&mapper, sender_as, receiver_as);
    // Use mapper to silence the unused-mut warning.
    let _ = mapper.translate(nexacore_kernel::memory::VirtAddr(0));
}

#[test]
fn cross_process_send_then_receive_round_trip() {
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let sender_task = TaskId(10);
    let receiver_task = TaskId(11);
    let kmain_task = TaskId(1);

    let channel = registry
        .create_channel(
            kmain_task,
            ChannelPolicy {
                queue_depth: 4,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            None,
            None,
            &stub,
        )
        .expect("channel created");

    // Sender enqueues "ping" — no waiter yet → WakeAction::None.
    let wake = registry
        .send(make_envelope(channel, b"ping"), sender_task, principal(0))
        .expect("send ok");
    assert_eq!(wake, WakeAction::None);

    // Receiver drains.
    let (got, wake) = registry
        .receive(channel, receiver_task, principal(0), false)
        .expect("receive ok");
    assert_eq!(wake, WakeAction::None);
    let env = got.expect("envelope delivered");
    assert_eq!(env.sender, sender_task, "sender id stamped by kernel");
    assert_eq!(env.channel, channel);
    assert_eq!(env.kind, MessageKind::Notification);
    assert_eq!(env.payload, b"ping");
}

#[test]
fn receiver_parks_then_wakes_on_subsequent_send() {
    // Mirrors the QEMU smoke ordering: receiver arrives first with
    // blocking=true on an empty queue; sender then enqueues and the
    // registry signals which task to wake.
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let sender_task = TaskId(10);
    let receiver_task = TaskId(11);

    let channel = registry
        .create_channel(
            TaskId(1),
            ChannelPolicy {
                queue_depth: 4,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            None,
            None,
            &stub,
        )
        .unwrap();

    // Receiver parks.
    let (msg, wake) = registry
        .receive(channel, receiver_task, principal(0), true)
        .expect("receive park ok");
    assert!(msg.is_none());
    assert_eq!(wake, WakeAction::Block(receiver_task));

    // Sender arrives — registry tells the syscall handler to wake the
    // receiver. This is exactly the contract the
    // `ipc_handlers::ipc_send` retry-loop relies on.
    let wake = registry
        .send(make_envelope(channel, b"ping"), sender_task, principal(0))
        .expect("send ok");
    assert_eq!(wake, WakeAction::Wake(receiver_task));

    // Receiver's retry path now drains the message.
    let (msg, wake) = registry
        .receive(channel, receiver_task, principal(0), true)
        .expect("receive retry ok");
    assert_eq!(wake, WakeAction::None);
    assert_eq!(msg.expect("message").payload, b"ping");
}

#[test]
fn block_policy_full_queue_parks_sender_and_wakes_on_drain() {
    // Mirrors the bandwidth-limited path: a `Block`-policy channel
    // with a depth of 1 forces the second send to park; the
    // subsequent receive wakes the parked sender.
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let s1 = TaskId(10);
    let s2 = TaskId(20);
    let r = TaskId(11);

    let channel = registry
        .create_channel(
            TaskId(1),
            ChannelPolicy {
                queue_depth: 1,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            None,
            None,
            &stub,
        )
        .unwrap();

    registry
        .send(make_envelope(channel, b"first"), s1, principal(0))
        .unwrap();
    let wake = registry
        .send(make_envelope(channel, b"second"), s2, principal(0))
        .unwrap();
    assert_eq!(wake, WakeAction::Block(s2));

    // The drain by the receiver wakes the second sender.
    let (msg, wake) = registry
        .receive(channel, r, principal(0), false)
        .expect("receive ok");
    assert_eq!(msg.expect("first").payload, b"first");
    assert_eq!(wake, WakeAction::Wake(s2));
}

#[test]
fn capability_send_subject_mismatch_denied_cross_process() {
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();

    // Owner mints a send-token bound to principal 42.
    let send_tok = KernelCapabilityToken {
        subject: principal(42),
        action: KernelAction::IpcSend,
        resource: KernelResource::IpcChannel(1),
    };
    let channel = registry
        .create_channel(
            TaskId(1),
            ChannelPolicy {
                queue_depth: 4,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            Some(send_tok),
            None,
            &stub,
        )
        .unwrap();

    // A sender with the wrong principal is rejected.
    let err = registry
        .send(make_envelope(channel, b"x"), TaskId(99), principal(7))
        .unwrap_err();
    assert_eq!(err, nexacore_kernel::KernelError::CapabilityDenied);

    // The matching principal proceeds.
    let wake = registry
        .send(make_envelope(channel, b"y"), TaskId(99), principal(42))
        .unwrap();
    assert_eq!(wake, WakeAction::None);
}

#[test]
fn capability_recv_subject_mismatch_denied_cross_process() {
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();

    let recv_tok = KernelCapabilityToken {
        subject: principal(7),
        action: KernelAction::IpcRecv,
        resource: KernelResource::IpcChannel(1),
    };
    let channel = registry
        .create_channel(
            TaskId(1),
            ChannelPolicy {
                queue_depth: 4,
                backpressure: BackpressurePolicy::Block,
                tee_bound: false,
            },
            None,
            Some(recv_tok),
            &stub,
        )
        .unwrap();

    // Sender has no subject restriction → ok.
    registry
        .send(make_envelope(channel, b"z"), TaskId(10), principal(0))
        .unwrap();

    // Recv from the wrong principal is denied.
    let err = registry
        .receive(channel, TaskId(11), principal(99), false)
        .unwrap_err();
    assert_eq!(err, nexacore_kernel::KernelError::CapabilityDenied);

    // Recv from the matching principal succeeds.
    let (msg, _) = registry
        .receive(channel, TaskId(11), principal(7), false)
        .unwrap();
    assert_eq!(msg.expect("message").payload, b"z");
}

#[test]
fn destroy_only_by_owner_across_synthetic_processes() {
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let owner = TaskId(1);
    let intruder = TaskId(99);

    let channel = registry
        .create_channel(
            owner,
            ChannelPolicy {
                queue_depth: 2,
                backpressure: BackpressurePolicy::Drop,
                tee_bound: false,
            },
            None,
            None,
            &stub,
        )
        .unwrap();

    assert_eq!(
        registry.destroy_channel(channel, intruder).unwrap_err(),
        nexacore_kernel::KernelError::CapabilityDenied
    );
    registry.destroy_channel(channel, owner).unwrap();
    assert_eq!(registry.channel_count(), 0);
}

#[test]
fn channel_id_monotonic_across_two_creates_one_destroy() {
    // Documents the MB12 id-allocation invariant: ids are not reused.
    let stub = Ed25519CapabilityProvider::placeholder();
    let mut registry = KernelIpcRegistry::new();
    let owner = TaskId(1);

    let policy = ChannelPolicy {
        queue_depth: 2,
        backpressure: BackpressurePolicy::Drop,
        tee_bound: false,
    };
    let a = registry
        .create_channel(owner, policy.clone(), None, None, &stub)
        .unwrap();
    registry.destroy_channel(a, owner).unwrap();
    let b = registry
        .create_channel(owner, policy, None, None, &stub)
        .unwrap();
    assert!(b.0 > a.0, "destroyed id MUST NOT be re-used");
}
