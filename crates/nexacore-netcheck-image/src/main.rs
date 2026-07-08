//! Bare-metal M0 networking self-test client for NexaCore OS.
//!
//! A `no_std + no_main` Ring 3 ELF the kernel spawns to validate the M0
//! socket-syscall path end to end. It issues `NetSocket` and `NetConnect`
//! syscalls and writes the outcomes to the kernel console (COM1 serial).
//!
//! ## What this proves
//!
//! `NetSocket` allocates a socket handle inside the userspace `nexacore-net`
//! service and needs no NIC. The kernel routes it through the two-channel
//! IPC relay (`nexacore.svc.net.stack` request → `nexacore.svc.net.stack.reply`
//! reply). A printed, non-error handle therefore proves the entire
//! kernel→nexacore-net relay round-trip works on real hardware, independently of
//! the NIC datapath.
//!
//! `NetConnect` to the Ollama bridge (`192.0.2.11:11434`) additionally
//! exercises the address-marshalling + connect relay path. Without a live NIC
//! the TCP handshake cannot complete, so a non-zero errno here is expected and
//! is reported, not treated as a hard failure.
//!
//! ## M0 closure (PLAN.md TASK-05)
//!
//! With the handshake ESTABLISHED, the client completes a minimal
//! `GET /api/tags` HTTP/1.1 exchange: `NetSend (108)` transmits the request,
//! a bounded `NetRecv (109)` poll loop accumulates the response, the status
//! line is parsed (expecting `200`) and the first chunk of the JSON body is
//! printed, then the socket is closed via `NetClose (112)`. This proves the
//! whole chain: syscall → 2-channel IPC relay → nexacore-net TCP → virtio-net
//! driver → wire → Ollama and back.
//!
//! ## Exit codes
//!
//! `0` success · `1` panic · `2` NetSocket failed · `3` NetConnect failed ·
//! `4` NetSend failed · `5` short send · `6` NetRecv errno · `7` response
//! timeout · `8` non-200 HTTP status · `9` malformed response (no body).
//!
//! No dependencies and no heap: the kernel builds the `SocketRequest` from the
//! syscall arguments, so the client only needs inline-asm syscall stubs. The
//! receive accumulator lives in BSS (`static mut`), NOT on the 4 KiB user
//! stack (same lesson as the driver image's service-loop buffers, `f9845f7`).

#![no_std]
#![no_main]
#![allow(unsafe_code)]

use core::panic::PanicInfo;

// =============================================================================
// Syscall numbers (mirror nexacore_kernel::syscall::SyscallNumber)
// =============================================================================

/// `TaskExit (11)` — terminate the calling task.
const SYS_TASK_EXIT: u64 = 11;
/// `TaskYield (12)` — yield the CPU to the next runnable task.
const SYS_TASK_YIELD: u64 = 12;
/// `WriteConsole (60)` — write a byte slice to the kernel console (COM1).
const SYS_WRITE_CONSOLE: u64 = 60;
/// `NetSocket (103)` — allocate a socket. ABI `(domain, type) -> rax=handle`.
const SYS_NET_SOCKET: u64 = 103;
/// `NetConnect (107)` — connect a socket. ABI `(handle, addr_ptr, addr_len)`.
const SYS_NET_CONNECT: u64 = 107;
/// `NetSend (108)` — send on a socket. ABI `(handle, buf_ptr, buf_len) ->
/// rax=bytes_sent`.
const SYS_NET_SEND: u64 = 108;
/// `NetRecv (109)` — receive from a socket. ABI `(handle, buf_ptr, buf_len) ->
/// rax=bytes_copied` (0 when nothing is buffered yet — poll + yield).
const SYS_NET_RECV: u64 = 109;
/// `NetClose (112)` — close a socket. ABI `(handle)`.
const SYS_NET_CLOSE: u64 = 112;

/// `SocketDomain::Inet` discriminant for the `NetSocket` ABI.
const DOMAIN_INET: u64 = 0;
/// `SocketType::Stream` discriminant for the `NetSocket` ABI.
const TYPE_STREAM: u64 = 0;

// =============================================================================
// Syscall stubs (System V AMD64 ABI)
// =============================================================================

/// Issue a two-register-return syscall. `rax` carries the number on entry and
/// the primary result on exit; `rdx` carries `a2` on entry and the secondary
/// result (errno / paired value) on exit.
///
/// # Safety
///
/// Pointer arguments must be valid for the duration of the call.
#[inline(always)]
unsafe fn syscall(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> (u64, u64) {
    let rax: u64;
    let rdx: u64;
    // SAFETY: canonical Ring 3 → Ring 0 transition; caller upholds pointer
    // validity. The kernel's nexacore_syscall_entry SHUFFLES the argument registers
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

/// Write `msg` to the kernel console (best-effort).
fn write(msg: &str) {
    let b = msg.as_bytes();
    // SAFETY: b is valid for the duration of the syscall.
    let _ = unsafe {
        syscall(
            SYS_WRITE_CONSOLE,
            b.as_ptr() as u64,
            b.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
}

/// Write `val` as a fixed 16-digit hex string (`0x…`) to the console.
fn write_hex(val: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i: usize = 0;
    while i < 16 {
        let shift: u32 = (15 - i as u32) * 4;
        #[allow(clippy::cast_possible_truncation, reason = "nibble masked to 0..16")]
        let nibble = ((val >> shift) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
        i += 1;
    }
    // SAFETY: buf is valid ASCII hex for the duration of the syscall.
    let _ = unsafe {
        syscall(
            SYS_WRITE_CONSOLE,
            buf.as_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
}

/// Yield the CPU so the nexacore-net service can register before we probe it.
fn task_yield() {
    // SAFETY: TaskYield takes no arguments. Issued through the generic
    // 6-argument stub ON PURPOSE: the kernel syscall entry SHUFFLES the
    // argument registers (rdi/rsi/rdx/r10/r8/r9) and returns a value pair
    // in rax/rdx WITHOUT restoring any of them, so a minimal `asm!` that
    // clobbers only rcx/r11 lets the compiler keep live values (e.g. the
    // NEXT syscall's arguments) in registers the kernel destroys.
    // Hardware-observed as a boot-timing heisenbug (TASK-13: corrupted
    // input_len -> spurious EINVAL after one ENOENT retry); the generic
    // stub declares the full clobber set.
    let _ = unsafe { syscall(SYS_TASK_YIELD, 0, 0, 0, 0, 0, 0) };
}

/// Terminate with exit `code`. Never returns.
fn exit(code: u32) -> ! {
    // SAFETY: TaskExit terminates the task and never returns.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") u64::from(code),
            options(noreturn),
        );
    }
}

// =============================================================================
// Panic handler
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write("[netcheck] PANIC\n");
    exit(1)
}

// =============================================================================
// Entry point
// =============================================================================

/// Packed `SocketApiAddr` for `192.0.2.11:11434` — four IPv4 octets followed
/// by the port in network (big-endian) byte order. `11434 = 0x2CAA`.
static CONNECT_ADDR: [u8; 6] = [192, 0, 2, 11, 0x2C, 0xAA];

/// The M0 closure request: minimal well-formed HTTP/1.1. `Connection: close`
/// lets the server end the stream after one response (no keep-alive state).
static HTTP_REQUEST: &[u8] =
    b"GET /api/tags HTTP/1.1\r\nHost: 192.0.2.11:11434\r\nConnection: close\r\nAccept: application/json\r\n\r\n";

/// Response accumulator capacity. `/api/tags` replies are small (one JSON
/// object per installed model); 2 KiB is ample to capture the status line,
/// headers, and the first body chunk that TASK-05's acceptance requires.
const ACC_CAP: usize = 2048;

/// Per-`NetRecv` chunk size — well under the relay payload bound.
const CHUNK_CAP: usize = 512;

/// Bounded poll budget: one `NetRecv` + one `TaskYield` per iteration. Each
/// relay round-trip is itself a blocking IPC rendezvous, so this bounds the
/// wall-clock wait to comfortably more than an LAN HTTP round-trip while
/// still guaranteeing termination (exit 7) if the response never comes.
const RECV_POLL_BUDGET: u32 = 50_000;

/// Receive accumulator — BSS, not the 4 KiB user stack (see module doc).
static mut ACC: [u8; ACC_CAP] = [0; ACC_CAP];

/// `NetRecv` staging chunk — BSS for the same reason.
static mut CHUNK: [u8; CHUNK_CAP] = [0; CHUNK_CAP];

/// ELF entry point. Runs the M0 socket self-test and exits.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write("[netcheck] start\n");

    // Give the System-priority nexacore-net service a chance to register its
    // socket-API channels before we issue the first NET syscall. A handful of
    // yields is ample under the cooperative scheduler.
    for _ in 0..16 {
        task_yield();
    }

    // 1. NetSocket(Inet, Stream) — exercises the kernel→nexacore-net relay. A
    //    non-error handle proves the round-trip works.
    write("[netcheck] NetSocket(Inet, Stream)...\n");
    // SAFETY: no pointer arguments.
    let (handle, sock_err) =
        unsafe { syscall(SYS_NET_SOCKET, DOMAIN_INET, TYPE_STREAM, 0, 0, 0, 0) };
    // Unconditional raw dump so the outcome is visible regardless of branch.
    write("[netcheck] NetSocket raw rax=");
    write_hex(handle);
    write(" rdx=");
    write_hex(sock_err);
    write("\n");
    if sock_err != 0 {
        write("[netcheck] NetSocket FAILED, errno=");
        write_hex(sock_err);
        write("\n");
        exit(2);
    }
    write("[netcheck] NetSocket OK, handle=");
    write_hex(handle);
    write("\n");

    // 2. NetConnect(handle, 192.0.2.11:11434) — exercises address marshalling
    //    and the connect relay. Without a live NIC the handshake cannot
    //    complete, so a non-zero errno here is expected (reported, not fatal).
    write("[netcheck] NetConnect 192.0.2.11:11434...\n");
    // SAFETY: CONNECT_ADDR is a valid 6-byte buffer for the syscall duration.
    let (_c_rax, conn_err) = unsafe {
        syscall(
            SYS_NET_CONNECT,
            handle,
            CONNECT_ADDR.as_ptr() as u64,
            CONNECT_ADDR.len() as u64,
            0,
            0,
            0,
        )
    };
    if conn_err == 0 {
        write("[netcheck] NetConnect OK (handshake completed)\n");
    } else {
        write("[netcheck] NetConnect returned errno=");
        write_hex(conn_err);
        write(" (no route to the NIC datapath)\n");
        exit(3);
    }

    // 3. NetSend — transmit the HTTP GET (TASK-05). The relay copies the
    //    buffer, nexacore-net emits it as PSH|ACK segment(s) in the same
    //    service-loop iteration.
    write("[netcheck] NetSend GET /api/tags...\n");
    // SAFETY: HTTP_REQUEST is a valid static buffer for the syscall duration.
    // Poll-send: with multiple TCP clients in the same boot (the AI
    // service's RemoteGpu path, TASK-13) the cooperative stack may
    // transiently accept 0 bytes while TX is busy — the same would-block
    // semantics as NetRecv. Retry with a yield (bounded), advancing on
    // partial writes.
    let mut sent_total: u64 = 0;
    let mut send_polls: u32 = 0;
    while sent_total < HTTP_REQUEST.len() as u64 {
        if send_polls >= RECV_POLL_BUDGET {
            write("[netcheck] NetSend timeout (TX busy)\n");
            exit(5);
        }
        // SAFETY: HTTP_REQUEST is a static buffer; offset bounded above.
        let (sent, send_err) = unsafe {
            syscall(
                SYS_NET_SEND,
                handle,
                HTTP_REQUEST.as_ptr() as u64 + sent_total,
                HTTP_REQUEST.len() as u64 - sent_total,
                0,
                0,
                0,
            )
        };
        if send_err != 0 {
            write("[netcheck] NetSend FAILED, errno=");
            write_hex(send_err);
            write("\n");
            exit(4);
        }
        if sent == 0 {
            send_polls += 1;
            task_yield();
            continue;
        }
        sent_total += sent;
    }
    write("[netcheck] NetSend OK (");
    write_hex(sent_total);
    write(" bytes)\n");

    // 4. NetRecv poll loop — accumulate the response until the header
    //    terminator AND at least one body byte are present (or the budget
    //    runs out). `rax == 0` means "nothing buffered yet": yield so the
    //    System-priority service/driver peers can move the bytes.
    let mut acc_len: usize = 0;
    let mut polls: u32 = 0;
    let body_at: usize;
    loop {
        if polls >= RECV_POLL_BUDGET {
            write("[netcheck] NetRecv timeout (no full response)\n");
            exit(7);
        }
        polls += 1;

        // SAFETY: CHUNK is a static BSS buffer, valid for the syscall; the
        // task is single-threaded so the static mut access cannot alias.
        let (n, recv_err) = unsafe {
            syscall(
                SYS_NET_RECV,
                handle,
                core::ptr::addr_of_mut!(CHUNK) as u64,
                CHUNK_CAP as u64,
                0,
                0,
                0,
            )
        };
        if recv_err != 0 {
            write("[netcheck] NetRecv FAILED, errno=");
            write_hex(recv_err);
            write("\n");
            exit(6);
        }
        if n == 0 {
            task_yield();
            continue;
        }

        // Append the chunk (clamped to the accumulator capacity).
        #[allow(clippy::cast_possible_truncation, reason = "n ≤ CHUNK_CAP = 512")]
        let n_usize = n as usize;
        let take = n_usize.min(ACC_CAP - acc_len);
        let mut i = 0;
        while i < take {
            // SAFETY: single-threaded task; indices bounded by take ≤
            // remaining capacity and n ≤ CHUNK_CAP.
            unsafe {
                (*core::ptr::addr_of_mut!(ACC))[acc_len + i] =
                    (*core::ptr::addr_of!(CHUNK))[i];
            }
            i += 1;
        }
        acc_len += take;

        // Stop once "\r\n\r\n" is present with at least one body byte after
        // it, or the accumulator is full (enough for the acceptance check).
        // SAFETY: single-threaded task; acc_len ≤ ACC_CAP.
        let acc = unsafe { &(*core::ptr::addr_of!(ACC))[..acc_len] };
        if let Some(pos) = find(acc, b"\r\n\r\n") {
            if acc_len > pos + 4 {
                body_at = pos + 4;
                break;
            }
        }
        if acc_len == ACC_CAP {
            body_at = 0; // header terminator never seen — malformed
            break;
        }
    }

    // 5. Parse the status line: "HTTP/1.1 NNN ...". The acceptance criterion
    //    is an explicit 200 + the first JSON chunk on the serial log.
    // SAFETY: single-threaded task; acc_len ≤ ACC_CAP.
    let acc = unsafe { &(*core::ptr::addr_of!(ACC))[..acc_len] };
    if body_at == 0 || acc.len() < 12 || !starts_with(acc, b"HTTP/1.1 ") {
        write("[netcheck] malformed HTTP response\n");
        exit(9);
    }
    write("[netcheck] HTTP status=");
    // Echo the three status digits verbatim from the wire.
    let status = &acc[9..12];
    write_bytes(status);
    write("\n");
    if status != b"200" {
        write("[netcheck] non-200 status\n");
        exit(8);
    }

    // First chunk of the JSON body (up to 64 bytes) — must show
    // `{"models":[...` for the M0 acceptance capture.
    let body = &acc[body_at..];
    let preview = &body[..body.len().min(64)];
    write("[netcheck] body=");
    write_bytes(preview);
    write("\n");

    // 6. NetClose — release the connection state in nexacore-net.
    // SAFETY: no pointer arguments.
    let (_cl_rax, close_err) = unsafe { syscall(SYS_NET_CLOSE, handle, 0, 0, 0, 0, 0) };
    if close_err == 0 {
        write("[netcheck] NetClose OK\n");
    } else {
        write("[netcheck] NetClose errno=");
        write_hex(close_err);
        write("\n");
    }

    write("[netcheck] M0 E2E COMPLETE: HTTP 200 from 192.0.2.11:11434\n");
    write("[netcheck] done\n");
    exit(0)
}

/// Write a raw byte slice to the kernel console (best-effort).
fn write_bytes(b: &[u8]) {
    // SAFETY: b is valid for the duration of the syscall.
    let _ = unsafe {
        syscall(
            SYS_WRITE_CONSOLE,
            b.as_ptr() as u64,
            b.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
}

/// Return the index of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// `true` when `haystack` begins with `prefix`.
fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && &haystack[..prefix.len()] == prefix
}
