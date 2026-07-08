//! NexaCore OS Intel e1000e bootable driver image — P6.7.9.c live wiring.
//!
//! `no_std + no_main` ELF entry that the kernel `DriverLoad (73)`
//! syscall ingests per `NCIP-Driver-Framework-013` § S5.3 step 9. The
//! kernel calls `spawn_from_elf` against this binary, which lands at
//! `_start` in a freshly minted Ring 3 process. Before transferring
//! control the kernel writes the per-driver capability deposit at the
//! well-known user-VA slot [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`]
//! (P6.7.8.9, NCIP-013 § S5.3 step 8); the image reads tokens from that
//! window via [`nexacore_driver_shared::caps::find_token`] and forwards them
//! to the kernel through the `MmioMap (70)` / `DmaMap (71)` /
//! `IrqAttach (72)` syscalls.
//!
//! ## Execution path
//!
//! Live wiring (P6.7.9.c):
//! 1. `find_token(ACTION_TAG_MMIO_MAP, ..)`  — retrieve the MMIO token.
//! 2. `find_token(ACTION_TAG_DMA_MAP, ..)`   — retrieve the DMA token.
//! 3. `find_token(ACTION_TAG_IRQ_ATTACH,..)` — retrieve the IRQ token.
//! 4. `syscall MmioMap`   — map the e1000e BAR0 128 KiB CSR window.
//! 5. `syscall DmaMap`    — install the 4 GiB IOVA arena.
//! 6. `syscall IrqAttach` — bind the combined RX/TX MSI-X vector.
//! 7. Step-by-step drive of the 13-phase bring-up FSM with real MMIO
//!    register operations at each phase:
//!    - DisableInterrupts: `IMC = 0xFFFFFFFF`
//!    - GlobalReset: `CTRL |= RST`, poll until cleared
//!    - ReadMac: `RAL[0]` + `RAH[0]`, verify `AV` bit
//!    - PhyInit: MDIC auto-negotiation kick
//!    - SetupRxRing: `RDBAL`/`RDBAH`/`RDLEN`/`RDH`/`RDT`
//!    - PostRxBuffers: advance `RDT` to `rx_ring_depth - 1`
//!    - SetupTxRing: `TDBAL`/`TDBAH`/`TDLEN`/`TDH`/`TDT`
//!    - ConfigureRxTx: `RCTL` + `TCTL` enable
//!    - EnableInterrupts: `IMS = RXT0 | TXDW | LSC`
//!    - AttachIrq + RegisterNetChannel: logical completion
//! 8. `TaskExit(0)` on success / non-zero sentinel on any failure.
//!
//! ## Standalone execution
//!
//! When this binary is executed without going through `DriverLoad` (a
//! diagnostic scenario), `find_token` returns `None` because the deposit
//! page is not mapped; the image then exits with sentinel codes 10/20/30
//! identifying which token is missing.
//!
//! Pattern mirrors the `nexacore-driver-nvme-image` sibling refactored in
//! P6.7.10 and the `nexacore-driver-net-virtio-image` sibling.
//!
//! Build:
//!
//! ```sh
//! cargo build --manifest-path crates/nexacore-driver-e1000e-image/Cargo.toml \
//!             --target x86_64-unknown-none --release
//! ```

#![no_std]
#![no_main]
#![allow(unsafe_code)]
#![warn(missing_docs)]

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

use nexacore_driver_e1000e::bringup::{BringUp, Event, Phase};
use nexacore_driver_e1000e::controller_regs::{
    CTRL_OFFSET, CTRL_RST_BIT, IMC_DISABLE_ALL, IMC_OFFSET, IMS_OFFSET, MDIC_OFFSET,
    RAH0_OFFSET, RAH_AV_BIT, RAL0_OFFSET, RCTL_OFFSET, RDBAL_OFFSET, RDBAH_OFFSET,
    RDLEN_OFFSET, RDH_OFFSET, RDT_OFFSET, TCTL_OFFSET, TDBAL_OFFSET, TDBAH_OFFSET,
    TDLEN_OFFSET, TDH_OFFSET, TDT_OFFSET, rctl_enable_value, tctl_enable_value,
};
use nexacore_driver_e1000e::interrupts::ENABLED_IMS;
use nexacore_driver_e1000e::ring_config::{
    DEFAULT_RX_RING_DEPTH, DEFAULT_TX_RING_DEPTH, RX_DESCRIPTOR_BYTES, TX_DESCRIPTOR_BYTES,
};
use nexacore_driver_shared::{
    ACTION_TAG_DMA_MAP, ACTION_TAG_IRQ_ATTACH, ACTION_TAG_MMIO_MAP, caps::find_token,
};

// =============================================================================
// Global allocator stub
// =============================================================================

struct PanicOnAlloc;

unsafe impl GlobalAlloc for PanicOnAlloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        panic!("nexacore-driver-e1000e-image: heap alloc requested but no allocator is wired");
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOC: PanicOnAlloc = PanicOnAlloc;

// =============================================================================
// Syscall numbers
// =============================================================================

/// `TaskExit (11)`.
const SYS_TASK_EXIT: u64 = 11;
/// `MmioMap (70)`.
const SYS_MMIO_MAP: u64 = 70;
/// `DmaMap (71)`.
const SYS_DMA_MAP: u64 = 71;
/// `IrqAttach (72)`.
const SYS_IRQ_ATTACH: u64 = 72;

// =============================================================================
// Driver-specific constants (mirror `manifest.toml`)
// =============================================================================

/// e1000e BAR0 physical base address (QEMU `-device e1000e` Q35 default).
const E1000E_BAR0_PHYS_BASE: u64 = 0xFEB0_0000;

/// e1000e BAR0 length per Intel 82574L datasheet § 10.1 (128 KiB CSR window).
const E1000E_BAR0_LEN: u64 = 0x20000;

/// MmioMap flags = 0 (uncached default).
const MMIO_FLAGS_DEFAULT: u64 = 0;

/// DMA arena IOVA base.
const DMA_IOVA_BASE: u64 = 0x0;

/// DMA arena length = 4 GiB per NCIP-Driver-Net-015 § S1.
const DMA_LEN_4_GIB: u64 = 0x1_0000_0000;

/// DMA direction = bidirectional (RX descriptors + TX descriptors share arena).
const DMA_DIR_BIDIR: u64 = 2;

/// Placeholder IRQ line for the e1000e combined MSI-X vector.
const IRQ_LINE_E1000E: u64 = 35;

/// Placeholder IPC channel ID the kernel signals on this IRQ vector.
const IPC_CHANNEL_PLACEHOLDER: u64 = 0;

// =============================================================================
// DMA ring layout constants
// =============================================================================

/// IOVA offset of the RX descriptor ring in the DMA arena. Page-aligned
/// at offset 0x0 (first 4 KiB page). 256 entries × 16 bytes = 4096.
const RX_RING_IOVA: u64 = 0x0;

/// IOVA offset of the TX descriptor ring. Placed at 0x1000 (second 4 KiB
/// page). 256 entries × 16 bytes = 4096.
const TX_RING_IOVA: u64 = 0x1000;

/// IOVA offset of the RX buffer pool. Starts at 0x2000, each buffer is
/// 2 KiB. 512 buffers × 2 KiB = 1 MiB total.
const RX_BUFFERS_IOVA: u64 = 0x2000;


// =============================================================================
// MDIC register field encoding
// =============================================================================

/// MDIC opcode: read (bits 27:26 = 0b10).
const MDIC_OP_READ: u32 = 0b10 << 26;

/// MDIC opcode: write (bits 27:26 = 0b01).
const MDIC_OP_WRITE: u32 = 0b01 << 26;

/// MDIC Ready bit (bit 28) — set by hardware on completion.
const MDIC_READY: u32 = 1 << 28;

/// MDIC Error bit (bit 30) — set by hardware on failure.
const MDIC_ERROR: u32 = 1 << 30;

/// PHY address field shift (bits 25:21).
const MDIC_PHY_ADDR_SHIFT: u32 = 21;

/// PHY register address field shift (bits 20:16).
const MDIC_REG_ADDR_SHIFT: u32 = 16;

/// MII Control Register address (PHY register 0).
const MII_CTRL_REG: u32 = 0;

/// MII Control: restart auto-negotiation (bit 9).
const MII_CTRL_RESTART_AUTONEG: u32 = 1 << 9;

/// MII Control: auto-negotiation enable (bit 12).
const MII_CTRL_AUTONEG_ENABLE: u32 = 1 << 12;

/// Default PHY address for e1000e (typically 1).
const PHY_ADDR_DEFAULT: u32 = 1;

/// Poll budget for MDIC ready bit.
const MDIC_POLL_LIMIT: u32 = 10_000;

/// Poll budget for CTRL.RST self-clear.
const CTRL_RST_POLL_LIMIT: u32 = 10_000;

// =============================================================================
// TaskExit sentinel codes
// =============================================================================

/// Successful FSM convergence to `Phase::Ready`.
const EXIT_OK: u64 = 0;
/// FSM converged to a terminal `Failed` state.
const EXIT_FSM_FAILED: u64 = 1;
/// No `MmioMap` token in the deposit window.
const EXIT_NO_MMIO_TOKEN: u64 = 10;
/// No `DmaMap` token in the deposit window.
const EXIT_NO_DMA_TOKEN: u64 = 20;
/// No `IrqAttach` token in the deposit window.
const EXIT_NO_IRQ_TOKEN: u64 = 30;
/// Base sentinel: `MmioMap` syscall returned non-zero errno.
const EXIT_MMIO_BASE: u64 = 40;
/// Base sentinel: `DmaMap` syscall returned non-zero errno.
const EXIT_DMA_BASE: u64 = 60;
/// Base sentinel: `IrqAttach` syscall returned non-zero errno.
const EXIT_IRQ_BASE: u64 = 80;
/// `CTRL.RST` did not self-clear within the poll budget.
const EXIT_RESET_TIMEOUT: u64 = 100;
/// `RAH[0].AV` is not set — MAC not loaded from EEPROM.
const EXIT_MAC_INVALID: u64 = 110;
/// MDIC transaction timed out (ready bit not set within budget).
const EXIT_MDIC_TIMEOUT: u64 = 120;
/// MDIC transaction returned an error (MDIC.Error bit set).
const EXIT_MDIC_ERROR: u64 = 125;

// =============================================================================
// LiveMmioBackend — volatile MMIO access
// =============================================================================

/// Thin newtype wrapping the BAR0 user-VA returned by `MmioMap`.
/// Provides raw volatile 32-bit register access for the e1000e CSR
/// window (128 KiB).
#[derive(Clone, Copy)]
struct LiveMmioBackend {
    mmio_va_base: u64,
}

impl LiveMmioBackend {
    /// Perform a volatile 32-bit write to the register at `offset` bytes
    /// from the BAR0 base.
    #[inline]
    fn write_register(self, offset: usize, value: u32) {
        // SAFETY: `mmio_va_base + offset` is inside the BAR0 region the
        // kernel mapped via MmioMap; the register file is at least 128 KiB
        // and marked uncached per NCIP-013 § S2.5.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *mut u32;
            ptr.write_volatile(value);
        }
    }

    /// Perform a volatile 32-bit read from the register at `offset` bytes
    /// from the BAR0 base.
    #[inline]
    fn read_register(self, offset: usize) -> u32 {
        // SAFETY: same as write_register — region is uncached and mapped.
        unsafe {
            let ptr = (self.mmio_va_base as usize + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

// =============================================================================
// Raw syscall wrapper
// =============================================================================

/// Issue a `syscall` with the given number and up to 5 arguments. Returns
/// the `(rax, rdx)` pair — the two-register convention used by the
/// driver-framework syscalls per `NCIP-Driver-Framework-013` § S2.
#[inline(always)]
unsafe fn syscall5(number: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> (u64, u64) {
    let mut rax: u64 = number;
    let mut rdx_out: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") rax,
            in("rdi") a0,
            in("rsi") a1,
            inout("rdx") a2 => rdx_out,
            in("r10") a3,
            in("r8")  a4,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    (rax, rdx_out)
}

/// Issue `TaskExit(code)` — diverges on the bare-metal kernel.
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_TASK_EXIT,
            in("rdi") code,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

// =============================================================================
// FSM step execution — real MMIO register operations
// =============================================================================

/// Execute the DisableInterrupts step: write `0xFFFFFFFF` to `IMC`
/// per Intel 82574L datasheet § 10.6 and NCIP-015 § S5.1 step 2.
#[inline]
fn step_disable_interrupts(mmio: LiveMmioBackend) {
    mmio.write_register(IMC_OFFSET, IMC_DISABLE_ALL);
}

/// Execute the GlobalReset step: set `CTRL.RST` (bit 26), then poll
/// until the bit self-clears. Returns `Ok(())` on success or
/// `Err(EXIT_RESET_TIMEOUT)` if the poll budget is exhausted.
/// Per Intel 82574L datasheet § 10.2 and NCIP-015 § S5.1 step 3.
#[inline]
fn step_global_reset(mmio: LiveMmioBackend) -> Result<(), u64> {
    let ctrl = mmio.read_register(CTRL_OFFSET);
    mmio.write_register(CTRL_OFFSET, ctrl | CTRL_RST_BIT);

    for _ in 0..CTRL_RST_POLL_LIMIT {
        let val = mmio.read_register(CTRL_OFFSET);
        if val & CTRL_RST_BIT == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(EXIT_RESET_TIMEOUT)
}

/// Execute the ReadMac step: read `RAL[0]` and `RAH[0]`, verify `AV`
/// bit. Returns the 6-byte MAC on success.
/// Per Intel 82574L datasheet § 10.7.4 and NCIP-015 § S5.1 step 4.
#[inline]
fn step_read_mac(mmio: LiveMmioBackend) -> Result<[u8; 6], u64> {
    let ral = mmio.read_register(RAL0_OFFSET);
    let rah = mmio.read_register(RAH0_OFFSET);

    if rah & RAH_AV_BIT == 0 {
        return Err(EXIT_MAC_INVALID);
    }

    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    Ok(mac)
}

/// Execute the PhyInit step: issue an MDIO read of MII_CTRL (register 0)
/// then write back with auto-negotiation restart enabled.
/// Per Intel 82574L datasheet § 10.5 and NCIP-015 § S5.1 step 5.
#[inline]
fn step_phy_init(mmio: LiveMmioBackend) -> Result<(), u64> {
    // Issue MDIO read of MII_CTRL
    let mdic_read = MDIC_OP_READ
        | (PHY_ADDR_DEFAULT << MDIC_PHY_ADDR_SHIFT)
        | (MII_CTRL_REG << MDIC_REG_ADDR_SHIFT);
    mmio.write_register(MDIC_OFFSET, mdic_read);

    // Poll for ready
    let mut mii_ctrl_data: u32 = 0;
    let mut ready = false;
    for _ in 0..MDIC_POLL_LIMIT {
        let val = mmio.read_register(MDIC_OFFSET);
        if val & MDIC_ERROR != 0 {
            return Err(EXIT_MDIC_ERROR);
        }
        if val & MDIC_READY != 0 {
            mii_ctrl_data = val & 0xFFFF;
            ready = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !ready {
        return Err(EXIT_MDIC_TIMEOUT);
    }

    // Write back with auto-negotiation enable + restart
    let new_mii_ctrl = mii_ctrl_data | MII_CTRL_AUTONEG_ENABLE | MII_CTRL_RESTART_AUTONEG;
    let mdic_write = MDIC_OP_WRITE
        | (PHY_ADDR_DEFAULT << MDIC_PHY_ADDR_SHIFT)
        | (MII_CTRL_REG << MDIC_REG_ADDR_SHIFT)
        | (new_mii_ctrl & 0xFFFF);
    mmio.write_register(MDIC_OFFSET, mdic_write);

    // Poll for write completion
    for _ in 0..MDIC_POLL_LIMIT {
        let val = mmio.read_register(MDIC_OFFSET);
        if val & MDIC_ERROR != 0 {
            return Err(EXIT_MDIC_ERROR);
        }
        if val & MDIC_READY != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(EXIT_MDIC_TIMEOUT)
}

/// Execute the SetupRxRing step: write `RDBAL`, `RDBAH`, `RDLEN`,
/// zero `RDH` and `RDT`.
/// Per Intel 82574L datasheet § 10.7 and NCIP-015 § S5.1 step 6.
#[inline]
fn step_setup_rx_ring(mmio: LiveMmioBackend) {
    let rx_ring_phys = RX_RING_IOVA;
    let rdlen = DEFAULT_RX_RING_DEPTH as u32 * RX_DESCRIPTOR_BYTES as u32;

    mmio.write_register(RDBAL_OFFSET, rx_ring_phys as u32);
    mmio.write_register(RDBAH_OFFSET, (rx_ring_phys >> 32) as u32);
    mmio.write_register(RDLEN_OFFSET, rdlen);
    mmio.write_register(RDH_OFFSET, 0);
    mmio.write_register(RDT_OFFSET, 0);
}

/// Execute the PostRxBuffers step: fill RX descriptor entries with
/// buffer IOVAs and advance `RDT` to `rx_ring_depth - 1`.
/// Per Intel 82574L datasheet § 10.7.1 and NCIP-015 § S5.1 step 7.
#[inline]
fn step_post_rx_buffers(mmio: LiveMmioBackend, dma_va_base: u64) {
    // Each legacy RX descriptor is 16 bytes:
    //   [0..8]  = buffer address (64-bit)
    //   [8..16] = status/error fields (zeroed by software on post)
    let rx_ring_va = dma_va_base + RX_RING_IOVA;
    for i in 0..DEFAULT_RX_RING_DEPTH {
        let desc_va = rx_ring_va + (i as u64) * RX_DESCRIPTOR_BYTES as u64;
        let buf_iova = RX_BUFFERS_IOVA + (i as u64) * 2048;
        // SAFETY: the DMA arena is mapped; each descriptor slot is inside
        // the RX ring page.
        unsafe {
            let ptr = desc_va as *mut u64;
            ptr.write_volatile(buf_iova);
            ptr.add(1).write_volatile(0);
        }
    }
    // Advance RDT to tell hardware all descriptors are available.
    mmio.write_register(RDT_OFFSET, DEFAULT_RX_RING_DEPTH - 1);
}

/// Execute the SetupTxRing step: write `TDBAL`, `TDBAH`, `TDLEN`,
/// zero `TDH` and `TDT`.
/// Per Intel 82574L datasheet § 10.8 and NCIP-015 § S5.1 step 8.
#[inline]
fn step_setup_tx_ring(mmio: LiveMmioBackend) {
    let tx_ring_phys = TX_RING_IOVA;
    let tdlen = DEFAULT_TX_RING_DEPTH as u32 * TX_DESCRIPTOR_BYTES as u32;

    mmio.write_register(TDBAL_OFFSET, tx_ring_phys as u32);
    mmio.write_register(TDBAH_OFFSET, (tx_ring_phys >> 32) as u32);
    mmio.write_register(TDLEN_OFFSET, tdlen);
    mmio.write_register(TDH_OFFSET, 0);
    mmio.write_register(TDT_OFFSET, 0);
}

/// Execute the ConfigureRxTx step: write `RCTL` and `TCTL` with the
/// canonical enable values.
/// Per Intel 82574L datasheet § 10.7-10.8 and NCIP-015 § S5.1 step 9.
#[inline]
fn step_configure_rx_tx(mmio: LiveMmioBackend) {
    mmio.write_register(RCTL_OFFSET, rctl_enable_value());
    mmio.write_register(TCTL_OFFSET, tctl_enable_value());
}

/// Execute the EnableInterrupts step: write `IMS = RXT0 | TXDW | LSC`.
/// Per Intel 82574L datasheet § 10.6 and NCIP-015 § S5.1 step 10.
#[inline]
fn step_enable_interrupts(mmio: LiveMmioBackend) {
    mmio.write_register(IMS_OFFSET, ENABLED_IMS);
}

// =============================================================================
// Driver entry — _start
// =============================================================================

/// ELF entry point. The kernel's `spawn_from_elf` jumps here with
/// `rsp = user_stack_top` and the capability deposit mapped read-only at
/// [`nexacore_driver_shared::DRIVER_CAP_DEPOSIT_VA`].
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Step 1 — Retrieve the three capability tokens from the deposit.
    let Some(mmio_token) = find_token(ACTION_TAG_MMIO_MAP, |_| true) else {
        unsafe { sys_exit(EXIT_NO_MMIO_TOKEN) };
    };
    let Some(dma_token) = find_token(ACTION_TAG_DMA_MAP, |_| true) else {
        unsafe { sys_exit(EXIT_NO_DMA_TOKEN) };
    };
    let Some(irq_token) = find_token(ACTION_TAG_IRQ_ATTACH, |_| true) else {
        unsafe { sys_exit(EXIT_NO_IRQ_TOKEN) };
    };

    // Step 2 — `MmioMap (70)`: install the e1000e CSR window (128 KiB).
    let (mmio_va, mmio_errno) = unsafe {
        syscall5(
            SYS_MMIO_MAP,
            E1000E_BAR0_PHYS_BASE,
            E1000E_BAR0_LEN,
            MMIO_FLAGS_DEFAULT,
            mmio_token.as_ptr() as u64,
            mmio_token.len() as u64,
        )
    };
    if mmio_errno != 0 {
        unsafe { sys_exit(EXIT_MMIO_BASE + mmio_errno) };
    }

    // Step 3 — `DmaMap (71)`: install the 4 GiB IOVA arena.
    let (dma_va, dma_errno) = unsafe {
        syscall5(
            SYS_DMA_MAP,
            DMA_IOVA_BASE,
            DMA_LEN_4_GIB,
            DMA_DIR_BIDIR,
            dma_token.as_ptr() as u64,
            dma_token.len() as u64,
        )
    };
    if dma_errno != 0 {
        unsafe { sys_exit(EXIT_DMA_BASE + dma_errno) };
    }

    // Step 4 — `IrqAttach (72)`: bind the MSI-X vector to an IPC channel.
    let (_irq_vec, irq_errno) = unsafe {
        syscall5(
            SYS_IRQ_ATTACH,
            IRQ_LINE_E1000E,
            IPC_CHANNEL_PLACEHOLDER,
            irq_token.as_ptr() as u64,
            irq_token.len() as u64,
            0,
        )
    };
    if irq_errno != 0 {
        unsafe { sys_exit(EXIT_IRQ_BASE + irq_errno) };
    }

    // Construct the MMIO backend from the mapped BAR0 VA.
    let mmio = LiveMmioBackend { mmio_va_base: mmio_va };

    // Step 5 — Drive the 13-step bring-up FSM with real MMIO operations
    // at each phase. The FSM is advanced after each successful hardware
    // operation; failure aborts with a phase-specific sentinel.
    let mut fsm = BringUp::new();

    // Phase 0 (PciEnumeration): completed by the kernel before DriverLoad;
    // the image starts with this phase already satisfied.
    fsm = advance_or_exit(&mut fsm);

    // Phase 1 (MmioMap): completed by syscall above (step 2).
    fsm = advance_or_exit(&mut fsm);

    // Phase 2 (DisableInterrupts): write IMC = 0xFFFFFFFF.
    step_disable_interrupts(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 3 (GlobalReset): CTRL.RST + poll.
    if let Err(code) = step_global_reset(mmio) {
        unsafe { sys_exit(code) };
    }
    // Re-disable interrupts after reset (hardware may re-enable defaults).
    step_disable_interrupts(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 4 (ReadMac): read RAL[0]/RAH[0], verify AV.
    let _mac = match step_read_mac(mmio) {
        Ok(mac) => mac,
        Err(code) => unsafe { sys_exit(code) },
    };
    fsm = advance_or_exit(&mut fsm);

    // Phase 5 (PhyInit): MDIO auto-negotiation.
    if let Err(code) = step_phy_init(mmio) {
        unsafe { sys_exit(code) };
    }
    fsm = advance_or_exit(&mut fsm);

    // Phase 6 (SetupRxRing): program RX descriptor ring registers.
    step_setup_rx_ring(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 7 (PostRxBuffers): fill descriptors + advance RDT.
    step_post_rx_buffers(mmio, dma_va);
    fsm = advance_or_exit(&mut fsm);

    // Phase 8 (SetupTxRing): program TX descriptor ring registers.
    step_setup_tx_ring(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 9 (ConfigureRxTx): enable RCTL + TCTL.
    step_configure_rx_tx(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 10 (EnableInterrupts): write IMS mask.
    step_enable_interrupts(mmio);
    fsm = advance_or_exit(&mut fsm);

    // Phase 11 (AttachIrq): completed by IrqAttach syscall (step 4).
    fsm = advance_or_exit(&mut fsm);

    // Phase 12 (RegisterNetChannel): logical completion — channel
    // registration is deferred to the supervisor in Phase 2.
    let _ = advance_or_exit(&mut fsm);

    // Phase 13 = Ready — verify FSM convergence.
    let code = if matches!(fsm.phase(), Phase::Ready) {
        EXIT_OK
    } else {
        EXIT_FSM_FAILED
    };
    unsafe { sys_exit(code) }
}

/// Advance the FSM by one phase via `Event::Advance`. If the FSM
/// rejects the advance (terminal state), exit with `EXIT_FSM_FAILED`.
#[inline]
fn advance_or_exit(fsm: &mut BringUp) -> BringUp {
    match fsm.on_event(Event::Advance) {
        Ok(next) => next,
        Err(_) => unsafe { sys_exit(EXIT_FSM_FAILED) },
    }
}

// =============================================================================
// Panic handler (required by `no_std`)
// =============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { sys_exit(2) }
}
