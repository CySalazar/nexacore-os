# Hardware Requirements

**Status:** Draft v0.1

## Philosophy

NexaCore OS requires hardware-rooted security. Without a hardware Trusted Execution Environment (TEE), the cryptographic privacy guarantees of the mesh protocol cannot be enforced. Therefore, **TEE attestation is a non-negotiable hardware requirement** for mesh participation.

This explicitly excludes pre-2022 hardware. We accept the trade-off: better baseline UX for compliant hardware, no degraded "best-effort" mode for older systems.

## Minimum baseline (v1)

NexaCore OS v1 supports x86_64 with hardware TEE.

### CPU

Either:

- **Intel** with Trust Domain Extensions (TDX): Sapphire Rapids (4th Gen Xeon Scalable, 2023+), Emerald Rapids, Granite Rapids, or any future processor with TDX. Consumer parts with TDX support arrive with future generations.
- **AMD** with SEV-SNP:
  - Server: EPYC 7003 (Milan, 2021+) and later (EPYC 7004 Genoa, EPYC 9004, etc.).
  - Consumer: Ryzen Pro 7040 series (2023+) and later Ryzen Pro / Threadripper Pro generations.

The TEE must be:

- Supported by the vendor's attestation chain (functional Quote Verification Service / SNP attestation).
- Up-to-date with vendor microcode and firmware patches addressing known side-channel attacks.

### Memory

| Use case | Minimum | Recommended |
|----------|---------|-------------|
| Tier 0 (local-only, light workloads) | 16 GB | 32 GB |
| Tier 0 (heavier local models) | 32 GB | 64 GB |
| Tier 1 (personal cluster participant) | 32 GB per device | 64 GB per device |
| Tier 2 (mesh node hosting MoE expert shards) | 64 GB | 128 GB |

ECC memory is recommended but not required for v1.

### Storage

| Use case | Minimum | Recommended |
|----------|---------|-------------|
| OS install + minimal models | 256 GB SSD | 512 GB NVMe |
| Active model caching | 512 GB NVMe | 1 TB NVMe |
| Tier 2 mesh node | 1 TB NVMe | 2 TB+ NVMe |

NVMe is strongly preferred over SATA SSD due to higher random I/O throughput needed for model weight access.

### Network

Mesh participation requires:

- Always-on broadband connection (no metered/cellular fallback as primary).
- **Upload bandwidth**: ≥ 25 Mbps for Tier 2 hosting; ≥ 100 Mbps recommended for hosting popular experts.
- **Latency**: stable to common geographic regions; ideally < 100 ms RTT to nearest 50 peers.
- **IPv6 support**: strongly preferred. The protocol functions over IPv4 + NAT but performance is reduced.

Tier 1 (personal cluster) requires LAN with < 5 ms inter-device latency. Wi-Fi 6 / Wi-Fi 6E or Gigabit Ethernet recommended.

### Optional acceleration

For accelerated inference:

- **NVIDIA GPU**: GeForce RTX 30/40/50 series, RTX A-series, datacenter GPUs (H100, etc.).
- **AMD GPU**: RX 7000 series and later with ROCm support.
- **Intel GPU**: Arc A/B-series, integrated Xe with sufficient VRAM.
- **NPU**: Intel AI Boost (Meteor Lake+), AMD Ryzen AI (XDNA), discrete NPUs as available.

The Tensor HAL dispatches across whatever is available. CPU-only is supported with degraded performance.

## Future support (v1.1+)

Targeted but not in v1 scope:

- **Apple Silicon (M1+)**: Apple Secure Enclave + Private-Cloud-Compute–style attestation pattern. Targeted v1.1.
- **ARMv9 with CCA Realms**: Realm Management Extension hardware. Targeted v2.x as availability matures.
- **ARM server (AmpereOne, Graviton 4+)**: for datacenter mesh nodes. Targeted v2.x.
- **RISC-V with PMP / TEE extensions**: research direction; no committed timeline.

## Explicitly unsupported

- **Pre-TEE hardware**: no software-only attestation fallback for the mesh. Such hardware cannot participate in Tier 1 or Tier 2.
- **Hardware with known unpatched TEE compromise**: Intel SGX in vulnerable configurations, AMD SEV in vulnerable configurations. The Foundation publishes a TEE deny-list, updated as new vulnerabilities are confirmed.
- **ARM Cortex-A consumer processors without CCA**: until ecosystem matures.
- **Mobile-first deployment**: phones are clients only, not mesh participants in v1. Mobile mesh participation is an open research question for later versions.

## Local-only operation (no mesh)

Users with hardware that does NOT meet TEE requirements can still run NexaCore OS for **Tier 0 (local-only)** inference. They cannot participate in Tier 1 (personal cluster) or Tier 2 (federated mesh).

This allows NexaCore OS to be evaluated on older hardware while maintaining the integrity of the mesh.

## Hardware certification program

The Foundation will operate a hardware certification program identifying:

- **NexaCore OS Certified**: hardware tested and confirmed compatible with full mesh participation.
- **NexaCore OS Compatible**: hardware that boots and runs NexaCore OS but with caveats noted.
- **NexaCore OS Trusted Platform**: hardware additionally evaluated for supply-chain integrity.

Certification is voluntary, vendor-paid, and subject to public testing protocols. Results are published in `/docs/certified-hardware.md` (TODO).

## Open hardware questions

- **Trusted Boot**: precise requirements for measured boot beyond what TEE attestation provides. Likely requires TPM 2.0 with specific PCR usage.
- **Firmware integrity**: what UEFI firmware features are required (Secure Boot variations, vendor-specific protections)?
- **Hardware Security Module (HSM) integration**: optional support for external HSMs for organizations with stricter requirements.

These will be detailed as the kernel implementation progresses.
