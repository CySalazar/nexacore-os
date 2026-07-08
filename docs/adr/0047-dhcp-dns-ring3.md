# ADR-0047: DHCP Client + DNS from Ring 3 (TASK-25, DE-F3)

**Status:** Accepted
**Date:** 2026-06-08
**Deciders:** agent analysis under operator-approved PLAN.md TASK-25
**Refs:** PLAN.md TASK-25 (DE-F3, M5 prerequisite), ADR-0046 (nexacore-net slab
fix), M0 networking (TASK-05, `f33c61a`), `crates/nexacore-net/src/{dhcp,dns,udp,ip}.rs`

## Context

The Live USB (M5) cannot assume a static IP, so the network stack must acquire
its address dynamically. `nexacore-net` already implements a full DHCP client
(`dhcp.rs`, 1385 lines, 24 tests: `DhcpClient` state machine Init→Selecting→
Requesting→Bound with T1 renew, `build_discover`/`build_request`/
`handle_message`, RFC-2132 option TLV parse with bounds checking) and a DNS stub
resolver (`dns.rs`, 710 lines, 21 tests: `DnsResolver::{build_query,
parse_response}`, caching). Neither is DRIVEN yet: `nexacore-net-image` brings the
interface up with a **static** `192.0.2.50/24` (M0). The NET syscalls are
unchanged; this is purely a service-image + nexacore-net integration.

Recon facts:
- `NetworkService::handle_frame(iface, bytes, now) -> Vec<ServiceOutput>` parses
  Ethernet/IP/UDP; `ServiceOutput::SendFrame { .. }` is a frame to TX. The image
  loop already does `handle_frame` → TX the `SendFrame`s.
- Frame builders exist: `udp::build_udp_packet`, `ip::build_ipv4_packet`; the
  Ethernet header is prepended for TX (as the TCP path already does).
- A real DHCP server is on the VM's LAN (`192.0.2.254`: offers `192.0.2.x`,
  /24, router `.254`, DNS `.254`+`1.1.1.1`+`8.8.8.8`).
- DHCP input is UNTRUSTED: parsing is already bounds-checked and ignores unknown
  options; the driver must keep that discipline.

## Decisions

### D1 — DHCP-at-boot in `nexacore-net-image`, static fallback

Before entering the socket-serving loop, the image runs a bounded DHCP exchange
on `eth0` (the MAC `52:54:00:12:34:56`):
1. `DhcpClient::new(mac, xid)`; `build_discover()` → wrap as a broadcast frame
   (Ethernet `ff:ff:ff:ff:ff:ff`, IP `0.0.0.0` → `255.255.255.255`, UDP
   `68`→`67`) → TX.
2. Poll RX (the existing event channel / `handle_frame`-style raw receive),
   feed any UDP-`68` datagram to `DhcpClient::handle_message`; on an OFFER,
   `build_request(server, offered)` → TX; on an ACK, capture the
   `DhcpLease { ip, netmask, gateway, dns, lease_time }`.
3. `add_interface(InterfaceConfig { ip, netmask, gateway, .. })` with the LEASED
   values (replacing the static add), and seed the `DnsResolver` with the leased
   DNS servers.
- **Static fallback:** if DISCOVER/REQUEST get no reply within a bounded number
  of retries (each with a timeout), fall back to the M0 static `192.0.2.50/24`
  and log it — the image always comes up with a usable interface.
- The exchange is driven directly at boot (raw frames) rather than through the
  socket API, because the interface has no IP yet and DHCP is broadcast UDP.

### D2 — DHCP/DNS frame construction reuses the nexacore-net builders

The broadcast/unicast frames are built from `dhcp.build_*()` payload →
`udp::build_udp_packet` → `ip::build_ipv4_packet` → an Ethernet header, in a
small `dhcp_net`/`dns_net` helper (in the image, or a thin `nexacore-net` helper if
cleaner). No new packet logic — only the layer-wrapping the existing builders
already support. Checksums/lengths are computed by the builders.

### D3 — DNS verification (the `nslookup` acceptance)

After the lease is bound, the image resolves a real name (e.g. the configured
upstream, or `one.one.one.one`) by `DnsResolver::build_query` → broadcast/unicast
UDP `:53` to a leased DNS server → `parse_response` → log the resolved A record.
This is the on-device equivalent of `nslookup` and proves DNS works E2E with the
DHCP-provided resolver. (A shell `nslookup` command over a DNS syscall is a
larger surface and a follow-up; the boot-time resolve satisfies the acceptance.)

### D4 — Untrusted-input discipline (security)

Every DHCP/DNS parse is bounds-checked and length-validated (already in
`decode_dhcp_message`/`parse_dhcp_options`/DNS parse); a malformed packet is
discarded cleanly (the `DhcpResult`/`Option` `None` path), never panicking or
trusting attacker-controlled lengths. Unknown DHCP options are ignored. The
lease state machine re-discovers on timeout (the `is_lease_expired`/
`should_renew` seam) so a lost lease self-heals.

## Alternatives considered

- **Keep the static IP** — rejected: the Live USB (M5) runs on arbitrary
  networks; DHCP is the prerequisite the PLAN names.
- **Drive DHCP through the socket API** — rejected: the interface has no IP
  before the lease and DHCP is broadcast; a boot-time raw-frame exchange is the
  natural fit.
- **A full recursive DNS resolver** — out of scope: the stub resolver (single
  query to a configured server) is what `nslookup` needs and what `dns.rs`
  already provides.
- **A `nslookup` shell command + DNS syscall** — deferred: the boot-time resolve
  proves the path; a user-facing `nslookup` over a new DNS API is a follow-up.

## Consequences

- `nexacore-net-image`: a boot-time DHCP exchange (discover/offer/request/ack →
  lease → `InterfaceConfig`), static fallback, + a DNS resolve check. The static
  M0 path becomes the fallback.
- Possibly a thin nexacore-net helper to wrap a UDP payload into a sendable frame
  (broadcast + unicast), reusing `build_udp_packet`/`build_ipv4_packet`.
- Host tests: DHCP parse/serialize incl. malformed (existing 24) + lease state
  machine (timeout → re-discover); DNS query/response (existing 21). Any new
  helper is unit-tested.
- VM-103: a DHCP lease from `192.0.2.254` is acquired, the IP is applied, a
  real DNS name resolves, and the M0 Ollama round-trip works with the
  DHCP-assigned IP (verbatim serial capture).
- Lease renewal at T1, a user-facing `nslookup`, and per-interface DHCP policy
  are tracked follow-ups.

## Verification appendix — TASK-25 CLOSED (2026-06-08)

Implemented (DHCP boot driver + DNS check in `nexacore-net-image`; option-55 +
offer-config carry in `nexacore-net` — agent team + in-session debug) and
**hardware-verified on the test VM**, zero #PF.

Host tests: `nexacore-net` 217 (184 + 33) — DHCP parse/serialize incl. malformed →
clean discard, lease state machine, DNS query/response. All pass.

the test VM (real DHCP server `192.0.2.254`; verbatim serial):

```
[nexacore-net] dhcp: discover sent
[nexacore-net] dhcp: offer received — sending request
[nexacore-net] dhcp: request sent
[nexacore-net] dhcp: BOUND ip=192.0.2.142 gw=192.0.2.254 dns=192.0.2.254 lease=43200s
[nexacore-net] interface up; entering service loop
[nexacore-net] dns: one.one.one.one -> 1.0.0.1
   ...
[ai-svc] rid=0x..1 backend_used=RemoteGpu      # Ollama round-trip on the DHCP IP
[aicheck] AiInvoke OK
```

All acceptance points met: a DHCP lease is acquired (IP `192.0.2.142`, gateway
+ DNS `192.0.2.254`, 43200 s), the IP is applied to the interface, a real DNS
name resolves (`one.one.one.one -> 1.0.0.1`) via the DHCP-provided resolver, and
the M0 Ollama round-trip works with the DHCP-assigned IP. Absent a server, the
static `192.0.2.50/24` fallback keeps the interface up.

### Bring-up findings (DHCP-from-scratch gotchas, all fixed in-session)

1. **Stack overflow #PF.** `run_dhcp`/`dns_check` each declared 4 KiB rx+tx
   stack buffers; inlined into `_start` they overflowed the 16 KiB user stack
   (cr2 = rsp). Fixed with `#[inline(never)]` so each 8 KiB frame is separate.
2. **ACK never received (iteration-counted window).** The server delays the ACK
   (~1 s, duplicate-address-detection ARP of the offered IP) far longer than the
   3000-iteration (~84 ms) window survived, so the client re-DISCOVERed and the
   server kept re-OFFERing. Fixed by making the receive window **time-based**
   (`TimeMonotonicNanos`, 5 s/attempt).
3. **No gateway/DNS in the lease.** The server's replies to this client carried
   ONLY server-id + lease-time, because the client sent no **Parameter Request
   List (option 55)**. Fixed by adding option 55 (requesting subnet/router/DNS/
   lease) to DISCOVER + REQUEST, and by carrying the OFFER's config into the
   lease for servers that still send a minimal ACK.
4. **DNS unresolved (iteration-counted window).** Same class as #2 — a recursive
   lookup takes 10-100+ ms; the 500-iteration (~14 ms) DNS window expired first.
   Fixed by making the DNS receive window time-based (3 s).
5. **Broadcast-flag dead end.** Setting the DHCP broadcast flag (so the server
   broadcasts replies) was tried but the virtio driver did not deliver the
   broadcast OFFER/ACK on the test VM, so unicast (flags=0) + the time-based window
   is the working combination. (A driver broadcast-RX path is a follow-up.)

Lease renewal at T1, a user-facing `nslookup` shell command over a DNS API, and
the virtio broadcast-RX path are tracked follow-ups.
