# Phase 2: Surgical CloseError Port - Discussion Log

**Date:** 2026-04-01
**Areas Discussed:** Error classification, Reconnect delay, QUIC keepalive, DNS reset scope

## Error Classification

**Q:** For forwardDown's device.WritePacket (TUN write), should a TUN write error remain fatal or be logged and continued?
**Options:** Keep fatal (match v1.27) | Match usque-android (also fatal)
**Selected:** Match usque-android — both approaches agree, keep TUN write errors fatal.

## Reconnect Delay

**Q:** How much of the reconnect delay logic should change?
**Options:** Only replace backoff | Simplify fully | Let me explain
**Selected:** Simplify fully — remove nextBackoff, network-grace, 200ms network-trigger delay. Everything becomes constant 1s. Keep waitForNetwork.

## QUIC Keepalive

**Q:** Should QUIC config stay adaptive (v1.27) or switch to usque-android's fixed settings?
**Options:** Keep v1.27 adaptive | Switch to fixed 30s | Let me explain
**Selected:** Switch to fixed 30s — match usque-android: 30s keepalive, 120s idle timeout, 1280 packets, PMTU disabled.

## DNS Reset Scope

**Q:** Should DNS connections be reset on ALL reconnects, or only on network-change reconnects?
**Options:** Reset on all reconnects | Keep v1.27 behavior
**Selected:** Reset on all reconnects — safer, DNS sockets may be stale after any reconnect.

---
*Discussion log for: 02-surgical-closeerror-port*
*Generated: 2026-04-01*
