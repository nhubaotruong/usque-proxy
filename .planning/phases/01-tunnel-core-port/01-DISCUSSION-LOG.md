# Phase 1: Tunnel Core Port - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-01
**Phase:** 01-tunnel-core-port
**Areas discussed:** Error classification, Reconnect strategy, Stats API, Network integration

---

## Gray Area Selection

| Option | Description | Selected |
|--------|-------------|----------|
| Error classification | Which errors trigger reconnect vs log-and-continue? | |
| Reconnect strategy | Constant 1s delay vs backoff for no-network? | |
| Stats API surface | What replaces delivery_ratio, rx_stall_sec, lifetime_rotations? | |
| Network integration | Keep SetConnectivity()/reconnectCh or simplify? | |

**User's choice:** "Match usque-android's approach for all gray areas"
**Notes:** User chose to port usque-android's patterns directly without discussing individual areas. The reference implementation already answers all gray areas clearly. All decisions locked to match usque-android's `tunnel.go` patterns, with Android-specific network integration (SetConnectivity/reconnectCh) kept as it's platform-specific and doesn't conflict.

---

## Claude's Discretion

- Buffer pool implementation details
- Exact goroutine spawning structure (as long as dual forwarding loops + error channel maintained)

## Deferred Ideas

None
