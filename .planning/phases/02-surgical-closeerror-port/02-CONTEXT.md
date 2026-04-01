# Phase 2: Surgical CloseError Port - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add CloseError-based error classification to forwardUp/forwardDown, replace exponential backoff with constant 1s reconnect delay, switch to fixed QUIC config, and reset DNS on all reconnects. All changes are to `usque-bind/bind.go` only — no Kotlin changes.

</domain>

<decisions>
## Implementation Decisions

### Error Classification
- **D-01:** In `forwardUp`, `ipConn.WritePacket` errors are classified: `connectip.CloseError` → fatal (send to errChan, return). All other errors → log and continue.
- **D-02:** In `forwardUp`, ICMP `device.WritePacket` errors are classified the same way: CloseError → fatal. Others → log and continue.
- **D-03:** In `forwardDown`, `ipConn.ReadPacket` errors are classified: CloseError → fatal. Others → log and continue.
- **D-04:** In `forwardDown`, `device.WritePacket` (TUN write) errors remain fatal — TUN write failure means the VPN interface is broken. This matches both v1.27 and usque-android behavior.
- **D-05:** In `forwardUp`, `device.ReadPacket` (TUN read) errors remain fatal — same reasoning as D-04.

### Reconnect Delay
- **D-06:** Replace `nextBackoff` (exponential 1s→60s with 25% jitter) with constant `reconnectDelay = 1 * time.Second`.
- **D-07:** Remove `networkGraceAttempts` and `networkGraceMax` — no grace period logic.
- **D-08:** Remove 200ms network-trigger micro-delay — all reconnects use the same 1s delay.
- **D-09:** Keep `waitForNetwork()` as-is — blocking on no-network is a separate concern from retry delay.
- **D-10:** Remove `nextBackoff` function entirely.
- **D-11:** Remove `backoff` variable and all backoff state tracking.

### QUIC Configuration
- **D-12:** Replace adaptive keepalive/PMTU with fixed usque-android values: `KeepAlivePeriod: 30s`, `MaxIdleTimeout: 120s`, `InitialPacketSize: 1280`, `DisablePathMTUDiscovery: true`.
- **D-13:** Remove `networkHint` atomic, `SetNetworkHint()` function, and the adaptive switch block.
- **D-14:** Remove `packetSize` constant (1242) — replaced by fixed 1280.
- **D-15:** Remove `NetworkType` from `tunnelConfig` struct and JSON parsing.

### DNS Reset
- **D-16:** Reset DNS connections (`dns.resetConnections()`) on ALL reconnects, not just network-change reconnects. Remove the `isNetworkReconnect` guard.

### Claude's Discretion
- Log message format for non-fatal errors (exact wording)
- Whether to use `errors.As` or type assertion for CloseError detection (prefer `errors.As` to match usque-android)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Reference Implementation
- `usque-android/api/tunnel.go` — Gold standard for CloseError detection pattern (lines 204-236) and constant reconnect delay (lines 173, 185, 254)

### Target File
- `usque-bind/bind.go` — The only file being modified. Read current v1.27 state before making changes.

</canonical_refs>

<code_context>
## Existing Code Insights

### Key Functions to Modify
- `forwardUp()` (line 774) — Currently treats all errors as fatal. Add CloseError classification.
- `forwardDown()` (line 818) — Same pattern. Add CloseError classification for ipConn.ReadPacket.
- `maintainTunnel()` (line 387) — Replace backoff logic with constant delay, remove adaptive QUIC config, reset DNS on all reconnects.

### Functions to Remove
- `nextBackoff()` — Exponential backoff calculation, no longer needed
- `SetNetworkHint()` — Adaptive keepalive network hint, replaced by fixed config

### Variables to Remove
- `networkHint` atomic — No longer used
- `backoff` local var in maintainTunnel — Replaced by constant
- `networkGraceAttempts` local var — Removed
- `isNetworkReconnect` local var — DNS reset is unconditional now

### Integration Points
- `connectip.CloseError` type from `github.com/Diniboy1123/connect-ip-go` — Must be imported for `errors.As` check
- `tunnelConfig.NetworkType` field — Remove from struct and JSON unmarshalling

</code_context>

<specifics>
## Specific Ideas

- Pattern for CloseError detection should exactly match usque-android: `errors.As(err, new(*connectip.CloseError))`
- Error messages should include context: "connection closed while writing to IP connection: %v" (matching usque-android format)
- The `mrand` import (`math/rand/v2`) can be removed since `nextBackoff` used it for jitter

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-surgical-closeerror-port*
*Context gathered: 2026-04-01*
