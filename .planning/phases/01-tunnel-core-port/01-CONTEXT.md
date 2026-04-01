# Phase 1: Tunnel Core Port - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace `maintainTunnel()` in `usque-bind/bind.go` with usque-android's proven forwarding loop pattern. The new tunnel core detects MASQUE session death through `connectip.CloseError` in the forwarding goroutines and reconnects immediately with a constant 1-second delay. QUIC keepalive period set to 30 seconds (matching usque-android).

</domain>

<decisions>
## Implementation Decisions

### Error Classification
- **D-01:** Fatal errors (trigger reconnect): `connectip.CloseError` on read or write, TUN device read/write failures — matching usque-android's `tunnel.go:204,215,231`
- **D-02:** Non-fatal errors (log and continue): individual packet write errors to Connect-IP, individual read errors from Connect-IP — matching usque-android's `tunnel.go:208,219,235`

### Reconnect Strategy
- **D-03:** Constant 1-second delay between reconnect attempts — no exponential backoff, no jitter (matching usque-android's `tunnel.go:254`)
- **D-04:** Infinite retry loop with no maximum attempt limit (matching usque-android's pattern)
- **D-05:** Keep `SetConnectivity()`/`reconnectCh` integration with Android network callbacks — when network is lost, wait instead of retrying; when network returns, reconnect immediately. This is Android-specific and doesn't conflict with the simpler tunnel loop.
- **D-06:** Keep network-triggered fast reconnect (200ms delay on network change instead of 1s) — this is valuable for WiFi↔cellular transitions

### Resource Cleanup
- **D-07:** Each reconnect cycle must close: ipConn, udpConn (if non-nil), HTTP/3 transport — matching usque-android's cleanup at `tunnel.go:247-253`
- **D-08:** DNS connections (`dns.resetConnections()`) also reset on reconnect — keep this existing behavior

### Stats API
- **D-09:** `getStats()` continues to return: `connected`, `running`, `rx_bytes`, `tx_bytes`, `has_network`, `last_error` — these are still useful
- **D-10:** Remove from stats: `delivery_ratio`, `rx_stall_sec`, `lifetime_rotations`, `tx_packets`, `rx_packets` — these were only needed by the old monitoring mechanisms

### QUIC Configuration
- **D-11:** KeepAlivePeriod: 30 seconds (was 25s, matching usque-android's proven value)
- **D-12:** Keep existing: MaxIdleTimeout 120s, InitialPacketSize 1280, DisablePathMTUDiscovery true
- **D-13:** Keep existing: QUIC session cache for 1-RTT resumption

### Claude's Discretion
- Buffer pool implementation: Claude can decide whether to adopt usque-android's `NetBuffer` pool or keep existing approach
- Goroutine structure: Claude can decide exact goroutine spawning pattern as long as dual forwarding loops with error channel are maintained

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Reference Implementation (usque-android)
- `usque-android/api/tunnel.go` — `MaintainTunnel()` lines 146-256: the gold standard forwarding loop with CloseError detection, reconnection, and resource cleanup
- `usque-android/api/masque.go` — `ConnectTunnel()` lines 93-150: QUIC + MASQUE handshake sequence
- `usque-android/internal/utils.go` — `DefaultQuicConfig()` lines 119-133: keepalive period configuration

### Current Implementation (to be replaced)
- `usque-bind/bind.go` — current `maintainTunnel()`, `livenessCheck()`, `Keepalive()`, reconnect logic
- `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt` — keepalive mechanisms (to be removed in Phase 2)

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` — system design and data flow
- `.planning/codebase/STACK.md` — technology stack details

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `usque-bind/bind.go`: `connectToServer()` / `dialWithHappyEyeballs()` — connection establishment can be reused, only the tunnel loop changes
- `usque-bind/bind.go`: `SetConnectivity()` / `waitForNetwork()` — network state management is valuable and should be kept
- `usque-bind/bind.go`: `dns.resetConnections()` — DNS cleanup on reconnect should be preserved

### Established Patterns
- JNI exports via gomobile: `StartTunnel`, `StopTunnel`, `Reconnect`, `GetStats` — interface must be maintained
- `reconnectCh` channel pattern for signaling reconnect from Kotlin/Android side
- Atomic timestamps for `lastRxTime`/`lastTxTime` — may still be useful for basic stats

### Integration Points
- `UsqueVpnService.kt` calls `Usquebind.startTunnel()` to launch the Go tunnel
- `UsqueVpnService.kt` calls `Usquebind.reconnect()` on network changes and Doze exit
- `UsqueVpnService.kt` calls `Usquebind.getStats()` every 60s for UI display
- `UsqueVpnService.kt` calls `Usquebind.keepalive()` — this will be removed in Phase 2

</code_context>

<specifics>
## Specific Ideas

Port usque-android's `MaintainTunnel()` pattern as closely as possible. The reference implementation at `usque-android/api/tunnel.go:146-256` is proven to run for days without silent connection death. Match its error detection, reconnection timing, and resource cleanup patterns.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-tunnel-core-port*
*Context gathered: 2026-04-01*
