# Phase 1: Tunnel Core Port - Research

**Researched:** 2026-04-01
**Domain:** Go tunnel forwarding loop, QUIC/MASQUE error handling, resource lifecycle
**Confidence:** HIGH

## Summary

Phase 1 replaces the current `maintainTunnel()` in `usque-bind/bind.go` with usque-android's proven forwarding loop pattern. The core change is twofold: (1) the forwarding goroutines (`forwardUp`/`forwardDown`) must classify errors as fatal (`connectip.CloseError`, TUN device failures) vs non-fatal (individual packet write/read errors), and (2) the reconnect loop must use a constant 1-second delay instead of exponential backoff with jitter.

The current implementation has three layers of complexity that this phase begins dismantling: exponential backoff (1s-60s with jitter), a `livenessCheck` goroutine that monitors rx stall and delivery ratio, and a 2-hour forced rotation timer. Phase 1 replaces the forwarding loops and reconnect strategy; Phase 2 removes the monitoring complexity.

**Primary recommendation:** Port usque-android's `MaintainTunnel()` error classification pattern into `forwardUp`/`forwardDown`, replace the backoff strategy with constant 1-second delay, update QUIC keepalive to 30s, and ensure clean resource teardown on each reconnect cycle.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Fatal errors (trigger reconnect): `connectip.CloseError` on read or write, TUN device read/write failures -- matching usque-android's `tunnel.go:204,215,231`
- **D-02:** Non-fatal errors (log and continue): individual packet write errors to Connect-IP, individual read errors from Connect-IP -- matching usque-android's `tunnel.go:208,219,235`
- **D-03:** Constant 1-second delay between reconnect attempts -- no exponential backoff, no jitter (matching usque-android's `tunnel.go:254`)
- **D-04:** Infinite retry loop with no maximum attempt limit (matching usque-android's pattern)
- **D-05:** Keep `SetConnectivity()`/`reconnectCh` integration with Android network callbacks -- when network is lost, wait instead of retrying; when network returns, reconnect immediately. This is Android-specific and doesn't conflict with the simpler tunnel loop.
- **D-06:** Keep network-triggered fast reconnect (200ms delay on network change instead of 1s) -- this is valuable for WiFi<->cellular transitions
- **D-07:** Each reconnect cycle must close: ipConn, udpConn (if non-nil), HTTP/3 transport -- matching usque-android's cleanup at `tunnel.go:247-253`
- **D-08:** DNS connections (`dns.resetConnections()`) also reset on reconnect -- keep this existing behavior
- **D-09:** `getStats()` continues to return: `connected`, `running`, `rx_bytes`, `tx_bytes`, `has_network`, `last_error` -- these are still useful
- **D-10:** Remove from stats: `delivery_ratio`, `rx_stall_sec`, `lifetime_rotations`, `tx_packets`, `rx_packets` -- these were only needed by the old monitoring mechanisms
- **D-11:** KeepAlivePeriod: 30 seconds (was 25s, matching usque-android's proven value)
- **D-12:** Keep existing: MaxIdleTimeout 120s, InitialPacketSize 1280, DisablePathMTUDiscovery true
- **D-13:** Keep existing: QUIC session cache for 1-RTT resumption

### Claude's Discretion
- Buffer pool implementation: Claude can decide whether to adopt usque-android's `NetBuffer` pool or keep existing approach
- Goroutine structure: Claude can decide exact goroutine spawning pattern as long as dual forwarding loops with error channel are maintained

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TUNL-01 | Forwarding goroutines detect `connectip.CloseError` and trigger immediate reconnection | Error classification pattern from usque-android `tunnel.go:204,215,231` -- `errors.As(err, new(*connectip.CloseError))` check in both forwarding directions |
| TUNL-02 | Reconnection uses constant 1-second delay instead of exponential backoff with jitter | Replace `nextBackoff()` and exponential logic with `time.Sleep(1 * time.Second)` matching usque-android `tunnel.go:254` |
| TUNL-03 | Each reconnect cycle cleanly tears down all resources (ipConn, udpConn, HTTP/3 transport) before retry | Existing `cleanup()` function already handles ipConn/udpConn/tr; add `wg.Wait()` for goroutine drain and `dns.resetConnections()` |
| TUNL-04 | Tunnel loop retries infinitely with no maximum attempt limit | Already the case in both implementations -- the `for {}` loop has no counter/limit |
| TUNL-05 | Non-fatal forwarding errors (individual packet write/read failures) are logged but don't trigger reconnection | Currently missing: `forwardUp`/`forwardDown` send ALL errors to errChan. Must add CloseError check to distinguish fatal from non-fatal |
| CMPT-05 | QUIC keepalive period set to 30 seconds | Change `KeepAlivePeriod` from `25 * time.Second` to `30 * time.Second` in `maintainTunnel` |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/Diniboy1123/connect-ip-go` | (current in go.mod) | CONNECT-IP (RFC 9484) | Provides `connectip.CloseError` type used for death detection, `connectip.Conn` for tunnel I/O |
| `github.com/quic-go/quic-go` | v0.59.0 | QUIC transport | QUIC session with keepalive; session death propagates as CloseError through connect-ip |
| `github.com/quic-go/quic-go/http3` | v0.59.0 | HTTP/3 transport | Required for MASQUE CONNECT-IP handshake |
| `github.com/Diniboy1123/usque` | v1.4.2 | MASQUE/WARP protocol | Provides `api.TunnelDevice`, `api.NetBuffer`, `api.ConnectTunnel`, `api.PrepareTlsConfig` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/yosida95/uritemplate/v3` | (current) | URI template expansion | Used in CONNECT-IP Dial for connect URI |

No new dependencies are needed. All required libraries are already in `usque-bind/go.mod`.

## Architecture Patterns

### Current vs Target Structure

The file structure does not change -- all work is within `usque-bind/bind.go`. The changes are to function internals:

```
usque-bind/
  bind.go          # [MODIFY] maintainTunnel, forwardUp, forwardDown, GetStats; remove nextBackoff, livenessCheck
  doh.go           # [KEEP] DNS-over-HTTPS interceptor (unchanged)
  doq.go           # [KEEP] DNS-over-QUIC interceptor (unchanged)
```

### Pattern 1: Error Classification in Forwarding Loops

**What:** Each forwarding goroutine checks whether an error is a `connectip.CloseError` (fatal) or a transient packet error (non-fatal). Fatal errors send to errChan; non-fatal errors log and continue.

**When to use:** Every error return from `ipConn.WritePacket`, `ipConn.ReadPacket`, and `device.WritePacket` (for ICMP).

**Reference pattern (from usque-android `tunnel.go:201-222`):**
```go
// In forwardUp - writing to Connect-IP
icmp, err := ipConn.WritePacket(buf[:n])
if err != nil {
    pool.Put(buf)
    if errors.As(err, new(*connectip.CloseError)) {
        errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
        return
    }
    log.Printf("Error writing to IP connection: %v, continuing...", err)
    continue
}

// ICMP reply writing - also check for CloseError
if len(icmp) > 0 {
    if err := device.WritePacket(icmp); err != nil {
        if errors.As(err, new(*connectip.CloseError)) {
            errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
            return
        }
        log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
    }
}
```

```go
// In forwardDown - reading from Connect-IP
n, err := ipConn.ReadPacket(buf, true)
if err != nil {
    if errors.As(err, new(*connectip.CloseError)) {
        errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
        return
    }
    log.Printf("Error reading from IP connection: %v, continuing...", err)
    continue
}
```

### Pattern 2: Constant Delay Reconnect Loop

**What:** After a tunnel connection dies, wait exactly 1 second before reconnecting. No exponential backoff, no jitter. Special case: 200ms delay on network-triggered reconnect.

**When to use:** After any fatal error from the forwarding loops, and after failed connection attempts.

**Reference pattern (adapted for usque-bind's Android integration):**
```go
const reconnectDelay = 1 * time.Second
// After error or cleanup:
if sleepCtxReconnectable(ctx, reconnectDelay, reconnectCh) {
    continue // reconnect signal arrived, skip delay
}
```

### Pattern 3: Clean Resource Teardown

**What:** Before every reconnect attempt, close ipConn, udpConn, and HTTP/3 transport in order, then wait for forwarding goroutines to exit.

**Reference pattern (from usque-android `tunnel.go:247-254`):**
```go
err = <-errChan
log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
ipConn.Close()
if udpConn != nil { udpConn.Close() }
if tr != nil { tr.Close() }
time.Sleep(reconnectDelay)
```

### Anti-Patterns to Avoid
- **Sending all errors to errChan indiscriminately:** This is the current bug. A single packet write failure tears down the entire tunnel. Must classify errors first.
- **Exponential backoff for tunnel reconnect:** Adds unnecessary delay. The server is either up or down; backing off to 60s just means longer outages.
- **Separate monitoring goroutine for stall detection:** The `livenessCheck` approach adds complexity. CloseError detection in the forwarding loop itself is sufficient (Phase 2 removes livenessCheck entirely, but Phase 1 should stop depending on it for the new forwarding loop errors).

## Key Differences: Current Code vs Reference

| Aspect | Current (`usque-bind/bind.go`) | Reference (`usque-android/tunnel.go`) | Phase 1 Target |
|--------|------|-----------|----------------|
| Error classification | All errors -> errChan (fatal) | CloseError -> fatal, others -> log+continue | Match reference |
| Backoff strategy | Exponential 1s-60s with 25% jitter | Constant delay (parameter) | Constant 1s |
| QUIC keepalive | 25s | 30s (parameter) | 30s |
| Lifetime rotation | 2h forced reconnect | None | Remove timer, keep for Phase 2 cleanup |
| Liveness check | Separate goroutine (rx stall + delivery ratio) | None (CloseError is sufficient) | Keep goroutine but stop spawning it for new connections (full removal in Phase 2) |
| Buffer pool | `api.NewNetBuffer(mtu)` | Same `api.NewNetBuffer(mtu)` | Keep current (already uses it) |
| `forwardDown` buffer | Direct allocation (not pooled) | Pool Get/Put | Keep current direct allocation (correct optimization -- buffer lives for connection lifetime) |
| DNS interception | Custom DNS interceptor/cache | None (not in reference) | Keep (usque-bind feature) |
| Happy Eyeballs | IPv4/IPv6 racing | Not in reference | Keep (usque-bind feature) |
| Network awareness | `waitForNetwork`, `SetConnectivity`, `reconnectCh` | Not in reference | Keep (Android integration) |

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CloseError detection | Custom error string matching | `errors.As(err, new(*connectip.CloseError))` | Type assertion is robust; string matching breaks on message changes |
| Buffer pooling | Custom buffer pool | `api.NewNetBuffer(mtu)` from usque library | Already battle-tested, handles capacity checks |
| QUIC session resumption | Manual TLS ticket storage | `tls.NewLRUClientSessionCache(8)` (already in place) | Standard library handles the complexity |
| Connection cleanup ordering | Ad-hoc close calls | Dedicated `cleanup()` function (already exists) | Ensures consistent teardown order |

## Common Pitfalls

### Pitfall 1: Goroutine Leak on Reconnect
**What goes wrong:** Forwarding goroutines from the previous connection keep running after cleanup, consuming CPU and potentially writing to closed connections.
**Why it happens:** If `ipConn.Close()` doesn't cause the blocking `ReadPacket`/`WritePacket` to return immediately, goroutines hang.
**How to avoid:** Use `sync.WaitGroup` and `wg.Wait()` after cleanup before starting the next connection (already done in current code at line 674). Verify that closing `ipConn` unblocks `ReadPacket`.
**Warning signs:** Growing goroutine count visible in pprof; "use of closed connection" log messages.

### Pitfall 2: Race Between reconnectCh and errChan
**What goes wrong:** A reconnect signal arrives simultaneously with a forwarding error, causing double-cleanup or attempting to use an already-closed connection.
**Why it happens:** The `select` on `errChan` and `reconnectCh` can pick either when both are ready.
**How to avoid:** The current code's pattern of `select { case err = <-errChan: ... case <-reconnectCh: ... }` handles this correctly -- only one path executes. The key is that cleanup runs unconditionally after the select.
**Warning signs:** Panic on nil pointer dereference in cleanup functions.

### Pitfall 3: Non-fatal Error Misclassification
**What goes wrong:** A TUN device `ReadPacket` error (which IS fatal per D-01) gets treated as non-fatal, or a Connect-IP transient error gets treated as fatal.
**Why it happens:** Confusion about which errors come from which source.
**How to avoid:** Follow the reference implementation exactly:
- `device.ReadPacket` error -> always fatal (errChan)
- `device.WritePacket` error -> fatal (errChan) -- if TUN is dead, we must reconnect
- `ipConn.WritePacket` error -> fatal only if CloseError; otherwise log and continue
- `ipConn.ReadPacket` error -> fatal only if CloseError; otherwise log and continue
- ICMP `device.WritePacket` error -> check for CloseError on the error itself (rare edge case from reference)
**Warning signs:** Tunnel disconnects on a single dropped packet.

### Pitfall 4: Stats Fields Removed Too Early
**What goes wrong:** Kotlin code still reads removed stats fields, causing JSON parse errors or null crashes.
**Why it happens:** D-10 says remove `delivery_ratio`, `rx_stall_sec`, `lifetime_rotations`, `tx_packets`, `rx_packets` from stats, but Kotlin code may reference them.
**How to avoid:** Check what Kotlin parses from `getStats()` JSON. If any removed field is read, it will just be absent from JSON (Go `json.Marshal` omits zero values for `omitempty`, but we use `map[string]interface{}` so we just don't add the key). Kotlin's JSON parsing should handle missing keys gracefully -- verify this.
**Warning signs:** App crash or error when reading stats after update.

### Pitfall 5: Forgetting to Drain reconnectCh After Successful Connect
**What goes wrong:** A stale reconnect signal from before the connection was established immediately tears down the fresh connection.
**Why it happens:** `reconnectCh` is buffered(1) and may have a signal queued from a previous iteration.
**How to avoid:** Current code already drains at line 627-630. Preserve this pattern.
**Warning signs:** Tunnel connects then immediately disconnects in a loop.

## Code Examples

### Example 1: New `forwardUp` with Error Classification

```go
// Source: adapted from usque-android/api/tunnel.go:192-223
func forwardUp(device api.TunnelDevice, ipConn *connectip.Conn, pool *api.NetBuffer, errChan chan<- error, dns *dnsInterceptor, dnsCache *tunnelDnsCache) {
    for {
        buf := pool.Get()
        n, err := device.ReadPacket(buf)
        if err != nil {
            pool.Put(buf)
            errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
            return
        }
        pkt := buf[:n]
        txBytes.Add(int64(n))

        // [DNS interception code unchanged...]

    sendPacket:
        icmp, err := ipConn.WritePacket(pkt)
        pool.Put(buf)
        if err != nil {
            if errors.As(err, new(*connectip.CloseError)) {
                errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
                return
            }
            log.Printf("Error writing to IP connection: %v, continuing...", err)
            continue
        }
        lastTxTime.Store(time.Now().UnixNano())
        if len(icmp) > 0 {
            if err := device.WritePacket(icmp); err != nil {
                if errors.As(err, new(*connectip.CloseError)) {
                    errChan <- fmt.Errorf("connection closed while writing ICMP: %v", err)
                    return
                }
                log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
            }
        }
    }
}
```

### Example 2: New `forwardDown` with Error Classification

```go
// Source: adapted from usque-android/api/tunnel.go:225-243
func forwardDown(device api.TunnelDevice, ipConn *connectip.Conn, _ *api.NetBuffer, errChan chan<- error, dnsCache *tunnelDnsCache) {
    buf := make([]byte, tunnelMTU)
    for {
        n, err := ipConn.ReadPacket(buf, true)
        if err != nil {
            if errors.As(err, new(*connectip.CloseError)) {
                errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
                return
            }
            log.Printf("Error reading from IP connection: %v, continuing...", err)
            continue
        }
        lastRxTime.Store(time.Now().UnixNano())
        rxBytes.Add(int64(n))
        if dnsCache != nil {
            dnsCache.cacheResponse(buf[:n])
        }
        if err := device.WritePacket(buf[:n]); err != nil {
            errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
            return
        }
    }
}
```

### Example 3: Simplified Reconnect Loop (main changes in `maintainTunnel`)

```go
// Key changes in the reconnect loop:
const reconnectDelay = 1 * time.Second

// Replace all backoff escalation with constant delay:
// REMOVE: backoff = nextBackoff(backoff, maxBackoff)
// REPLACE WITH: (just use reconnectDelay everywhere)

// After connection failure:
if !hasNetwork.Load() {
    log.Println("no network -- waiting for connectivity")
    waitForNetwork(ctx)
} else {
    sleepCtxReconnectable(ctx, reconnectDelay, reconnectCh)
}

// After forwarding loop error:
cleanup(ipConn, udpConn, tr)
wg.Wait()
if dns != nil { dns.resetConnections() }
// Network-triggered reconnect still gets 200ms for routing stabilization
if networkTriggered.Swap(false) {
    sleepCtxReconnectable(ctx, 200*time.Millisecond, reconnectCh)
} else {
    sleepCtxReconnectable(ctx, reconnectDelay, reconnectCh)
}
```

## Scope Boundary: What Phase 1 Changes vs Keeps

### CHANGES (Phase 1)
1. `forwardUp()` -- add CloseError classification (TUNL-01, TUNL-05)
2. `forwardDown()` -- add CloseError classification (TUNL-01, TUNL-05)
3. `maintainTunnel()` reconnect loop -- replace exponential backoff with constant 1s delay (TUNL-02)
4. `maintainTunnel()` QUIC config -- change KeepAlivePeriod from 25s to 30s (CMPT-05)
5. `GetStats()` -- remove `delivery_ratio`, `rx_stall_sec`, `lifetime_rotations`, `tx_packets`, `rx_packets` fields (D-10)
6. Remove `nextBackoff()` function (no longer needed)
7. Remove atomic variables: `txPackets`, `rxPackets`, `lastDeliveryRatio`, `lifetimeRotations` (D-10)
8. Remove `maxConnLifetime` constant and the `lifetimeTimer` select case (no more forced rotation)

### KEEPS (unchanged in Phase 1)
1. `livenessCheck()` -- still spawned but will be removed in Phase 2 (RMVL-01)
2. `Keepalive()` exported function -- removed in Phase 2 (RMVL-03)
3. `connectHappyEyeballs()` -- usque-bind's IPv4/IPv6 racing (not in reference, but valuable)
4. `connectTunnelProtected()` -- socket protection (Android-specific, not in reference)
5. `SetConnectivity()`/`waitForNetwork()` -- network awareness (D-05)
6. `Reconnect()` with `reconnectCh` -- network-triggered fast reconnect (D-06)
7. DNS interception (`dnsInterceptor`, `tunnelDnsCache`) -- usque-bind feature
8. Certificate caching (`cachedCert`, `certExpiry`) -- usque-bind optimization
9. `StartTunnel()`/`StopTunnel()` JNI interface -- compatibility (CMPT-01)
10. `FdAdapter` and fd dup pattern -- Android TUN fd handling

### DECISION: livenessCheck in Phase 1

The `livenessCheck` goroutine is spawned at line 641 in the current `maintainTunnel`. Per CONTEXT.md, it belongs to Phase 2 removal (RMVL-01). However, since Phase 1 removes the `lifetimeRotations` and `lastDeliveryRatio` atomics that `livenessCheck` writes to, there are two options:

**Recommendation:** Remove the `livenessCheck` spawn in Phase 1 but keep the function definition (dead code until Phase 2 cleans it up). Reason: the new CloseError-based detection makes livenessCheck redundant, and it writes to atomics we're removing. Alternatively, keep spawning it but remove the delivery ratio section -- this is Claude's discretion per CONTEXT.md goroutine structure flexibility.

## Project Constraints (from CLAUDE.md)

- GSD workflow enforcement: do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it
- No DI framework; direct instantiation in ViewModel
- Go standard `log.Printf`/`log.Println` for logging (captured in Android logcat via gomobile)
- `companion object` used for constants and static factory fields
- Private backing `MutableStateFlow` prefixed with `_`

## Sources

### Primary (HIGH confidence)
- `usque-android/api/tunnel.go` -- Complete reference implementation of MaintainTunnel with CloseError detection (read directly from repository)
- `usque-android/api/masque.go` -- ConnectTunnel handshake sequence (read directly from repository)
- `usque-android/internal/utils.go` -- DefaultQuicConfig with keepalive parameter (read directly from repository)
- `usque-bind/bind.go` -- Current implementation to be modified (read directly from repository, all 1138 lines)

### Secondary (MEDIUM confidence)
- `.planning/phases/01-tunnel-core-port/01-CONTEXT.md` -- User decisions D-01 through D-13

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries already in use, no new dependencies
- Architecture: HIGH -- reference implementation is in the repository and fully readable
- Pitfalls: HIGH -- derived from direct code comparison between current and reference implementations

**Research date:** 2026-04-01
**Valid until:** 2026-05-01 (stable domain -- Go libraries and patterns don't change rapidly)
