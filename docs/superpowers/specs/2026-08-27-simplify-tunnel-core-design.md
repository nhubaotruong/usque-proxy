# Simplify Usque Tunnel Core — Design

**Date:** 2026-08-27
**Status:** Approved in brainstorming (2026-08-27)
**Scope:** `usque-bind/` (Go) + `app/` (Kotlin) — tunnel lifecycle simplification with full feature parity on Android 11+ (minSdk 30).

## Goal

Replace the custom tunnel lifecycle (~1,200 Go lines + ~280 Kotlin lines) with the proven pattern from `usque-android`: a thin Go binding around upstream `api.MaintainTunnel`, with feature parity preserved (DNS modes, split tunneling, Office365/local-network bypass, stats UI, registration, Zero Trust, Doze handling).

## Decisions (user-approved)

| # | Decision | Rationale |
| --- | ---------- | ----------- |
| D1 | Keep minSdk 30 (Android 11/12 support) | User: "keep old android compat" |
| D2 | Thin wrapper around upstream `api.MaintainTunnel` | Upstream already has CloseError detection, 1s reconnect, idle-wait, HTTP2/H3, keepalive — the same code Phase 02 hand-ported |
| D3 | Change JNI signature: drop `VpnProtector` | Self-exclusion (`addDisallowedApplication(packageName)`) already prevents the routing loop in all three split modes; both sides change in the same commit |
| D4 | Delete dead-man's switch | Reference app has none; reliability comes from CloseError + 1s reconnect; START_STICKY covers process death |

## Current State

### Go (`usque-bind/`, ~3,238 lines)

- `bind.go` (1,158): custom `maintainTunnel` reconnect loop, happy-eyeballs racing, HTTP3+HTTP2 dual transports, `forwardUp`/`forwardDown` with CloseError classification, cert caching, stats, `waitForNetwork`, `SetConnectivity`/`Reconnect`/`StopTunnel`, registration, `GetStats`.
- `doh.go` (1,211): custom DoH proxy (padding, EDNS0, LRU cache, checksums, response builders) + `dnsInterceptor` + system-DNS forwarder + `tunnelDnsCache`.
- `direct.go` (394): gVisor userspace route forwarder for Android <13 (`VpnService.Builder.excludeRoute` is API 33+).
- `doq.go` (231): DoQ proxy.
- Registration via `Register`/`RegisterWithJWT`/`Enroll` + cert generation in `bind.go`.

### Kotlin (`UsqueVpnService.kt`, 734 lines)

- `startVpn`: VpnService.Builder with catch-all routes, `excludeRouteCompat` (API<33 fallback), `exclude_prefixes` passthrough, split modes, `setUnderlyingNetworks`, tunnel verification.
- Dead-man's switch (15/60-min `getStats()` + `reconnect()`), network watcher, power watcher, wake locks, notification, restart debounce.

## Target Design

### 1. Go tunnel core (`bind.go`: 1,158 → ~400 lines)

**Delete:** `maintainTunnel`, `connectHappyEyeballs`, `connectTunnelProtected`, `connectTunnelProtectedH2`, `forwardUp`, `forwardDown`, `waitForNetwork`, `sleepCtx`, `cleanup`, `protectUDPConn`, `isDNSQuery`, `taggedEndpoint`, `connResult`, `quicSessionCache` wiring, `networkCh`/`reconnectCh`, `connectedAt`, `connectCount`, cert-renewal cache, `Reconnect()`, `SetConnectivity()`.

**New thin `StartTunnel`:**

1. Parse config JSON into `tunnelConfig` (unchanged fields: SNI, ConnectURI, DoH/DoQ URLs, SystemDNS, PrivateDNS, UseHTTP2, ExcludePrefixes).
2. Dup TUN fd (fdsan fix stays: `syscall.Dup` + `os.NewFile`, close on ctx.Done to unblock reads).
3. Generate cert once via `selfSignedCert`, `api.PrepareTlsConfig`, set `tlsCfg.ClientSessionCache = quicSessionCache` (1-RTT session resumption).
4. Build `filterDevice` — the one new component: wraps `FdAdapter`; `ReadPacket` loops internally (read fd → DNS query? → `dns.forwardUp(req)` → continue; excluded prefix? → `direct.inject(pkt)` → continue; else return pkt to upstream pump). `WritePacket` writes to fd. Counts `tx_bytes` (in ReadPacket) / `rx_bytes` (in WritePacket).
5. Call `api.MaintainTunnel(ctx, MaintainTunnelConfig{TLSConfig, KeepalivePeriod: 30s, InitialPacketSize: 1242, Endpoint, Device: filterDevice, MTU: 1280, ReconnectDelay: 1s, AlwaysReconnect: false, UseHTTP2})`.
   - `Endpoint`: `*net.UDPAddr` from `EndpointV4:443` (H3, default) or `*net.TCPAddr` (H2 when `UseHTTP2`).
6. State callbacks: `"connecting"` on start; `"connected"` after ~3s (reference heuristic, if still running); `"stopped"` on exit. `OnError` only for fatal start errors (config parse, cert gen, TLS prep). Keep 5-min `OnStats` ticker.
7. `StartTunnel` returns error on fatal failures (gomobile → Java exception, unchanged).

**Upstream provides (free):** CloseError detection, reconnect loop, pump shutdown grace, ICMP handling, idle-wait (`AlwaysReconnect: false` = current `waitForTraffic` behavior), HTTP2/H3 transport, keepalive.

### 2. DNS + direct forwarder (`doh.go`/`doq.go`/`direct.go`)

- **Kept as-is** — re-hooked: `filterDevice.ReadPacket` calls them instead of `forwardUp`.
- `direct.go`: `dialProtected` → plain `net.Dial`; `VpnProtector` param removed (self-exclusion prevents loop). Same for DoH/DoQ/system-DNS sockets.
- `dohProxy.protector` field deleted.
- `bind_test.go`, `direct_test.go`, `doh_test.go` updated for new entry points.

### 3. Kotlin service (`UsqueVpnService.kt`: 734 → ~450 lines)

**Delete:** `startDeadMansSwitch`, `DEAD_MANS_INTERVAL_MS`/`DEAD_MANS_POWER_SAVE_MS`, `deadMansJob`, `protectFd`/VpnProtector impl, `restartTunnel()` + `reconnectDebounceJob` + `reconnectWakeLock`, `setConnectivity` call in `NetworkWatcher`.

**Keep:** `excludeRouteCompat` (API 33+ `excludeRoute` / <33 `exclude_prefixes` — the only remaining version check, required for Android 11/12 parity), `excludeLocalNetworks`, Office365 bypass, split modes, `waitForTunnelVerified`, `setUnderlyingNetworks`, power watcher (Doze), connect wake lock, notification, tile, boot receiver, `startVpn` flow (minus removed pieces).

**`NetworkWatcher` simplifies:** only `onUnderlyingNetworks` remains; `onNetworkChanged`/`onNetworkSwitched` deleted.

**`TunnelConfigBuilder`:** unchanged (exclude_prefixes passthrough stays for API<33).

**`VpnViewModel`:** `restartTunnel` usage removed; stats fields updated.

### 4. Stats surface

- `GetStats` JSON: keep `tx_bytes`, `rx_bytes`, `uptime_sec`, `running`, `connected`. **Drop:** `connect_count`, `last_error`, `connected_since_ms`, `has_network` (its only writer `SetConnectivity` is deleted).
- `TunnelStats`/`parseTunnelStats`: remove `connectCount`, `lastError`, `hasNetwork`; keep the rest (nothing displays `hasNetwork` — verified by grep).
- `MainScreen`: unchanged rows (tx/rx bytes, uptime); `connectedSince` derived from `uptime_sec` in ViewModel.
- `ListenerEventMapper`: stays (maps connecting/connected/disconnected/stopped; dedup harmless).

### 5. Trade-offs (accepted, match the reference)

- **IPv4-only endpoint** — happy-eyeballs/IPv6 racing removed; IPv6-only networks would fail to connect.
- **`connected` is approximate** (3s heuristic) — UI shows fewer state flickers during internal reconnects.
- **No forced reconnect on network switch** — upstream auto-reconnects (CloseError + 1s + idle-wait gating).
- **Stats minor discrepancy** — DNS responses counted as rx_bytes; acceptable.

## Error Handling

- Fatal errors (config, cert, TLS): `StartTunnel` returns error → Java exception → `tunnelJob` finally → `TunnelStateHolder.lastError`.
- Runtime errors: upstream logs and reconnects; `OnError` not called per-reconnect (no source). UI no longer shows per-reconnect errors.
- `StopTunnel`: cancel context → MaintainTunnel exits → `"stopped"` → Kotlin tears down.

## Testing

1. `go test ./usque-bind/...` — update `bind_test.go`/`direct_test.go`/`doh_test.go` for new entry points (filterDevice, no protector).
2. Kotlin: `ListenerEventMapper` unit tests stay green; add/update tests for `TunnelStats` field removal if any reference them.
3. Build: `build-usque.sh` (gomobile bind) → `./gradlew assembleDebug`.
4. Manual QA (device, arm64): connect, idle 15+ min, WiFi↔cellular switch, Doze entry/exit, stop/start cycle, all split modes, all DNS modes, Android 11/12 device or emulator for userspace-exclusion path.

## Out of Scope

- `usque-rs` (Rust) — untouched.
- DNS subsystem internals — kept as-is, only re-hooked.
- Doze/battery exemption, notification, tile, boot receiver — untouched.
- Upstream library version bump — pinned version stays.
