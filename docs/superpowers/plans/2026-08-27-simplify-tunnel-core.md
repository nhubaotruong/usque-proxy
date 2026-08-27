# Simplify Usque Tunnel Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the custom tunnel lifecycle in `usque-bind` with a thin wrapper around upstream `api.MaintainTunnel`, deleting the dead-man's switch, VpnProtector, and reconnect machinery — keeping full feature parity on Android 11+ (minSdk 30).

**Architecture:** Go keeps only the interception layer (DNS + userspace exclusion + byte stats) in a `filterDevice` wrapper around the TUN fd; upstream's proven `MaintainTunnel` (CloseError detection, 1s reconnect, idle-wait, HTTP2/H3) owns the tunnel loop. Kotlin drops the dead-man's switch, VpnProtector, and network-change restarts; reliability comes from upstream reconnect + START_STICKY, exactly like the reference app.

**Tech Stack:** Go 1.26.3 (gomobile bind), `github.com/Diniboy1123/usque v1.5.1-0.20260720063354-6aa03fc97d12` (`api.MaintainTunnel`), Kotlin 2.3.21 / AGP 9.2.0, minSdk 30.

**Spec:** `docs/superpowers/specs/2026-08-27-simplify-tunnel-core-design.md`

## Global Constraints

- minSdk 30 (Android 11/12) support MUST keep: `excludeRouteCompat` (API 33+ `excludeRoute` / <33 `exclude_prefixes` → Go userspace forwarder) — the only remaining version check.
- Feature parity: DNS modes (Cloudflare/System/Custom DoH/Custom DoQ), split modes, Office365 + local-network bypass, registration (Register/RegisterWithJWT/Enroll), stats UI, Doze/battery exemption, notification, tile, boot receiver — all must keep working.
- JNI signature change: `Usquebind.startTunnel(configJson, fd, listener)` — `VpnProtector` param removed on both sides in the same logical change.
- Upstream pin stays `v1.5.1-0.20260720063354-6aa03fc97d12` — no version bump.
- `build-usque.sh` MUST be run after Go changes before any Kotlin build (AAR is the JNI contract).
- Commits: conventional, ≤72 chars, present tense. No `git add .` — stage files explicitly.

## Spec Amendments (from review; flagged at plan approval)

1. **PowerStateWatcher.kt is deleted, not kept.** Its two consumers are both removed: `onPowerSaveChanged` fed the dead-man's switch interval (deleted) and `onDeviceIdleChanged` triggered Doze-exit `restartTunnel()` (deleted). Keeping it would be dead code. Battery exemption (MainActivity), foreground service, and upstream reconnect cover Doze.
2. **`has_network` dropped** from GetStats/TunnelStats (its only writer, `SetConnectivity`, is deleted) — already amended in spec.
3. **No `doh_test.go` exists** (spec mentioned it) — only `bind_test.go` and `direct_test.go`; plan covers the actual files.
4. **`connectedSinceMs`** — `TunnelStats` has no such field; the ViewModel derives `connectedSince` from `uptime_sec`. Go drops the `connected_since_ms` key.

## File Structure

| File | Change | Responsibility after change |
| --- | --- | --- |
| `usque-bind/device.go` | **Create** | `filterDevice`: TUN fd wrapper implementing `api.TunnelDevice`; intercepts DNS + excluded prefixes, counts tx/rx bytes |
| `usque-bind/bind.go` | **Modify** | Thin `StartTunnel` → `api.MaintainTunnel`; register/enroll/stats/state callbacks; deletes ~700 lines of tunnel loop |
| `usque-bind/doh.go` | **Modify** | Drop `protector` from `newDohProxy`/`newDnsInterceptor`/`newSystemDnsResolver`/`newSystemDnsInterceptor`/`queryServer`; plain dials |
| `usque-bind/doq.go` | **Modify** | Drop `protector` from `newDoqProxy`/`newDoqDnsInterceptor`; plain dial |
| `usque-bind/direct.go` | **Modify** | Drop `protector` field/param; `dialProtected` → `net.DialContext` |
| `usque-bind/bind_test.go` | **Modify** | Stats shape (new keys), StartTunnel signature |
| `usque-bind/device_test.go` | **Create** | filterDevice passthrough + byte counting tests |
| `usque-bind/direct_test.go` | **Modify** | `newDirectForwarder` new signature |
| `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt` | **Modify** | Remove dead-man's switch, protector, restartTunnel, PowerStateWatcher wiring, reconnectWakeLock |
| `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/NetworkWatcher.kt` | **Modify** | Keep only `onUnderlyingNetworks` |
| `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/PowerStateWatcher.kt` | **Delete** | Dead code after removals (amendment 1) |
| `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/TunnelStatsParser.kt` | **Modify** | Drop `hasNetwork`, `connectCount`, `lastError` |
| `app/src/test/java/com/nhubaotruong/usqueproxy/TunnelStatsParserTest.kt` | **Modify** | Match trimmed fields |
| `app/libs/usquebind.aar` | **Regenerate** | Via `build-usque.sh` |

---

## Task 1: Go — drop VpnProtector from DNS/direct plumbing

**Files:**

- Modify: `usque-bind/doh.go`, `usque-bind/doq.go`, `usque-bind/direct.go`, `usque-bind/bind.go`
- Test: `usque-bind/direct_test.go`

**Interfaces:**

- Consumes: existing `tunnelConfig`, `dnsInterceptor`, `directForwarder` types (unchanged).
- Produces: `newDohProxy(url string) *dohProxy`; `newDnsInterceptor(ctx context.Context, cfg *tunnelConfig) *dnsInterceptor`; `newSystemDnsResolver(servers []string) *systemDnsResolver`; `newSystemDnsInterceptor(ctx context.Context, servers []string) *dnsInterceptor`; `newDoqProxy(addr string) *doqProxy`; `newDoqDnsInterceptor(ctx context.Context, doqAddr string) *dnsInterceptor`; `newDirectForwarder(prefixes []string, mtu uint32, writePkt func([]byte) error) (*directForwarder, error)`.

Rationale (spec D3): the app self-excludes via `addDisallowedApplication(packageName)` in all split modes, so every socket the Go code opens (QUIC, DoH, DoQ, system-DNS, direct relays) bypasses the TUN automatically. `protect()` is redundant.

- [ ] **Step 1: Update the failing test first**

In `usque-bind/direct_test.go`, change the `newDirectForwarder` call to the new signature. Read the file first; it constructs a forwarder with a protector arg — drop that argument:

```go
// before:
df, err := newDirectForwarder([]string{"10.0.0.0/8"}, 1280, nil, writePkt)
// after:
df, err := newDirectForwarder([]string{"10.0.0.0/8"}, 1280, writePkt)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd usque-bind && go test -run TestDirectInject ./...
```

Expected: FAIL — `newDirectForwarder` called with 3 args, but has 4.

- [ ] **Step 3: Edit `direct.go`**

Remove the `protector` field from `directForwarder`, the param from `newDirectForwarder` (and its `protector: protector,` assignment), and replace both `dialProtected(...)` calls:

```go
// handleTCP (was: conn, err := dialProtected(df.ctx, "tcp", dst, df.protector))
conn, err := net.DialContext(df.ctx, "tcp", dst)
// handleUDP (was: conn, err := dialProtected(df.ctx, "udp", dst, df.protector))
conn, err := net.DialContext(df.ctx, "udp", dst)
```

Then delete the whole `dialProtected` function at the bottom of the file.

- [ ] **Step 4: Edit `doh.go`**

1. `newDohProxy(url string, protector VpnProtector)` → `newDohProxy(url string)`. In `makeClient`'s `DialContext`, delete the post-dial protect block (the `if tc, ok := conn.(*net.TCPConn)` block) and return `conn, nil` directly. In `makeH3Client`'s `Dial`, delete the `protectUDPConn(udpConn, protector)` call and its error branch.
2. `newDnsInterceptor(ctx context.Context, cfg *tunnelConfig, protector VpnProtector)` → drop the param; call `newDohProxy(cfg.DoHURL)`.
3. `systemDnsResolver`: drop the `protector` field; `newSystemDnsResolver(servers []string)` drops the param; in `queryServer` delete the `protectUDPConn(conn, s.protector)` block.
4. `newSystemDnsInterceptor(ctx context.Context, servers []string)` drops the param.

- [ ] **Step 5: Edit `doq.go`**

`newDoqProxy(addr string, protector VpnProtector)` → `newDoqProxy(addr string)`; delete the `protectUDPConn(udpConn, protector)` block in `makeConn`. `newDoqDnsInterceptor(ctx context.Context, doqAddr string)` drops the param.

- [ ] **Step 6: Edit `bind.go` — remove dead helper**

Delete `protectUDPConn` (bind.go ~line 1119). Temporarily, `maintainTunnel` still calls the old signatures — update its call sites to the new ones (it still receives `protector` as a param; leave that for Task 2, but the calls to `newDnsInterceptor(ctx, cfg)` / `newDoqDnsInterceptor(ctx, cfg.DoQURL)` / `newSystemDnsInterceptor(ctx, cfg.SystemDNS)` / `newDirectForwarder(cfg.ExcludePrefixes, mtu, device.WritePacket)` must compile).

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd usque-bind && go build ./... && go vet ./... && go test ./...
```

Expected: build clean, all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add usque-bind/doh.go usque-bind/doq.go usque-bind/direct.go usque-bind/bind.go usque-bind/direct_test.go
git commit -m "feat(bind): drop VpnProtector from dns and direct layers"
```

---

## Task 2: Go — filterDevice wrapper (new file)

**Files:**

- Create: `usque-bind/device.go`
- Test: `usque-bind/device_test.go`

**Interfaces:**

- Consumes: `dnsInterceptor` (`forwardUp(dnsRequest)`, `close()`), `tunnelDnsCache` (`checkAndRespond(pkt, writeFunc) bool`, `cacheResponse(pkt)`), `directForwarder` (`shouldForward(pkt) bool`, `inject(pkt)`, `close()`), globals `txBytes`/`rxBytes` (atomic.Int64), `dnsQueryPool`.
- Produces: `filterDevice` struct with `file *os.File`, `dns *dnsInterceptor`, `dnsCache *tunnelDnsCache`, `direct *directForwarder`; methods `ReadPacket(buf []byte) (int, error)` and `WritePacket(pkt []byte) error` — satisfies `api.TunnelDevice`.

Behavior contract (must match old `forwardUp`/`forwardDown` exactly):

- `ReadPacket` loops: read from fd → count `txBytes` → if DNS query and `dns != nil`, copy the query via `dnsQueryPool`, `dns.forwardUp(...)` with `writeFunc: f.WritePacket`, continue; if DNS query and `dnsCache != nil` and `checkAndRespond` returns true, continue; if `direct.shouldForward(pkt)`, `direct.inject(pkt)`, continue; else return `(n, nil)`.
- `WritePacket`: count `rxBytes`, if `dnsCache != nil` call `dnsCache.cacheResponse(pkt)` (downlink path), write to fd.

- [ ] **Step 1: Write the failing tests**

Create `usque-bind/device_test.go`:

```go
package usquebind

import (
 "os"
 "testing"
)

// TestFilterDevicePassthrough verifies non-DNS, non-excluded packets pass
// through unchanged and tx_bytes is counted.
func TestFilterDevicePassthrough(t *testing.T) {
 pr, pw, err := os.Pipe()
 if err != nil {
  t.Fatal(err)
 }
 defer pr.Close()
 defer pw.Close()

 fd := &filterDevice{file: pr}
 txBytes.Store(0)

 // Fake IPv4 UDP packet (not port 53): 20B IP + 8B UDP + 4B payload
 pkt := []byte{
  0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
  0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
  0x08, 0x08, 0x08, 0x08, 0x00, 0x50, 0x01, 0xbb,
  0x00, 0x08, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
 }
 go pw.Write(pkt)

 buf := make([]byte, 1500)
 n, err := fd.ReadPacket(buf)
 if err != nil {
  t.Fatalf("ReadPacket: %v", err)
 }
 if n != len(pkt) {
  t.Fatalf("ReadPacket returned %d bytes, want %d", n, len(pkt))
 }
 for i := range pkt {
  if buf[i] != pkt[i] {
   t.Fatalf("byte %d: got %#x, want %#x", i, buf[i], pkt[i])
  }
 }
 if got := txBytes.Load(); got != int64(len(pkt)) {
  t.Fatalf("tx_bytes = %d, want %d", got, len(pkt))
 }
}

// TestFilterDeviceWritePacket verifies rx_bytes counting.
func TestFilterDeviceWritePacket(t *testing.T) {
 pr, pw, err := os.Pipe()
 if err != nil {
  t.Fatal(err)
 }
 defer pr.Close()
 defer pw.Close()

 fd := &filterDevice{file: pw}
 rxBytes.Store(0)

 pkt := []byte{0x45, 0x00, 0x00, 0x10}
 if err := fd.WritePacket(pkt); err != nil {
  t.Fatalf("WritePacket: %v", err)
 }
 if got := rxBytes.Load(); got != int64(len(pkt)) {
  t.Fatalf("rx_bytes = %d, want %d", got, len(pkt))
 }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd usque-bind && go test -run TestFilterDevice ./...
```

Expected: FAIL — undefined `filterDevice`.

- [ ] **Step 3: Implement `device.go`**

```go
package usquebind

import (
 "os"
)

// filterDevice wraps the TUN fd and applies per-packet filters before
// packets reach the upstream tunnel pump: DNS interception (DoH/DoQ/system
// resolver or tunnel cache) and userspace route exclusion (Android < 13).
// It implements api.TunnelDevice for upstream MaintainTunnel.
type filterDevice struct {
 file     *os.File
 dns      *dnsInterceptor
 dnsCache *tunnelDnsCache
 direct   *directForwarder
}

// ReadPacket implements api.TunnelDevice.ReadPacket. It loops internally:
// DNS queries and excluded-prefix packets are consumed here (intercepted or
// relayed directly); only tunnel-bound packets are returned to the pump.
func (f *filterDevice) ReadPacket(buf []byte) (int, error) {
 for {
  n, err := f.file.Read(buf)
  if err != nil {
   return 0, err
  }
  pkt := buf[:n]
  txBytes.Add(int64(n))

  // Intercept DNS packets (IPv4 and IPv6)
  if srcIP, srcPort, dstIP, query, isIPv6, ok := detectDNSQuery(pkt); ok && isDNSQuery(query) {
   if f.dns != nil {
    bufPtr := dnsQueryPool.Get().(*[]byte)
    queryCopy := append((*bufPtr)[:0], query...)
    f.dns.forwardUp(dnsRequest{
     srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
     query: queryCopy, writeFunc: f.WritePacket,
     isIPv6: isIPv6, poolBuf: bufPtr,
    })
    continue
   }
   if f.dnsCache != nil && f.dnsCache.checkAndRespond(pkt, f.WritePacket) {
    continue
   }
  }

  // Userspace route exclusion: relay directly, do not tunnel.
  if f.direct != nil && f.direct.shouldForward(pkt) {
   f.direct.inject(pkt)
   continue
  }

  return n, nil
 }
}

// WritePacket implements api.TunnelDevice.WritePacket. Counts rx bytes and
// feeds the DNS response cache for tunnel-downlink packets.
func (f *filterDevice) WritePacket(pkt []byte) error {
 rxBytes.Add(int64(len(pkt)))
 if f.dnsCache != nil {
  f.dnsCache.cacheResponse(pkt)
 }
 _, err := f.file.Write(pkt)
 return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd usque-bind && go build ./... && go vet ./... && go test ./...
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add usque-bind/device.go usque-bind/device_test.go
git commit -m "feat(bind): add filterDevice tun wrapper for interception"
```

---

## Task 3: Go — thin StartTunnel via api.MaintainTunnel

**Files:**

- Modify: `usque-bind/bind.go`, `usque-bind/bind_test.go`

**Interfaces:**

- Consumes: `filterDevice` (Task 2), new DNS/direct signatures (Task 1), `api.MaintainTunnel(ctx, api.MaintainTunnelConfig{...})` from upstream.
- Produces: `StartTunnel(configJSON string, tunFd int, listener TunnelListener) error` (protector param REMOVED); `GetStats() string` with keys `running`, `connected`, `tx_bytes`, `rx_bytes`, `uptime_sec` only; `StopTunnel()`, `IsRunning()` unchanged; internal `endpointFromConfig(cfg *tunnelConfig) net.Addr`.

- [ ] **Step 1: Write the failing test**

Update `usque-bind/bind_test.go`:

1. `TestGetStatsShape` — new key set:

```go
func TestGetStatsShape(t *testing.T) {
 s := GetStats()
 var m map[string]interface{}
 if err := json.Unmarshal([]byte(s), &m); err != nil {
  t.Fatalf("stats not valid JSON: %v", err)
 }
 for _, k := range []string{"running", "connected", "tx_bytes", "rx_bytes", "uptime_sec"} {
  if _, ok := m[k]; !ok {
   t.Errorf("stats missing key %q", k)
  }
 }
 for _, k := range []string{"has_network", "connect_count", "last_error"} {
  if _, ok := m[k]; ok {
   t.Errorf("stats must not contain key %q", k)
  }
 }
 if _, ok := m["running"].(bool); !ok {
  t.Errorf("running must be bool, got %T", m["running"])
 }
 if _, ok := m["tx_bytes"].(float64); !ok {
  t.Errorf("tx_bytes must be number, got %T", m["tx_bytes"])
 }
}
```

2. `TestStartTunnelInvalidConfig` — new signature (protector arg gone):

```go
func TestStartTunnelInvalidConfig(t *testing.T) {
 err := StartTunnel("{not json", 0, nil)
 if err == nil || !strings.Contains(err.Error(), "invalid config JSON") {
  t.Fatalf("expected invalid config JSON error, got %v", err)
 }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd usque-bind && go test -run 'TestGetStatsShape|TestStartTunnelInvalidConfig' ./...
```

Expected: FAIL — wrong arity (compiler) for `StartTunnel`, stats keys mismatch.

- [ ] **Step 3: Rewrite `bind.go`**

3a. **Delete these functions and types** (entire bodies): `FdAdapter` struct + its `ReadPacket`/`WritePacket` methods (replaced by `filterDevice`), `maintainTunnel`, `connectHappyEyeballs`, `connectTunnelProtected`, `connectTunnelProtectedH2`, `forwardUp`, `forwardDown`, `waitForNetwork`, `sleepCtx`, `cleanup`, `protectUDPConn` (already gone in Task 1), `SetConnectivity`, `Reconnect`, `taggedEndpoint`, `connResult`, and the `VpnProtector` interface definition (`type VpnProtector interface { ProtectFd(fd int) bool }` at bind.go ~line 93 — gomobile exports every public type, so it must go or `VpnProtector.class` stays in the AAR and Task 4's verification fails). **Keep** `selfSignedCert`, `isDNSQuery`, `sni()`/`connectUri()` methods, `setListener`/`getListener`/`safeNotify`/`notifyState`/`notifyStats`/`notifyError`, all register/enroll functions.

3b. **Trim global state** — delete `hasNetwork`, `connectedAt`, `connectCount`, `lastError`, `networkCh`, `reconnectCh` (keep `mu`, `cancel`, `done`, `running`, `connected`, `startTime`, `txBytes`, `rxBytes`, `quicSessionCache`). `lastError` is safe to delete: all its writers (maintainTunnel lines 614–686, StartTunnel init line 236) and its only reader (GetStats line 333) are removed by this rewrite — `notifyError` does NOT touch it (it only calls `l.OnError(err)`).

3c. **Rewrite `StartTunnel`** (replaces the old 4-arg version):

```go
func StartTunnel(configJSON string, tunFd int, listener TunnelListener) error {
 mu.Lock()
 if running.Load() {
  d := done
  mu.Unlock()
  // Previous tunnel still shutting down — wait up to 5s
  if d != nil {
   select {
   case <-d:
   case <-time.After(5 * time.Second):
    return errors.New("timeout waiting for previous tunnel to stop")
   }
  }
  mu.Lock()
  if running.Load() {
   mu.Unlock()
   return errors.New("tunnel already running")
  }
 }

 var tcfg tunnelConfig
 if err := json.Unmarshal([]byte(configJSON), &tcfg); err != nil {
  mu.Unlock()
  return fmt.Errorf("invalid config JSON: %w", err)
 }
 config.AppConfig = tcfg.Config
 config.ConfigLoaded = true
	if tcfg.EndpointV4 == "" {
		mu.Unlock()
		return fmt.Errorf("no endpoint v4 in config")
	}

 ctx, c := context.WithCancel(context.Background())
 cancel = c
 done = make(chan struct{})
 running.Store(true)
 connected.Store(false)
 startTime = time.Now()
 txBytes.Store(0)
 rxBytes.Store(0)
 mu.Unlock()

 setListener(listener)
 defer setListener(nil)

 // dup() gives Go an unowned copy of the TUN fd (fdsan fix, see spec).
 dupFd, err := syscall.Dup(tunFd)
 if err != nil {
  return fmt.Errorf("dup tun fd: %w", err)
 }
 tunFile := os.NewFile(uintptr(dupFd), "tun")
 defer tunFile.Close()
 // On shutdown, unblock the TUN read in filterDevice.
 go func() {
  <-ctx.Done()
  tunFile.Close()
 }()

 device := &filterDevice{file: tunFile}

 // DNS interception (DoH, DoQ, or System DNS) or tunnel cache fallback.
 if tcfg.DoHURL != "" {
  device.dns = newDnsInterceptor(ctx, &tcfg)
  if device.dns != nil {
   defer device.dns.close()
   log.Println("DNS interception enabled: all port 53 traffic via DoH")
  }
 } else if tcfg.DoQURL != "" {
  device.dns = newDoqDnsInterceptor(ctx, tcfg.DoQURL)
  if device.dns != nil {
   defer device.dns.close()
   log.Println("DNS interception enabled: all port 53 traffic via DoQ")
  }
 } else if len(tcfg.SystemDNS) > 0 {
  device.dns = newSystemDnsInterceptor(ctx, tcfg.SystemDNS)
  if device.dns != nil {
   defer device.dns.close()
   if tcfg.PrivateDNS {
    log.Printf("System DNS interception enabled (Private DNS active): forwarding port-53 via sockets to %v", tcfg.SystemDNS)
   } else {
    log.Printf("System DNS interception enabled: forwarding via sockets to %v", tcfg.SystemDNS)
   }
  }
 } else {
  device.dnsCache = newTunnelDnsCache(512)
  log.Println("DNS tunnel cache enabled")
 }

 // Userspace route exclusion (Android < 13): only set when exclude_prefixes
 // arrive from Kotlin (API < 33 path).
 if len(tcfg.ExcludePrefixes) > 0 {
  df, derr := newDirectForwarder(tcfg.ExcludePrefixes, 1280, device.WritePacket)
  if derr != nil {
   log.Printf("Userspace route exclusion disabled: %v", derr)
  } else if df != nil {
   device.direct = df
   defer df.close()
   log.Printf("Userspace route exclusion enabled for %d prefixes", len(df.prefixes))
  }
 }

 privKey, err := tcfg.GetEcPrivateKey()
 if err != nil {
  return fmt.Errorf("private key: %w", err)
 }
 peerPubKey, err := tcfg.GetEcEndpointPublicKey()
 if err != nil {
  return fmt.Errorf("endpoint public key: %w", err)
 }
 cert, err := selfSignedCert(privKey)
 if err != nil {
  return fmt.Errorf("cert generation: %w", err)
 }
 tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, tcfg.sni(), false)
 if err != nil {
  return fmt.Errorf("TLS config: %w", err)
 }
 tlsCfg.ClientSessionCache = quicSessionCache

 // Connected heuristic: upstream MaintainTunnel has no connect callback;
 // report connected shortly after start if the loop is still alive
 // (matches the reference usque-android pattern).
 go func() {
  select {
  case <-time.After(3 * time.Second):
   if running.Load() {
    connected.Store(true)
    notifyState("connected")
    notifyStats()
   }
  case <-ctx.Done():
  }
 }()

 // Stats ticker: one notifyStats() per ~5 min while connected.
 statsTicker := time.NewTicker(5 * time.Minute)
 defer statsTicker.Stop()
 go func() {
  for {
   select {
   case <-ctx.Done():
    return
   case <-statsTicker.C:
    if connected.Load() {
     notifyStats()
    }
   }
  }
 }()

	notifyState("connecting")
	api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
  TLSConfig:         tlsCfg,
  KeepalivePeriod:   30 * time.Second,
  InitialPacketSize: 1242,
  Endpoint:          endpointFromConfig(&tcfg),
  Device:            device,
  MTU:               1280,
  ReconnectDelay:    1 * time.Second,
  AlwaysReconnect:   false,
  UseHTTP2:          tcfg.UseHTTP2,
 })

 running.Store(false)
 connected.Store(false)
 notifyState("stopped")
 close(done)
 return nil
}

// endpointFromConfig resolves the WARP endpoint. HTTP/2 uses TCP, H3 uses UDP.
func endpointFromConfig(cfg *tunnelConfig) net.Addr {
 hostport := net.JoinHostPort(cfg.EndpointV4, "443")
 if cfg.UseHTTP2 {
  addr, err := net.ResolveTCPAddr("tcp", hostport)
  if err != nil {
   log.Printf("resolve endpoint %q: %v", hostport, err)
   return nil
  }
  return addr
 }
 addr, err := net.ResolveUDPAddr("udp", hostport)
 if err != nil {
  log.Printf("resolve endpoint %q: %v", hostport, err)
  return nil
 }
 return addr
}
```

3d. **Rewrite `GetStats`**:

```go
// GetStats returns JSON with tunnel statistics.
func GetStats() string {
 stats := map[string]interface{}{
  "running":    running.Load(),
  "connected":  connected.Load(),
  "tx_bytes":   txBytes.Load(),
  "rx_bytes":   rxBytes.Load(),
  "uptime_sec": 0,
 }
 if running.Load() {
  stats["uptime_sec"] = int(time.Since(startTime).Seconds())
 }
 b, _ := json.Marshal(stats)
 return string(b)
}
```

3e. **Delete `SetConnectivity` and `Reconnect`** entirely (no Kotlin callers remain after Task 4). Keep `StopTunnel` (cancel ctx) and `IsRunning`.

3f. **Fix imports** — remove now-unused: `connectip`, `net/http`, `http3`, `http2`, `quic-go` (doh.go/doq.go keep their own). Keep `uritemplate` (used by register/enroll flow). Let `go build` tell you the exact list; remove only what the compiler flags.

- [ ] **Step 4: Run all Go tests to verify they pass**

```bash
cd usque-bind && go build ./... && go vet ./... && go test ./...
```

Expected: build clean, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add usque-bind/bind.go usque-bind/bind_test.go
git commit -m "feat(bind): run tunnel via upstream MaintainTunnel"
```

---

## Task 4: Regenerate the AAR

**Files:**

- Regenerate: `app/libs/usquebind.aar`

- [ ] **Step 1: Run the bind script**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && ./build-usque.sh
```

Expected: script runs `gomobile bind` for arm64 (+ x86_64 if debug), writes `app/libs/usquebind.aar`.

- [ ] **Step 2: Verify the JNI surface**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && unzip -l app/libs/usquebind.aar | head
```

Expected: `classes.jar` present with `usquebind/Usquebind.class`, `usquebind/TunnelListener.class`; no `usquebind/VpnProtector.class`.

**⚠ Do NOT run any Kotlin build (`compileDebugKotlin`/`assembleDebug`/unit tests) between Task 4 and Task 5.** The Kotlin sources still reference `Usquebind.setConnectivity`/`reconnect`/`VpnProtector`, which no longer exist in the regenerated AAR — this is expected; Task 5 removes those references. First Kotlin compile happens at Task 5 Step 4.

- [ ] **Step 3: Commit**

```bash
git add app/libs/usquebind.aar
git commit -m "build: regenerate usquebind aar without VpnProtector"
```

---

## Task 5: Kotlin — simplify UsqueVpnService + NetworkWatcher + delete PowerStateWatcher

**Files:**

- Modify: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`, `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/NetworkWatcher.kt`
- Delete: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/PowerStateWatcher.kt`

**Interfaces:**

- Consumes: regenerated AAR (`Usquebind.startTunnel(configJson: String, fd: Long, listener: TunnelListener)`).
- Produces: `NetworkWatcher(context, onUnderlyingNetworks: (Array<Network>?) -> Unit)` (two lambdas removed).

- [ ] **Step 1: Edit `UsqueVpnService.kt` — remove dead-man's switch + protector**

1a. Remove import `usquebind.VpnProtector`.
1b. Remove companion consts `DEAD_MANS_INTERVAL_MS`, `DEAD_MANS_POWER_SAVE_MS`.
1c. Remove fields: `deadMansJob`, `reconnectDebounceJob`, `isDeviceIdle`, `powerSave`, `reconnectWakeLock`.
1d. In `networkWatcher` lazy block, delete the `onNetworkChanged = {...}` and `onNetworkSwitched = {...}` lambdas — keep only `onUnderlyingNetworks`. New wiring:

```kotlin
    private val networkWatcher by lazy {
        NetworkWatcher(
            this,
            onUnderlyingNetworks = { networks ->
                if (TunnelStateHolder.isRunning) setUnderlyingNetworks(networks)
            },
        )
    }
```

1e. Delete the `powerStateWatcher` lazy block entirely.
1f. In `onCreate()`, delete `powerStateWatcher.register()`.
1g. In `startVpn`, replace the protector object + call:

```kotlin
        tunnelJob = serviceScope.launch {
            try {
                Usquebind.startTunnel(configJson, fd.toLong(), this@UsqueVpnService)
            } catch (e: Throwable) {
                // ... unchanged ...
            } finally {
                // ... unchanged ...
            }
        }

        networkWatcher.register()
        // startDeadMansSwitch() deleted
```

1h. Delete the whole `startDeadMansSwitch()` function and its `// Dead-man's switch ...` doc comment.
1i. Delete the whole `restartTunnel()` function (and its doc comment).
1j. In `stopVpnInternal`, delete `reconnectDebounceJob?.cancel()` and `deadMansJob?.cancel()`.
1k. In `onDestroy`, delete `reconnectDebounceJob?.cancel()`, `deadMansJob?.cancel()`, `powerStateWatcher.unregister()`.
1l. In `onRevoke`, delete `reconnectDebounceJob?.cancel()`, `deadMansJob?.cancel()`, `powerStateWatcher.unregister()`.
1m. Remove unused imports flagged by the compiler: `kotlinx.coroutines.delay` (only used by restartTunnel), `kotlinx.coroutines.isActive` (check), `PowerManager` (check — still used by `powerManager`/`connectWakeLock`, keep).

- [ ] **Step 2: Edit `NetworkWatcher.kt` — keep only underlying-networks updates**

```kotlin
package com.nhubaotruong.usqueproxy.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log

/**
 * Tracks the system default network via [ConnectivityManager.registerDefaultNetworkCallback]
 * and updates the VPN's underlying networks so Android routes the tunnel's own
 * traffic outside the TUN. Tunnel reconnect is handled entirely by the Go side
 * (upstream MaintainTunnel: CloseError + 1s reconnect), matching the reference app.
 */
class NetworkWatcher(
    private val context: Context,
    private val onUnderlyingNetworks: (Array<Network>?) -> Unit,
) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    private var currentNetwork: Network? = null

    @Volatile
    private var underlyingNetworkSet = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            currentNetwork = network
            underlyingNetworkSet = false
            onUnderlyingNetworks(arrayOf(network))
            underlyingNetworkSet = true
        }

        override fun onLosing(network: Network, maxMsToLive: Int) {
            Log.d(TAG, "Network losing: $network (${maxMsToLive}ms to live)")
        }

        override fun onLost(network: Network) {
            Log.i(TAG, "Default network lost: $network")
            if (currentNetwork == network) {
                currentNetwork = null
                onUnderlyingNetworks(null)
            }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (network == currentNetwork && !underlyingNetworkSet &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) {
                underlyingNetworkSet = true
                onUnderlyingNetworks(arrayOf(network))
            }
        }
    }

    fun register() {
        currentNetwork = cm.activeNetwork
        cm.registerDefaultNetworkCallback(callback)
    }

    fun unregister() = runCatching { cm.unregisterNetworkCallback(callback) }

    companion object {
        private const val TAG = "UsqueVpnService"
    }
}
```

- [ ] **Step 3: Delete `PowerStateWatcher.kt`**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && rm app/src/main/java/com/nhubaotruong/usqueproxy/vpn/PowerStateWatcher.kt
```

- [ ] **Step 4: Compile**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && ./gradlew :app:compileDebugKotlin
```

Expected: BUILD SUCCESSFUL. Fix any unused-import or missing-reference errors flagged by the compiler (e.g., leftover `yield` import if unused).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt app/src/main/java/com/nhubaotruong/usqueproxy/vpn/NetworkWatcher.kt app/src/main/java/com/nhubaotruong/usqueproxy/vpn/PowerStateWatcher.kt
git commit -m "feat(app): drop dead-mans switch, protector, and restart machinery"
```

---

## Task 6: Kotlin — trim TunnelStats fields

**Files:**

- Modify: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/TunnelStatsParser.kt`, `app/src/test/java/com/nhubaotruong/usqueproxy/TunnelStatsParserTest.kt`

**Interfaces:**

- Produces: `TunnelStats(txBytes: Long, rxBytes: Long, connected: Boolean, running: Boolean, uptimeSec: Long)` — `connectCount`, `hasNetwork`, `lastError` REMOVED.

- [ ] **Step 1: Write the failing test**

Replace `TunnelStatsParserTest.kt` with:

```kotlin
package com.nhubaotruong.usqueproxy

import com.nhubaotruong.usqueproxy.vpn.parseTunnelStats
import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelStatsParserTest {
    @Test
    fun parsesFullStatsJson() {
        val s = parseTunnelStats(
            """{"running":true,"connected":true,"tx_bytes":1234,"rx_bytes":5678,"uptime_sec":3600}"""
        )
        assertEquals(1234L, s.txBytes)
        assertEquals(5678L, s.rxBytes)
        assertEquals(true, s.connected)
        assertEquals(true, s.running)
        assertEquals(3600L, s.uptimeSec)
    }

    @Test
    fun defaultsMissingFieldsSafely() {
        val s = parseTunnelStats("""{"running":false}""")
        assertEquals(0L, s.txBytes)
        assertEquals(false, s.connected)
        assertEquals(0L, s.uptimeSec)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && ./gradlew :app:testDebugUnitTest --tests "com.nhubaotruong.usqueproxy.TunnelStatsParserTest"
```

Expected: FAIL — `TunnelStats` still has `connectCount`/`lastError` (assertNull on removed field may pass; the real failure is `assertEquals(2L, s.connectCount)` in the old test — make sure you replaced the file first).

- [ ] **Step 3: Edit `TunnelStatsParser.kt`**

```kotlin
package com.nhubaotruong.usqueproxy.vpn

import org.json.JSONObject

/** Parsed stats from Go `getStats()` JSON. Unknown/missing fields default safely. */
data class TunnelStats(
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val connected: Boolean = false,
    val running: Boolean = false,
    val uptimeSec: Long = 0,
)

/** Parses the Go `getStats()` JSON. Unknown/missing fields default safely. */
fun parseTunnelStats(json: String): TunnelStats {
    val o = JSONObject(json)
    return TunnelStats(
        txBytes = o.optLong("tx_bytes", 0L),
        rxBytes = o.optLong("rx_bytes", 0L),
        connected = o.optBoolean("connected", false),
        running = o.optBoolean("running", false),
        uptimeSec = o.optLong("uptime_sec", 0L),
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && ./gradlew :app:testDebugUnitTest
```

Expected: ALL unit tests PASS (TunnelStatsParserTest, TunnelConfigBuilderTest, ListenerEventMapperTest).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/nhubaotruong/usqueproxy/vpn/TunnelStatsParser.kt app/src/test/java/com/nhubaotruong/usqueproxy/TunnelStatsParserTest.kt
git commit -m "feat(app): trim tunnel stats fields"
```

---

## Task 7: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Go side**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy/usque-bind && go build ./... && go vet ./... && go test ./...
```

Expected: clean build, all tests PASS.

- [ ] **Step 2: Kotlin side**

```bash
cd /var/home/nhubao/StudioProjects/usque-proxy && ./gradlew :app:testDebugUnitTest :app:assembleDebug
```

Expected: BUILD SUCCESSFUL, all unit tests PASS.

- [ ] **Step 3: Manual QA checklist (device, arm64; Android 11/12 emulator for userspace-exclusion path)**

1. Connect via WARP license: UI shows Connecting → Connected within ~5s; stats rows show tx/rx growing.
2. Idle 15+ min with screen off: tunnel stays alive (no silent death); bytes still counted on next use.
3. WiFi↔cellular switch: traffic resumes within ~5s WITHOUT a restart (upstream CloseError + 1s reconnect; `setUnderlyingNetworks` updated).
4. Toggle VPN off/on 10× rapidly: no fdsan crash, no stale "connected" state.
5. Airplane mode on → off: tunnel reconnects automatically after network returns (no SetConnectivity).
6. Split modes: ALL, EXCLUDE (selected app bypassed), INCLUDE (only selected apps tunneled) — each works.
7. DNS modes: Cloudflare (cache), System, Custom DoH, Custom DoQ — DNS resolution works in each.
8. Office365 + local-network bypass toggles: Office/SMB traffic works.
9. Doze entry/exit: tunnel reconnects after exit (no PowerStateWatcher — upstream handles).
10. Android 11/12 emulator: excluded-prefix apps still bypass via userspace forwarder; everything else same.

- [ ] **Step 4: Report**

Report results per checklist item with evidence (screenshots/logcat lines). Do NOT claim completion until every checklist item has a verdict.

---

## Self-Review Notes (run before execution)

- **Spec coverage:** D1 (excludeRouteCompat + exclude_prefixes — untouched in Tasks 5/6), D2 (Tasks 1–3), D3 (Tasks 1, 3, 4, 5), D4 (Tasks 5), stats trim (Tasks 3, 6), trade-offs accepted.
- **Type consistency:** `newDirectForwarder(prefixes, mtu, writePkt)` — 3 args everywhere (Tasks 1, 3); `StartTunnel(configJSON, tunFd, listener)` — 3 args everywhere (Tasks 3, 5); `TunnelStats` 5 fields everywhere (Task 6).
- **Watch out:** `api.MaintainTunnelConfig.OnConnect`/`OnDisconnect`/`HookEnv` exist in upstream but MUST be left empty (no hooks — keep it simple). `endpointFromConfig` returns nil on resolve failure → upstream would panic on nil Endpoint; configs always carry `EndpointV4`, but if concerned, validate `tcfg.EndpointV4 != ""` in StartTunnel and return an error early.
