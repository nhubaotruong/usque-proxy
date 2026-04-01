# Requirements: Usque Proxy — Tunnel Reliability Overhaul

**Defined:** 2026-04-01
**Core Value:** VPN tunnel connections must stay reliably alive for hours/days without silent death

## v1 Requirements

### Tunnel Core

- [x] **TUNL-01**: Forwarding goroutines detect `connectip.CloseError` and trigger immediate reconnection
- [x] **TUNL-02**: Reconnection uses constant 1-second delay instead of exponential backoff with jitter
- [x] **TUNL-03**: Each reconnect cycle cleanly tears down all resources (ipConn, udpConn, HTTP/3 transport) before retry
- [x] **TUNL-04**: Tunnel loop retries infinitely with no maximum attempt limit
- [x] **TUNL-05**: Non-fatal forwarding errors (individual packet write/read failures) are logged but don't trigger reconnection

### Complexity Removal

- [ ] **RMVL-01**: Remove `livenessCheck` goroutine (stall detection, delivery ratio monitoring)
- [ ] **RMVL-02**: Remove 2-hour forced tunnel rotation (`maxConnLifetime`, `lifetimeRotations`)
- [ ] **RMVL-03**: Remove `Keepalive()` exported function and all JNI keepalive calls
- [ ] **RMVL-04**: Remove Android ScheduledExecutor keepalive (2-minute interval)
- [ ] **RMVL-05**: Remove Android AlarmManager keepalive (8-minute interval)
- [ ] **RMVL-06**: Remove keepalive debounce mechanism (`lastKeepaliveTimeMs`)
- [ ] **RMVL-07**: Remove watchdog stall detection (rx byte comparison, total stall counters)
- [ ] **RMVL-08**: Remove `consecutiveKeepaliveFailures` tracking and full VPN restart logic
- [ ] **RMVL-09**: Remove `degradedThreshold`, `degradedCount`, delivery ratio stats tracking

### Compatibility

- [ ] **CMPT-01**: JNI interface (`Usquebind.startTunnel`, `stopTunnel`, `reconnect`, `getStats`) remains functional
- [ ] **CMPT-02**: `getStats()` still returns connection status, rx/tx bytes for UI display
- [ ] **CMPT-03**: Network callbacks (`setConnectivity`, network change → reconnect) continue working
- [ ] **CMPT-04**: Doze mode handling (screen on/off reconnect, idle mode receiver) continues working
- [x] **CMPT-05**: QUIC keepalive period set to 30 seconds (matching usque-android's proven value)

## v2 Requirements

### Observability

- **OBSV-01**: Add forwarding loop error classification logging (fatal vs non-fatal)
- **OBSV-02**: Track reconnection count and last reconnection reason in stats
- **OBSV-03**: Surface connection health to UI based on forwarding loop state rather than byte counters

## Out of Scope

| Feature | Reason |
|---------|--------|
| DNS subsystem changes | DoH/DoQ works fine; only reset-on-reconnect is relevant |
| UI/UX changes | Focus is tunnel reliability, not presentation |
| usque-rs (Rust lib) changes | Rust library is separate, Go layer is the problem |
| New VPN features | Pure reliability refactor |
| Android service lifecycle changes | Doze/battery handling stays as-is minus keepalive |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| TUNL-01 | Phase 1 | Complete |
| TUNL-02 | Phase 1 | Complete |
| TUNL-03 | Phase 1 | Complete |
| TUNL-04 | Phase 1 | Complete |
| TUNL-05 | Phase 1 | Complete |
| RMVL-01 | Phase 2 | Pending |
| RMVL-02 | Phase 2 | Pending |
| RMVL-03 | Phase 2 | Pending |
| RMVL-04 | Phase 2 | Pending |
| RMVL-05 | Phase 2 | Pending |
| RMVL-06 | Phase 2 | Pending |
| RMVL-07 | Phase 2 | Pending |
| RMVL-08 | Phase 2 | Pending |
| RMVL-09 | Phase 2 | Pending |
| CMPT-01 | Phase 3 | Pending |
| CMPT-02 | Phase 3 | Pending |
| CMPT-03 | Phase 3 | Pending |
| CMPT-04 | Phase 3 | Pending |
| CMPT-05 | Phase 1 | Complete |

**Coverage:**
- v1 requirements: 19 total
- Mapped to phases: 19
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-01*
*Last updated: 2026-04-01 after initial definition*
