# Usque Proxy — Dep Update, Event-Driven Seam, Battery & Testing Plan

**Date:** 2026-08-27
**Status:** Approved design (brainstorming session, all sections approved by user)
**Scope:** One execution pass covering: dependency updates, Kotlin↔Go liveness seam redesign, battery reduction, and a comprehensive testing plan (unit/UI/instrumentation/manual).

---

## 1. Context

Usque Proxy is an Android VPN app (Kotlin/Compose + Go via gomobile AAR) tunneling through Cloudflare MASQUE (QUIC + Connect-IP). The project's core value: tunnel connections must stay alive for hours/days without silent death, with immediate detection and reconnect.

Current problems identified during research:

1. **Battery**: the Kotlin watchdog polls `Usquebind.getStats()` via JNI every 60s forever (1440 JNI wakes/day), even when the tunnel is healthy. Doubles interval in power-save but never stops.
2. **Testability**: zero real tests exist (only `ExampleUnitTest`/`ExampleInstrumentedTest` boilerplate). Compose UI test deps are declared but unused. CI has only a release build job.
3. **Stale docs**: CLAUDE.md documents Go 1.24.2 / usque v1.4.2 / AGP 9.1.0 — reality is Go 1.25.5 / usque v1.5.1-pseudo / AGP 9.2.0.
4. **Dep drift**: `connect-ip-go`, `gomobile`, `gvisor`, `wireguard`, `x/net` all have newer versions; `accompanist-drawablepainter` is deprecated.

## 2. Decisions (user-approved)

| # | Decision | Choice |
| --- | ---------- | -------- |
| D1 | Sequencing | Plan document first, then execute everything in one pass |
| D2 | Liveness reporting | **Event-driven `TunnelListener`** (Go pushes state/stats/errors to Kotlin), keep `getStats()` for on-demand, 15–30 min dead-man's switch poll as insurance |
| D3 | Test layers | Compose UI tests + device tests/manual QA plan + **minimal unit layer for the seam** |
| D4 | Devices | Emulator via the android-cli skill; battery verified via measurable proxies (wakelock/alarm/wakeup counts, JNI call frequency); real-device Battery Historian documented as manual step |
| D5 | Dep policy | **Mixed**: stable tags where they exist, master (pseudo-versions) for usque |
| D6 | CI | No CI test job — local testing only |
| D7 | Unit gap | Minimal unit layer for the seam (Kotlin JVM + small Go test set) |

## 3. Section 1 — Dependency Update

### Go (`usque-bind/go.mod`)

- `github.com/Diniboy1123/usque` → newest master commit (pseudo-version; already tracking master)
- `github.com/Diniboy1123/connect-ip-go` → newest commit (no tags; 2026-06-13 available)
- `github.com/quic-go/quic-go` → latest stable tag (currently v0.59.0)
- `golang.org/x/mobile` (gomobile) → newest commit
- `gvisor.dev/gvisor`, `golang.zx2c4.com/wireguard`, `golang.org/x/net` → latest stable/commit as applicable
- Indirect deps follow `go get -u` resolution
- **JNI surface refactored freely** — no compatibility constraint (user mandate): `startTunnel` gains a `TunnelListener` parameter; `getStats`, `reconnect`, `setConnectivity` refactored as needed; Kotlin call sites updated in the same pass
- **quic-go migration risk**: quic-go makes breaking API changes between minor versions. After updating, run `go build` in `usque-bind/` first — if it fails, pin quic-go back to v0.59.0 and document why
- **CI gomobile pin**: `.github/workflows/release.yml` hardcodes gomobile at `v0.0.0-20260410095206-2cfb76559b7b` — update it to match the new `golang.org/x/mobile` version in go.mod

### Android (`gradle/libs.versions.toml`)

- Check for newer: Compose BOM (2026.04.01), Navigation (2.9.8), Lifecycle (2.10.0), core-ktx (1.18.0), activity-compose (1.13.0), datastore (1.2.1)
- **`accompanist-drawablepainter` stays pinned** — `DrawablePainter` was not promoted to standard Compose; accompanist remains the canonical way to render Android `Drawable` in Compose. Noted as future cleanup, does not block the dep pass.

### Rebuild & verify

- `bash build-usque.sh` → new `app/libs/usquebind.aar` → `assembleDebug` → emulator smoke test
- **Refresh CLAUDE.md** (Go 1.25.5, usque version, AGP 9.2.0, Kotlin 2.3.21, BOM 2026.04.01, Nav 2.9.8, gomobile version, NDK 29)

## 4. Section 2 — TunnelListener Seam (core)

### Go side (`usque-bind/bind.go`)

- New exported interface:

  ```go
  type TunnelListener interface {
      OnStateChanged(state string)
      OnStats(stats string)
      OnError(err string)
  }
  ```

  gomobile generates `usquebind.TunnelListener` for Kotlin.
- **`StartTunnel` signature changed directly** to `StartTunnel(config, fd, protector, listener)` — no legacy, no compatibility constraint (user mandate); the single Kotlin call site is updated in the same pass
- Go calls back on: connect/disconnect state changes, fatal errors, and a periodic stats tick (~5 min while connected). `getStats()` remains for on-demand queries.
- Callback threading: same path as existing `VpnProtector.ProtectFd` (Go goroutine → Java) — proven in this codebase. Listener holder must be goroutine-safe.

### Kotlin side (`UsqueVpnService.kt`)

- Implement `TunnelListener` → map callbacks to `_events.tryEmit(...)` (thread-safe) + notification updates.
- **Delete the 60s watchdog loop**; replace with a dead-man's switch: one coroutine sleeping 15–30 min (60 min in power-save), single `getStats()` check, no-op if healthy, trigger reconnect if Go went silent. ~1440 JNI wakes/day → ~48–96/day.
- Network callbacks, Doze handling, wake locks: kept event-driven and bounded; refactored into dedicated helpers where it improves testability

### Refactor scope (user mandate: no legacy, no compatibility)

**Go (`usque-bind/bind.go`):**

- Add `TunnelListener` interface (`OnStateChanged`, `OnStats`, `OnError`)
- Change `StartTunnel` signature to accept `listener TunnelListener` directly
- Add callback points in the tunnel loop: on connect, on disconnect, on fatal error, periodic stats tick (~5 min)
- Keep `getStats()` for on-demand UI refresh; keep `reconnect()`, `setConnectivity()` (refactor freely if needed)
- Keep `waitForNetwork` (already event-driven), `KeepAlivePeriod: 30s` (deliberate tradeoff)

**Kotlin (`UsqueVpnService.kt` — 846 lines, split it):**

- Delete `startWatchdog()` entirely (the 60s polling loop)
- Implement `TunnelListener` → map callbacks to `_events.tryEmit()` + notification updates
- Add a dead-man's switch: one coroutine, 15–30 min sleep (60 min power-save), single `getStats()` check
- Extract `startVpn` config assembly into a `TunnelConfigBuilder` — pure function, testable
- Extract notification management into a `VpnNotification` helper
- Extract network callback registration into a `NetworkWatcher`
- Extract Doze/power-save receiver into a `PowerStateWatcher`
- Move companion object statics (`isRunning`, `lastError`, `events`) into a state holder — improves testability

### Risks

- **gomobile callback threading**: Go callbacks into Java arrive on arbitrary goroutine threads. `tryEmit` on `MutableSharedFlow` is thread-safe — verify in practice.
- **Stats push frequency**: never per-packet/per-second; state change + ~5 min periodic summary only.
- **Stats JSON schema stability**: the `getStats()` JSON shape (`connected`, `running`, `rx_bytes`, `tx_bytes`, `has_network`, `last_error`) must remain stable after the usque update — Kotlin parsing (dead-man's switch, ViewModel stats display) breaks silently if fields change. Verify schema unchanged or update Kotlin parsing in the same pass.

## 5. Section 3 — Battery

- Polling eliminated (Section 2) — dominant win.
- **QUIC `KeepAlivePeriod: 30s` stays** — deliberate tradeoff: keeps NAT mappings alive, prevents silent death. ~2,880 tiny packets/day; changing risks the exact bug the project exists to fix. Documented, not changed.
- Notification updates move to state-change-only (via listener).
- Wake locks stay bounded (2-min connect, reconnect, released in `finally`) — already best practice.
- Doze/power-save: keep idle-mode receiver; dead-man's switch extends in power-save; verify with `dumpsys deviceidle force-idle`.
- **Verification (emulator proxies)**: `dumpsys batterystats` (wakelock time, wakeup count), `dumpsys alarm` (alarm count), logcat JNI-call frequency, before/after comparison. Real-device Battery Historian + mA numbers documented as manual steps.

### Concrete battery targets (24h, `dumpsys batterystats`, API 35–36)

| Metric | Current | Target (well-behaved VPN) | Reference |
| --- | --- | --- | --- |
| JNI `getStats()` calls/day | ~1,440 (60s poll) | **<100** (dead-man's switch only) | WireGuard: 0 (event-driven) |
| Wakeup alarms/day | keepalive-dependent | **<50** | ~30–60 (keepalive only) |
| Partial wakelock time/day | ~2–4 min (connect/reconnect) | **<5 min total** | <2 min if no reconnects |
| Background CPU time/day | high (60s JNI + JSON parse) | **<60 s** (listener callbacks) | <30 s if stable |
| Battery drain %/day | high (constant polling) | **<2% idle, <5% active** | 1–3% idle |
| QUIC keepalive packets/day | ~2,880 (30s interval) | unchanged (deliberate tradeoff) | same — NAT survival |

## 6. Section 4 — Testing

### Minimal unit layer (the seam) — no mocking framework

- **Kotlin JVM**: `TunnelListener`→`VpnServiceEvent` mapping test; stats-JSON→`TunnelStats` parsing test; config-JSON building test (pure functions extracted where needed).
- **Go**: `go test` for stats JSON shape, config validation, DNS query detection (pure functions in bind.go).

### Compose UI tests (emulator; deps already declared)

- Navigation: Main → Settings → SplitTunnel, back stack, state restoration
- Connect/disconnect flow with injected/fake service state
  - State injection: UI tests manipulate `UsqueVpnService.isRunning` / `lastError` / `events` companion statics directly (simplest path for the minimal layer); if brittle, hoist state into `VpnViewModel` constructor injection in a future refactor
- Error banner (RestartBanner)
- Settings toggles persist
- Split-tunnel include/exclude
- Tile state

### Instrumentation tests (emulator)

- Service lifecycle: start intent → Connecting → Started events; stop → Stopped; restart intent
- JNI seam with real AAR: anonymous WARP registration + real tunnel connect on emulator
- Doze: `force-idle` while connected → no crash, reconnect on exit
- Process-death restore and network switching: best-effort on emulator; documented as manual steps where the emulator cannot simulate

### Manual QA plan (document)

- Battery profiling (Battery Historian, real device)
- 24–72h soak, silent-death detection
- WiFi↔cellular transitions, airplane mode
- Private DNS interplay
- Split-tunnel correctness
- Quick Settings tile
- Boot auto-connect

### Expanded testing scenarios

**Network transitions:**

- WiFi → cellular: graceful handoff, no 30s+ gap
- Cellular → WiFi: reconnect within 5s
- Airplane mode on → off: tunnel resumes
- Weak signal / high packet loss: QUIC recovers, no crash
- Dual SIM switch (if applicable)

**Lifecycle edge cases:**

- Screen off + backgrounded 1h → reconnect on wake
- Process killed by OOM killer → START_STICKY restore
- Deep Doze (force-idle 30 min) → no crash, reconnect on exit
- App Standby bucket downgrade → tunnel persists
- Configuration change (rotation, theme) during connect
- Quick Settings tile toggle during connecting state (race)

**Long-run soak:**

- 24h connected, idle: no silent death, battery <5%
- 72h connected with periodic traffic: stats accuracy, no fd leak, no memory growth
- 100 connect/disconnect cycles: no fd/wakelock leak, no ANR

**DNS scenarios:**

- Private DNS on → tunnel DNS interception behavior
- Private DNS off → system DNS forwarding
- DoH/DoQ modes → resolution + fallback
- DNS over VPN when split-tunnel excludes the VPN app itself

**Split tunnel:**

- Include mode: only specified apps through VPN
- Exclude mode: specified apps bypass VPN, including self
- App uninstalled while in split-tunnel list → graceful handling
- System apps in include list

## 7. Section 5 — Compiler Tuning & Build Best Practices

1. **R8 keep rules for gomobile JNI**: verify `proguard-rules.pro` keeps `usquebind.**` classes (`-keep class usquebind.** { *; }`) — R8 can strip JNI-bound classes
2. **Baseline Profiles**: add `baseline-prof.txt` for the Kotlin side (Compose screens, ViewModel init) — 15–30% faster cold start
3. **Go PGO**: ensure `build-usque.sh` passes `-pgo=default.pgo` to `gomobile bind` if `usque-bind/default.pgo` exists
4. **Compose compiler reports**: enable `composeCompilerReports` for stability/performance metrics during development
5. **Resource shrinking verification**: confirm `isShrinkResources = true` actually removes unused resources (`usage.txt`)
6. **StrictMode in debug**: thread + VM policies to catch disk/network-on-main-thread violations early
7. **Wakelock audit**: `adb shell dumpsys power | grep -A5 UsqueProxy` in QA checklist — no leaks across connect/disconnect cycles
8. **ANR awareness**: `onStartCommand` must return within ~5s; document risk if `startVpn` blocks
9. **Compose performance**: `derivedStateOf` for derived state; pipe `isRunning`/`lastError` through StateFlow, don't read statics in composables
10. **TUN fd lifecycle**: ensure `vpnInterface?.close()` in `stopVpnInternal` and `onDestroy` — fd leaks cause 'too many open files'

## 8. Section 6 — Execution Order

- **Phase 0 — Baseline**: build AAR + app, emulator smoke test, capture logcat/batterystats baseline
- **Phase 1 — Deps**: Go + Android updates, accompanist decision, AAR rebuild, smoke test, CLAUDE.md refresh; compiler tuning: R8 keep rules for `usquebind.**`, `baseline-prof.txt`, PGO flag in `build-usque.sh`, `composeCompilerReports`, resource-shrink verification
- **Phase 2 — Seam**: `TunnelListener` in Go + Kotlin, remove 60s watchdog, dead-man's switch; StrictMode (debug), TUN fd lifecycle audit
- **Phase 3 — Battery verification**: before/after `dumpsys` measurements on emulator
- **Phase 4 — Tests**: unit (seam) → Compose UI tests → instrumentation tests, run on emulator via android-cli skill
- **Phase 5 — Manual QA plan**: written document
- **Phase 6 — Docs**: spec + CLAUDE.md + new docs committed

## 9. Deliverables

1. Updated deps + rebuilt AAR (JNI surface refactored: `startTunnel` takes `TunnelListener`)
2. `TunnelListener` seam (Go + Kotlin), watchdog removed, dead-man's switch
3. Battery improvements with measured before/after evidence
4. Test suite: unit (seam), Compose UI, instrumentation
5. Manual QA plan document
6. Refreshed CLAUDE.md + spec committed

## 10. Acceptance Criteria

- [x] `go build` + `go test` pass in `usque-bind/`; AAR rebuilds; app assembles
- [x] JNI surface refactored: `startTunnel(config, fd, protector, listener)`; `getStats`/`reconnect`/`setConnectivity` present as needed; Kotlin call sites updated
- [x] No 60s polling in logcat; dead-man's switch fires only at its long interval
- [x] Before/after `dumpsys` shows reduced wakeup/alarm/JNI activity
- [x] Compose UI tests + instrumentation tests pass on emulator
- [x] Manual QA plan document written
- [x] CLAUDE.md reflects actual versions
- [x] `getStats()` JSON schema verified unchanged after dep update (or Kotlin parsing updated in the same pass)
- [ ] Battery targets met on emulator: JNI calls <100/day, wakelock <5 min/day, background CPU <60 s/day, alarms <50/day — deferred to real-device manual QA (JNI 0/day and alarms 0/day measured; wakelock duration and background CPU not measurable on emulator)
- [x] R8 keep rules verified for `usquebind.**`; release build works with minification
- [x] Baseline profile + PGO verified in build
