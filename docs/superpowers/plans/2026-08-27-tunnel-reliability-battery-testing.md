# Tunnel Reliability, Battery & Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the 60s JNI polling watchdog, replace it with an event-driven Go→Kotlin `TunnelListener` seam plus a dead-man's switch, update all dependencies, refactor the 846-line `UsqueVpnService.kt` into testable units, and add unit/UI/instrumentation tests with measured battery verification.

**Architecture:** Go (`usque-bind`) pushes state/stats/error callbacks to Kotlin through a gomobile `TunnelListener` interface; the Kotlin service maps callbacks to a `SharedFlow` of `VpnServiceEvent`s the ViewModel already collects. The 60s watchdog is deleted; a 15–30 min dead-man's switch polls `getStats()` once as insurance. The service is split into focused files (`TunnelConfigBuilder`, `VpnNotification`, `NetworkWatcher`, `PowerStateWatcher`, `TunnelStateHolder`) so the seam logic is pure-JVM testable. No legacy, no compatibility constraints — the JNI surface is refactored freely (user mandate).

**Tech Stack:** Go 1.25.5 + gomobile (AAR), Kotlin 2.3.x + Compose BOM 2026.04.x, JUnit 4, Compose UI Test, AndroidX Test, Gradle 9.x, JDK 21 (Temurin at `~/.local/jdk`).

**Spec:** `docs/superpowers/specs/2026-08-27-tunnel-reliability-battery-testing-design.md`

## Global Constraints

- **No legacy, no compatibility** — JNI surface may change; Kotlin call sites updated in the same pass (user mandate).
- `JAVA_HOME=/var/home/nhubao/.local/jdk` must be exported for every gradle invocation (no system JDK).
- Go toolchain: `GOTOOLCHAIN=go1.24.2` pinned in `usque-bind/go.mod`; actual local Go is 1.25.5 — keep the pin unless the dep update requires raising it.
- AAR rebuild order: any Go change requires `bash build-usque.sh` before Kotlin compiles against it.
- `QUIC KeepAlivePeriod: 30s` stays (deliberate tradeoff — NAT survival).
- Stats JSON schema (`running`, `connected`, `tx_bytes`, `rx_bytes`, `uptime_sec`, `has_network`, `connect_count`, `last_error`, `connected_since_ms`) stays stable; Kotlin parsing updated in the same pass if it changes.
- Unit tests: `./gradlew :app:testDebugUnitTest`; Go tests: `cd usque-bind && go test ./...`.
- Emulator tests via the android-cli skill; battery via `dumpsys batterystats`/alarm/wakeup proxies.
- Conventional commits, ≤72 chars, file-scoped `git add` (never `git add .`).

## File Structure

**Go (`usque-bind/`):**

- `bind.go` — modify: `TunnelListener` interface, `StartTunnel` signature, listener holder, callback helpers, stats ticker, DNS-detection extraction
- `bind_test.go` — create: stats shape, config validation, DNS detection tests

**Kotlin (`app/src/main/java/com/nhubaotruong/usqueproxy/`):**

- `vpn/UsqueVpnService.kt` — modify: implement listener, delete watchdog, dead-man's switch, delegate to helpers
- `vpn/VpnServiceEvent.kt` — create: sealed interface moved out of the companion (pure JVM)
- `vpn/TunnelStateHolder.kt` — create: `isRunning`, `lastError`, `events` statics
- `vpn/TunnelConfigBuilder.kt` — create: pure config-JSON builder
- `vpn/TunnelStatsParser.kt` — create: `TunnelStats` data class + `parseTunnelStats`
- `vpn/VpnNotification.kt` — create: notification helper
- `vpn/NetworkWatcher.kt` — create: connectivity callbacks
- `vpn/PowerStateWatcher.kt` — create: Doze/power-save receiver
- `ui/viewmodel/VpnViewModel.kt` — modify: import new locations, collect Stats events
- `tile/VpnTileService.kt`, `MainActivity.kt` — modify: state-holder references

**Tests:**

- `app/src/test/java/com/nhubaotruong/usqueproxy/` — `TunnelStatsParserTest.kt`, `TunnelConfigBuilderTest.kt`, `ListenerEventMapperTest.kt`
- `app/src/androidTest/java/com/nhubaotruong/usqueproxy/` — `NavigationTest.kt`, `ConnectFlowTest.kt`, `ErrorBannerTest.kt`, `SettingsPersistenceTest.kt`, `SplitTunnelTest.kt`, `ServiceLifecycleTest.kt`, `DozeTest.kt`
- `usque-bind/bind_test.go`

**Build/docs:**

- `app/proguard-rules.pro`, `app/src/main/baseline-prof.txt`, `app/build.gradle.kts`, `build-usque.sh`, `.github/workflows/release.yml`, `gradle/libs.versions.toml`, `usque-bind/go.mod`, `CLAUDE.md`, `docs/manual-qa-plan.md`

---

### Task 1: Baseline build & smoke (Phase 0)

**Files:**

- Run: `bash build-usque.sh`, `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`

**Interfaces:**

- Consumes: nothing
- Produces: recorded baseline (logcat/batterystats) for Task 10 comparison

- [ ] **Step 1: Build the AAR**
  Run: `cd /var/home/nhubao/StudioProjects/usque-proxy && bash build-usque.sh`
  Expected: `app/libs/usquebind.aar` regenerated.

- [ ] **Step 2: Build the app**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:assembleDebug`
  Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Run existing unit tests (ground truth)**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:testDebugUnitTest`
  Expected: BUILD SUCCESSFUL (only `ExampleUnitTest` exists).

- [ ] **Step 4: Record baseline battery numbers (emulator)**
  Run (emulator via android-cli skill): install debug APK, connect tunnel, wait 10 min, then:
  `adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy`
  `adb shell dumpsys alarm | grep -A5 usqueproxy`
  `adb logcat -d | grep -c "getStats"`
  Record the three numbers in `docs/battery-baseline.md`.

- [ ] **Step 5: Commit**
  `git add docs/battery-baseline.md` (plus `app/libs/usquebind.aar` only if changed)
  `git commit -m "docs: record battery baseline"`

---

### Task 2: Go dependency update (Phase 1)

**Files:**

- Modify: `usque-bind/go.mod`, `usque-bind/go.sum`, `.github/workflows/release.yml`

**Interfaces:**

- Consumes: nothing
- Produces: updated go.mod; AAR rebuilt with new deps; JNI surface unchanged by this task (signature change comes in Task 5)

- [ ] **Step 1: Update direct deps**
  Run: `cd usque-bind && go get github.com/Diniboy1123/usque@master github.com/Diniboy1123/connect-ip-go@master github.com/quic-go/quic-go@latest golang.org/x/mobile@latest golang.org/x/net@latest gvisor.dev/gvisor@latest golang.zx2c4.com/wireguard@latest && go mod tidy`

- [ ] **Step 1b: Reinstall gomobile to match the updated module**
  Run: `cd usque-bind && go install golang.org/x/mobile/cmd/gomobile@latest`
  Expected: `gomobile` binary on PATH matches the new `golang.org/x/mobile` version (otherwise `build-usque.sh` may produce a broken AAR).

- [ ] **Step 2: Build — quic-go migration gate**
  Run: `cd usque-bind && go build ./...`
  Expected: PASS. If quic-go broke the API, pin back: `go get github.com/quic-go/quic-go@v0.59.0`, document why in the commit message, and continue.

- [ ] **Step 3: Run Go tests**
  Run: `cd usque-bind && go test ./...`
  Expected: PASS (no tests yet — package compiles).

- [ ] **Step 4: Update CI gomobile pin**
  Edit `.github/workflows/release.yml`: replace the hardcoded gomobile version `v0.0.0-20260410095206-2cfb76559b7b` with the `golang.org/x/mobile` version now in `go.mod` (read it via `go list -m golang.org/x/mobile`).

- [ ] **Step 5: Rebuild AAR + app smoke**
  Run: `bash build-usque.sh && export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:assembleDebug`
  Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Commit**
  `git add usque-bind/go.mod usque-bind/go.sum .github/workflows/release.yml app/libs/usquebind.aar`
  `git commit -m "deps: update Go tunnel dependencies and gomobile pin"`

---

### Task 3: Android dependency update (Phase 1)

**Files:**

- Modify: `gradle/libs.versions.toml`

**Interfaces:**

- Consumes: nothing
- Produces: updated version catalog; app compiles

- [ ] **Step 1: Check available versions**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:dependencies --configuration debugRuntimeClasspath | grep -E "compose-bom|navigation|lifecycle|core-ktx|activity-compose|datastore"` and compare against the catalog. Also check the AndroidX releases page via web search for: Compose BOM, Navigation, Lifecycle, core-ktx, activity-compose, datastore.

- [ ] **Step 2: Update the catalog**
  Edit `gradle/libs.versions.toml` to the newest stable versions found. Keep `accompanist-drawablepainter` pinned at its current version (no replacement exists — documented in spec).

- [ ] **Step 3: Build**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:assembleDebug`
  Expected: BUILD SUCCESSFUL. If a dep requires a higher `compileSdk`/AGP, raise `compileSdk` in `app/build.gradle.kts` (target stays 36).

- [ ] **Step 4: Commit**
  `git add gradle/libs.versions.toml app/build.gradle.kts`
  `git commit -m "deps: update AndroidX and Compose dependencies"`

---

### Task 4: Compiler tuning & build hardening (Phase 1)

**Files:**

- Modify: `app/proguard-rules.pro`, `app/build.gradle.kts`, `build-usque.sh`, `app/src/main/java/com/nhubaotruong/usqueproxy/MainActivity.kt`
- Create: `app/src/main/baseline-prof.txt`

**Interfaces:**

- Consumes: nothing
- Produces: release-safe R8 config, baseline profile, PGO flag, StrictMode in debug

- [ ] **Step 1: R8 keep rules for gomobile JNI**
  Append to `app/proguard-rules.pro`:

  ```proguard
  # gomobile-generated JNI classes — R8 must not strip or rename them
  -keep class usquebind.** { *; }
  -keep class go.** { *; }
  ```

- [ ] **Step 2: Baseline profile**
  Create `app/src/main/baseline-prof.txt` with the cold-start path:

  ```text
  HSPLandroidx.compose.ui.platform.ComposeView;-><init>(...) : baseline
  HSPLcom/nhubaotruong/usqueproxy/MainActivity;->onCreate(...) : baseline
  HSPLcom/nhubaotruong/usqueproxy/ui/nav/AppNavigationKt;->AppNavigation(...) : baseline
  HSPLcom/nhubaotruong/usqueproxy/ui/screen/HomeScreenKt;->HomeScreen(...) : baseline
  HSPLcom/nhubaotruong/usqueproxy/ui/viewmodel/VpnViewModel;-><init>(...) : baseline
  ```

  (Adjust class names to the actual navigation/screen composables after reading `ui/nav/` and `ui/screen/`.)

- [ ] **Step 3: Enable baseline profile + compose compiler reports in build.gradle.kts**
  In `app/build.gradle.kts`, add the Compose compiler plugin block (verify the project uses `org.jetbrains.kotlin.plugin.compose` first and match its style):

  ```kotlin
  composeCompiler {
      reportsDestination = layout.buildDirectory.dir("compose-reports")
      metricsDestination = layout.buildDirectory.dir("compose-metrics")
  }
  ```

  and enable baseline profile generation per the AGP baseline-profile plugin if the project's Gradle version supports it; otherwise ship the static `baseline-prof.txt` from Step 2 (it is consumed automatically when present).

- [ ] **Step 4: PGO flag in build-usque.sh**
  Edit `build-usque.sh`: pass `-pgo=default.pgo` to `gomobile bind` only when `usque-bind/default.pgo` exists:

  ```bash
  PGO_FLAG=""
  if [ -f usque-bind/default.pgo ]; then PGO_FLAG="-pgo=default.pgo"; fi
  gomobile bind $PGO_FLAG -target=android/arm64 -o app/libs/usquebind.aar usque-bind
  ```

  (Match the script's existing invocation style — read it first.)

- [ ] **Step 5: StrictMode in debug**
  In `MainActivity.onCreate`, before `setContent`:

  ```kotlin
  if (BuildConfig.DEBUG) {
      StrictMode.setThreadPolicy(
          StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build()
      )
      StrictMode.setVmPolicy(
          StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build()
      )
  }
  ```

  Add imports `android.os.StrictMode` and `com.nhubaotruong.usqueproxy.BuildConfig`.

- [ ] **Step 6: Verify release build with minification**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:assembleRelease`
  Expected: BUILD SUCCESSFUL. Then verify `usquebind` classes survived:
  `unzip -l app/build/outputs/apk/release/app-release.apk | grep -c "usquebind"` (expect > 0).

- [ ] **Step 7: Commit**
  `git add app/proguard-rules.pro app/src/main/baseline-prof.txt app/build.gradle.kts build-usque.sh app/src/main/java/com/nhubaotruong/usqueproxy/MainActivity.kt`
  `git commit -m "build: add R8 keep rules, baseline profile, PGO flag, StrictMode"`

---

### Task 5: Go TunnelListener seam (Phase 2 — Go side)

**Files:**

- Modify: `usque-bind/bind.go`
- Create: `usque-bind/bind_test.go`

**Interfaces:**

- Consumes: nothing
- Produces (exact signatures later tasks rely on):

  ```go
  type TunnelListener interface {
      OnStateChanged(state string)
      OnStats(stats string)
      OnError(err string)
  }
  func StartTunnel(configJSON string, tunFd int, protector VpnProtector, listener TunnelListener) error
  ```

  gomobile generates Kotlin `usquebind.TunnelListener` with `onStateChanged(state: String)`, `onStats(stats: String)`, `onError(err: String)`, and `Usquebind.startTunnel(config: String, tunFd: Int, protector: VpnProtector?, listener: TunnelListener?)`.

- [ ] **Step 1: Write the failing Go tests**
  Create `usque-bind/bind_test.go`:

  ```go
  package usquebind

  import (
      "encoding/json"
      "strings"
      "testing"
  )

  // TestGetStatsShape verifies the stats JSON schema Kotlin parses.
  func TestGetStatsShape(t *testing.T) {
      s := GetStats()
      var m map[string]interface{}
      if err := json.Unmarshal([]byte(s), &m); err != nil {
          t.Fatalf("stats not valid JSON: %v", err)
      }
      for _, k := range []string{"running", "connected", "tx_bytes", "rx_bytes", "uptime_sec", "has_network", "connect_count"} {
          if _, ok := m[k]; !ok {
              t.Errorf("stats missing key %q", k)
          }
      }
      if _, ok := m["running"].(bool); !ok {
          t.Errorf("running must be bool, got %T", m["running"])
      }
      if _, ok := m["tx_bytes"].(float64); !ok {
          t.Errorf("tx_bytes must be number, got %T", m["tx_bytes"])
      }
  }

  // TestStartTunnelInvalidConfig verifies config validation happens before any network I/O.
  func TestStartTunnelInvalidConfig(t *testing.T) {
      err := StartTunnel("{not json", 0, nil, nil)
      if err == nil || !strings.Contains(err.Error(), "invalid config JSON") {
          t.Fatalf("expected invalid config JSON error, got %v", err)
      }
  }

  // TestIsDNSQuery verifies DNS query detection (extracted pure function).
  func TestIsDNSQuery(t *testing.T) {
      // DNS query: header with QR=0, opcode=0, one question
      q := []byte{
          0x12, 0x34, // ID
          0x01, 0x00, // flags: RD set, QR=0
          0x00, 0x01, // QDCOUNT=1
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
          0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // name
          0x00, 0x01, 0x00, 0x01, // A, IN
      }
      if !isDNSQuery(q) {
          t.Error("expected DNS query to be detected")
      }
      // Non-DNS: short garbage
      if isDNSQuery([]byte{0x00, 0x01, 0x02, 0x03}) {
          t.Error("expected short/garbage packet to not be a DNS query")
      }
  }
  ```

- [ ] **Step 2: Run tests to verify they fail**
  Run: `cd usque-bind && go test ./...`
  Expected: FAIL — `isDNSQuery` undefined; `StartTunnel` has 3 args (compile error). This is the TDD red state.

- [ ] **Step 3: Add the TunnelListener interface and listener holder**
  In `bind.go`, after the `VpnProtector` interface (line ~92), add:

  ```go
  // TunnelListener receives tunnel state, stats, and error callbacks from Go.
  // Implemented in Kotlin via gomobile; callbacks arrive on arbitrary goroutines.
  type TunnelListener interface {
      OnStateChanged(state string)
      OnStats(stats string)
      OnError(err string)
  }

  // listenerBox keeps a single concrete type in atomic.Value (Store panics on type change).
  type listenerBox struct {
      l TunnelListener // may be nil
  }

  var listenerHolder atomic.Value

  func setListener(l TunnelListener) {
      listenerHolder.Store(&listenerBox{l: l})
  }

  func getListener() TunnelListener {
      v := listenerHolder.Load()
      if v == nil {
          return nil
      }
      return v.(*listenerBox).l
  }

  // safeNotify guards against a panicking Kotlin listener (gomobile callback
  // threading risk) — a Java exception must not kill the tunnel goroutine.
  func safeNotify(fn func()) {
      defer func() { recover() }()
      fn()
  }

  func notifyState(state string) {
      safeNotify(func() {
          if l := getListener(); l != nil {
              l.OnStateChanged(state)
          }
      })
  }

  func notifyStats() {
      safeNotify(func() {
          if l := getListener(); l != nil {
              l.OnStats(GetStats())
          }
      })
  }

  func notifyError(err string) {
      safeNotify(func() {
          if l := getListener(); l != nil {
              l.OnError(err)
          }
      })
  }
  ```

- [ ] **Step 4: Change StartTunnel signature and wire the listener**
  Edit `StartTunnel` (line 137): add `listener TunnelListener` as the 4th parameter; call `setListener(listener)` after the state reset block (after line 178) and `setListener(nil)` in a defer after `maintainTunnel` returns:

  ```go
  func StartTunnel(configJSON string, tunFd int, protector VpnProtector, listener TunnelListener) error {
      // ... existing guard + unmarshal + state reset ...
      setListener(listener)
      defer setListener(nil)
      // ... existing tunFile/device setup ...
      err := maintainTunnel(ctx, &tcfg, device, protector)
      // ... existing teardown ...
  }
  ```

  In the teardown (after `maintainTunnel` returns, before `close(done)`), add `notifyState("stopped")` so Kotlin always learns the tunnel ended (the ViewModel's `Stopped` handler depends on it).

- [ ] **Step 5: Add callback points in maintainTunnel**
  In `maintainTunnel` (line 378), at the exact existing anchors:
  - Before the dial attempt (where `connectCount.Add(1)` is, line 508): `notifyState("connecting")`
  - Where `connected.Store(true)` succeeds (line 563): `notifyState("connected")` and `notifyStats()`
  - Where `connected.Store(false)` fires on drop (lines 577, 583, 594): `notifyState("disconnected")`
  - Where `lastError.Store(err.Error())` fires (lines 489, 500, 545, 556): `notifyError(err.Error())`
  - Add a stats ticker while connected (after line 565):

  ```go
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
  ```

  Note: if the loop structure makes a goroutine awkward, use a `select` in the existing loop's idle path instead — the requirement is one `notifyStats()` per ~5 min while connected.

- [ ] **Step 6: Extract isDNSQuery pure function**
  In `forwardUp` (line 852), the DNS query detection is currently inline — extract it to a package-level pure function and call it from `forwardUp`:

  ```go
  // isDNSQuery reports whether pkt looks like a DNS query (QR=0, opcode=0, QDCOUNT>=1).
  func isDNSQuery(pkt []byte) bool {
      if len(pkt) < 12 {
          return false
      }
      flags := uint16(pkt[2])<<8 | uint16(pkt[3])
      qr := flags >> 15
      opcode := (flags >> 11) & 0xF
      qdcount := uint16(pkt[4])<<8 | uint16(pkt[5])
      return qr == 0 && opcode == 0 && qdcount >= 1
  }
  ```

  Read the existing detection code in `forwardUp` first and preserve its exact semantics (it may check more, e.g. port 53 or the pool usage) — the extracted function must match the current behavior.

- [ ] **Step 7: Run tests to verify they pass**
  Run: `cd usque-bind && go build ./... && go test ./...`
  Expected: PASS (all three tests).

- [ ] **Step 8: Rebuild AAR**
  Run: `bash build-usque.sh`
  Expected: AAR regenerated with `TunnelListener` and 4-arg `startTunnel`.

- [ ] **Step 9: Commit**
  `git add usque-bind/bind.go usque-bind/bind_test.go app/libs/usquebind.aar`
  `git commit -m "feat(bind): add TunnelListener callbacks and stats ticker"`

---

### Task 6: Kotlin service refactor (Phase 2 — Kotlin side)

**Files:**

- Create: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/VpnServiceEvent.kt`, `TunnelStateHolder.kt`, `TunnelConfigBuilder.kt`, `TunnelStatsParser.kt`, `VpnNotification.kt`, `NetworkWatcher.kt`, `PowerStateWatcher.kt`
- Modify: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`, `ui/viewmodel/VpnViewModel.kt`, `tile/VpnTileService.kt`, `MainActivity.kt`

**Interfaces:**

- Consumes: Task 5's `usquebind.TunnelListener` / 4-arg `startTunnel` (from the rebuilt AAR)
- Produces:
  - `VpnServiceEvent` sealed interface (top-level): `Connecting`, `Started`, `Disconnecting`, `Stopped`, `Error(message: String)`, `Stats(stats: TunnelStats)`
  - `TunnelStateHolder`: `var isRunning: Boolean`, `var lastError: String?`, `val events: SharedFlow<VpnServiceEvent>`, `fun clearError()`, `fun emit(event: VpnServiceEvent)`
  - `TunnelConfigBuilder.build(prefs: VpnPrefs): String`
  - `TunnelStatsParser.parseTunnelStats(json: String): TunnelStats`
  - `VpnNotification(context)`: `showConnecting()`, `showConnected()`, `showError(msg: String)`, `cancel()`
  - `NetworkWatcher(context, onNetworkChanged: (Boolean) -> Unit)`: `register()`, `unregister()`
  - `PowerStateWatcher(context, onPowerSaveChanged: (Boolean) -> Unit)`: `register()`, `unregister()`

- [ ] **Step 1: Move VpnServiceEvent to its own file**
  Create `vpn/VpnServiceEvent.kt`:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  /** Typed events from the VPN service to the UI, emitted via [TunnelStateHolder.events]. */
  sealed interface VpnServiceEvent {
      data object Connecting : VpnServiceEvent
      data object Started : VpnServiceEvent
      data object Disconnecting : VpnServiceEvent
      data object Stopped : VpnServiceEvent
      data class Error(val message: String) : VpnServiceEvent
      data class Stats(val stats: TunnelStats) : VpnServiceEvent
  }
  ```

  Delete the inner `VpnServiceEvent` sealed interface from `UsqueVpnService.kt`'s companion.

- [ ] **Step 2: Create TunnelStatsParser**
  Create `vpn/TunnelStatsParser.kt`:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import org.json.JSONObject

  data class TunnelStats(
      val txBytes: Long = 0,
      val rxBytes: Long = 0,
      val connected: Boolean = false,
      val running: Boolean = false,
      val uptimeSec: Long = 0,
      val hasNetwork: Boolean = true,
      val connectCount: Long = 0,
      val lastError: String? = null,
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
          hasNetwork = o.optBoolean("has_network", true),
          connectCount = o.optLong("connect_count", 0L),
          lastError = o.optString("last_error", "").ifEmpty { null },
      )
  }
  ```

- [ ] **Step 3: Create TunnelStateHolder**
  Create `vpn/TunnelStateHolder.kt`:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import kotlinx.coroutines.flow.MutableSharedFlow
  import kotlinx.coroutines.flow.SharedFlow
  import kotlinx.coroutines.flow.asSharedFlow

  /** Process-wide tunnel state, replacing the service companion statics. */
  object TunnelStateHolder {
      @Volatile var isRunning: Boolean = false
      @Volatile var lastError: String? = null

      private val _events = MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)
      val events: SharedFlow<VpnServiceEvent> = _events.asSharedFlow()

      fun emit(event: VpnServiceEvent) {
          _events.tryEmit(event)
      }

      fun clearError() {
          lastError = null
      }
  }
  ```

- [ ] **Step 4: Create TunnelConfigBuilder**
  Create `vpn/TunnelConfigBuilder.kt`. Read the current config assembly in `UsqueVpnService.startVpn` (lines ~255–438) first and extract it verbatim into a pure function:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import com.nhubaotruong.usqueproxy.data.VpnPrefs
  import org.json.JSONObject

  /**
   * Builds the tunnel config JSON passed to `Usquebind.startTunnel`.
   * Pure function — no Android dependencies, unit-testable.
   */
  object TunnelConfigBuilder {
      fun build(prefs: VpnPrefs): String {
          val active = prefs.activeConfigJson
          require(active.isNotEmpty()) { "no active config" }
          val o = JSONObject(active)
          prefs.customSni.takeIf { it.isNotBlank() }?.let { o.put("sni", it) }
          prefs.connectUri.takeIf { it.isNotBlank() }?.let { o.put("connect_uri", it) }
          prefs.dohUrl.takeIf { it.isNotBlank() }?.let { o.put("doh_url", it) }
          prefs.doqUrl.takeIf { it.isNotBlank() }?.let { o.put("doq_url", it) }
          o.put("system_dns", JSONObject().put("dns", prefs.systemDns)) // match existing shape
          o.put("private_dns_active", prefs.privateDnsActive)
          o.put("use_http2", prefs.useHttp2)
          return o.toString()
      }
  }
  ```

  **Important:** the exact JSON keys and the system_dns shape must match what the current `startVpn` produces — copy the existing code's structure exactly; the snippet above is the target shape, adjust to the real one.

- [ ] **Step 5: Create VpnNotification**
  Create `vpn/VpnNotification.kt` — move the notification create/update/stop code out of the service:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import android.app.Notification
  import android.app.NotificationChannel
  import android.app.NotificationManager
  import android.content.Context
  import androidx.core.app.NotificationCompat

  class VpnNotification(private val context: Context) {
      private val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

      init {
          nm.createNotificationChannel(
              NotificationChannel(CHANNEL_ID, "VPN status", NotificationManager.IMPORTANCE_LOW)
          )
      }

      fun showConnecting() = show("Connecting…", "Establishing secure tunnel")
      fun showConnected() = show("Connected", "Traffic is protected")
      fun showError(message: String) = show("Connection error", message)
      fun cancel() = nm.cancel(NOTIFICATION_ID)

      private fun show(title: String, text: String) {
          val n: Notification = NotificationCompat.Builder(context, CHANNEL_ID)
              .setSmallIcon(android.R.drawable.stat_sys_vpn_ic) // match existing icon
              .setContentTitle(title)
              .setContentText(text)
              .setOngoing(true)
              .build()
          nm.notify(NOTIFICATION_ID, n)
      }

      companion object {
          const val CHANNEL_ID = "vpn_status"
          const val NOTIFICATION_ID = 1
      }
  }
  ```

  Match the existing notification code in the service (icon, channel id, flags) — read it first.

- [ ] **Step 6: Create NetworkWatcher**
  Create `vpn/NetworkWatcher.kt` — move the ConnectivityManager callback registration out of the service:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import android.content.Context
  import android.net.ConnectivityManager
  import android.net.Network
  import android.net.NetworkCapabilities
  import android.net.NetworkRequest

  /** Registers connectivity callbacks and forwards availability to the tunnel. */
  class NetworkWatcher(
      private val context: Context,
      private val onNetworkChanged: (Boolean) -> Unit,
  ) {
      private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
      private val request = NetworkRequest.Builder()
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          .build()
      private val callback = object : ConnectivityManager.NetworkCallback() {
          override fun onAvailable(network: Network) = onNetworkChanged(true)
          override fun onLost(network: Network) = onNetworkChanged(false)
      }

      fun register() = cm.registerNetworkCallback(request, callback)
      fun unregister() = runCatching { cm.unregisterNetworkCallback(callback) }
  }
  ```

  Match the existing callback behavior in the service (it may also call `Usquebind.setConnectivity` directly — the service wires `onNetworkChanged` to that).

- [ ] **Step 7: Create PowerStateWatcher**
  Create `vpn/PowerStateWatcher.kt` — move the Doze/power-save receiver out of the service:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  import android.content.BroadcastReceiver
  import android.content.Context
  import android.content.Intent
  import android.content.IntentFilter
  import android.os.PowerManager

  /** Observes Doze/power-save state so the dead-man's switch can extend its interval. */
  class PowerStateWatcher(
      private val context: Context,
      private val onPowerSaveChanged: (Boolean) -> Unit,
  ) {
      private val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
      private val receiver = object : BroadcastReceiver() {
          override fun onReceive(context: Context?, intent: Intent?) {
              onPowerSaveChanged(pm.isPowerSaveMode)
          }
      }

      fun register() {
          context.registerReceiver(receiver, IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED))
          onPowerSaveChanged(pm.isPowerSaveMode)
      }

      fun unregister() = runCatching { context.unregisterReceiver(receiver) }
  }
  ```

  Match the existing receiver/action in the service (it may use `ACTION_DEVICE_IDLE_MODE_CHANGED` too — include both if the current code does).

- [ ] **Step 8: Rewrite UsqueVpnService**
  Rewrite `vpn/UsqueVpnService.kt` to:
  - Extend `VpnService` and implement `usquebind.TunnelListener`:

  ```kotlin
  override fun onStateChanged(state: String) {
      when (state) {
          "connecting" -> TunnelStateHolder.emit(VpnServiceEvent.Connecting)
          "connected" -> {
              TunnelStateHolder.emit(VpnServiceEvent.Started)
              notification.showConnected()
          }
          "disconnected" -> TunnelStateHolder.emit(VpnServiceEvent.Disconnecting)
          "stopped" -> {
              TunnelStateHolder.emit(VpnServiceEvent.Stopped)
              notification.cancel()
          }
      }
  }

  override fun onStats(stats: String) {
      TunnelStateHolder.emit(VpnServiceEvent.Stats(parseTunnelStats(stats)))
  }

  override fun onError(err: String) {
      TunnelStateHolder.lastError = err
      TunnelStateHolder.emit(VpnServiceEvent.Error(err))
      notification.showError(err)
  }
  ```

  - Delete `startWatchdog()` entirely (the 60s polling loop).
  - Add the dead-man's switch coroutine (started in `onStartCommand` after the tunnel job launches, cancelled in `onDestroy`):

  ```kotlin
  private fun startDeadMansSwitch() {
      deadMansJob = serviceScope.launch {
          while (isActive) {
              val interval = if (powerSave) DEAD_MANS_POWER_SAVE_MS else DEAD_MANS_INTERVAL_MS
              delay(interval)
              if (!TunnelStateHolder.isRunning) continue
              val healthy = withContext(Dispatchers.IO) {
                  val s = parseTunnelStats(Usquebind.getStats())
                  s.running && s.connected
              }
              if (!healthy) {
                  Log.w(TAG, "dead-man's switch: tunnel silent, reconnecting")
                  withContext(Dispatchers.IO) { Usquebind.reconnect() }
              }
          }
      }
  }
  ```

  with constants `DEAD_MANS_INTERVAL_MS = 15 * 60_000L`, `DEAD_MANS_POWER_SAVE_MS = 60 * 60_000L`, and `powerSave` updated by `PowerStateWatcher`.
  - Replace companion statics with `TunnelStateHolder` (keep `ACTION_STOP`/`ACTION_RESTART`/`ACTION_KEEPALIVE_ALARM` constants in the companion).

  - **Set `TunnelStateHolder.isRunning` explicitly**: `= true` in `onStartCommand` before launching the tunnel job; `= false` in `stopVpnInternal`/`onDestroy` after `Usquebind.stopTunnel()`. The dead-man's switch and UI both read it — if never set, the switch never health-checks.
  - Wire `NetworkWatcher` `onNetworkChanged` → `Usquebind.setConnectivity(available)` (on IO dispatcher).
  - Wire `PowerStateWatcher` `onPowerSaveChanged` → update `powerSave` flag.
  - Use `TunnelConfigBuilder.build(prefs)` in `startVpn`; call `Usquebind.startTunnel(config, fd, protector, this)`.
  - Keep the keepalive `ScheduledExecutorService` + `AlarmManager` dual keepalive, wake-lock acquire/release in `finally`, and `vpnInterface?.close()` in `stopVpnInternal`/`onDestroy` (TUN fd lifecycle — verify it exists; add if missing).

- [ ] **Step 9: Update VpnViewModel**
  Edit `ui/viewmodel/VpnViewModel.kt`:
  - Replace `UsqueVpnService.Companion.VpnServiceEvent.X` with `VpnServiceEvent.X` (import `com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent`).
  - Replace `UsqueVpnService.isRunning` → `TunnelStateHolder.isRunning`, `UsqueVpnService.lastError` → `TunnelStateHolder.lastError`, `UsqueVpnService.clearError()` → `TunnelStateHolder.clearError()`, `UsqueVpnService.events` → `TunnelStateHolder.events`.
  - Delete the local `TunnelStats` data class; import from `vpn.TunnelStats`.
  - Add a `Stats` event branch in the collector:

  ```kotlin
  is VpnServiceEvent.Stats -> {
      _stats.value = event.stats
      if (_connectedSince.value == null && event.uptimeSec > 0) {
          _connectedSince.value = System.currentTimeMillis() - event.uptimeSec * 1000L
      }
  }
  ```

  - Keep `refreshStats()` (on-demand JNI) but have it use `parseTunnelStats`.

- [ ] **Step 10: Update VpnTileService and MainActivity**
  Edit `tile/VpnTileService.kt` (4 refs) and `MainActivity.kt` (1 ref): point `UsqueVpnService.isRunning`/`events` at `TunnelStateHolder`. Grep for any remaining `UsqueVpnService.` static references and fix them all.

- [ ] **Step 11: Build**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:assembleDebug`
  Expected: BUILD SUCCESSFUL. Fix compile errors until green.

- [ ] **Step 12: Commit**
  `git add app/src/main/java/com/nhubaotruong/usqueproxy/vpn app/src/main/java/com/nhubaotruong/usqueproxy/ui/viewmodel/VpnViewModel.kt app/src/main/java/com/nhubaotruong/usqueproxy/tile/VpnTileService.kt app/src/main/java/com/nhubaotruong/usqueproxy/MainActivity.kt`
  `git commit -m "refactor(vpn): event-driven TunnelListener seam, dead-man's switch, service split"`

---

### Task 7: Kotlin unit tests for the seam (Phase 4 — unit layer)

**Files:**

- Create: `app/src/test/java/com/nhubaotruong/usqueproxy/TunnelStatsParserTest.kt`, `TunnelConfigBuilderTest.kt`, `ListenerEventMapperTest.kt`

**Interfaces:**

- Consumes: Task 6's `parseTunnelStats`, `TunnelConfigBuilder`, `VpnServiceEvent`
- Produces: passing `:app:testDebugUnitTest`

- [ ] **Step 1: Write TunnelStatsParserTest**

  ```kotlin
  package com.nhubaotruong.usqueproxy

  import com.nhubaotruong.usqueproxy.vpn.parseTunnelStats
  import org.junit.Assert.assertEquals
  import org.junit.Assert.assertNull
  import org.junit.Test

  class TunnelStatsParserTest {
      @Test
      fun parsesFullStatsJson() {
          val s = parseTunnelStats(
              """{"running":true,"connected":true,"tx_bytes":1234,"rx_bytes":5678,"uptime_sec":3600,"has_network":true,"connect_count":2}"""
          )
          assertEquals(1234L, s.txBytes)
          assertEquals(5678L, s.rxBytes)
          assertEquals(true, s.connected)
          assertEquals(3600L, s.uptimeSec)
          assertEquals(2L, s.connectCount)
          assertNull(s.lastError)
      }

      @Test
      fun defaultsMissingFieldsSafely() {
          val s = parseTunnelStats("""{"running":false}""")
          assertEquals(0L, s.txBytes)
          assertEquals(false, s.connected)
          assertNull(s.lastError)
      }

      @Test
      fun parsesLastErrorWhenPresent() {
          val s = parseTunnelStats("""{"running":true,"connected":false,"last_error":"dial failed"}""")
          assertEquals("dial failed", s.lastError)
      }
  }
  ```

- [ ] **Step 2: Write TunnelConfigBuilderTest**

  ```kotlin
  package com.nhubaotruong.usqueproxy

  import com.nhubaotruong.usqueproxy.data.ProfileType
  import com.nhubaotruong.usqueproxy.data.VpnPrefs
  import com.nhubaotruong.usqueproxy.vpn.TunnelConfigBuilder
  import org.json.JSONObject
  import org.junit.Assert.assertEquals
  import org.junit.Assert.assertTrue
  import org.junit.Test

  class TunnelConfigBuilderTest {
      private val baseConfig = """{"private_key":"pk","id":"abc","access_token":"tok","endpoint_v4":"1.2.3.4","ipv4":"10.0.0.2"}"""

      @Test
      fun mergesPrefsOverridesIntoActiveConfig() {
          val prefs = VpnPrefs().copy(
              warpConfigJson = baseConfig,
              activeProfile = ProfileType.WARP,
              customSni = "custom.example.com",
              useHttp2 = true,
          )
          val json = JSONObject(TunnelConfigBuilder.build(prefs))
          assertEquals("custom.example.com", json.getString("sni"))
          assertEquals(true, json.getBoolean("use_http2"))
          assertEquals("pk", json.getString("private_key"))
      }

      @Test
      fun throwsWhenNoActiveConfig() {
          val prefs = VpnPrefs()
          try {
              TunnelConfigBuilder.build(prefs)
              assertTrue("expected IllegalArgumentException", false)
          } catch (e: IllegalArgumentException) {
              // expected
          }
      }
  }
  ```

  (Verified: `VpnPrefs` IS a `data class` in `data/VpnPreferences.kt` line 17 — `.copy()` works. Property names to confirm against the real file: `warpConfigJson`, `activeProfile`, `customSni`, `useHttp2`.)

- [ ] **Step 3: Write ListenerEventMapperTest**
  The service's `onStateChanged`/`onError` mapping is a pure switch — extract it into a small mapper in `vpn/ListenerEventMapper.kt`:

  ```kotlin
  package com.nhubaotruong.usqueproxy.vpn

  object ListenerEventMapper {
      fun mapState(state: String): VpnServiceEvent? = when (state) {
          "connecting" -> VpnServiceEvent.Connecting
          "connected" -> VpnServiceEvent.Started
          "disconnected" -> VpnServiceEvent.Disconnecting
          "stopped" -> VpnServiceEvent.Stopped
          else -> null
      }

      fun mapError(err: String): VpnServiceEvent.Error = VpnServiceEvent.Error(err)
  }
  ```

  and the test:

  ```kotlin
  package com.nhubaotruong.usqueproxy

  import com.nhubaotruong.usqueproxy.vpn.ListenerEventMapper
  import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
  import org.junit.Assert.assertEquals
  import org.junit.Assert.assertNull
  import org.junit.Test

  class ListenerEventMapperTest {
      @Test
      fun mapsGoStatesToEvents() {
          assertEquals(VpnServiceEvent.Connecting, ListenerEventMapper.mapState("connecting"))
          assertEquals(VpnServiceEvent.Started, ListenerEventMapper.mapState("connected"))
          assertEquals(VpnServiceEvent.Disconnecting, ListenerEventMapper.mapState("disconnected"))
          assertNull(ListenerEventMapper.mapState("unknown"))
      }

      @Test
      fun mapsErrors() {
          assertEquals(VpnServiceEvent.Error("boom"), ListenerEventMapper.mapError("boom"))
      }
  }
  ```

  Update the service's `onStateChanged` to delegate to `ListenerEventMapper`.

- [ ] **Step 4: Run the unit tests**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:testDebugUnitTest`
  Expected: BUILD SUCCESSFUL, all new tests pass.

- [ ] **Step 5: Commit**
  `git add app/src/test app/src/main/java/com/nhubaotruong/usqueproxy/vpn/ListenerEventMapper.kt`
  `git commit -m "test: add seam unit tests for stats parsing, config building, event mapping"`

---

### Task 8: Compose UI tests (Phase 4)

**Files:**

- Create: `app/src/androidTest/java/com/nhubaotruong/usqueproxy/NavigationTest.kt`, `ConnectFlowTest.kt`, `ErrorBannerTest.kt`, `SettingsPersistenceTest.kt`, `SplitTunnelTest.kt`

**Interfaces:**

- Consumes: Task 6's `TunnelStateHolder` (test state injection), existing Compose UI
- Produces: passing `:app:connectedDebugAndroidTest` on emulator

- [ ] **Step 1: Start the emulator**
  Use the android-cli skill: create/start an API 35+ arm64 emulator, wait for boot (`adb wait-for-device` + `sys.boot_completed`).

- [ ] **Step 2: Write NavigationTest**

  ```kotlin
  package com.nhubaotruong.usqueproxy

  import androidx.compose.ui.test.junit4.createAndroidComposeRule
  import androidx.compose.ui.test.onNodeWithText
  import androidx.compose.ui.test.performClick
  import com.nhubaotruong.usqueproxy.ui.MainActivity
  import org.junit.Rule
  import org.junit.Test

  class NavigationTest {
      @get:Rule
      val rule = createAndroidComposeRule<MainActivity>()

      @Test
      fun navigatesToSettingsAndBack() {
          rule.onNodeWithText("Settings").performClick()
          rule.onNodeWithText("Split Tunnel").performClick()
          rule.onNodeWithText("Settings").performClick() // back via top bar
          rule.onNodeWithText("Settings").assertExists()
      }
  }
  ```

  (Adjust node texts to the real UI strings — read `ui/screen/` first.)

- [ ] **Step 3: Write ConnectFlowTest**

  ```kotlin
  @Test
  fun connectButtonReflectsStateHolder() {
      TunnelStateHolder.isRunning = false
      rule.onNodeWithText("Connect").assertExists()
      TunnelStateHolder.isRunning = true
      rule.onNodeWithText("Disconnect").assertExists()
  }
  ```

  (Set `TunnelStateHolder` state before/after `rule.activity` recreation as needed; the UI must read `TunnelStateHolder`/`events` via the ViewModel.)

- [ ] **Step 4: Write ErrorBannerTest**
  Emit `TunnelStateHolder.emit(VpnServiceEvent.Error("test failure"))` and assert the RestartBanner appears with the message; tap restart and assert it clears.

- [ ] **Step 5: Write SettingsPersistenceTest and SplitTunnelTest**
  Toggle a setting (e.g. auto-connect), recreate the activity, assert it persisted. For split tunnel: switch mode to INCLUDE, assert the app list shows, toggle an app, assert selection persists.

- [ ] **Step 6: Run the UI tests**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:connectedDebugAndroidTest`
  Expected: PASS. Iterate on flaky selectors (use `onNodeWithText` with the real strings).

- [ ] **Step 7: Commit**
  `git add app/src/androidTest`
  `git commit -m "test: add Compose UI tests for navigation, connect flow, error banner, settings"`

---

### Task 9: Instrumentation tests (Phase 4)

**Files:**

- Create: `app/src/androidTest/java/com/nhubaotruong/usqueproxy/ServiceLifecycleTest.kt`, `DozeTest.kt`

**Interfaces:**

- Consumes: Task 6's service + Task 5's AAR
- Produces: passing instrumentation tests on emulator

- [ ] **Step 1: Write ServiceLifecycleTest**

  ```kotlin
  package com.nhubaotruong.usqueproxy

  import android.content.Context
  import android.content.Intent
  import androidx.test.core.app.ApplicationProvider
  import androidx.test.ext.junit.runners.AndroidJUnit4
  import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
  import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
  import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
  import kotlinx.coroutines.flow.first
  import kotlinx.coroutines.runBlocking
  import org.junit.Assert.assertEquals
  import org.junit.Test
  import org.junit.runner.RunWith

  @RunWith(AndroidJUnit4::class)
  class ServiceLifecycleTest {
      private val context: Context = ApplicationProvider.getApplicationContext()

      @Test
      fun startIntentEmitsConnecting() = runBlocking {
          val intent = Intent(context, UsqueVpnService::class.java)
          context.startForegroundService(intent)
          val event = TunnelStateHolder.events.first { it is VpnServiceEvent.Connecting }
          assertEquals(VpnServiceEvent.Connecting, event)
          context.stopService(Intent(context, UsqueVpnService::class.java))
      }
  }
  ```

  (The service must emit `Connecting` synchronously in `onStartCommand` before the tunnel job blocks — verify the service does this. VPN consent: pre-grant with `adb shell appops set com.nhubaotruong.usqueproxy ACTIVATE_VPN allow`; if the dialog still appears on API 35+, click it via `UiAutomation` (`device.findObject(By.text("Allow"))`) in the test, or skip the test if consent cannot be automated.)

- [ ] **Step 2: Write DozeTest**

  ```kotlin
  @Test
  fun forceIdleWhileConnectedDoesNotCrash() = runBlocking {
      // Requires a connected tunnel; best-effort: skip if not connected.
      if (!TunnelStateHolder.isRunning) return@runBlocking
      Runtime.getRuntime().exec(arrayOf("su", "0", "dumpsys", "deviceidle", "force-idle")).waitFor()
      Thread.sleep(5_000)
      Runtime.getRuntime().exec(arrayOf("su", "0", "dumpsys", "deviceidle", "unforce")).waitFor()
      // Assert process still alive and service still running
      assertEquals(true, TunnelStateHolder.isRunning)
  }
  ```

  (On emulator without root, use `adb shell dumpsys deviceidle force-idle` from the host instead — documented as best-effort per spec.)

- [ ] **Step 3: Run instrumentation tests**
  Run: `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:connectedDebugAndroidTest`
  Expected: PASS (or documented skips for network-dependent cases).

- [ ] **Step 4: Commit**
  `git add app/src/androidTest`
  `git commit -m "test: add service lifecycle and Doze instrumentation tests"`

---

### Task 10: Battery verification (Phase 3)

**Files:**

- Create: `docs/battery-verification.md`

**Interfaces:**

- Consumes: Task 1 baseline, Task 6 seam
- Produces: measured before/after evidence against the spec's targets

- [ ] **Step 1: Measure after-state on emulator**
  With the new build installed and tunnel connected for 10+ min:
  `adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy`
  `adb shell dumpsys alarm | grep -A5 usqueproxy`
  `adb logcat -d | grep -c "getStats"`

- [ ] **Step 2: Compare against baseline and targets**
  Fill `docs/battery-verification.md` with a table: metric | baseline | after | target. Targets from the spec: JNI calls <100/day, alarms <50/day, wakelock <5 min/day, background CPU <60 s/day, drain <2% idle/<5% active. Extrapolate the 10-min sample to 24h.

- [ ] **Step 3: Verify no 60s polling in logcat**
  Run: `adb logcat -d | grep -iE "watchdog|poll|getStats"` — expect no periodic 60s pattern; only dead-man's switch activity at its long interval.

- [ ] **Step 4: Commit**
  `git add docs/battery-verification.md`
  `git commit -m "docs: record battery before/after verification"`

---

### Task 11: Manual QA plan document (Phase 5)

**Files:**

- Create: `docs/manual-qa-plan.md`

**Interfaces:**

- Consumes: spec Section 4 (expanded scenarios)
- Produces: QA checklist document

- [ ] **Step 1: Write the QA plan**
  Create `docs/manual-qa-plan.md` covering every scenario from the spec's "Expanded testing scenarios" (network transitions, lifecycle edge cases, long-run soak, DNS, split tunnel) plus: Battery Historian on a real device, 24–72h soak with silent-death detection, WiFi↔cellular, airplane mode, Private DNS, Quick Settings tile, boot auto-connect, wakelock audit (`adb shell dumpsys power | grep -A5 UsqueProxy`), 100 connect/disconnect cycles. Each item: steps, expected result, pass/fail checkbox.

- [ ] **Step 2: Commit**
  `git add docs/manual-qa-plan.md`
  `git commit -m "docs: add manual QA plan"`

---

### Task 12: Docs refresh (Phase 6)

**Files:**

- Modify: `CLAUDE.md`, `docs/superpowers/specs/2026-08-27-tunnel-reliability-battery-testing-design.md` (mark completed acceptance criteria)

**Interfaces:**

- Consumes: all tasks
- Produces: accurate project docs

- [ ] **Step 1: Refresh CLAUDE.md**
  Update: Go version (1.25.5), usque version (new pseudo-version from Task 2), AGP, Kotlin, Compose BOM, Navigation, gomobile version, NDK — read the actual versions from `go.mod` and `libs.versions.toml`. Update the architecture section: `TunnelListener` seam, `TunnelStateHolder`, dead-man's switch, new vpn/ files.

- [ ] **Step 2: Update the spec's acceptance criteria**
  Check off every criterion that passed; leave battery/QA items unchecked if deferred to real-device manual QA.

- [ ] **Step 3: Final verification**
  Run: `cd usque-bind && go build ./... && go test ./...` and `export JAVA_HOME=/var/home/nhubao/.local/jdk && ./gradlew :app:testDebugUnitTest`
  Expected: all green.

- [ ] **Step 4: Commit**
  `git add CLAUDE.md docs/superpowers/specs/2026-08-27-tunnel-reliability-battery-testing-design.md`
  `git commit -m "docs: refresh CLAUDE.md and mark completed acceptance criteria"`
