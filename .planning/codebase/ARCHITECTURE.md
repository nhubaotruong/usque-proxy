# Architecture

**Analysis Date:** 2026-04-01

## Pattern Overview

**Overall:** Multi-language Android VPN application with a polyglot native core

**Key Characteristics:**

- Android app (Kotlin/Compose) acts as the UI and OS integration shell
- Core VPN tunnel logic lives in a Go library (`usque-bind`) compiled to an AAR via `gomobile`
- A standalone Rust CLI (`usque-rs`) provides a desktop/Linux reference implementation of the same MASQUE tunnel, not shipped in the Android app
- The Go AAR (`usquebind.aar`) is the single bridge between the Android layer and Cloudflare WARP's MASQUE (CONNECT-IP over QUIC/HTTP3) protocol
- Android ViewModel holds all UI state as `StateFlow`; the service emits events via `SharedFlow` instead of polling

## Layers

**UI Layer:**

- Purpose: Render app screens, collect user input, subscribe to state flows
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/ui/`
- Contains: Composable screens (`screen/`), reusable components (`component/`), navigation (`nav/`), Material3 theme (`theme/`)
- Depends on: ViewModel
- Used by: `MainActivity`

**ViewModel Layer:**

- Purpose: Translate user actions into service intents and JNI calls; expose state as `StateFlow`
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/ui/viewmodel/VpnViewModel.kt`
- Contains: `VpnViewModel` (single ViewModel), `VpnState` enum, `TunnelStats` data class
- Depends on: `UsqueVpnService` static state/events, `usquebind.Usquebind` JNI (for stats/register), `VpnPreferences`
- Used by: All composable screens via `AppNavigation`

**Data/Preferences Layer:**

- Purpose: Persist user settings and VPN configuration via DataStore; provide typed read model
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/data/`
- Contains: `VpnPreferences.kt` (DataStore wrapper), `VpnPrefs` data class, `AppRepository.kt`, `Office365Endpoints.kt`, enums (`SplitMode`, `DnsMode`, `ProfileType`, `ThemeMode`)
- Depends on: Jetpack DataStore Preferences
- Used by: `VpnViewModel`, `UsqueVpnService`, `BootReceiver`

**VPN Service Layer:**

- Purpose: Android OS VPN integration — owns the TUN fd, lifecycle, dead-man's switch, network/power callbacks
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`
- Contains: `UsqueVpnService` (extends `VpnService`, implements `TunnelListener`), `VpnServiceEvent` sealed interface, `TunnelStateHolder`, `ListenerEventMapper`, `TunnelConfigBuilder`, `TunnelStatsParser`, `VpnNotification`, `NetworkWatcher`, `PowerStateWatcher`
- Depends on: `usquebind.Usquebind` (Go JNI), `usquebind.VpnProtector`, `VpnPreferences`
- Used by: `VpnViewModel` (starts/stops via `Intent`), system via `BootReceiver`/`VpnTileService`

**Go Tunnel Library (usque-bind):**

- Purpose: Implement the full MASQUE tunnel: QUIC/HTTP3 session, CONNECT-IP proxy, DNS interception, keepalive, reconnect loop, stats
- Location: `usque-bind/` (Go package `usquebind`)
- Key files: `bind.go` (main tunnel + JNI API), `doh.go` (DNS-over-HTTPS + HTTP/3 probe), `doq.go` (DNS-over-QUIC)
- Depends on: `github.com/Diniboy1123/usque` (upstream MASQUE library), `github.com/Diniboy1123/connect-ip-go`, `quic-go`, `golang.org/x/mobile`
- Used by: Compiled to `app/libs/usquebind.aar` via `gomobile bind`; consumed from Kotlin via JNI class `usquebind.Usquebind`

**Rust CLI (usque-rs):**

- Purpose: Standalone MASQUE client for Linux/desktop — equivalent functionality to `usque-bind` but for native TUN devices
- Location: `usque-rs/` (binary crate)
- Key files: `src/main.rs`, `src/tunnel.rs`, `src/register.rs`, `src/tun_device.rs`, `src/config.rs`, `src/tls.rs`, `src/packet.rs`, `src/icmp.rs`
- Depends on: `quiche` (BoringSSL QUIC), `tokio`, `mio`, `ring`, `rcgen`, `tun`, `rtnetlink`
- Used by: Not consumed by Android app; independent binary

**Reference Android (usque-android submodule):**

- Purpose: Upstream `usque` Go library's own Android demo/binding — used as reference, not the production app
- Location: `usque-android/` (git submodule)

## Data Flow

**VPN Connect Flow:**

1. User taps Connect in `MainScreen.kt` → `onRequestVpnPermission()` in `MainActivity`
2. `MainActivity` calls `VpnService.prepare()` to check Android VPN permission
3. On grant, `VpnViewModel.connect()` calls `ContextCompat.startForegroundService(ctx, Intent(UsqueVpnService))`
4. `UsqueVpnService.onStartCommand()` builds a `VpnService.Builder`, opens a TUN fd (`vpnInterface`)
5. Service reads config JSON from `VpnPreferences.activeConfigJson` (DataStore), applies split-tunnel, DNS, and route settings
6. Service launches a coroutine calling `Usquebind.startTunnel(configJson, tunFd, protector, listener)` (blocking JNI)
7. Go `StartTunnel()` in `bind.go` dups the fd, starts `maintainTunnel()` which enters a reconnect loop
8. `maintainTunnel()` resolves endpoints, establishes QUIC session to `consumer-masque.cloudflareclient.com:443`, sends HTTP/3 CONNECT-IP request
9. On success, Go emits packets between the TUN device (`FdAdapter`) and the MASQUE proxy indefinitely
10. Service emits `VpnServiceEvent.Started` via `TunnelStateHolder.events`; `VpnViewModel` sets `_vpnState = CONNECTED`

**Registration Flow:**

1. User enters license key or JWT in `SettingsScreen.kt` → `VpnViewModel.register(license)` or `registerWithJwt(jwt)`
2. ViewModel calls `Usquebind.register(license)` or `Usquebind.registerWithJWT(jwt)` on `Dispatchers.IO`
3. Go `Register()`/`RegisterWithJWT()` in `bind.go` calls `api.Register()` against `https://api.cloudflareclient.com`, generates EC P-256 key pair, enrolls public key
4. Returns serialized config JSON to Kotlin; saved via `VpnPreferences.saveWarpConfig()` / `saveZtConfig()` to DataStore

**Dead-Man's Switch (replaces the old keepalive/watchdog loop):**

1. Go pushes liveness via `TunnelListener` callbacks (`OnStateChanged`/`OnStats`/`OnError`); stats tick ~5 min while connected
2. `UsqueVpnService.startDeadMansSwitch()` runs one coroutine: `delay(15 min)` (60 min in power-save), then a single `Usquebind.getStats()` check
3. If the tunnel reports neither running nor connected, call `Usquebind.reconnect()`; no-op if healthy
4. No `AlarmManager`/`ScheduledExecutorService`/60s polling — the old dual keepalive and `watchdogRunnable` were removed

**State Updates:**

1. `TunnelStateHolder.emit()` pushes `VpnServiceEvent` to `MutableSharedFlow(replay = 1, extraBufferCapacity = 16)`
2. `VpnViewModel.init` collects the SharedFlow; updates `_vpnState`, `_tunnelError`, `_connectedSince`
3. `AppNavigation` runs a `LaunchedEffect` polling `viewModel.refreshState()` every 5s (reads only volatile `isRunning` — no JNI)
4. `MainScreen` runs a separate `LaunchedEffect` calling `viewModel.refreshStats()` only while stats are visible (calls `Usquebind.getStats()` JNI on demand)

## Key Abstractions

**`VpnProtector` interface:**

- Purpose: Allows Go to call Android `VpnService.protect(fd)` so outbound QUIC sockets bypass the TUN device (no routing loop)
- Examples: Implemented inline in `UsqueVpnService.kt` as a lambda passed to `Usquebind.startTunnel()`
- Pattern: Defined in Go as `type VpnProtector interface { ProtectFd(fd int) bool }`, exposed via gomobile

**`FdAdapter` struct (Go):**

- Purpose: Wraps an `os.File` (Android TUN fd) to satisfy `api.TunnelDevice` interface — `ReadPacket()`/`WritePacket()`
- Examples: `usque-bind/bind.go` lines 97–108

**`VpnServiceEvent` sealed interface:**

- Purpose: Typed events from service to ViewModel without polling
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/VpnServiceEvent.kt` — `Connecting`, `Started`, `Disconnecting`, `Stopped`, `Error(message)`, `Stats(stats)`
- Pattern: `TunnelStateHolder._events: MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)`

**`TunnelListener` interface (Go):**

- Purpose: Go→Kotlin liveness push — Go calls back on state changes, periodic stats (~5 min while connected), and fatal errors; replaces Kotlin-side polling
- Examples: `usque-bind/bind.go` `TunnelListener` interface (`OnStateChanged`/`OnStats`/`OnError`); gomobile generates `usquebind.TunnelListener`, implemented by `UsqueVpnService`
- Pattern: `StartTunnel(configJSON, tunFd, protector, listener)` — callbacks arrive on Go goroutines; `tryEmit` on `MutableSharedFlow` is thread-safe

**`TunnelStateHolder` object:**

- Purpose: Process-wide tunnel state, replacing the service companion statics
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/TunnelStateHolder.kt`
- Pattern: `@Volatile isRunning`/`lastError` + `MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)`; consumed by `VpnViewModel`

**`ListenerEventMapper` object:**

- Purpose: Maps Go listener callbacks to typed `VpnServiceEvent`s; dedups repeated errors (each distinct error surfaced once)
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/ListenerEventMapper.kt` — pure logic, no Android deps, unit-tested

**Dead-man's switch:**

- Purpose: Catches silent tunnel death without polling
- Examples: `UsqueVpnService.startDeadMansSwitch()` — coroutine `delay(15 min)` (60 min in power-save), single `getStats()` check, `reconnect()` if silent
- Pattern: Replaces the removed 60s polling watchdog; ≤96 JNI calls/day (≤24/day in power-save) vs 1440/day before

**`VpnPrefs` data class:**

- Purpose: Immutable snapshot of all user preferences, emitted as a `Flow` from DataStore
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/data/VpnPreferences.kt`
- Pattern: Computed properties `activeConfigJson` and `isActiveRegistered` delegate to the active `ProfileType`

**`tunnelConfig` struct (Go):**

- Purpose: Extends `config.Config` with Android-specific overrides (custom SNI, ConnectURI, DoH/DoQ URLs, system DNS list, Private DNS flag)
- Examples: `usque-bind/bind.go` lines 65–73

## Entry Points

**`MainActivity`:**

- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/MainActivity.kt`
- Triggers: App launch, `ACTION_CONNECT_VPN` intent from tile/boot
- Responsibilities: Hosts single `VpnViewModel`, requests VPN permission, sets Compose content tree, triggers auto-connect on startup

**`UsqueVpnService`:**

- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`
- Triggers: `startForegroundService` from ViewModel/BootReceiver/TileService; `ACTION_STOP`/`ACTION_RESTART` intents
- Responsibilities: TUN fd lifecycle, VPN builder configuration, coroutine launch of Go tunnel, dead-man's switch, network/power callbacks, notification management

**`BootReceiver`:**

- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/receiver/BootReceiver.kt`
- Triggers: `ACTION_BOOT_COMPLETED`
- Responsibilities: Reads DataStore prefs; starts `UsqueVpnService` if `autoConnect` enabled and VPN permission is still granted

**`VpnTileService`:**

- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/tile/VpnTileService.kt`
- Triggers: Quick Settings tile interaction
- Responsibilities: Toggle VPN on/off; open app with `ACTION_CONNECT_VPN` if permission is missing

**`usque-rs/src/main.rs` (Rust CLI):**

- Location: `usque-rs/src/main.rs`
- Triggers: CLI invocation (`usque-rs register` / `usque-rs nativetun`)
- Responsibilities: Parse CLI args via `clap`, dispatch to `register::register()` or `tunnel::maintain_tunnel()`

## Error Handling

**Strategy:** Errors from Go are surfaced to Kotlin as exceptions (JNI) or via stats JSON. Transient errors during reconnect are suppressed with a grace period before surfacing to the UI.

**Patterns:**

- Go `StartTunnel()` returns a Go `error`; gomobile converts this to a Java `Exception` thrown from `Usquebind.startTunnel()`
- `UsqueVpnService` catches the exception in `tunnelJob`'s `finally` block; stores in `TunnelStateHolder.lastError`
- `ListenerEventMapper` dedups `OnError` callbacks (each distinct error surfaced once); the dead-man's switch reads `last_error` via a single `getStats()` check per interval
- `VpnViewModel` exposes `tunnelError: StateFlow<String?>` which composables observe; cleared by `clearTunnelError()`
- Rust CLI uses `anyhow::Result` for all fallible operations; errors propagate to `main()` and print to stderr

## Cross-Cutting Concerns

**Logging:**

- Kotlin: `android.util.Log` with `TAG = "UsqueVpnService"`
- Go: standard `log.Printf` / `log.Println`; output captured in Android logcat via gomobile runtime

**Validation:**

- Config JSON is validated at tunnel start time in Go (`json.Unmarshal` into `tunnelConfig`); invalid JSON returns an error before any network activity
- DataStore migrations are handled inline in `VpnPreferences.prefsFlow` map block (legacy key fallback)

**Authentication:**

- Two profile types: `WARP` (license key or anonymous) and `ZERO_TRUST` (JWT from team domain)
- Credentials stored only in Android DataStore as config JSON blob (base64 EC private key inside)
- QUIC TLS uses per-connection client certificates generated by Go (`rcgen` in Rust, `crypto/x509` in Go)

**Battery / Doze:**

- App requests battery optimization exemption at startup (`MainActivity.checkBatteryOptimization()`)
- No `AlarmManager`/`ScheduledExecutorService` keepalive: the dead-man's switch is a coroutine delay (15 min, 60 min in power-save); Go keeps QUIC `KeepAlivePeriod: 30s` to hold NAT mappings
- `PARTIAL_WAKE_LOCK` acquired for connect (2-min cap) and reconnect (10s cap) attempts, released in `finally` block

---

*Architecture analysis: 2026-04-01*
