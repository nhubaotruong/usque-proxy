<!-- GSD:project-start source:PROJECT.md -->
## Project

**Usque Proxy — Tunnel Reliability Overhaul**

An Android VPN app (usque-proxy) that tunnels traffic through Cloudflare's MASQUE protocol using QUIC + Connect-IP. The app currently suffers from silent connection death after 2-4 hours — it reports "connected" but traffic stops flowing. The goal is to replace the current complex tunnel management approach with the simpler, proven pattern from usque-android, which doesn't suffer from this problem.

**Core Value:** VPN tunnel connections must stay reliably alive for hours/days without silent death — if the connection breaks, detect it immediately and reconnect.

### Constraints

- **Tech stack**: Go (gomobile) + Kotlin, Android VPN service — no changes
- **Protocol**: QUIC + MASQUE Connect-IP via quic-go and connect-ip-go libraries
- **Compatibility**: Must maintain existing JNI interface (`Usquebind.startTunnel`, `getStats`, etc.)
- **Android**: Keep Doze handling, battery exemption, network callbacks — these are Android-specific concerns the simpler Go approach doesn't affect
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages

- Kotlin - Android application layer (`app/src/main/java/com/nhubaotruong/usqueproxy/`)
- Go 1.26.3 - Native tunnel/VPN binding layer (`usque-bind/`, `usque-android/`)
- Rust (edition 2021) - Experimental MASQUE client reference implementation (`usque-rs/`)
- Bash - Build automation (`build-usque.sh`)

## Runtime

- Android: compileSdk 37, minSdk 35 (Android 15+), targetSdk 36 (Android 16)
- ABI: arm64-v8a (release, see `app/build.gradle.kts` `ndk.abiFilters`); x86_64 added for debug builds (emulator testing)
- JVM: Java 21 source/target compatibility
- Gradle 9.5.0 (main app, `gradle/wrapper/gradle-wrapper.properties`)
- Go modules (`usque-bind/go.mod`, `usque-android/go.mod`)
- Cargo (`usque-rs/Cargo.toml`)
- Lockfiles: `app/libs/usquebind.aar` (pre-built), `usque-bind/go.sum`, `usque-rs/Cargo.lock`

## Frameworks

- Jetpack Compose BOM `2026.08.00` - UI framework
- Compose Material3 - UI component library
- Compose Navigation `2.10.0` - In-app navigation
- AndroidX Lifecycle `2.11.0` - ViewModel, lifecycle-aware coroutines
- Kotlin Coroutines - Async/concurrent logic throughout VPN service
- AndroidX core-ktx `1.19.0` - Core AndroidX APIs
- AndroidX Activity Compose `1.13.0` - Activity/Compose integration
- Android Gradle Plugin (AGP) `9.2.0`
- Kotlin Compose compiler plugin `2.3.21`
- gomobile `v0.0.0-20260821190718-4776eadac327` - Generates `usquebind.aar` from Go code
- gobind - Companion to gomobile for JVM bindings
- JUnit 4 `4.13.2` - Unit tests
- AndroidX Test (JUnit, Espresso `3.7.0`) - Instrumentation tests
- Compose UI Test JUnit4 - Compose UI testing

## Key Dependencies

- `github.com/Diniboy1123/usque v1.5.1-0.20260720063354-6aa03fc97d12` - Core MASQUE/WARP protocol implementation (Go)
- `github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33` - CONNECT-IP (RFC 9484) implementation (Go)
- `github.com/quic-go/quic-go v0.60.0` - QUIC transport (Go), used for MASQUE tunnel and DoQ DNS
- `gvisor.dev/gvisor v0.0.0-20260826181857-eb77d6c8310a` - Userspace networking stack for the TUN device
- `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446` - WireGuard networking primitives
- `usquebind.aar` (local `app/libs/`) - Pre-built gomobile AAR providing `usquebind.Usquebind`, `usquebind.VpnProtector`, and `usquebind.TunnelListener` to Kotlin
- `androidx.datastore:datastore-preferences 1.2.1` - Persistent settings storage
- `com.google.accompanist:accompanist-drawablepainter 0.37.3` - Drawable rendering in Compose
- `androidx.compose.material:material-icons-extended` - Extended icon set
- `quiche 0.22` with `boringssl-vendored` - QUIC + HTTP/3 (Cloudflare's library)
- `tokio 1` - Async runtime
- `reqwest 0.12` with `rustls-tls` - HTTPS client for WARP API registration
- `rcgen 0.13`, `p256 0.13` - TLS certificate generation and ECDSA

## Configuration

- `keystore.properties` (git-ignored) - Contains `storeFile`, `storePassword`, `keyAlias`, `keyPassword` for release signing
- `local.properties` (git-ignored) - Android SDK path
- `gradle.properties` - JVM heap (`-Xmx2048m`), AndroidX flags, Gradle configuration cache enabled
- `gradle/libs.versions.toml` - Version catalog for all Android/Kotlin dependencies
- `app/build.gradle.kts` - Single-module Android app build config; reads `keystore.properties` for signing
- `build-usque.sh` - Invokes `gomobile bind` to produce `app/libs/usquebind.aar` from `usque-bind/`
- PGO: optional profile-guided optimization if `usque-bind/default.pgo` exists

## Platform Requirements

- JDK 25 (used in CI via `actions/setup-java`, temurin)
- Go 1.26.3 (toolchain pinned via `GOTOOLCHAIN=go1.26.3` in `build-usque.sh`)
- Android SDK: platforms `android-37`, `android-36`, `android-31`, build-tools `36.0.0`, NDK `29.0.14206865`
- gomobile + gobind installed from `golang.org/x/mobile` at `v0.0.0-20260821190718-4776eadac327` (CI pin matches go.mod)
- `build-usque.sh` must be run before `./gradlew assembleRelease` to produce the AAR
- Android 15+ (API 35) devices, arm64-v8a only
- Release APK signed with provided keystore, distributed via GitHub Releases
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Project Structure

- **`app/`** — `com.nhubaotruong.usqueproxy` — the Usque WARP/ZeroTrust VPN app (simpler, no DI framework)
- **`android/app/`** — `com.zaneschepke.wireguardautotunnel` — the WireGuard Auto-Tunnel app (full Koin DI, Orbit MVI, Room)

## Naming Patterns

- PascalCase for all Kotlin class files: `TunnelManager.kt`, `VpnViewModel.kt`, `AppRepository.kt`
- Extension function files named after type: `Extensions.kt`, `ContextExtensions.kt`, `TunnelExtensions.kt`, `StringExtensions.kt`
- Interface names without `I` prefix: `TunnelRepository`, `TunnelProvider`, `TunnelBackend`
- Sealed class hierarchy names reflect parent: `BackendCoreException`, `LocalSideEffect`, `BackendMessage`
- Module files suffixed with `Module`: `AppModule.kt`, `DatabaseModule.kt`, `TunnelModule.kt`
- camelCase for all functions
- Boolean-returning functions use `is`/`has` prefix: `isRunning`, `hasVpnPermission`, `isActive`
- Suspend functions for IO-bound work: `getInstalledApps()`, `startTunnel()`, `stopTunnel()`
- Handler/manager factory functions use descriptive verbs: `handleRestore()`, `handleReboot()`, `handleLockDownModeInit()`
- camelCase for properties and local vars
- Private backing MutableStateFlow prefixed with `_`: `_vpnState`, `_activeTunnels`, `_stats`, `_connectedSince`
- Public StateFlow exposed without prefix: `vpnState`, `activeTunnels`, `stats`
- Constants in `companion object` or top-level: `RESTART_TUNNEL_DELAY`, `STATE_POLL_INTERVAL`, `STATS_POLL_INTERVAL`
- Enums in SCREAMING_SNAKE_CASE values: `VpnState.DISCONNECTED`, `SplitMode.ALL`, `AppMode.LOCK_DOWN`
- Data classes with all-default constructors for state: `VpnPrefs()`, `TunnelStats()`, `GlobalAppUiState()`
- Sealed classes for event/side-effect hierarchies: `LocalSideEffect`, `BackendCoreException`, `BackendMessage`
- `typealias` used for readability: `TunnelName = String?`, `QuickConfig = String`
- `domain/` — interfaces, models, enums, repository contracts, events/exceptions
- `data/` — Room entities, DAOs, migrations, AppDatabase
- `core/` — services, tunnel backends, notifications, shortcuts
- `ui/` — screens, components, viewmodels, navigation, themes, state
- `di/` — Koin module definitions (android/app only)
- `util/` — pure utilities, extension functions, constants

## Code Style

- No `.editorconfig` or `.ktlint` config files detected — formatting is enforced by Android Studio/IDE defaults
- Trailing commas used on multi-line parameter lists and collections
- 4-space indentation
- Max line length approximately 100 chars (inferred from code patterns)
- Kotlin's standard library style throughout
- `@OptIn` annotations placed at function or class level when using experimental APIs
- Common opt-ins: `@OptIn(ExperimentalCoroutinesApi::class)`, `@OptIn(ExperimentalAtomicApi::class)`, `@OptIn(ExperimentalMaterial3Api::class)`
- `@Composable` on all Compose functions, `private` on screen-internal composables

## Import Organization

- Avoided in main source; `import com.zaneschepke.wireguardautotunnel.viewmodel.*` seen in DI modules only

## Error Handling

- Custom sealed exception hierarchy: `BackendCoreException` with typed subclasses (`NotAuthorized`, `DnsFailure`, `InvalidConfig`, etc.)
- Each exception carries a `stringRes: Int` for UI display via `toStringValue()` returning `StringValue.StringResource`
- Errors propagated via `SharedFlow<Pair<String?, BackendCoreException>>` — never thrown across coroutine boundaries
- `runCatching { }` used for fallible operations with `.onFailure { e -> Timber.e(e, ...) }` chaining:
- `tryEmit` used for non-suspending event emission on `MutableSharedFlow`
- `localErrorEvents.emit(null to NotAuthorized())` pattern for broadcasting errors to UI
- `try/catch(e: Exception)` with `_registerError.value = e.message` in ViewModel
- `runCatching { }` used in Compose `LaunchedEffect` loops: `runCatching { viewModel.refreshStats() }`
- `runCatching { SplitMode.valueOf(...) }.getOrDefault(SplitMode.ALL)` for safe enum parsing

## Logging

- `Timber.d(...)` for lifecycle/state changes
- `Timber.w(...)` for recoverable unexpected states
- `Timber.e(exception, message)` for failures
- Log messages include the entity ID: `"Shutting down tunnel monitoring job for tunnelId: $id"`
- Usque VPN app (`app/`) uses no logging — no Timber dependency

## State Management

- Orbit MVI pattern via `ContainerHost<State, SideEffect>` in ViewModels
- `intent { ... }` blocks for actions; `reduce { state.copy(...) }` for state updates
- `postSideEffect(...)` for one-shot UI events
- `StateFlow` with `SharingStarted.WhileSubscribed(5_000L)` for lifecycle-aware exposure
- Plain `AndroidViewModel` with manual `MutableStateFlow` properties
- Private `_name` backing + public `name: StateFlow` read-only exposure
- Event-driven updates via `UsqueVpnService.events` collected in ViewModel `init`

## Coroutines

- `withContext(ioDispatcher)` wraps all blocking/IO work
- `supervisorScope` used for parallel launches where one failure should not cancel siblings
- Injected `CoroutineDispatcher` (never hardcoded `Dispatchers.IO` in android/app — qualifiers used)
- Exception: `app/` uses `Dispatchers.IO` directly (no DI)
- `applicationScope` for long-running coroutines outside ViewModel lifecycle
- `ensureActive()` called inside long loops to respect cancellation

## Function Design

- Suspend functions returning `Result<Unit>` for tunnel operations
- `Unit` returns for fire-and-forget
- Nullable returns (`TunnelConfig?`, `TunnelStatistics?`) instead of exceptions for "not found"

## Module Design

- Interfaces defined in `domain/repository/` — implementations in `data/repository/`
- Koin DI wires implementations to interfaces: `singleOf(::WireGuardNotification) bind NotificationManager::class`
- Handler classes (e.g., `TunnelMonitorHandler`, `DynamicDnsHandler`) receive all dependencies via constructor — no service locator pattern inside classes
- No DI framework; direct instantiation in ViewModel: `private val prefs = VpnPreferences(application)`
- `companion object` used for constants and static factory fields (`ACTION_STOP`, `ACTION_RESTART`, `events` SharedFlow)

## Comments

- Inline comments on non-obvious behavior: `// Keep current state — avoid UI flicker during brief disconnect`
- KDoc on public interfaces and key API methods
- `TODO` comments for known limitations: `// TODO this can crash if we haven't started foreground service yet`
- Migration notes in DataStore prefs: `// legacy, for migration`
- Single-line KDoc `/** Called from composable LaunchedEffect — checks volatile booleans, no JNI. */` used on ViewModel public functions
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview

- Android app (Kotlin/Compose) acts as the UI and OS integration shell
- Core VPN tunnel logic lives in a Go library (`usque-bind`) compiled to an AAR via `gomobile`
- A standalone Rust CLI (`usque-rs`) provides a desktop/Linux reference implementation of the same MASQUE tunnel, not shipped in the Android app
- The Go AAR (`usquebind.aar`) is the single bridge between the Android layer and Cloudflare WARP's MASQUE (CONNECT-IP over QUIC/HTTP3) protocol
- Android ViewModel holds all UI state as `StateFlow`; the service emits events via `SharedFlow` instead of polling

## Layers

- Purpose: Render app screens, collect user input, subscribe to state flows
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/ui/`
- Contains: Composable screens (`screen/`), reusable components (`component/`), navigation (`nav/`), Material3 theme (`theme/`)
- Depends on: ViewModel
- Used by: `MainActivity`
- Purpose: Translate user actions into service intents and JNI calls; expose state as `StateFlow`
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/ui/viewmodel/VpnViewModel.kt`
- Contains: `VpnViewModel` (single ViewModel), `VpnState` enum (stats model `TunnelStats` lives in `vpn/TunnelStatsParser.kt`)
- Depends on: `TunnelStateHolder` (events/state), `usquebind.Usquebind` JNI (for stats/register), `VpnPreferences`
- Used by: All composable screens via `AppNavigation`
- Purpose: Persist user settings and VPN configuration via DataStore; provide typed read model
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/data/`
- Contains: `VpnPreferences.kt` (DataStore wrapper), `VpnPrefs` data class, `AppRepository.kt`, `Office365Endpoints.kt`, enums (`SplitMode`, `DnsMode`, `ProfileType`, `ThemeMode`)
- Depends on: Jetpack DataStore Preferences
- Used by: `VpnViewModel`, `UsqueVpnService`, `BootReceiver`
- Purpose: Android OS VPN integration — owns the TUN fd, lifecycle, dead-man's switch, network/power callbacks
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`
- Contains: `UsqueVpnService` (extends `VpnService`, implements `TunnelListener`), `VpnServiceEvent` sealed interface, `TunnelStateHolder`, `ListenerEventMapper`, `TunnelConfigBuilder`, `TunnelStatsParser`, `VpnNotification`, `NetworkWatcher`, `PowerStateWatcher`
- Depends on: `usquebind.Usquebind` (Go JNI), `usquebind.VpnProtector`, `usquebind.TunnelListener`, `VpnPreferences`
- Used by: `VpnViewModel` (starts/stops via `Intent`), system via `BootReceiver`/`VpnTileService`
- Purpose: Implement the full MASQUE tunnel: QUIC/HTTP3 session, CONNECT-IP proxy, DNS interception, keepalive, reconnect loop, stats
- Location: `usque-bind/` (Go package `usquebind`)
- Key files: `bind.go` (main tunnel + JNI API + `TunnelListener` callbacks), `doh.go` (DNS-over-HTTPS + HTTP/3 probe), `doq.go` (DNS-over-QUIC)
- Depends on: `github.com/Diniboy1123/usque` (upstream MASQUE library), `github.com/Diniboy1123/connect-ip-go`, `quic-go`, `golang.org/x/mobile`
- Used by: Compiled to `app/libs/usquebind.aar` via `gomobile bind`; consumed from Kotlin via JNI class `usquebind.Usquebind`
- Purpose: Standalone MASQUE client for Linux/desktop — equivalent functionality to `usque-bind` but for native TUN devices
- Location: `usque-rs/` (binary crate)
- Key files: `src/main.rs`, `src/tunnel.rs`, `src/register.rs`, `src/tun_device.rs`, `src/config.rs`, `src/tls.rs`, `src/packet.rs`, `src/icmp.rs`
- Depends on: `quiche` (BoringSSL QUIC), `tokio`, `mio`, `ring`, `rcgen`, `tun`, `rtnetlink`
- Used by: Not consumed by Android app; independent binary
- Purpose: Upstream `usque` Go library's own Android demo/binding — used as reference, not the production app
- Location: `usque-android/` (git submodule)

## Data Flow

## Key Abstractions

- Purpose: Allows Go to call Android `VpnService.protect(fd)` so outbound QUIC sockets bypass the TUN device (no routing loop)
- Examples: Implemented in `UsqueVpnService.kt` as an anonymous `VpnProtector` passed to `Usquebind.startTunnel()`
- Pattern: Defined in Go as `type VpnProtector interface { ProtectFd(fd int) bool }`, exposed via gomobile
- Purpose: Wraps an `os.File` (Android TUN fd) to satisfy `api.TunnelDevice` interface — `ReadPacket()`/`WritePacket()`
- Examples: `usque-bind/bind.go` lines 152–163
- Purpose: Typed events from the VPN service to the UI, emitted via `TunnelStateHolder.events`
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/VpnServiceEvent.kt` — `Connecting`, `Started`, `Disconnecting`, `Stopped`, `Error(message)`, `Stats(stats)`
- Pattern: `TunnelStateHolder._events: MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)`
- Purpose: Go→Kotlin liveness push — Go calls back on state changes, periodic stats (~5 min while connected), and fatal errors; replaces Kotlin-side polling
- Examples: `usque-bind/bind.go` `TunnelListener` interface (`OnStateChanged`/`OnStats`/`OnError`); gomobile generates `usquebind.TunnelListener`, implemented by `UsqueVpnService`
- Pattern: `StartTunnel(configJSON, tunFd, protector, listener)` — callbacks arrive on Go goroutines; `tryEmit` on `MutableSharedFlow` is thread-safe
- Purpose: Process-wide tunnel state, replacing the service companion statics
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/TunnelStateHolder.kt`
- Pattern: `@Volatile isRunning`/`lastError` + `MutableSharedFlow<VpnServiceEvent>(replay = 1, extraBufferCapacity = 16)`; consumed by `VpnViewModel`
- Purpose: Maps Go listener callbacks to typed `VpnServiceEvent`s; dedups repeated errors (each distinct error surfaced once)
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/ListenerEventMapper.kt` — pure logic, no Android deps, unit-tested
- Purpose: Dead-man's switch — catches silent tunnel death without polling
- Examples: `UsqueVpnService.startDeadMansSwitch()` — coroutine `delay(15 min)` (60 min in power-save), single `getStats()` check, `reconnect()` if silent
- Pattern: Replaces the removed 60s polling watchdog; ≤96 JNI calls/day (≤24/day in power-save) vs 1440/day before
- Purpose: Immutable snapshot of all user preferences, emitted as a `Flow` from DataStore
- Examples: `app/src/main/java/com/nhubaotruong/usqueproxy/data/VpnPreferences.kt`
- Pattern: Computed properties `activeConfigJson` and `isActiveRegistered` delegate to the active `ProfileType`
- Purpose: Extends `config.Config` with Android-specific overrides (custom SNI, ConnectURI, DoH/DoQ URLs, system DNS list, Private DNS flag)
- Examples: `usque-bind/bind.go` lines 65–73

## Entry Points

- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/MainActivity.kt`
- Triggers: App launch, `ACTION_CONNECT_VPN` intent from tile/boot
- Responsibilities: Hosts single `VpnViewModel`, requests VPN permission, sets Compose content tree, triggers auto-connect on startup
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt`
- Triggers: `startForegroundService` from ViewModel/BootReceiver/TileService; `ACTION_STOP`/`ACTION_RESTART` intents
- Responsibilities: TUN fd lifecycle, VPN builder configuration, coroutine launch of Go tunnel, dead-man's switch, network/power callbacks, notification management
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/receiver/BootReceiver.kt`
- Triggers: `ACTION_BOOT_COMPLETED`
- Responsibilities: Reads DataStore prefs; starts `UsqueVpnService` if `autoConnect` enabled and VPN permission is still granted
- Location: `app/src/main/java/com/nhubaotruong/usqueproxy/tile/VpnTileService.kt`
- Triggers: Quick Settings tile interaction
- Responsibilities: Toggle VPN on/off; open app with `ACTION_CONNECT_VPN` if permission is missing
- Location: `usque-rs/src/main.rs`
- Triggers: CLI invocation (`usque-rs register` / `usque-rs nativetun`)
- Responsibilities: Parse CLI args via `clap`, dispatch to `register::register()` or `tunnel::maintain_tunnel()`

## Error Handling

- Go `StartTunnel()` returns a Go `error`; gomobile converts this to a Java `Exception` thrown from `Usquebind.startTunnel()`
- `UsqueVpnService` catches the exception in `tunnelJob`'s `finally` block; stores in `TunnelStateHolder.lastError`
- `ListenerEventMapper` dedups `OnError` callbacks (each distinct error surfaced once); the dead-man's switch reads `last_error` via a single `getStats()` check per interval
- `VpnViewModel` exposes `tunnelError: StateFlow<String?>` which composables observe; cleared by `clearTunnelError()`
- Rust CLI uses `anyhow::Result` for all fallible operations; errors propagate to `main()` and print to stderr

## Cross-Cutting Concerns

- Kotlin: `android.util.Log` with `TAG = "UsqueVpnService"`
- Go: standard `log.Printf` / `log.Println`; output captured in Android logcat via gomobile runtime
- Config JSON is validated at tunnel start time in Go (`json.Unmarshal` into `tunnelConfig`); invalid JSON returns an error before any network activity
- DataStore migrations are handled inline in `VpnPreferences.prefsFlow` map block (legacy key fallback)
- Two profile types: `WARP` (license key or anonymous) and `ZERO_TRUST` (JWT from team domain)
- Credentials stored only in Android DataStore as config JSON blob (base64 EC private key inside)
- QUIC TLS uses per-connection client certificates generated by Go (`rcgen` in Rust, `crypto/x509` in Go)
- App requests battery optimization exemption at startup (`MainActivity.checkBatteryOptimization()`)
- No `AlarmManager`/`ScheduledExecutorService` keepalive: the dead-man's switch is a coroutine delay (15 min, 60 min in power-save); Go keeps QUIC `KeepAlivePeriod: 30s` to hold NAT mappings
- `PARTIAL_WAKE_LOCK` acquired for connect (2-min cap) and reconnect (10s cap) attempts, released in `finally` block
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
