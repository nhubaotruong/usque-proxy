# Technology Stack

**Analysis Date:** 2026-04-01

## Languages

**Primary:**

- Kotlin - Android application layer (`app/src/main/java/com/nhubaotruong/usqueproxy/`)
- Go 1.26.3 - Native tunnel/VPN binding layer (`usque-bind/`, `usque-android/`)

**Secondary:**

- Rust (edition 2021) - Experimental MASQUE client reference implementation (`usque-rs/`)
- Bash - Build automation (`build-usque.sh`)

## Runtime

**Environment:**

- Android: compileSdk 37, minSdk 35 (Android 15+), targetSdk 36 (Android 16)
- ABI: arm64-v8a (release, see `app/build.gradle.kts` `ndk.abiFilters`); x86_64 added for debug builds (emulator testing)
- JVM: Java 21 source/target compatibility

**Package Manager:**

- Gradle 9.5.0 (main app, `gradle/wrapper/gradle-wrapper.properties`)
- Go modules (`usque-bind/go.mod`, `usque-android/go.mod`)
- Cargo (`usque-rs/Cargo.toml`)
- Lockfiles: `app/libs/usquebind.aar` (pre-built), `usque-bind/go.sum`, `usque-rs/Cargo.lock`

## Frameworks

**Core (Android):**

- Jetpack Compose BOM `2026.08.00` - UI framework
- Compose Material3 - UI component library
- Compose Navigation `2.10.0` - In-app navigation
- AndroidX Lifecycle `2.11.0` - ViewModel, lifecycle-aware coroutines
- Kotlin Coroutines - Async/concurrent logic throughout VPN service

**Build/Dev:**

- Android Gradle Plugin (AGP) `9.2.0`
- Kotlin Compose compiler plugin `2.3.21`
- gomobile `v0.0.0-20260821190718-4776eadac327` - Generates `usquebind.aar` from Go code
- gobind - Companion to gomobile for JVM bindings

**Testing:**

- JUnit 4 `4.13.2` - Unit tests
- AndroidX Test (JUnit, Espresso `3.7.0`) - Instrumentation tests
- Compose UI Test JUnit4 - Compose UI testing

## Key Dependencies

**Critical:**

- `github.com/Diniboy1123/usque v1.5.1-0.20260720063354-6aa03fc97d12` - Core MASQUE/WARP protocol implementation (Go)
- `github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33` - CONNECT-IP (RFC 9484) implementation (Go)
- `github.com/quic-go/quic-go v0.60.0` - QUIC transport (Go), used for MASQUE tunnel and DoQ DNS
- `gvisor.dev/gvisor v0.0.0-20260826181857-eb77d6c8310a` - Userspace networking stack for the TUN device
- `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446` - WireGuard networking primitives
- `usquebind.aar` (local `app/libs/`) - Pre-built gomobile AAR providing `usquebind.Usquebind` and `usquebind.VpnProtector` to Kotlin

**Infrastructure (Android):**

- `androidx.datastore:datastore-preferences 1.2.1` - Persistent settings storage
- `com.google.accompanist:accompanist-drawablepainter 0.37.3` - Drawable rendering in Compose
- `androidx.compose.material:material-icons-extended` - Extended icon set

**Rust (usque-rs, experimental):**

- `quiche 0.22` with `boringssl-vendored` - QUIC + HTTP/3 (Cloudflare's library)
- `tokio 1` - Async runtime
- `reqwest 0.12` with `rustls-tls` - HTTPS client for WARP API registration
- `rcgen 0.13`, `p256 0.13` - TLS certificate generation and ECDSA

## Configuration

**Environment:**

- `keystore.properties` (git-ignored) - Contains `storeFile`, `storePassword`, `keyAlias`, `keyPassword` for release signing
- `local.properties` (git-ignored) - Android SDK path
- `gradle.properties` - JVM heap (`-Xmx2048m`), AndroidX flags, Gradle configuration cache enabled

**Build:**

- `gradle/libs.versions.toml` - Version catalog for all Android/Kotlin dependencies
- `app/build.gradle.kts` - Single-module Android app build config; reads `keystore.properties` for signing
- `build-usque.sh` - Invokes `gomobile bind` to produce `app/libs/usquebind.aar` from `usque-bind/`
- PGO: optional profile-guided optimization if `usque-bind/default.pgo` exists

## Platform Requirements

**Development:**

- JDK 25 (used in CI via `actions/setup-java`, temurin)
- Go 1.26.3 (toolchain pinned via `GOTOOLCHAIN=go1.26.3` in `build-usque.sh`)
- Android SDK: platforms `android-37`, `android-36`, `android-31`, build-tools `36.0.0`, NDK `29.0.14206865`
- gomobile + gobind installed from `golang.org/x/mobile` at `v0.0.0-20260821190718-4776eadac327` (CI pin matches go.mod)
- `build-usque.sh` must be run before `./gradlew assembleRelease` to produce the AAR

**Production:**

- Android 15+ (API 35) devices, arm64-v8a only
- Release APK signed with provided keystore, distributed via GitHub Releases

---

*Stack analysis: 2026-04-01*
