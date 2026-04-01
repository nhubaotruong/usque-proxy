# Usque Proxy — Tunnel Reliability Overhaul

## What This Is

An Android VPN app (usque-proxy) that tunnels traffic through Cloudflare's MASQUE protocol using QUIC + Connect-IP. The app currently suffers from silent connection death after 2-4 hours — it reports "connected" but traffic stops flowing. The goal is to replace the current complex tunnel management approach with the simpler, proven pattern from usque-android, which doesn't suffer from this problem.

## Core Value

VPN tunnel connections must stay reliably alive for hours/days without silent death — if the connection breaks, detect it immediately and reconnect.

## Requirements

### Validated

- ✓ QUIC + MASQUE tunnel establishment — existing
- ✓ Android VPN service with TUN device — existing
- ✓ DNS resolution (DoH/DoQ/System) — existing
- ✓ Network change detection (WiFi ↔ cellular) — existing
- ✓ Android Doze mode handling (battery exemption, alarm keepalive) — existing
- ✓ Dual-stack Happy Eyeballs connection racing — existing
- ✓ Self-signed certificate generation and caching — existing
- ✓ Split tunneling and DNS configuration — existing
- ✓ Debug/stats UI for tunnel diagnostics — existing

### Active

- [ ] Replace complex liveness detection with usque-android's simpler dual-goroutine error detection pattern
- [ ] Adopt usque-android's CloseError-based immediate reconnection instead of multi-layer stall detection
- [ ] Simplify reconnection strategy: constant retry delay instead of exponential backoff with jitter
- [ ] Remove 2-hour forced tunnel rotation (shouldn't be needed if forwarding loops detect death properly)
- [ ] Remove delivery ratio monitoring (symptom-based detection replaced by cause-based detection)
- [ ] Remove Android-side watchdog stall detection (Go-side forwarding loops handle this)
- [ ] Clean resource teardown per reconnect cycle (match usque-android's cleanup pattern)
- [ ] Verify QUIC keepalive period is sufficient (usque-android uses 30s, usque-proxy uses 25s)

### Out of Scope

- New features or UI changes — this is a reliability-focused refactor
- DNS subsystem changes — DoH/DoQ works fine, only reset-on-reconnect matters
- Android service lifecycle changes — Doze handling, battery exemption, alarm keepalive stay as-is
- usque-rs (Rust library) changes — focus is on Go tunnel layer and Kotlin service

## Context

**The problem:** After 2-4 hours, the MASQUE session expires server-side while the QUIC transport layer stays alive (kept alive by QUIC keepalive packets). The app shows "connected" because the QUIC connection is healthy, but no IP traffic flows through the dead Connect-IP session.

**Why usque-android works:** Its dual forwarding goroutines (TUN→server and server→TUN) immediately detect `connectip.CloseError` when trying to read/write on a dead session. This triggers instant reconnection. The error detection is at the forwarding layer, not a separate monitoring layer.

**Why usque-proxy's current approach is fragile:** It relies on *observing symptoms* (delivery ratio drops, rx stalls, watchdog byte counters) rather than *detecting the cause* (forwarding loop errors). This creates detection windows where traffic stops but the monitoring hasn't triggered yet. The complexity of multiple overlapping detection mechanisms (Go liveness goroutine, Android watchdog, keepalive probes, delivery ratio) makes the system harder to reason about and debug.

**Reference implementation:** `usque-android/api/tunnel.go` — `MaintainTunnel()` function (lines 146-256) is the gold standard for simple, reliable tunnel lifecycle management.

**Key files to modify:**
- `usque-bind/bind.go` — Go tunnel core (replace `maintainTunnel`, `livenessCheck`, reconnect logic)
- `app/src/main/java/com/nhubaotruong/usqueproxy/vpn/UsqueVpnService.kt` — simplify watchdog, remove stall detection

## Constraints

- **Tech stack**: Go (gomobile) + Kotlin, Android VPN service — no changes
- **Protocol**: QUIC + MASQUE Connect-IP via quic-go and connect-ip-go libraries
- **Compatibility**: Must maintain existing JNI interface (`Usquebind.startTunnel`, `getStats`, etc.)
- **Android**: Keep Doze handling, battery exemption, network callbacks — these are Android-specific concerns the simpler Go approach doesn't affect

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Port usque-android's approach over incremental fixes | Current complex approach has layered fixes that didn't solve the root cause; simpler pattern proven to work | — Pending |
| Keep Android-side Doze/battery handling | These are platform concerns separate from tunnel reliability; usque-android doesn't run as Android service | — Pending |
| Remove symptom-based detection (delivery ratio, stall counters) | Replace with cause-based detection (forwarding loop errors) | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-01 after initialization*
