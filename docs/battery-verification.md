# Battery Verification (Task 10 — Phase 3)

After-state measurement of the event-driven tunnel design (Task 6 seam) against the
spec's battery targets. Baseline was deferred in Task 1 (`docs/battery-baseline.md`):
the arm64-only APK could not run on the x86_64 emulator at that time. The debug
build now ships x86_64 (Task 8), so the after-state was measured on the
`baseline35` emulator (x86_64, android-35 google_apis).

## Measurement conditions

- Emulator: `baseline35` AVD (sdk_gphone64_x86_64, API 35), `ACTIVATE_VPN` appop
  granted via `cmd appops set com.nhubaotruong.usqueproxy ACTIVATE_VPN allow`.
- Anonymous WARP registration: **succeeded** (Settings → Register Device).
- Tunnel: **connected** (VPN established, foreground service, stats flowing,
  `speed.cloudflare.com` loaded through the tunnel).
- Sample: **15+ minutes of continuous connected time** (04:14:48 → 04:30+ local),
  process alive at measurement time, no reconnect events.
- Commands run at the end of the window:
  `adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy`,
  `adb shell dumpsys alarm | grep -A5 usqueproxy`,
  `adb logcat -d | grep -c "getStats"`.

## Results

| Metric | Baseline | After (15-min sample) | Extrapolated 24h | Target | Verdict |
| --- | --- | --- | --- | --- | --- |
| JNI `getStats` calls (logcat proxy) | deferred | 0 | 0/day | <100/day | ✅ PASS |
| Alarms (`dumpsys alarm`) | deferred | 0 | 0/day | <50/day | ✅ PASS |
| Wakelock time | deferred | not measurable on emulator | deferred | <5 min/day | ⏸ deferred |
| Background CPU | deferred | not measurable on emulator | deferred | <60 s/day | ⏸ deferred |
| Drain (idle / active) | deferred | not measurable on emulator | deferred | <2% / <5% | ⏸ deferred |
| 60s polling pattern in logcat | deferred | none (see below) | — | none | ✅ PASS |

### Notes on the measured rows

- **JNI `getStats` (logcat proxy):** zero logcat lines mention `getStats` in the
  whole session. Stats reach the UI via `TunnelListener` callbacks (event-driven
  seam), so Kotlin never polls. The dead-man's switch performs one `getStats` per
  15 min (96/day max in normal mode, 24/day in power-save) but does not log the
  call — it only logs when it decides to reconnect. The 96/day design ceiling is
  within the <100/day target but leaves no margin; worth watching on real device.
- **Alarms:** the new design removed the dual keepalive (2-min
  `ScheduledExecutorService` + 8-min `AlarmManager`). `dumpsys alarm` shows zero
  alarms for the package. The dead-man's switch is a coroutine delay, not an alarm.
- **No 60s polling:** `adb logcat -d | grep -iE "watchdog|poll|getStats"` shows no
  app-side periodic pattern (only unrelated `netd tetherGetStats` system lines).
  The service logged exactly 5 lines in 15+ min, all at startup
  (Power Save Mode / DNS / local networks / VPN established / network change).
  The 15-min dead-man's switch tick passed with no reconnect log (tunnel healthy).
- **Wakelocks (qualitative):** batterystats lists only `UsqueProxy:connect` and
  `UsqueProxy:reconnect` — brief, per-attempt wakelocks. No periodic keepalive
  wakelock exists in the new design.

### Deferred rows — real-device capture commands

The emulator's batterystats energy model is unsupported (all consumers report
`-1 (unsupported)`, battery pinned at 100%), so drain, wakelock duration, and
background CPU cannot be measured there. Record on an arm64 Android 15+ device
with the debug APK, tunnel connected 10+ min:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.nhubaotruong.usqueproxy/.MainActivity
# UI: Settings tab → "Register Device" → Home tab → "Connect"
# wait 10+ minutes with the tunnel connected, then:
adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy
adb shell dumpsys alarm | grep -A5 usqueproxy
adb logcat -d | grep -c "getStats"
# wakelock durations:
adb shell dumpsys batterystats --checkin | grep UsqueProxy
# drain: read battery level before/after an idle hour (screen off, Doze)
```

## Findings (reported, not fixed — Task 10 is measurement only)

1. **Crash: NPE in `VpnViewModel` init when the app is opened while the tunnel is
   running.** `VpnViewModel.kt` init block (lines 38–69) launches the
   `TunnelStateHolder.events` collector before the `_vpnState`/`_stats` property
   initializers (lines 74–77) run. `events` is a `MutableSharedFlow(replay = 1)`;
   when the service has already emitted (tunnel running), the replayed `Stats`
   event is delivered synchronously during `collect`, hitting the not-yet-
   initialized `_stats` → `NullPointerException` on the main thread. Reproduced
   twice (every new `MainActivity` instance while connected). The process dies;
   the foreground service restarts and reconnects, but the UI crashes on every
   app open while connected. Regression introduced by the Task 6 event-driven
   seam. **Fix suggestion (not applied):** move the `_vpnState`/`_stats`
   initializers above the init block, or start the collector in a
   `viewModelScope.launch` after all properties are initialized.
2. **`PROTOCOL_VIOLATION` from remote on connect** (`connect-ip: failed to read
   response: http3: parsing frame failed: PROTOCOL_VIOLATION (remote)`). Appears
   on the emulator on most connects; the tunnel recovers/reconnects and stays up.
   Likely emulator NAT/QUIC interference; verify on real device.
