# Manual QA Plan — Tunnel Reliability & Battery (Task 11, Phase 5)

**Branch:** `feat/tunnel-reliability`
**Date:** 2026-08-27
**Scope:** Real-device verification of the event-driven tunnel seam (Task 6), battery targets, and the scenarios the emulator cannot faithfully simulate. This is the manual companion to the automated suite (10 unit + 10 instrumentation tests, all green) and the emulator battery verification (`docs/battery-verification.md`).

## 1. Purpose

The automated suite covers the seam, UI, service lifecycle, and Doze on the emulator. This plan covers what only a physical device can prove:

- Battery numbers (drain, wakelock duration, background CPU) — deferred from Task 10 (emulator energy model unsupported).
- Long-run reliability (24–72 h soak, silent-death detection) — the project's core value.
- Network transitions, Private DNS interplay, split-tunnel correctness, boot auto-connect, Quick Settings tile.
- Dead-man's switch behavior and the deferred items recorded in the SDD ledger.

## 2. Prerequisites & setup

**Device:** arm64 Android 15+ (API 35–36), physical device with a SIM and WiFi. USB debugging enabled.

**Build:** debug APK (ships x86_64 + arm64; use the arm64 slice on device):

```bash
bash build-usque.sh          # if the AAR changed
JAVA_HOME=/var/home/nhubao/.local/jdk ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**First-run setup (per device, per install):**

1. Launch: `adb shell am start -n com.nhubaotruong.usqueproxy/.MainActivity`.
2. Grant VPN permission when prompted.
3. Settings tab → **Register Device** (anonymous WARP registration; succeeds without credentials).
4. Home tab → **Connect**. Confirm the tunnel establishes (notification shows connected, `speed.cloudflare.com` loads through the tunnel).
5. Grant battery-optimization exemption if prompted (Settings → battery → unrestricted).

> **Note — `ACTIVATE_VPN` appop:** instrumentation test runs reset the `ACTIVATE_VPN` appop. Before any manual test run, re-grant it:
> `adb shell cmd appops set com.nhubaotruong.usqueproxy ACTIVATE_VPN allow`

**Baseline capture (before the soak):** with the tunnel connected 10+ min, record the three numbers for comparison against `docs/battery-baseline.md` and `docs/battery-verification.md`:

```bash
adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy
adb shell dumpsys alarm | grep -A5 usqueproxy
adb logcat -d | grep -c "getStats"
# wakelock durations:
adb shell dumpsys batterystats --checkin | grep UsqueProxy
```

## 3. How to run

- Each item is a checkbox. Mark **PASS** only if the expected result is fully met; otherwise mark **FAIL** and record the observed behavior in the notes column (or in the report).
- Reset state between items: disconnect via the app, or `adb shell am force-stop com.nhubaotruong.usqueproxy` where noted.
- Record logcat during every item: `adb logcat -s UsqueVpnService:* GoLog:*` (Go log lines arrive under the `GoLog` tag via gomobile).
- **Silent-death detection during soak:** every 2–4 h, load a page through the tunnel (e.g. `speed.cloudflare.com`) and check the notification still shows connected. If traffic fails while the notification says connected, that is a silent death — capture `adb logcat -d` immediately and mark FAIL.

---

## 4. Network transitions

### NT-1 WiFi → cellular handoff

- **Steps:** Connect on WiFi. Confirm connected. Disable WiFi (or leave the AP range) so the device falls back to cellular. Watch the notification and logcat.
- **Expected:** Tunnel reconnects over cellular with no 30 s+ gap; notification returns to connected; traffic flows. No crash, no stuck "Connecting".
- [ ] PASS / [ ] FAIL — Notes:

### NT-2 Cellular → WiFi

- **Steps:** Connect on cellular. Re-enable WiFi and join the AP.
- **Expected:** Reconnect within 5 s; traffic flows over WiFi; no error banner.
- [ ] PASS / [ ] FAIL — Notes:

### NT-3 Airplane mode on → off

- **Steps:** Connect. Toggle airplane mode ON, wait 30 s, toggle OFF.
- **Expected:** Tunnel resumes automatically after radios return; no manual reconnect needed; no crash.
- [ ] PASS / [ ] FAIL — Notes:

### NT-4 Weak signal / high packet loss

- **Steps:** Connect, then move to a location with 1–2 bars (or stand near a Faraday-ish spot). Keep the screen on and load pages for 5 min. Then return to strong signal.
- **Expected:** QUIC recovers without crash; no permanent disconnect; tunnel reconnects when signal returns. `PROTOCOL_VIOLATION`-class errors may appear transiently — see DV-1.
- [ ] PASS / [ ] FAIL — Notes:

### NT-5 Dual SIM switch (if device supports it)

- **Steps:** With two SIMs active, connect, then switch the default data SIM in Settings → Network.
- **Expected:** Tunnel reconnects over the new data SIM; no crash; no manual intervention.
- [ ] PASS / [ ] FAIL — Notes: *(N/A if single-SIM device)*

---

## 5. Lifecycle edge cases

### LC-1 Screen off + backgrounded 1 h

- **Steps:** Connect, press Home, turn the screen off, leave untouched for 1 h. Wake, unlock, load a page.
- **Expected:** Tunnel still connected (or reconnected); traffic flows immediately; no error banner.
- [ ] PASS / [ ] FAIL — Notes:

### LC-2 Process killed by OOM killer → START_STICKY restore

- **Steps:** Connect. Kill the process without stopping the service: `adb shell am crash com.nhubaotruong.usqueproxy` (preferred — `am kill` only targets background processes, and a process hosting a foreground service is exempt, so it would not exercise START_STICKY). Wait 10 s.
- **Expected:** The foreground service restarts (START_STICKY); tunnel reconnects; notification returns. App UI, when opened, shows connected state without crashing (regression guard for the Task 10 NPE fix).
- [ ] PASS / [ ] FAIL — Notes:

### LC-3 Deep Doze (force-idle 30 min) — meaningful path

- **Steps:** Connect. Force Doze: `adb shell dumpsys deviceidle force-idle`. Leave 30 min (screen off). Exit Doze: `adb shell dumpsys deviceidle unforce`; wake and load a page.
- **Expected:** No crash while idle; tunnel reconnects on exit; notification accurate. *(This is the manual-only path the automated DozeTest cannot run green — see DV-2.)*
- [ ] PASS / [ ] FAIL — Notes:

### LC-4 App Standby bucket downgrade

- **Steps:** Connect. Downgrade the bucket: `adb shell am set-standby-bucket com.nhubaotruong.usqueproxy restricted`. Wait 15 min, then load a page.
- **Expected:** Tunnel persists; reconnect works; no crash.
- [ ] PASS / [ ] FAIL — Notes:

### LC-5 Configuration change during connect

- **Steps:** Start connecting; immediately rotate the device (or toggle dark theme) mid-connect. Repeat 3×.
- **Expected:** No crash, no stuck state; tunnel completes or cleanly retries; UI state consistent after rotation.
- [ ] PASS / [ ] FAIL — Notes:

### LC-6 Quick Settings tile toggle during connecting (race)

- **Steps:** Tap Connect, then immediately tap the QS tile (toggle off) while the notification still says "Connecting". Repeat 3×.
- **Expected:** No crash; final state matches the last user action; no zombie tunnel (traffic must not keep flowing after the tile shows disconnected).
- [ ] PASS / [ ] FAIL — Notes:

### LC-7 Boot auto-connect

- **Steps:** With `autoConnect` enabled in settings, connect, then reboot the device. After boot, wait 60 s.
- **Expected:** VPN reconnects automatically (BootReceiver path); notification shows connected; no manual action needed. If VPN permission was revoked by the reboot, the app must not crash.
- [ ] PASS / [ ] FAIL — Notes:

### LC-8 100 connect/disconnect cycles

- **Steps:** Script or manually cycle Connect/Disconnect 100 times via the QS tile toggle (or the app button). Do not use `adb shell am startservice` — the service is `exported="false"` with `BIND_VPN_SERVICE`, so external start/stop intents are denied. After the last cycle, run the wakelock audit (BA-3) and check for ANRs: `adb logcat -d | grep -i anr`.
- **Expected:** No ANR, no crash, no fd leak, no wakelock accumulation, no notification desync. Check fd count before and after the cycles: `adb shell pidof com.nhubaotruong.usqueproxy`, then `adb shell ls /proc/<pid>/fd | wc -l` — the count must be stable (within noise).
- [ ] PASS / [ ] FAIL — Notes:

---

## 6. Long-run soak

### SO-1 24 h connected, idle — silent-death detection

- **Steps:** Connect, leave the device idle (screen off, on charger or not) for 24 h. Every 2–4 h, wake and load a page through the tunnel; check the notification state. Record battery level at start and end.
- **Expected:** No silent death (traffic always flows when checked; notification never claims connected while traffic is dead). Battery drain < 5% over the window (see BA-1 for the formal idle-hour measurement). No crash.
- [ ] PASS / [ ] FAIL — Notes:

### SO-2 72 h connected with periodic traffic

- **Steps:** Connect and keep the device on a desk with periodic traffic (e.g. a music stream or a scripted page load every 30 min) for 72 h. Check stats in the app UI daily.
- **Expected:** Stats keep updating and are plausible (rx/tx grow, no reset without reconnect); no memory growth (check `adb shell dumpsys meminfo com.nhubaotruong.usqueproxy` daily — RSS stable within noise); no fd leak; no silent death.
- [ ] PASS / [ ] FAIL — Notes:

### SO-3 Dead-man's switch: 15-min tick with no reconnect

- **Steps:** Connect and leave the tunnel healthy. Watch logcat for 20+ min.
- **Expected:** The dead-man's switch performs one `getStats()` per 15 min (design ceiling ~96/day) and logs **nothing** while healthy — no reconnect log, no error. This confirms the switch is a silent insurance policy, not a poller. *(Design ceiling leaves zero margin under the <100/day target — record the observed count on device; see `docs/battery-verification.md`.)*
- [ ] PASS / [ ] FAIL — Notes:

### SO-4 Dead-man's switch: 60-min power-save tick

- **Steps:** Connect. Enable Power Save Mode (Settings → Battery → Power Saver). Watch logcat for 70+ min.
- **Expected:** No reconnect while healthy; the switch interval extends to 60 min in power-save (24/day ceiling); tunnel stays up.
- [ ] PASS / [ ] FAIL — Notes:

---

## 7. DNS scenarios

### DN-1 Private DNS on → tunnel DNS interception

- **Steps:** Settings → Network → Private DNS → "Private DNS provider hostname" (e.g. `dns.google`). Connect. Load pages and resolve hostnames.
- **Expected:** No DNS failure; tunnel DNS interception behaves (queries go through the tunnel per the app's DNS mode); no crash, no resolution loop.
- [ ] PASS / [ ] FAIL — Notes:

### DN-2 Private DNS off → system DNS forwarding

- **Steps:** Private DNS = Off. Connect. Load pages.
- **Expected:** Normal resolution via system DNS through the tunnel; no errors.
- [ ] PASS / [ ] FAIL — Notes:

### DN-3 DoH / DoQ modes — resolution + fallback

- **Steps:** Settings → DNS: set **DoH** (custom URL, e.g. `https://dns.google/dns-query`), connect, resolve. Repeat with **DoQ** (e.g. `dns.adguard-dns.com`). Then set an invalid custom URL and connect.
- **Expected:** Resolution works in both modes; invalid custom URL fails gracefully (error surfaced, tunnel does not hang); switching modes mid-session applies on next connect.
- [ ] PASS / [ ] FAIL — Notes:

### DN-4 DNS over VPN when split-tunnel excludes the VPN app itself

- **Steps:** Split mode = EXCLUDE with the app itself excluded (see ST-2). Connect. Resolve hostnames.
- **Expected:** DNS still resolves (no loop where the app's own DNS traffic bypasses the tunnel while the tunnel needs DNS); no crash.
- [ ] PASS / [ ] FAIL — Notes:

---

## 8. Split tunnel

### ST-1 Include mode: only specified apps through VPN

- **Steps:** Split mode = INCLUDE; add 2–3 apps (e.g. a browser and a streaming app). Connect. Check the IP seen by an included app (e.g. `whatismyipaddress.com` in the browser) vs. an excluded app.
- **Expected:** Included apps see the WARP egress IP; all other apps see the local IP; traffic flows for both.
- [ ] PASS / [ ] FAIL — Notes:

### ST-2 Exclude mode: specified apps bypass VPN, including self

- **Steps:** Split mode = EXCLUDE; add the VPN app itself plus one other app. Connect.
- **Expected:** Excluded apps see the local IP; everything else goes through the tunnel; the VPN app itself keeps working (no self-bypass crash).
- [ ] PASS / [ ] FAIL — Notes:

### ST-3 App uninstalled while in split-tunnel list

- **Steps:** Add an app to the include list, connect, then uninstall that app.
- **Expected:** No crash; the stale entry is handled gracefully (removed or ignored); tunnel keeps running.
- [ ] PASS / [ ] FAIL — Notes:

### ST-4 System apps in include list

- **Steps:** Split mode = INCLUDE; add a system app (e.g. Play Store or Settings). Connect.
- **Expected:** No crash; the system app's traffic routes through the tunnel (or is handled per the app's policy without breaking the tunnel).
- [ ] PASS / [ ] FAIL — Notes:

> **Environment note (from the automated suite):** `SplitTunnelTest` (instrumentation) requires the test APK to be the **only user app** on the device. On a real device with other apps installed, rely on these manual items instead of that test.

---

## 9. Battery & power (real-device measurements)

> These rows were deferred from Task 10 because the emulator's energy model is unsupported (all consumers report `-1 (unsupported)`, battery pinned at 100%). Targets are from the spec, Section 3.

### BA-1 Drain: idle < 2% / active < 5% per day

- **Steps:** Charge to 100%, disconnect charger, connect the tunnel, screen off, leave idle overnight (≥ 8 h, Doze engaged — a 1 h window extrapolated to 24 h is too noisy at 1% battery granularity). Record battery level at start and end. Then use the device normally (screen on, browsing through the tunnel) for 1 h and record again. Extrapolate to 24 h.
- **Expected:** < 2%/day idle; < 5%/day active. Record raw numbers.
- [ ] PASS / [ ] FAIL — Notes:

### BA-2 Wakelock duration < 5 min/day; background CPU < 60 s/day

- **Steps:** With the tunnel connected 10+ min (and after the LC-8 cycle run), capture:

  ```bash
  adb shell dumpsys batterystats | grep -A5 com.nhubaotruong.usqueproxy
  adb shell dumpsys batterystats --checkin | grep UsqueProxy
  adb shell dumpsys alarm | grep -A5 usqueproxy
  adb logcat -d | grep -c "getStats"
  ```

- **Expected:** Partial wakelock time < 5 min/day (only `UsqueProxy:connect` / `UsqueProxy:reconnect` exist — brief, per-attempt); background CPU < 60 s/day; alarms < 50/day; `getStats` logcat count ≈ 0 (the dead-man's switch does not log its check — see SO-3).
- [ ] PASS / [ ] FAIL — Notes:

### BA-3 Wakelock audit — no leaks across cycles

- **Steps:** After LC-8 (100 cycles), run: `adb shell dumpsys power | grep -A5 UsqueProxy`
- **Expected:** No wakelock held at rest (the grep shows no active `UsqueProxy:*` wakelock when the tunnel is connected and idle); no accumulation across cycles.
- [ ] PASS / [ ] FAIL — Notes:

### BA-4 Battery Historian on a real device

- **Steps:**
  1. `adb shell dumpsys batterystats --reset` (start clean).
  2. Use the device normally with the tunnel connected for ≥ 1 h (ideally overnight).
  3. `adb bugreport` (or `adb shell dumpsys batterystats > batterystats.txt`).
  4. Upload the bugreport to <https://battery-historian.appspot.com> (or run the local Docker image) and inspect the app's row: wakelock bars, wakeup alarms, CPU, network.
- **Expected:** No periodic wakelock/alarm pattern (the old 60 s watchdog and dual keepalive are gone); only connect/reconnect events; no "held wakelock" bars spanning minutes.
- [ ] PASS / [ ] FAIL — Notes:

---

## 10. Deferred verification items (from the SDD ledger)

### DV-1 `PROTOCOL_VIOLATION` on connect — verify on device

- **Steps:** Connect 5× (disconnect between attempts). Watch logcat for `http3: parsing frame failed: PROTOCOL_VIOLATION (remote)`.
- **Expected:** On a real device this should be rare or absent (the emulator occurrence is suspected to be emulator NAT/QUIC interference). If it appears on every connect on-device, the tunnel must still recover/reconnect and stay up — record frequency and whether recovery is automatic.
- [ ] PASS / [ ] FAIL — Notes:

### DV-2 DozeTest meaningful path (force-idle with connected tunnel)

- **Steps:** This is LC-3. The automated `DozeTest` only exercises the unconnected path; the connected path is manual-only. Run LC-3 and record the result here as the Doze coverage evidence.
- [ ] PASS / [ ] FAIL — Notes: *(see LC-3)*

### DV-3 Notification accuracy during reconnect

- **Steps:** Force a reconnect (toggle airplane mode briefly, or kill the process per LC-2). Watch the notification during the transition.
- **Expected:** Known limitation (ledger Task 6, ruling #3): there is no "Reconnecting" state in the event set — the notification may show the previous state during the reconnect window. Acceptable if the final state is correct; record any misleading long-lived state as a FAIL.
- [ ] PASS / [ ] FAIL — Notes:

### DV-4 Silent death persists? → traffic-progress check

- **Steps:** If SO-1/SO-2 show silent death (connected-but-dead), the dead-man's switch currently checks `running && connected` only (ledger Task 6, ruling #2). Record the failure and the time-to-detection.
- **Expected:** No silent death. If it occurs, this item documents the evidence for adding a traffic-progress check to the switch (follow-up work, not part of this plan).
- [ ] PASS / [ ] FAIL — Notes:

---

## 11. Results summary

| Section | Items | PASS | FAIL | N/A |
| --- | --- | --- | --- | --- |
| 4. Network transitions | NT-1..NT-5 | | | |
| 5. Lifecycle edge cases | LC-1..LC-8 | | | |
| 6. Long-run soak | SO-1..SO-4 | | | |
| 7. DNS scenarios | DN-1..DN-4 | | | |
| 8. Split tunnel | ST-1..ST-4 | | | |
| 9. Battery & power | BA-1..BA-4 | | | |
| 10. Deferred items | DV-1..DV-4 | | | |

**Overall verdict:** [ ] READY FOR RELEASE / [ ] ISSUES FOUND (list: )

**Tester / date / device model / Android version:**

## 12. References

- Spec: `docs/superpowers/specs/2026-08-27-tunnel-reliability-battery-testing-design.md` (Section 4 — expanded testing scenarios; Section 3 — battery targets)
- Emulator battery verification: `docs/battery-verification.md` (deferred rows + capture commands)
- Baseline: `docs/battery-baseline.md`
- SDD ledger: `.superpowers/sdd/2026-08-27-tunnel-reliability-battery-testing/progress.md` (deferred items)
