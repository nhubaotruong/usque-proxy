package com.nhubaotruong.usqueproxy

import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream

/**
 * Best-effort Doze test: forces the device into deep idle while the tunnel is
 * connected and asserts the process survives. Skips gracefully when no tunnel is
 * connected (e.g. in CI runs where the tunnel cannot reach Cloudflare).
 *
 * force-idle is executed via UiAutomation shell commands (shell privileges,
 * equivalent to `adb shell dumpsys deviceidle force-idle` from the host) — the
 * brief's `su`-based approach requires a rooted device and does not work on the
 * google_apis emulator.
 */
@RunWith(AndroidJUnit4::class)
class DozeTest {
    companion object {
        private const val TAG = "DozeTest"

        /**
         * Re-grants the ACTIVATE_VPN appop from the test process. AGP's install
         * invalidates the host-side pre-grant (package uid churn), and the VPN
         * service's `startForeground` (FGS type systemExempted) throws
         * SecurityException without it. Runs before ErrorBannerTest
         * (alphabetical order), whose Restart flow starts the service.
         */
        @JvmStatic
        @BeforeClass
        fun grantVpnConsent() {
            val uiAutomation = InstrumentationRegistry.getInstrumentation().uiAutomation
            try {
                shell(uiAutomation, "appops set com.nhubaotruong.usqueproxy ACTIVATE_VPN allow")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to grant ACTIVATE_VPN appop: ${e.message}")
            }
        }

        private fun shell(uiAutomation: android.app.UiAutomation, cmd: String) {
            val pfd: ParcelFileDescriptor = uiAutomation.executeShellCommand(cmd)
            pfd.use { p ->
                FileInputStream(p.fileDescriptor).use { it.readBytes() }
            }
        }
    }

    @Test
    fun forceIdleWhileConnectedDoesNotCrash() {
        // Block body (not `= runBlocking`) so the method compiles to void —
        // JUnit 4 rejects non-void test methods.
        runBlocking {
            // Requires a connected tunnel; best-effort: skip if not connected.
            if (!TunnelStateHolder.isRunning) {
                Log.i(TAG, "Skipping: tunnel not connected (isRunning=false)")
                return@runBlocking
            }
            val uiAutomation = InstrumentationRegistry.getInstrumentation().uiAutomation
            try {
                shell(uiAutomation, "dumpsys deviceidle force-idle")
                Thread.sleep(5_000)
                shell(uiAutomation, "dumpsys deviceidle unforce")
            } catch (e: Exception) {
                // Best-effort: force-idle unavailable on this image — skip, do not block.
                Log.i(TAG, "Skipping: force-idle unavailable (${e.message})")
                return@runBlocking
            }
            // Assert process still alive and service still running
            assertEquals(true, TunnelStateHolder.isRunning)
        }
    }
}
