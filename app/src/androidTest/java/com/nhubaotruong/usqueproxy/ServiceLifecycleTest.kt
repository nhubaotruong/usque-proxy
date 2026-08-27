package com.nhubaotruong.usqueproxy

import android.content.Context
import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream

/**
 * The service must emit [VpnServiceEvent.Connecting] synchronously in
 * [UsqueVpnService.onStartCommand] (via launchStartJob) before the tunnel job
 * blocks on network I/O. Requires VPN consent: the ACTIVATE_VPN appop is
 * re-granted from the test process (shell privileges) because AGP's install
 * invalidates the host-side pre-grant.
 */
@RunWith(AndroidJUnit4::class)
class ServiceLifecycleTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun startIntentEmitsConnecting() {
        // Block body (not `= runBlocking`) so the method compiles to void —
        // JUnit 4 rejects non-void test methods.
        runBlocking {
            grantVpnConsent()
            // A previous test (ErrorBannerTest's Restart flow) may have left a
            // Connecting event in the replay buffer. Reading the flow with
            // `first` would match that stale event, so instead we subscribe
            // through a Channel, consume the replayed event, and only then
            // accept the next (fresh) emission from THIS start. Otherwise the
            // test would pass on the stale event and stop the service before
            // onStartCommand ran, tripping the system's startForeground timeout.
            val events = TunnelStateHolder.events
            val channel = Channel<VpnServiceEvent>(Channel.UNLIMITED)
            val collector = CoroutineScope(Dispatchers.Default).launch {
                events.collect { channel.trySend(it) }
            }
            try {
                // Consume any stale replayed event (replay=1) so we only match
                // a fresh emission from THIS start.
                withTimeoutOrNull(1_000) { channel.receive() }
                val intent = Intent(context, UsqueVpnService::class.java)
                context.startForegroundService(intent)
                // Timeout guard: fail instead of hanging if the service never emits.
                val event = withTimeout(30_000) { channel.receive() }
                assertEquals(VpnServiceEvent.Connecting, event)
                context.stopService(Intent(context, UsqueVpnService::class.java))
            } finally {
                collector.cancel()
            }
        }
    }

    private fun grantVpnConsent() {
        val uiAutomation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val pfd: ParcelFileDescriptor = uiAutomation.executeShellCommand(
            "appops set com.nhubaotruong.usqueproxy ACTIVATE_VPN allow",
        )
        pfd.use { p ->
            FileInputStream(p.fileDescriptor).use { it.readBytes() }
        }
    }
}
