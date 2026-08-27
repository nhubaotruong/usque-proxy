package com.nhubaotruong.usqueproxy

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import com.nhubaotruong.usqueproxy.vpn.TunnelStats
import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
import org.junit.After
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test

/**
 * Regression test for the VpnViewModel init NPE: the event collector used to
 * launch BEFORE the _stats/_vpnState MutableStateFlow initializers ran, and the
 * replay=1 SharedFlow delivered the last pending event (a Stats event while the
 * tunnel is running) synchronously via Dispatchers.Main.immediate -> NPE on
 * every app open with a running tunnel.
 *
 * Seeds a pending Stats event (last, so the replay buffer delivers it) before
 * MainActivity launches, then asserts the app comes up and reflects the running
 * tunnel instead of crashing.
 */
class ViewModelInitTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    companion object {
        @JvmStatic
        @BeforeClass
        fun seedPendingTunnelEvents() {
            // Simulate a running tunnel with a pending replay event. Stats is
            // emitted LAST so the replay=1 buffer delivers it synchronously to
            // the ViewModel collector during construction (the crash path).
            TunnelStateHolder.isRunning = true
            TunnelStateHolder.emit(VpnServiceEvent.Connecting)
            TunnelStateHolder.emit(VpnServiceEvent.Stats(TunnelStats(uptimeSec = 3_600)))
        }
    }

    @After
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.clearError()
        // Overwrite the replay buffer with a benign event so later tests start clean.
        TunnelStateHolder.emit(VpnServiceEvent.Stopped)
    }

    @Test
    fun appOpensWithoutCrashWhenStatsEventIsPending() {
        // Activity launched with a pending Stats event in the replay buffer.
        // Before the fix this crashed in VpnViewModel init; now the UI must come
        // up and reflect the running tunnel (refreshState polls isRunning).
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Disconnect").fetchSemanticsNodes().isNotEmpty()
        }
    }
}
