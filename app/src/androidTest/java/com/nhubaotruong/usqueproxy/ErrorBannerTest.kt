package com.nhubaotruong.usqueproxy

import android.content.Intent
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
import com.nhubaotruong.usqueproxy.vpn.VpnServiceEvent
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Error surface tests:
 *  - VpnServiceEvent.Error must surface the message on Home with a Dismiss action.
 *  - Toggling a setting while the tunnel is running must show the RestartBanner,
 *    and "Restart now" must clear it.
 */
class ErrorBannerTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Before
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.lastError = null
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        ctx.stopService(Intent(ctx, UsqueVpnService::class.java))
    }

    @Test
    fun errorEventShowsMessageAndDismissClears() {
        TunnelStateHolder.emit(VpnServiceEvent.Error("test failure"))
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("test failure").fetchSemanticsNodes().isNotEmpty()
        }

        rule.onNodeWithText("Dismiss").performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("test failure").fetchSemanticsNodes().isEmpty()
        }
    }

    @Test
    fun restartBannerAppearsAndRestartClears() {
        TunnelStateHolder.isRunning = true
        rule.onNodeWithText("Settings").performClick()

        // Toggling a setting while the tunnel is running marks a restart as needed
        rule.onNodeWithText("Bypass local network").performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Restart to apply changes").fetchSemanticsNodes().isNotEmpty()
        }

        rule.onNodeWithText("Restart now").performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Restart to apply changes").fetchSemanticsNodes().isEmpty()
        }

        // Restore the setting for other tests
        rule.onNodeWithText("Bypass local network").performClick()
    }
}
