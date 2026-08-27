package com.nhubaotruong.usqueproxy

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The connect button must reflect [TunnelStateHolder.isRunning] via the ViewModel
 * (polled by AppNavigation's refreshState loop, ~1s interval).
 */
class ConnectFlowTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Before
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.lastError = null
    }

    @Test
    fun connectButtonReflectsStateHolder() {
        rule.onNodeWithText("Connect").assertExists()

        TunnelStateHolder.isRunning = true
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Disconnect").fetchSemanticsNodes().isNotEmpty()
        }

        TunnelStateHolder.isRunning = false
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithText("Connect").fetchSemanticsNodes().isNotEmpty()
        }
    }
}
