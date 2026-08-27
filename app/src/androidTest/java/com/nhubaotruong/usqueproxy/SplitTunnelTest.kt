package com.nhubaotruong.usqueproxy

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Split-tunnel INCLUDE mode: the app list must load, toggling an app must move it
 * to the "Included" section, and the selection must persist across recreation.
 * The test APK itself (com.nhubaotruong.usqueproxy.test) is the only user app on
 * the emulator, so it is a deterministic list entry.
 */
class SplitTunnelTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    private val testAppPackage = "com.nhubaotruong.usqueproxy.test"

    @Before
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.lastError = null
    }

    private fun includedHeaderCount(): Int =
        rule.onAllNodesWithText("Included").fetchSemanticsNodes().size

    @Test
    fun includeModeShowsAppsAndSelectionPersists() {
        rule.onNodeWithText("Split Tunnel").performClick()
        rule.onNodeWithText("Include Only").performClick()

        // App list loads asynchronously from PackageManager
        rule.waitUntil(timeoutMillis = 10_000) {
            rule.onAllNodesWithText(testAppPackage).fetchSemanticsNodes().isNotEmpty()
        }

        val wasIncluded = includedHeaderCount() > 0

        rule.onNodeWithText(testAppPackage).performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            (includedHeaderCount() > 0) != wasIncluded
        }

        // Selection persists across activity recreation
        rule.activityRule.scenario.onActivity { it.recreate() }
        rule.onNodeWithText("Split Tunnel").performClick()
        rule.onNodeWithText("Include Only").performClick()
        rule.waitUntil(timeoutMillis = 10_000) {
            rule.onAllNodesWithText(testAppPackage).fetchSemanticsNodes().isNotEmpty()
        }
        if (wasIncluded) {
            rule.onAllNodesWithText("Included").assertCountEquals(0)
        } else {
            rule.onNodeWithText("Included").assertExists()
        }

        // Restore the original selection for other tests
        rule.onNodeWithText(testAppPackage).performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            (includedHeaderCount() > 0) == wasIncluded
        }
    }
}
