package com.nhubaotruong.usqueproxy

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Bottom-nav pager navigation between Home / Split Tunnel / Settings.
 * Uses the real nav bar labels from [com.nhubaotruong.usqueproxy.ui.nav.AppNavigation].
 */
class NavigationTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Before
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.lastError = null
    }

    @Test
    fun navigatesBetweenTabs() {
        // Home is the default tab
        rule.onNodeWithText("Connect").assertExists()

        // Settings tab — "Profile" is the first section header, always visible
        rule.onNodeWithText("Settings").performClick()
        rule.onNodeWithText("Profile").assertExists()

        // Split Tunnel tab — "Split Tunneling" is the screen title
        rule.onNodeWithText("Split Tunnel").performClick()
        rule.onNodeWithText("Split Tunneling").assertExists()

        // Back to Home
        rule.onNodeWithText("Home").performClick()
        rule.onNodeWithText("Connect").assertExists()
    }
}
