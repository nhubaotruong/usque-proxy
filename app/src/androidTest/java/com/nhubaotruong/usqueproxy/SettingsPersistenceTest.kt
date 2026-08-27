package com.nhubaotruong.usqueproxy

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.test.hasAnySibling
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Settings changes are persisted to DataStore and survive activity recreation.
 * The switch state is read from the real semantics tree (ToggleableState).
 */
class SettingsPersistenceTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Before
    fun resetTunnelState() {
        TunnelStateHolder.isRunning = false
        TunnelStateHolder.lastError = null
    }

    private fun autoConnectSwitch() = rule.onNode(
        isToggleable() and hasAnySibling(hasText("Connect on startup")),
        useUnmergedTree = true,
    )

    private fun switchState(): ToggleableState =
        autoConnectSwitch().fetchSemanticsNode().config[SemanticsProperties.ToggleableState]

    @Test
    fun autoConnectSettingPersistsAcrossRecreation() {
        rule.onNodeWithText("Settings").performClick()

        val initiallyOn = switchState() == ToggleableState.On
        val target = if (initiallyOn) ToggleableState.Off else ToggleableState.On

        autoConnectSwitch().performClick()
        rule.waitUntil(timeoutMillis = 5_000) { switchState() == target }

        rule.activityRule.scenario.onActivity { it.recreate() }

        // Pager resets to Home on recreation — navigate back to Settings
        rule.onNodeWithText("Settings").performClick()
        rule.waitUntil(timeoutMillis = 5_000) { switchState() == target }

        // Restore the original value for other tests
        autoConnectSwitch().performClick()
        rule.waitUntil(timeoutMillis = 5_000) {
            switchState() == if (initiallyOn) ToggleableState.On else ToggleableState.Off
        }
        assertEquals(initiallyOn, switchState() == ToggleableState.On)
    }
}
