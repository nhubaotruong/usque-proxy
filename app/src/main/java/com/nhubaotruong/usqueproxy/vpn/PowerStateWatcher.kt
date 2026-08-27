package com.nhubaotruong.usqueproxy.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager

/**
 * Observes Doze/power-save state so the dead-man's switch can extend its interval
 * and the service can reconnect when the device exits Doze.
 */
class PowerStateWatcher(
    private val context: Context,
    private val onPowerSaveChanged: (Boolean) -> Unit,
    private val onDeviceIdleChanged: (Boolean) -> Unit,
) {
    private val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> onPowerSaveChanged(pm.isPowerSaveMode)
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> onDeviceIdleChanged(pm.isDeviceIdleMode)
            }
        }
    }

    fun register() {
        context.registerReceiver(
            receiver,
            IntentFilter().apply {
                addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
                addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            },
            Context.RECEIVER_NOT_EXPORTED,
        )
        onPowerSaveChanged(pm.isPowerSaveMode)
        onDeviceIdleChanged(pm.isDeviceIdleMode)
    }

    fun unregister() = runCatching { context.unregisterReceiver(receiver) }
}
