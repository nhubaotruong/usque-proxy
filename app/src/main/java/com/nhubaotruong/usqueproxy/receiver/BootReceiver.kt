package com.nhubaotruong.usqueproxy.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import com.nhubaotruong.usqueproxy.data.VpnPreferences
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val prefs = VpnPreferences(context).prefsFlow.first()
                if (!prefs.autoConnect) return@launch
                if (!prefs.isActiveRegistered || prefs.activeConfigJson.isEmpty()) return@launch

                // VPN permission persists across reboots; if revoked, we can't prompt from a receiver
                if (VpnService.prepare(context) != null) {
                    Log.w(TAG, "VPN permission not granted, skipping auto-connect")
                    return@launch
                }

                Log.i(TAG, "Auto-connecting VPN on boot")
                val svcIntent = Intent(context, UsqueVpnService::class.java)
                ContextCompat.startForegroundService(context, svcIntent)
            } finally {
                pendingResult.finish()
            }
        }
    }
}
