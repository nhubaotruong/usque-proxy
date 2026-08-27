package com.nhubaotruong.usqueproxy.tile

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.vpn.TunnelStateHolder
import com.nhubaotruong.usqueproxy.vpn.UsqueVpnService

class VpnTileService : TileService() {

    companion object {
        fun requestUpdate(context: Context) {
            requestListeningState(
                context,
                ComponentName(context, VpnTileService::class.java),
            )
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (TunnelStateHolder.isRunning) {
            updateTile(Tile.STATE_INACTIVE, "Disconnecting...")
            val intent = Intent(this, UsqueVpnService::class.java).apply {
                action = UsqueVpnService.ACTION_STOP
            }
            startService(intent)
        } else {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                // Permission not granted — open app to handle it
                openApp(MainActivity.ACTION_CONNECT_VPN)
            } else {
                updateTile(Tile.STATE_ACTIVE, "Connecting...")
                val intent = Intent(this, UsqueVpnService::class.java)
                ContextCompat.startForegroundService(this, intent)
            }
        }
    }

    private fun updateTile(
        state: Int = if (TunnelStateHolder.isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE,
        subtitle: String = if (TunnelStateHolder.isRunning) "Connected" else "Disconnected",
    ) {
        val tile = qsTile ?: return
        tile.state = state
        tile.subtitle = subtitle
        tile.updateTile()
    }

    private fun openApp(action: String? = null) {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (action != null) this.action = action
        }
        startActivityAndCollapse(
            PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
    }
}
