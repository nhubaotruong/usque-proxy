package com.nhubaotruong.usqueproxy.tile

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.nhubaotruong.usqueproxy.MainActivity
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

    fun onTileLongClick() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        collapseAndStartActivity(intent)
    }

    override fun onClick() {
        super.onClick()
        val tile = qsTile ?: return
        if (UsqueVpnService.isRunning) {
            // Immediately show inactive state
            tile.state = Tile.STATE_INACTIVE
            tile.subtitle = "Disconnecting..."
            tile.updateTile()
            // Stop VPN
            val intent = Intent(this, UsqueVpnService::class.java).apply {
                action = UsqueVpnService.ACTION_STOP
            }
            startService(intent)
        } else {
            // Start VPN — need to check permission first
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                // Permission not granted — launch MainActivity to handle it
                val intent = Intent(this, MainActivity::class.java).apply {
                    action = MainActivity.ACTION_CONNECT_VPN
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                collapseAndStartActivity(intent)
            } else {
                // Immediately show active state
                tile.state = Tile.STATE_ACTIVE
                tile.subtitle = "Connecting..."
                tile.updateTile()
                // Permission granted — start service directly
                val intent = Intent(this, UsqueVpnService::class.java)
                ContextCompat.startForegroundService(this, intent)
            }
        }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        if (UsqueVpnService.isRunning) {
            tile.state = Tile.STATE_ACTIVE
            tile.subtitle = "Connected"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.subtitle = "Disconnected"
        }
        tile.updateTile()
    }

    private fun collapseAndStartActivity(intent: Intent) {
        startActivityAndCollapse(
            android.app.PendingIntent.getActivity(
                this, 0, intent,
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
    }
}
