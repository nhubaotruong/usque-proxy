package com.nhubaotruong.usqueproxy.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.nhubaotruong.usqueproxy.MainActivity
import com.nhubaotruong.usqueproxy.R

/** Owns the VPN foreground notification — create/update/cancel, extracted from the service. */
class VpnNotification(private val context: Context) {
    private val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    init {
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "UsqueProxy VPN status" },
        )
    }

    fun showConnecting() = show("Connecting...")
    fun showConnected() = show("VPN is active")
    fun showDisconnecting() = show("Disconnecting...")
    fun showError(message: String) = show("Connection error", message)
    fun show(status: String) = show("UsqueProxy", status)
    /** Notification for [android.app.Service.startForeground] — shows the connecting state. */
    fun buildConnecting(): Notification = build("UsqueProxy", "Connecting...")
    fun cancel() = nm.cancel(NOTIFICATION_ID)

    private fun show(title: String, text: String) {
        runCatching { nm.notify(NOTIFICATION_ID, build(title, text)) }
    }

    private fun build(title: String, text: String): Notification {
        val stopIntent = Intent(context, UsqueVpnService::class.java).apply {
            action = UsqueVpnService.ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            context, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE,
        )
        val openIntent = Intent(context, MainActivity::class.java)
        val openPending = PendingIntent.getActivity(
            context, 0, openIntent, PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentIntent(openPending)
            .addAction(Notification.Action.Builder(null, "Disconnect", stopPending).build())
            .setOngoing(true)
            .build()
    }

    companion object {
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1
    }
}
