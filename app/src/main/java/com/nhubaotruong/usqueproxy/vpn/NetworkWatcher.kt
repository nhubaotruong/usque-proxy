package com.nhubaotruong.usqueproxy.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log

/**
 * Tracks the system default network via [ConnectivityManager.registerDefaultNetworkCallback].
 * Fires reliably on WiFi ↔ cellular switches, even in background (foreground service).
 *
 * Service-specific actions are wired through lambdas: [onNetworkChanged] feeds
 * `Usquebind.setConnectivity`, [onNetworkSwitched] triggers a tunnel restart on
 * network change, and [onUnderlyingNetworks] updates the VPN's underlying
 * networks so Android routes the tunnel's own traffic outside the TUN.
 */
class NetworkWatcher(
    private val context: Context,
    private val onNetworkChanged: (Boolean) -> Unit,
    private val onNetworkSwitched: () -> Unit,
    private val onUnderlyingNetworks: (Array<Network>?) -> Unit,
) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    private var currentNetwork: Network? = null

    @Volatile
    private var underlyingNetworkSet = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val previous = currentNetwork
            currentNetwork = network
            underlyingNetworkSet = false
            onUnderlyingNetworks(arrayOf(network))
            underlyingNetworkSet = true
            // Tell Go side network is available — it triggers reconnect internally
            // if it was waiting. Only force Android-side reconnect if network changed.
            onNetworkChanged(true)
            if (network != previous) {
                Log.i(TAG, "Default network changed: $previous -> $network")
                onNetworkSwitched()
            }
        }

        override fun onLosing(network: Network, maxMsToLive: Int) {
            // Network handoff in progress — new network should arrive via onAvailable.
            Log.d(TAG, "Network losing: $network (${maxMsToLive}ms to live)")
        }

        override fun onLost(network: Network) {
            Log.i(TAG, "Default network lost: $network")
            if (currentNetwork == network) {
                currentNetwork = null
                onUnderlyingNetworks(null)
                // Don't trigger reconnect — the Go side will detect the broken
                // connection and wait for SetConnectivity(true) instead of
                // hammering failed dials. This saves significant battery.
                onNetworkChanged(false)
            }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Only update once per network — this callback fires very frequently
            // (signal changes, bandwidth updates, etc.) and each setUnderlyingNetworks
            // call wakes the system. We only need it once to confirm validation.
            if (network == currentNetwork && !underlyingNetworkSet &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) {
                underlyingNetworkSet = true
                onUnderlyingNetworks(arrayOf(network))
            }
        }
    }

    fun register() {
        currentNetwork = cm.activeNetwork
        cm.registerDefaultNetworkCallback(callback)
    }

    fun unregister() = runCatching { cm.unregisterNetworkCallback(callback) }

    companion object {
        private const val TAG = "UsqueVpnService"
    }
}
