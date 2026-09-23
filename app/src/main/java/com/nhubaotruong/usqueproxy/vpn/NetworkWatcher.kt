package com.nhubaotruong.usqueproxy.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log

/**
 * Tracks the system default network via [ConnectivityManager.registerDefaultNetworkCallback]
 * and updates the VPN's underlying networks so Android routes the tunnel's own
 * traffic outside the TUN. Tunnel reconnect is handled entirely by the Go side
 * (upstream MaintainTunnel: CloseError + 1s reconnect), matching the reference app.
 */
class NetworkWatcher(
    private val context: Context,
    private val onUnderlyingNetworks: (Array<Network>?) -> Unit,
) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    private var currentNetwork: Network? = null

    @Volatile
    private var underlyingNetworkSet = false

    private val callback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                currentNetwork = network
                underlyingNetworkSet = false
                onUnderlyingNetworks(arrayOf(network))
                underlyingNetworkSet = true
            }

            override fun onLosing(
                network: Network,
                maxMsToLive: Int,
            ) {
                Log.d(TAG, "Network losing: $network (${maxMsToLive}ms to live)")
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Default network lost: $network")
                if (currentNetwork == network) {
                    currentNetwork = null
                    onUnderlyingNetworks(null)
                }
            }

            override fun onCapabilitiesChanged(
                network: Network,
                caps: NetworkCapabilities,
            ) {
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
