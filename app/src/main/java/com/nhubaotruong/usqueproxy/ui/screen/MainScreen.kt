package com.nhubaotruong.usqueproxy.ui.screen

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.ui.viewmodel.TunnelStats
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnState
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: VpnViewModel,
    onNavigateToSettings: () -> Unit,
    onRequestVpnPermission: () -> Unit,
) {
    val vpnState by viewModel.vpnState.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val prefs by viewModel.vpnPrefs.collectAsState()
    val tunnelError by viewModel.tunnelError.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("UsqueProxy") },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            ConnectButton(
                state = vpnState,
                isRegistered = prefs.isActiveRegistered,
                onConnect = onRequestVpnPermission,
                onDisconnect = { viewModel.disconnect() },
            )

            Spacer(Modifier.height(24.dp))

            StatusText(vpnState, prefs.activeProfile)

            tunnelError?.let { error ->
                Spacer(Modifier.height(12.dp))
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 32.dp),
                )
                TextButton(onClick = { viewModel.clearTunnelError() }) {
                    Text("Dismiss")
                }
            }

            if (vpnState == VpnState.CONNECTED) {
                Spacer(Modifier.height(16.dp))
                StatsDisplay(stats)
            }
        }
    }
}

@Composable
private fun ConnectButton(
    state: VpnState,
    isRegistered: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val scale by animateFloatAsState(
        targetValue = if (state == VpnState.CONNECTING) 0.95f else 1f,
        animationSpec = tween(300),
        label = "button_scale",
    )

    val containerColor by animateColorAsState(
        targetValue = when (state) {
            VpnState.DISCONNECTED -> MaterialTheme.colorScheme.primaryContainer
            VpnState.CONNECTING -> MaterialTheme.colorScheme.tertiaryContainer
            VpnState.CONNECTED -> MaterialTheme.colorScheme.errorContainer
        },
        label = "button_color",
    )

    FilledTonalButton(
        onClick = {
            when (state) {
                VpnState.DISCONNECTED -> onConnect()
                VpnState.CONNECTED -> onDisconnect()
                VpnState.CONNECTING -> {} // ignore
            }
        },
        enabled = state != VpnState.CONNECTING && isRegistered,
        modifier = Modifier
            .size(160.dp)
            .scale(scale),
        colors = androidx.compose.material3.ButtonDefaults.filledTonalButtonColors(
            containerColor = containerColor,
        ),
    ) {
        Text(
            text = when (state) {
                VpnState.DISCONNECTED -> "Connect"
                VpnState.CONNECTING -> "Connecting..."
                VpnState.CONNECTED -> "Disconnect"
            },
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun StatusText(state: VpnState, activeProfile: ProfileType) {
    val text = when (state) {
        VpnState.DISCONNECTED -> "Not connected"
        VpnState.CONNECTING -> "Establishing tunnel..."
        VpnState.CONNECTED -> when (activeProfile) {
            ProfileType.WARP -> "Connected via WARP"
            ProfileType.ZERO_TRUST -> "Connected via ZeroTrust"
        }
    }
    val color = when (state) {
        VpnState.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
        VpnState.CONNECTING -> MaterialTheme.colorScheme.tertiary
        VpnState.CONNECTED -> MaterialTheme.colorScheme.primary
    }
    Text(text, style = MaterialTheme.typography.bodyLarge, color = color)
}

@Composable
private fun StatsDisplay(stats: TunnelStats) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            formatUptime(stats.uptimeSec),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Upload", style = MaterialTheme.typography.labelSmall)
                Text(formatBytes(stats.txBytes), style = MaterialTheme.typography.bodyMedium)
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Download", style = MaterialTheme.typography.labelSmall)
                Text(formatBytes(stats.rxBytes), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

private fun formatUptime(seconds: Int): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return "%02d:%02d:%02d".format(h, m, s)
}

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
    bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024))
    else -> "%.2f GB".format(bytes / (1024.0 * 1024 * 1024))
}
