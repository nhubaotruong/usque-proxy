package com.nhubaotruong.usqueproxy.ui.screen

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import com.nhubaotruong.usqueproxy.data.AppInfo
import com.nhubaotruong.usqueproxy.data.SplitMode
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel

@Composable
fun SplitTunnelScreen(viewModel: VpnViewModel) {
    val prefs by viewModel.vpnPrefs.collectAsState()
    val apps by viewModel.installedApps.collectAsState()
    val needsRestart by viewModel.needsRestart.collectAsState()
    var searchQuery by remember { mutableStateOf("") }

    LaunchedEffect(prefs.splitMode) {
        if (prefs.splitMode != SplitMode.ALL) {
            viewModel.loadInstalledApps()
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        if (needsRestart) {
            item {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "Restart to apply changes",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                        )
                        Button(
                            onClick = { viewModel.restartVpn() },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.tertiary,
                                contentColor = MaterialTheme.colorScheme.onTertiary,
                            ),
                        ) {
                            Text("Restart now")
                        }
                    }
                }
                Spacer(Modifier.height(4.dp))
            }
        }

        item {
            Text(
                "Split Tunneling",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(vertical = 12.dp),
            )
            val modes = SplitMode.entries
            val labels = listOf("All Apps", "Include Only", "Exclude Selected")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                modes.forEachIndexed { index, mode ->
                    SegmentedButton(
                        selected = prefs.splitMode == mode,
                        onClick = { viewModel.setSplitMode(mode) },
                        shape = SegmentedButtonDefaults.itemShape(index, modes.size),
                    ) {
                        Text(labels[index], style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
        }

        if (prefs.splitMode != SplitMode.ALL) {
            item {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    label = { Text("Search apps") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Spacer(Modifier.height(8.dp))
            }

            val filtered = apps.filter {
                searchQuery.isBlank() || it.label.contains(searchQuery, ignoreCase = true)
                        || it.packageName.contains(searchQuery, ignoreCase = true)
            }
            val activeApps = when (prefs.splitMode) {
                SplitMode.INCLUDE -> prefs.includedApps
                SplitMode.EXCLUDE -> prefs.excludedApps
                SplitMode.ALL -> emptySet()
            }
            val selected = filtered.filter { it.packageName in activeApps }
            val unselected = filtered.filter { it.packageName !in activeApps }

            if (selected.isNotEmpty()) {
                item {
                    Text(
                        if (prefs.splitMode == SplitMode.INCLUDE) "Included" else "Excluded",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(vertical = 4.dp),
                    )
                }
                items(selected, key = { it.packageName }) { app ->
                    AppRow(app, checked = true, onToggle = { viewModel.toggleApp(app.packageName) })
                }
                if (unselected.isNotEmpty()) {
                    item { HorizontalDivider(Modifier.padding(vertical = 4.dp)) }
                }
            }

            if (unselected.isNotEmpty()) {
                item {
                    Text(
                        "Other apps",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp),
                    )
                }
                items(unselected, key = { it.packageName }) { app ->
                    AppRow(app, checked = false, onToggle = { viewModel.toggleApp(app.packageName) })
                }
            }
        }

        item { Spacer(Modifier.height(16.dp)) }
    }
}

@Composable
private fun AppRow(app: AppInfo, checked: Boolean, onToggle: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle() }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = rememberDrawablePainter(app.icon),
            contentDescription = null,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(app.label, style = MaterialTheme.typography.bodyMedium)
            Text(
                app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Checkbox(checked = checked, onCheckedChange = { onToggle() })
    }
}
