package com.nhubaotruong.usqueproxy.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.nhubaotruong.usqueproxy.ui.component.RestartBanner
import com.nhubaotruong.usqueproxy.data.DnsMode
import com.nhubaotruong.usqueproxy.data.ProfileType
import com.nhubaotruong.usqueproxy.data.ThemeMode
import com.nhubaotruong.usqueproxy.ui.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel) {
    val prefs by viewModel.vpnPrefs.collectAsState()
    val isRegistering by viewModel.isRegistering.collectAsState()
    val registerError by viewModel.registerError.collectAsState()
    val needsRestart by viewModel.needsRestart.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        // Restart banner
        if (needsRestart) {
            item {
                RestartBanner(onRestart = { viewModel.restartVpn() })
                Spacer(Modifier.height(4.dp))
            }
        }

        // Profile selector
        item {
            SectionHeader("Profile")
            val profiles = ProfileType.entries
            val profileLabels = listOf("WARP", "ZeroTrust")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                profiles.forEachIndexed { index, profile ->
                    SegmentedButton(
                        selected = prefs.activeProfile == profile,
                        onClick = { viewModel.setActiveProfile(profile) },
                        shape = SegmentedButtonDefaults.itemShape(index, profiles.size),
                    ) {
                        Text(profileLabels[index])
                    }
                }
            }
            Spacer(Modifier.height(4.dp))
            HorizontalDivider()
        }

        // Registration section
        item {
            SectionHeader("Registration")
            if (prefs.isActiveRegistered) {
                val profileLabel = when (prefs.activeProfile) {
                    ProfileType.WARP -> "Device registered"
                    ProfileType.ZERO_TRUST -> "Device registered (ZeroTrust)"
                }
                Text(
                    profileLabel,
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = { viewModel.enroll() },
                        enabled = !isRegistering,
                        modifier = Modifier.weight(1f),
                    ) {
                        if (isRegistering) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                            )
                            Spacer(Modifier.width(8.dp))
                        }
                        Text(if (isRegistering) "Re-enrolling..." else "Re-enroll")
                    }
                    Button(
                        onClick = { viewModel.clearRegistration() },
                        enabled = !isRegistering,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ),
                    ) {
                        Text("Clear")
                    }
                }
            } else if (prefs.activeProfile == ProfileType.WARP) {
                var license by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = license,
                    onValueChange = { license = it },
                    label = { Text("License key (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { viewModel.register(license) },
                    enabled = !isRegistering,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (isRegistering) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(if (isRegistering) "Registering..." else "Register Device")
                }
            } else {
                var jwt by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = jwt,
                    onValueChange = { jwt = it },
                    label = { Text("JWT token") },
                    placeholder = { Text("From https://<team>/warp") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { viewModel.registerWithJwt(jwt) },
                    enabled = !isRegistering && jwt.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (isRegistering) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(if (isRegistering) "Registering..." else "Register with JWT")
                }
            }
            registerError?.let {
                Text(it, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
        }

        // Network section
        item {
            SectionHeader("Network")
            SwitchRow("Bypass local network", prefs.bypassLocalNetwork) {
                viewModel.setBypassLocalNetwork(it)
            }
            SwitchRow("Bypass Microsoft Office 365", prefs.bypassOffice365) {
                viewModel.setBypassOffice365(it)
            }
            SwitchRow("Metered connection", prefs.isMetered) {
                viewModel.setMetered(it)
            }
            Text("DNS", style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(vertical = 8.dp))
            val dnsModes = DnsMode.entries
            val dnsLabels = listOf("System", "Cloudflare", "Custom DoH")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                dnsModes.forEachIndexed { index, mode ->
                    SegmentedButton(
                        selected = prefs.dnsMode == mode,
                        onClick = { viewModel.setDnsMode(mode) },
                        shape = SegmentedButtonDefaults.itemShape(index, dnsModes.size),
                    ) {
                        Text(dnsLabels[index], style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
            if (prefs.dnsMode == DnsMode.CUSTOM_DOH) {
                Spacer(Modifier.height(8.dp))
                var dohUrl by remember(prefs.dohUrl) { mutableStateOf(prefs.dohUrl) }
                OutlinedTextField(
                    value = dohUrl,
                    onValueChange = {
                        dohUrl = it
                        viewModel.setDohUrl(it)
                    },
                    label = { Text("DoH URL") },
                    placeholder = { Text("https://dns.google/dns-query") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
            }
            SwitchRow("Prevent DNS leaks", prefs.preventDnsLeak) {
                viewModel.setPreventDnsLeak(it)
            }
            if (prefs.preventDnsLeak && prefs.dnsMode == DnsMode.SYSTEM) {
                Text(
                    "Enable Private DNS in system settings for encrypted DNS",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 4.dp),
                )
            }
            HorizontalDivider()
        }

        // Connection section
        item {
            SectionHeader("Connection")
            var sni by remember(prefs.customSni) { mutableStateOf(prefs.customSni) }
            OutlinedTextField(
                value = sni,
                onValueChange = {
                    sni = it
                    viewModel.setCustomSni(it)
                },
                label = { Text("Custom SNI") },
                placeholder = {
                    Text(
                        if (prefs.activeProfile == ProfileType.ZERO_TRUST)
                            "zt-masque.cloudflareclient.com"
                        else
                            "consumer-masque.cloudflareclient.com"
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            var uri by remember(prefs.connectUri) { mutableStateOf(prefs.connectUri) }
            OutlinedTextField(
                value = uri,
                onValueChange = {
                    uri = it
                    viewModel.setConnectUri(it)
                },
                label = { Text("Connect URI") },
                placeholder = { Text("https://cloudflareaccess.com") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(Modifier.height(4.dp))
            HorizontalDivider()
        }

        // Appearance section
        item {
            SectionHeader("Appearance")
            val themeModes = ThemeMode.entries
            val themeLabels = listOf("System", "Light", "Dark")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                themeModes.forEachIndexed { index, mode ->
                    SegmentedButton(
                        selected = prefs.themeMode == mode,
                        onClick = { viewModel.setThemeMode(mode) },
                        shape = SegmentedButtonDefaults.itemShape(index, themeModes.size),
                    ) {
                        Text(themeLabels[index])
                    }
                }
            }
            Spacer(Modifier.height(4.dp))
            HorizontalDivider()
        }

        item { Spacer(Modifier.height(16.dp)) }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 12.dp),
    )
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
