package com.zhanry.nestlink

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import org.json.JSONObject

internal data class NativeNetworkSettingsRow(
    val generation: Long,
    val revision: Long,
    val durable: Boolean?,
    val useDeploymentStun: Boolean,
    val privatePrefixes: List<String>,
)

internal fun parseNativeNetworkSettings(json: String): NativeNetworkSettingsRow {
    require(json.length <= 8192)
    val root = JSONObject(json)
    val settings = root.getJSONObject("settings")
    val prefixes = settings.getJSONArray("private_network_prefixes")
    require(root.getLong("generation") > 0 && root.getLong("revision") >= 0 && prefixes.length() <= 32)
    return NativeNetworkSettingsRow(
        generation = root.getLong("generation"),
        revision = root.getLong("revision"),
        durable = if (root.isNull("durable")) null else root.getBoolean("durable"),
        useDeploymentStun = settings.getBoolean("use_deployment_stun"),
        privatePrefixes = List(prefixes.length()) { prefixes.getString(it) },
    )
}

/** Display and collect consent only; Rust validates CIDRs and owns persistence. */
@Composable
internal fun NativeNetworkSettingsPanel(
    row: NativeNetworkSettingsRow?,
    busy: Boolean,
    onSave: (Long, Long, Boolean, String) -> Unit,
) {
    if (row == null) return
    var prefixes by remember(row) { mutableStateOf(row.privatePrefixes.joinToString("\n")) }
    var stun by remember(row) { mutableStateOf(row.useDeploymentStun) }
    var approved by remember(row) { mutableStateOf(false) }
    val chosen = prefixes.lines().map(String::trim).filter(String::isNotEmpty)
    val changed = stun != row.useDeploymentStun || chosen != row.privatePrefixes
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.native_network_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.native_network_description), style = MaterialTheme.typography.bodySmall)
        Row {
            Checkbox(stun, onCheckedChange = { stun = it; approved = false }, enabled = !busy)
            Text(stringResource(R.string.native_network_stun))
        }
        OutlinedTextField(
            value = prefixes,
            onValueChange = { if (it.length <= 4096) { prefixes = it; approved = false } },
            label = { Text(stringResource(R.string.native_network_cidrs)) },
            placeholder = { Text("192.168.1.0/24\nfd12:3456::/32") },
            enabled = !busy,
            minLines = 3,
            maxLines = 6,
            modifier = Modifier.fillMaxWidth(),
        )
        Row {
            Checkbox(approved, onCheckedChange = { approved = it }, enabled = !busy)
            Text(stringResource(R.string.native_network_consent))
        }
        Text(stringResource(R.string.native_network_idle), style = MaterialTheme.typography.bodySmall)
        if (row.durable == false) {
            Text(stringResource(R.string.native_network_durability), color = MaterialTheme.colorScheme.error)
        }
        OutlinedButton(
            onClick = { onSave(row.generation, row.revision, stun, prefixes) },
            enabled = !busy && (changed || row.durable == false) && approved,
        ) { Text(stringResource(R.string.native_network_save)) }
    }
}

internal fun nativeNetworkSettingsJson(stun: Boolean, prefixes: String): String = JSONObject()
    .put("use_deployment_stun", stun)
    .put("private_network_prefixes", JSONArray(prefixes.lines().map(String::trim).filter(String::isNotEmpty)))
    .toString()
