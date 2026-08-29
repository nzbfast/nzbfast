package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * The ONE settings sheet the plan's addendum A allows a phone: where the
 * downloads go, whether to hold off on a metered network, and what this
 * phone told the engine about itself. Everything the desktop dashboard
 * does beyond that stays on the desktop.
 *
 * The bottom card is a READOUT and not a set of knobs, deliberately. The
 * numbers are derived (TODO 281 AN4, DeviceProfile) and the point of
 * showing them is that a phone-shaped default is a claim about the device
 * which the user can check - "8 workers on 8 big cores", "512 MB" - not
 * another thing to tune wrongly.
 */
@Composable
fun SettingsScreen(
    sourceLabel: String,
    exportFolder: String?,
    pauseOnMetered: Boolean,
    freeText: String,
    profileLines: List<String>,
    onPickExportFolder: () -> Unit,
    onClearExportFolder: () -> Unit,
    onPauseOnMetered: (Boolean) -> Unit,
    onDisconnect: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Downloading from", style = MaterialTheme.typography.titleMedium)
                Text(sourceLabel, style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = onDisconnect) { Text("Change") }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Where downloads go", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Downloads are written inside the app, which is the fastest place " +
                        "this phone has and needs no permission. Pick a folder and " +
                        "finished downloads are copied there as well.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(freeText, style = MaterialTheme.typography.bodySmall)
                if (exportFolder != null) {
                    Text(
                        exportFolder,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onPickExportFolder) {
                        Text(if (exportFolder == null) "Choose a folder" else "Change folder")
                    }
                    if (exportFolder != null) {
                        TextButton(onClick = onClearExportFolder) { Text("Keep in app only") }
                    }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Hold on mobile data", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Pause downloads while this phone is on a metered network, " +
                                "and carry on when it is back on Wi-Fi.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Switch(checked = pauseOnMetered, onCheckedChange = onPauseOnMetered)
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("This phone", style = MaterialTheme.typography.titleMedium)
                Text(
                    "What the engine on this device was told to size itself from.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                for (line in profileLines) {
                    Text(line, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
