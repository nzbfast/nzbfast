package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * On-device first run: the engine needs a Usenet provider before it
 * can download - the same three fields as the dashboard wizard.
 *
 * [suggestedConnections] is TODO 281 AN4 on the one screen where the
 * number is decided. The daemon's own default for a saved server is 8,
 * which is a figure for a machine on a line that does not move; a phone
 * changes line every time it leaves the house, so the default offered
 * here is derived from what the platform says the current network can do
 * (DeviceProfile.connectionsForLine). It is a DEFAULT and not a lock: the
 * field is editable, because a provider's account limit is a fact about
 * the account that no amount of measuring this end can discover.
 */
@Composable
fun ServerSetupScreen(
    busy: Boolean,
    status: String?,
    suggestedConnections: Int,
    lineNote: String,
    onTest: (host: String, port: Int, tls: Boolean, user: String, pass: String, conns: Int) -> Unit,
    onSave: (host: String, port: Int, tls: Boolean, user: String, pass: String, conns: Int) -> Unit,
) {
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("563") }
    var tls by rememberSaveable { mutableStateOf(true) }
    var user by rememberSaveable { mutableStateOf("") }
    var pass by rememberSaveable { mutableStateOf("") }
    var conns by rememberSaveable { mutableStateOf(suggestedConnections.toString()) }
    val portNum = port.toIntOrNull() ?: 563
    val connNum = (conns.toIntOrNull() ?: suggestedConnections).coerceIn(1, 60)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("News server", style = MaterialTheme.typography.headlineMedium)
        Text(
            "The engine on this phone needs your Usenet provider to download.",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Host") },
            placeholder = { Text("news.example.com") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter(Char::isDigit).take(5) },
                label = { Text("Port") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Checkbox(checked = tls, onCheckedChange = { tls = it })
            Text("SSL/TLS")
        }
        OutlinedTextField(
            value = user,
            onValueChange = { user = it },
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = conns,
            onValueChange = { conns = it.filter(Char::isDigit).take(2) },
            label = { Text("Connections") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(lineNote, style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { onTest(host.trim(), portNum, tls, user.trim(), pass, connNum) },
                enabled = !busy && host.isNotBlank(),
            ) { Text("Test") }
            Button(
                onClick = { onSave(host.trim(), portNum, tls, user.trim(), pass, connNum) },
                enabled = !busy && host.isNotBlank(),
            ) { Text("Save and continue") }
        }
        if (busy) CircularProgressIndicator()
        if (status != null) {
            Text(status, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
