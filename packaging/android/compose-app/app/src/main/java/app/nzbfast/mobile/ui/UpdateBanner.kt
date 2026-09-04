package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * The one line of news this app has: a newer nzbfast is out.
 *
 * A card at the top of Home rather than a dialog or a system
 * notification. A release is not urgent and interrupting a download to
 * say so would be out of proportion; a card that can be waved away with
 * one tap, and that stays findable in Settings afterwards, is the size of
 * the fact.
 *
 * It offers a LINK and nothing else. There is no download button because
 * there is nothing this app is allowed to do with an APK - see
 * [app.nzbfast.mobile.UpdateNotice] for why that is a boundary rather
 * than a stub.
 */
@Composable
fun UpdateBanner(
    version: String,
    currentVersion: String,
    onOpenReleases: () -> Unit,
    onDismiss: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("nzbfast $version is out", style = MaterialTheme.typography.titleMedium)
            Text(
                if (currentVersion.isEmpty()) {
                    "The releases page has the new version."
                } else {
                    "You are running $currentVersion. The releases page has the new version."
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onOpenReleases) { Text("Open releases page") }
                TextButton(onClick = onDismiss) { Text("Not now") }
            }
        }
    }
}
