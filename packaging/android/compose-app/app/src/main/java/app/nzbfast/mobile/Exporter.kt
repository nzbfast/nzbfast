package app.nzbfast.mobile

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File

/**
 * TODO 281 AN3: copying a finished payload out of app-private storage into
 * a folder the user picked.
 *
 * WHY DOWNLOADS DO NOT GO STRAIGHT THERE. The plan's decision, and it is
 * about the writer rather than about permissions: the one-pass path
 * preallocates a file and writes RANGES into it as articles arrive, out of
 * order, from several threads. A SAF document has neither operation - a
 * `content://` URI opens as a stream, there is no `pwrite` and no
 * `set_len`, and re-opening one costs an IPC round trip into the provider
 * that owns it. Aiming the engine at one would cost preallocation, range
 * writes and the resume-at-offset journal in a single move. Copying a
 * FINISHED payload out, on the other hand, is one sequential read and one
 * sequential write, which is the shape SAF is actually good at.
 *
 * Written against `DocumentsContract` directly rather than through
 * androidx.documentfile: the whole of what is needed here is create,
 * list-children and open-output, all three of them platform API since
 * before this app's minSdk, and a dependency that exists to wrap three
 * calls is a dependency that has to be resolved on every build of this
 * app forever.
 */
object Exporter {

    /** What one export did, for the caller to report. */
    data class Result(val copied: Int, val skipped: Int, val error: String?)

    /**
     * Copy everything at [source] into a folder named [jobName] under
     * [tree], for the job [nzoId].
     *
     * IDEMPOTENT by construction, which matters because the caller is a
     * POLL: a destination file that already exists is skipped rather than
     * written again. That is also why the existing child is looked up
     * before creating one - `DocumentsContract.createDocument` does not
     * refuse a name it already holds, it invents a fresh one ("movie
     * (1).mkv"), so a create-first loop would fill the user's folder with
     * numbered copies of the same file on every poll.
     *
     * TWO THINGS KEEP THE SKIP HONEST, because a name is not an identity
     * (Codex sweep 27 Aug, C01). The destination folder is keyed to
     * [nzoId] through a marker file, so a second job with the same
     * displayed name gets its own folder rather than being silently
     * skipped against the first one's bytes. And a file only ever gets
     * its finished name AFTER a full-length copy: the write goes to a
     * temp name, the copied length is checked against the source, and
     * the rename is last - so a copy cut short by process death never
     * matches the finished-name check and is deleted and redone on the
     * next poll.
     */
    fun export(ctx: Context, tree: Uri, source: File, jobName: String, nzoId: String): Result {
        val cr = ctx.contentResolver
        val files = when {
            source.isDirectory -> source.walkTopDown().filter { it.isFile }.toList()
            source.isFile -> listOf(source)
            else -> return Result(0, 0, "the payload is no longer on this phone")
        }
        if (files.isEmpty()) return Result(0, 0, "nothing to copy")

        val treeDocId = runCatching { DocumentsContract.getTreeDocumentId(tree) }.getOrNull()
            ?: return Result(0, 0, "that folder is not available any more")
        val treeDoc = DocumentsContract.buildDocumentUriUsingTree(tree, treeDocId)

        val dest = destDirFor(cr, tree, treeDoc, safeName(jobName), nzoId)
            ?: return Result(0, 0, "could not create a folder there")
        val destId = DocumentsContract.getDocumentId(dest)

        var copied = 0
        var skipped = 0
        // Listed ONCE, before the loop: the child listing is a provider
        // query, and asking it per file turns an export of a 40-part set
        // into 40 IPC round trips that all answer the same question.
        val existing = childNames(cr, tree, destId)
        for (f in files) {
            // A nested path is FLATTENED with its parent folders in the
            // name rather than recreated as a tree. A payload that
            // extracted into subdirectories is rare, and one file per
            // provider round trip is already the expensive part; making it
            // recursive would add a directory create per level for a shape
            // almost nothing produces.
            val name = safeName(f.relativeToOrSelf(source).path.replace('/', '_'))
            if (existing.contains(name)) {
                skipped++
                continue
            }
            val tmpName = name + PART_SUFFIX
            if (existing.contains(tmpName)) {
                // A leftover temp is a copy that never finished (process
                // death mid write). It never matches the finished-name
                // check above, so it cannot be mistaken for done; delete
                // it and copy again.
                childOf(cr, tree, destId, tmpName, dirsOnly = false)?.let {
                    runCatching { DocumentsContract.deleteDocument(cr, it) }
                }
            }
            val srcLen = f.length()
            val out = runCatching {
                DocumentsContract.createDocument(cr, dest, GENERIC_MIME, tmpName)
            }.getOrNull() ?: return Result(copied, skipped, "could not write $name")
            val wrote = runCatching {
                cr.openOutputStream(out).use { os ->
                    if (os == null) return@runCatching -1L
                    f.inputStream().use { it.copyTo(os, 256 * 1024) }
                }
            }.getOrDefault(-1L)
            // Only a full-length copy is promoted to the finished name,
            // measured against the source as it stood before the copy: a
            // truncated write must never become a file the skip keeps.
            if (wrote != srcLen) {
                runCatching { DocumentsContract.deleteDocument(cr, out) }
                return Result(copied, skipped, "could not write $name")
            }
            val renamed = runCatching {
                DocumentsContract.renameDocument(cr, out, name)
            }.getOrNull()
            if (renamed == null) {
                runCatching { DocumentsContract.deleteDocument(cr, out) }
                return Result(copied, skipped, "could not write $name")
            }
            copied++
        }
        return Result(copied, skipped, null)
    }

    /**
     * The destination directory for THIS job, keyed by [nzoId].
     *
     * The existing-first lookup is for the reason in [export]: create
     * does not fail on a duplicate name, so an unconditional create makes
     * a second folder called "job (1)" every time a poll comes round. But
     * an existing directory of the right NAME is not enough - two
     * distinct jobs can carry one displayed name, and reusing the first
     * one's folder would skip the second's files against the wrong bytes.
     * So a directory counts as this job's only when its [MARKER] records
     * this [nzoId]; otherwise the name is stepped ("job (2)", ...) until
     * one that is ours or free turns up.
     */
    private fun destDirFor(
        cr: ContentResolver,
        tree: Uri,
        parent: Uri,
        name: String,
        nzoId: String,
    ): Uri? {
        val parentId = DocumentsContract.getDocumentId(parent)
        for (k in 0 until 20) {
            val candidate = if (k == 0) name else safeName("$name (${k + 1})")
            val existing = childOf(cr, tree, parentId, candidate, dirsOnly = true)
            if (existing == null) {
                val dir = runCatching {
                    DocumentsContract.createDocument(
                        cr,
                        parent,
                        DocumentsContract.Document.MIME_TYPE_DIR,
                        candidate,
                    )
                }.getOrNull() ?: return null
                // The marker goes in FIRST: a folder with no marker is
                // never this job's on a later poll, so a death between
                // create and marker costs one stepped name, not a wrong
                // skip.
                if (!writeMarker(cr, dir, nzoId)) return null
                return dir
            }
            val dirId = DocumentsContract.getDocumentId(existing)
            if (markerMatches(cr, tree, dirId, nzoId)) return existing
        }
        return null
    }

    /** Whether [dirId]'s [MARKER] records exactly [nzoId]. */
    private fun markerMatches(
        cr: ContentResolver,
        tree: Uri,
        dirId: String,
        nzoId: String,
    ): Boolean {
        val marker = childOf(cr, tree, dirId, MARKER, dirsOnly = false) ?: return false
        val content = runCatching {
            cr.openInputStream(marker)?.use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull() ?: return false
        return content == nzoId
    }

    private fun writeMarker(cr: ContentResolver, dir: Uri, nzoId: String): Boolean {
        val doc = runCatching {
            DocumentsContract.createDocument(cr, dir, GENERIC_MIME, MARKER)
        }.getOrNull() ?: return false
        return runCatching {
            cr.openOutputStream(doc).use { os ->
                if (os == null) return@runCatching false
                os.write(nzoId.toByteArray(Charsets.UTF_8))
                true
            }
        }.getOrDefault(false)
    }

    private fun childOf(
        cr: ContentResolver,
        tree: Uri,
        parentId: String,
        name: String,
        dirsOnly: Boolean,
    ): Uri? {
        val kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId)
        return runCatching {
            cr.query(
                kids,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                ),
                null,
                null,
                null,
            )?.use { c ->
                while (c.moveToNext()) {
                    if (c.getString(1) != name) continue
                    if (dirsOnly && c.getString(2) != DocumentsContract.Document.MIME_TYPE_DIR) {
                        continue
                    }
                    return@use DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0))
                }
                null
            }
        }.getOrNull()
    }

    private fun childNames(cr: ContentResolver, tree: Uri, parentId: String): Set<String> {
        val kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId)
        return runCatching {
            val out = HashSet<String>()
            cr.query(
                kids,
                arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
                null,
                null,
                null,
            )?.use { c -> while (c.moveToNext()) out.add(c.getString(0)) }
            out
        }.getOrDefault(emptySet())
    }

    /**
     * A name a document provider will accept.
     *
     * The separator is stripped because a display name is a NAME and not a
     * path: a provider handed "a/b" is free to read it as a nested create,
     * to reject it, or to write a file with a slash in it, and which of
     * those happens depends on whose provider it is. The rest of the set
     * is what the FAT-derived filesystems behind an SD card refuse.
     */
    internal fun safeName(raw: String): String {
        val cleaned = raw.map { c ->
            if (c in "/\\:*?\"<>|" || c.code < 0x20) '_' else c
        }.joinToString("").trim().trimEnd('.')
        // 200 rather than 255: the provider may append a disambiguating
        // suffix of its own, and a name that survives to disk is worth
        // more than the last few characters of one that does not.
        val bounded = if (cleaned.length > 200) cleaned.take(200) else cleaned
        return bounded.ifEmpty { "download" }
    }

    /**
     * One general type for every file, deliberately.
     *
     * A provider handed a SPECIFIC mime type is entitled to rewrite the
     * display name so the extension matches it, and several do - which
     * turns "movie.mkv" into "movie.mkv.mkv" and makes the
     * already-exported check in [export] miss its own output on the next
     * poll. The extension in the name is what file managers and the media
     * scanner key off in any case, and it is preserved exactly because
     * nothing is claimed about the type.
     */
    private const val GENERIC_MIME = "application/octet-stream"

    /**
     * The per-folder identity record: a hidden file inside each export
     * directory whose content is the nzo_id the folder was created for.
     * It is what lets [destDirFor] tell "this job's folder" from "another
     * job that happened to share the displayed name".
     */
    private const val MARKER = ".nzbfast-job"

    /**
     * The in-flight suffix. A copy is written under `<name>.nzbfast-part`
     * and renamed only after its length checks out, so nothing with the
     * finished name is ever less than the whole file. [safeName] caps at
     * 200 so the suffix keeps the temp under a provider's 255.
     */
    private const val PART_SUFFIX = ".nzbfast-part"
}
