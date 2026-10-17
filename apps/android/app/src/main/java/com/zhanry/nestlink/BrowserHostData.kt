package com.zhanry.nestlink

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Full proof comparison; key order cannot alias or invalidate an identity. */
internal fun sameBrowserProofJson(left: String, right: String): Boolean = runCatching {
    require(left.length <= 4_096 && right.length <= 4_096)
    val a = JSONObject(left)
    val b = JSONObject(right)
    val stringKeys = setOf("request_id", "session_id", "controller_device_id", "host_device_id")
    val hashKeys = setOf("controller_key_sha256", "host_key_sha256", "permit_sha256")
    val keys = stringKeys + hashKeys + "connection_generation"
    require(a.keys().asSequence().toSet() == keys && b.keys().asSequence().toSet() == keys)
    require(stringKeys.all { key ->
        val value = a.getString(key)
        a.get(key) is String && b.get(key) is String && value.length == 36 &&
            UUID.fromString(value).toString() == value && value != "00000000-0000-0000-0000-000000000000" && value == b.getString(key)
    })
    require((a.get("connection_generation") is Int || a.get("connection_generation") is Long) && (b.get("connection_generation") is Int || b.get("connection_generation") is Long))
    require(a.getLong("connection_generation") > 0 && a.getLong("connection_generation") == b.getLong("connection_generation"))
    require(hashKeys.all { key ->
        val aa = a.getJSONArray(key)
        val bb = b.getJSONArray(key)
        aa.length() == 32 && bb.length() == 32 && (0 until 32).all { index ->
            val value = aa.getLong(index)
            val other = bb.getLong(index)
            (aa.get(index) is Int || aa.get(index) is Long) && (bb.get(index) is Int || bb.get(index) is Long) &&
                value in 0L..255L && other in 0L..255L && value == other
        }
    })
    true
}.getOrDefault(false)

internal fun HostCaptureBinding.BrowserHost.hasExactProof(): Boolean = runCatching {
    sameBrowserProofJson(bindingJson, bindingJson) && JSONObject(bindingJson).let {
        it.getString("request_id") == requestId && it.getLong("connection_generation") == connectionGeneration
    }
}.getOrDefault(false)

internal data class BrowserHostDataRow(
    val filesAvailable: Boolean = false,
    val clipboardAvailable: Boolean = false,
    val fileRead: Boolean = false,
    val fileWrite: Boolean = false,
    val clipboardRead: Boolean = false,
    val clipboardWrite: Boolean = false,
    val localRead: Boolean = false,
    val localWrite: Boolean = false,
    val restartRequired: Boolean = false,
)

internal fun parseBrowserHostData(json: String, binding: HostCaptureBinding.BrowserHost): BrowserHostDataRow {
    require(json.length <= 32_768)
    require(binding.hasExactProof())
    val payload = JSONObject(json)
    require(sameBrowserProofJson(payload.getJSONObject("binding").toString(), binding.bindingJson)) { uiText(UiTextKey.THE_BROWSER_SESSION_HAS_BEEN_REPLACED_41991) }
    val data = payload.getJSONObject("data")
    val row = BrowserHostDataRow(
        filesAvailable = data.getBoolean("files_available"), clipboardAvailable = data.getBoolean("clipboard_available"),
        fileRead = data.getBoolean("permitted_file_read"), fileWrite = data.getBoolean("permitted_file_write"),
        clipboardRead = data.getBoolean("permitted_clipboard_read"), clipboardWrite = data.getBoolean("permitted_clipboard_write"),
        localRead = data.getBoolean("local_clipboard_read"), localWrite = data.getBoolean("local_clipboard_write"),
        restartRequired = data.getBoolean("clipboard_restart_required"),
    )
    require((!row.localRead || row.clipboardRead) && (!row.localWrite || row.clipboardWrite))
    return row
}

internal fun parseBrowserHostFiles(json: String, binding: HostCaptureBinding.BrowserHost): NativeHostFilesRow {
    require(json.length <= 131_072)
    require(binding.hasExactProof())
    val payload = JSONObject(json)
    val actual = payload.getJSONObject("identity")
    require(actual.length() == 1 && sameBrowserProofJson(actual.getJSONObject("browser_binding").toString(), binding.bindingJson)) { uiText(UiTextKey.THE_BROWSER_FILE_STATUS_BELONGS_TO_C32E9) }
    return parseLocalHostFilesPayload(payload)
}

internal enum class BrowserSafDirection { Share, Export }

/** A one-use local capability. A URI and an FD never become a wire root path. */
internal class BrowserSafGrant internal constructor(
    val handle: Long,
    val binding: HostCaptureBinding.BrowserHost,
    val direction: BrowserSafDirection,
    val artifactId: String?,
    val displayName: String? = null,
) {
    val id: String = UUID.randomUUID().toString()
    private val consumed = AtomicBoolean(false)
    fun consume(handle: Long, owner: HostCaptureBinding?, direction: BrowserSafDirection): Boolean =
        consumed.compareAndSet(false, true) && this.handle == handle && this.direction == direction &&
            owner is HostCaptureBinding.BrowserHost && owner.hasExactProof() && binding.sameOwner(owner)
}

internal class BrowserSafGrantRegistry {
    private var pending: BrowserSafGrant? = null
    @Synchronized fun issue(handle: Long, binding: HostCaptureBinding.BrowserHost, direction: BrowserSafDirection, artifactId: String? = null, displayName: String? = null): BrowserSafGrant {
        check(pending == null) { uiText(UiTextKey.FINISH_OR_CANCEL_THE_OPEN_SYSTEM_C69C8) }
        require(handle > 0 && binding.hasExactProof())
        require((direction == BrowserSafDirection.Export) == (artifactId != null))
        return BrowserSafGrant(handle, binding, direction, artifactId, displayName).also { pending = it }
    }
    @Synchronized fun take(direction: BrowserSafDirection): BrowserSafGrant? =
        pending?.takeIf { it.direction == direction }?.also { pending = null }
    @Synchronized fun cancel(grant: BrowserSafGrant) { if (pending === grant) pending = null }
    @Synchronized fun hasPending(): Boolean = pending != null
}

internal data class BrowserSafCleanupTarget<T>(
    val id: String,
    val handle: Long,
    val target: T,
    val displayName: String,
    val busy: Boolean = true,
    val detail: String = uiText(UiTextKey.THE_CURRENT_FILE_TASK_STILL_OWNS_8F314),
)

/** Cleanup authority for a created target outlives any remote session owner. */
internal class BrowserSafCleanupRegistry<T> {
    private val entries = linkedMapOf<String, BrowserSafCleanupTarget<T>>()
    private val updates = MutableStateFlow<List<BrowserSafCleanupTarget<T>>>(emptyList())
    val state: StateFlow<List<BrowserSafCleanupTarget<T>>> = updates.asStateFlow()
    @Synchronized fun retain(handle: Long, target: T, displayName: String): BrowserSafCleanupTarget<T>? {
        if (entries.values.any { it.target == target }) return null
        return BrowserSafCleanupTarget(UUID.randomUUID().toString(), handle, target, displayName).also {
            entries[it.id] = it
            updates.value = entries.values.toList()
        }
    }
    @Synchronized fun hasRetained(): Boolean = entries.isNotEmpty()
    @Synchronized fun waiting(id: String, detail: String) {
        entries[id]?.let { entries[id] = it.copy(busy = true, detail = detail) }
        updates.value = entries.values.toList()
    }
    @Synchronized fun finish(id: String, receipt: SafDestinationCleanupReceipt) {
        if (receipt.complete) entries.remove(id)
        else entries[id]?.let { entries[id] = it.copy(busy = false, detail = receipt.detail) }
        updates.value = entries.values.toList()
    }
    @Synchronized fun retry(id: String): BrowserSafCleanupTarget<T>? {
        val entry = entries[id]?.takeUnless { it.busy } ?: return null
        entries[id] = entry.copy(busy = true, detail = uiText(UiTextKey.RETRYING_CLEANUP_OF_THE_SYSTEM_SAVE_406FA))
        updates.value = entries.values.toList()
        return entry
    }
    @Synchronized fun observe(id: String, status: NativeSafExportRow): Boolean {
        if (status.ownerRetained()) {
            waiting(id, uiText(UiTextKey.SAVING_OR_DESTINATION_CLEANUP_IS_STILL_CDBE4))
            return false
        }
        finish(id, SafDestinationCleanupReceipt(
            status.destinationCleanupComplete,
            status.destinationCleanupError ?: uiText(UiTextKey.DESTINATION_CLEANUP_IS_UNCONFIRMED_RETRY_CLEANUP_49619),
        ))
        return true
    }
}

internal fun <T> browserSafProviderCall(authorize: () -> Boolean, operation: () -> T): T {
    check(authorize()) { uiText(UiTextKey.THE_BROWSER_FILE_PERMISSION_LEASE_HAS_7E72B) }
    return operation()
}

private data class BrowserLocalOwner(val handle: Long, val binding: HostCaptureBinding.BrowserHost)

/** Process-local owners survive a Compose replacement and Activity rotation. */
private object BrowserHostLocalOwners {
    val grants = BrowserSafGrantRegistry()
    val destinations = BrowserSafCleanupRegistry<Uri>()
    private var owner: BrowserLocalOwner? = null
    private var endpoint: NativeClipboardEndpoint? = null
    @Synchronized fun update(value: BrowserLocalOwner?) {
        if (owner == value) return
        endpoint?.close()
        endpoint = null
        owner = value
    }
    @Synchronized fun current(value: BrowserLocalOwner): Boolean = owner == value && !NativeSafPickerOwners.isClosing(value.handle)
    @Synchronized fun currentHandle(): Long = owner?.handle ?: 0L
    @Synchronized fun endpoint(value: BrowserLocalOwner): NativeClipboardEndpoint? = endpoint.takeIf { owner == value }
    @Synchronized fun install(value: BrowserLocalOwner, candidate: NativeClipboardEndpoint) {
        check(current(value) && endpoint == null) { uiText(UiTextKey.THE_BROWSER_CLIPBOARD_SESSION_HAS_BEEN_94380) }
        endpoint = candidate
    }
    @Synchronized fun discard(value: BrowserLocalOwner, candidate: NativeClipboardEndpoint) {
        candidate.close()
        if (owner == value && endpoint === candidate) endpoint = null
    }
}

private object BrowserHostDataWorkers {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    fun launch(handle: Long, work: suspend () -> Unit) {
        // NonCancellable preserves the actual blocked provider call. Close waits
        // for this same retained Job before releasing the JNI session handle.
        val worker = scope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) { work() }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }
}

private fun browserCurrent(owner: BrowserLocalOwner): Boolean =
    BrowserHostLocalOwners.current(owner) && runCatching {
        parseBrowserHostData(NativeSdk.nativeBrowserHostDataStatus(owner.handle, owner.binding.bindingJson), owner.binding)
        true
    }.getOrDefault(false)

private fun browserFileCurrent(owner: BrowserLocalOwner, write: Boolean): Boolean =
    BrowserHostLocalOwners.current(owner) && runCatching {
        NativeSdk.nativeBrowserHostFilePlatformAllowed(owner.handle, owner.binding.bindingJson, write)
    }.getOrDefault(false)

private fun browserDisplayName(resolver: ContentResolver, uri: Uri): String {
    val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        if (!cursor.moveToFirst()) null else cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let(cursor::getString)
    } ?: "document"
    require(isPortableDocumentName(name)) { uiText(UiTextKey.THE_SELECTED_FILE_NAME_IS_NOT_3B07F) }
    return name
}

private fun browserCleanupDestination(context: Context, uri: Uri): SafDestinationCleanupReceipt {
    val resolver = context.contentResolver
    return cleanupCreatedSafDestination(
        deleteDocument = { DocumentsContract.isDocumentUri(context, uri) && DocumentsContract.deleteDocument(resolver, uri) },
        clearDocument = {
            val descriptor = resolver.openFileDescriptor(uri, "rw") ?: error(uiText(UiTextKey.THE_SAVE_DESTINATION_COULD_NOT_BE_88DA2))
            descriptor.use { pfd ->
                val fd = pfd.fileDescriptor
                require(OsConstants.S_ISREG(Os.fstat(fd).st_mode))
                Os.ftruncate(fd, 0L)
                Os.fsync(fd)
                check(Os.fstat(fd).st_size == 0L)
            }
        },
    )
}

private suspend fun observeBrowserExportDestination(
    context: Context,
    owner: BrowserLocalOwner,
    grant: BrowserSafGrant,
    destination: BrowserSafCleanupTarget<Uri>,
) {
    while (true) {
        val status = runCatching {
            val raw = NativeSdk.nativeBrowserHostFileExportStatus(owner.handle, owner.binding.bindingJson, grant.id)
            if (raw.trim() == "null") null else parseNativeSafExport(raw, requireNotNull(grant.artifactId))
        }
        if (status.isFailure) {
            BrowserHostLocalOwners.destinations.waiting(destination.id, uiText(UiTextKey.SAVING_AND_CLEANUP_HAVE_NOT_BEEN_3D12C))
        } else {
            val row = status.getOrNull()
            if (row == null) {
                // No Rust owner was created, including a rejected JNI call.
                BrowserHostLocalOwners.destinations.finish(destination.id, browserCleanupDestination(context, destination.target))
                return
            }
            if (BrowserHostLocalOwners.destinations.observe(destination.id, row)) return
            if (NativeSafPickerOwners.isClosing(owner.handle) || !BrowserHostLocalOwners.current(owner)) {
                runCatching { NativeSdk.nativeBrowserHostFileExportCancel(owner.handle, owner.binding.bindingJson, row.exportId) }
            }
        }
        delay(350)
    }
}

/** Keep this composed with a null binding while no browser session is active,
 * so delayed SAF results are still consumed and stale save targets cleaned. */
@Composable
internal fun BrowserHostDataPanel(
    handle: Long,
    binding: HostCaptureBinding.BrowserHost?,
    foreground: NativeClipboardForeground,
    visible: Boolean,
) {
    val context = LocalContext.current.applicationContext
    val owner = binding?.let { BrowserLocalOwner(handle, it) }
    SideEffect { BrowserHostLocalOwners.update(owner) }
    var data by remember(owner) { mutableStateOf(BrowserHostDataRow()) }
    var files by remember(owner) { mutableStateOf(NativeHostFilesRow()) }
    var busy by remember(owner) { mutableStateOf(false) }
    var pending by remember { mutableStateOf(BrowserHostLocalOwners.grants.hasPending()) }
    var error by remember(owner) { mutableStateOf("") }
    var chooseRead by remember(owner) { mutableStateOf(false) }
    var chooseWrite by remember(owner) { mutableStateOf(false) }
    var shareConsent by remember(owner) { mutableStateOf(false) }
    var receiveConsent by remember(owner) { mutableStateOf(false) }
    val cleanupTargets by BrowserHostLocalOwners.destinations.state.collectAsState()

    fun launchOwned(target: BrowserLocalOwner, work: () -> Unit) {
        if (!BrowserHostLocalOwners.current(target)) return
        busy = true
        BrowserHostDataWorkers.launch(target.handle) {
            val failure = runCatching { check(browserCurrent(target)) { uiText(UiTextKey.THE_BROWSER_SESSION_HAS_BEEN_REPLACED_41991) }; work() }.exceptionOrNull()
            withContext(Dispatchers.Main) {
                if (BrowserHostLocalOwners.current(target)) { busy = false; error = failure?.message.orEmpty() }
            }
        }
    }

    val sharePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val grant = BrowserHostLocalOwners.grants.take(BrowserSafDirection.Share)
        pending = BrowserHostLocalOwners.grants.hasPending()
        if (uri != null && grant != null) {
            val target = BrowserLocalOwner(grant.handle, grant.binding)
            launchOwned(target) {
                check(grant.consume(target.handle, owner?.binding, BrowserSafDirection.Share)) { uiText(UiTextKey.THE_SELECTED_FILE_BELONGS_TO_A_20BC0) }
                val authorized = { browserFileCurrent(target, false) }
                val name = browserSafProviderCall(authorized) { browserDisplayName(context.contentResolver, uri) }
                val descriptor = browserSafProviderCall(authorized) { context.contentResolver.openFileDescriptor(uri, "r") ?: error(uiText(UiTextKey.THE_SELECTED_FILE_COULD_NOT_BE_1BB5B)) }
                descriptor.use { pfd ->
                    browserSafProviderCall(authorized) { require(OsConstants.S_ISREG(Os.fstat(pfd.fileDescriptor).st_mode)) { uiText(UiTextKey.ONLY_SEEKABLE_REGULAR_FILES_ARE_SUPPORTED_CAE08) } }
                    browserSafProviderCall(authorized) { NativeSdk.nativeBrowserHostFileShare(target.handle, target.binding.bindingJson, grant.id, name, pfd.detachFd()) }
                }
            }
        }
    }
    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val grant = BrowserHostLocalOwners.grants.take(BrowserSafDirection.Export)
        pending = BrowserHostLocalOwners.grants.hasPending()
        if (uri != null) {
            // Even a lost/restored picker grant must clean a newly created target.
            val target = grant?.let { BrowserLocalOwner(it.handle, it.binding) }
            val retainedHandle = grant?.handle ?: BrowserHostLocalOwners.currentHandle()
            val destination = BrowserHostLocalOwners.destinations.retain(retainedHandle, uri, grant?.displayName ?: uiText(UiTextKey.BROWSER_SAVED_FILE_BDD3D))
            if (destination == null) return@rememberLauncherForActivityResult
            if (target != null && BrowserHostLocalOwners.current(target)) busy = true
            BrowserHostDataWorkers.launch(retainedHandle) {
                var submitted = false
                var failure: Throwable? = null
                try {
                    check(grant != null && target != null && grant.consume(target.handle, owner?.binding, BrowserSafDirection.Export)) { uiText(UiTextKey.THE_SAVE_DESTINATION_BELONGS_TO_A_174EC) }
                    val artifact = requireNotNull(grant.artifactId)
                    val authorized = { browserFileCurrent(target, true) }
                    val descriptor = browserSafProviderCall(authorized) { context.contentResolver.openFileDescriptor(uri, "rw") ?: error(uiText(UiTextKey.THE_SAVE_DESTINATION_COULD_NOT_BE_C4CD4)) }
                    descriptor.use { pfd ->
                        browserSafProviderCall(authorized) { require(OsConstants.S_ISREG(Os.fstat(pfd.fileDescriptor).st_mode)) { uiText(UiTextKey.THE_SAVE_DESTINATION_MUST_BE_A_7C18E) } }
                        browserSafProviderCall(authorized) {
                            val detached = pfd.detachFd()
                            submitted = true // JNI owns rejection cleanup or the actual export.
                            NativeSdk.nativeBrowserHostFileExport(target.handle, target.binding.bindingJson, grant.id, artifact, detached)
                        }
                    }
                } catch (caught: Throwable) {
                    failure = caught
                } finally {
                    if (!submitted) {
                        val cleanup = browserCleanupDestination(context, uri)
                        BrowserHostLocalOwners.destinations.finish(destination.id, cleanup)
                        if (!cleanup.complete) failure = IllegalStateException(uiText(UiTextKey.CLEANUP_IS_UNCONFIRMED_CHECK_AND_DELETE_D98D6))
                    }
                    withContext(Dispatchers.Main) {
                        if (target != null && BrowserHostLocalOwners.current(target)) { busy = false; error = failure?.message.orEmpty() }
                    }
                    if (submitted) observeBrowserExportDestination(context, requireNotNull(target), requireNotNull(grant), destination)
                }
            }
        }
    }

    LaunchedEffect(owner) {
        if (owner == null || handle <= 0) return@LaunchedEffect
        while (isActive && BrowserHostLocalOwners.current(owner)) {
            runCatching {
                withContext(Dispatchers.IO) {
                    val actualFiles = parseBrowserHostFiles(NativeSdk.nativeBrowserHostFilesStatus(handle, owner.binding.bindingJson), owner.binding)
                    val actualData = parseBrowserHostData(NativeSdk.nativeBrowserHostDataStatus(handle, owner.binding.bindingJson), owner.binding)
                    actualFiles to actualData
                }
            }.onSuccess { (actualFiles, actualData) ->
                if (BrowserHostLocalOwners.current(owner)) { files = actualFiles; data = actualData }
            }.onFailure { if (BrowserHostLocalOwners.current(owner)) error = it.message ?: uiText(UiTextKey.COULD_NOT_READ_LOCAL_CONSENT_STATUS_90015) }
            pending = BrowserHostLocalOwners.grants.hasPending()
            delay(500)
        }
    }
    if (!visible) return
    if (cleanupTargets.isNotEmpty()) Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        Text(uiText(UiTextKey.SYSTEM_SAVE_DESTINATIONS_3DF11), style = MaterialTheme.typography.titleMedium)
        cleanupTargets.forEach { target ->
            Text(target.displayName, style = MaterialTheme.typography.titleSmall)
            Text(target.detail, color = if (target.busy) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
            if (!target.busy) OutlinedButton(onClick = {
                BrowserHostLocalOwners.destinations.retry(target.id)?.let { retained ->
                    BrowserHostDataWorkers.launch(retained.handle) {
                        BrowserHostLocalOwners.destinations.finish(retained.id, browserCleanupDestination(context, retained.target))
                    }
                }
            }) { Text(uiText(UiTextKey.RETRY_DESTINATION_CLEANUP_179BC)) }
        }
        Text(uiText(UiTextKey.FINISH_THESE_TASKS_OR_THEIR_CLEANUP_73D42), style = MaterialTheme.typography.bodySmall)
    }
    if (owner == null || handle <= 0) return

    fun pickShare() {
        runCatching {
            val grant = BrowserHostLocalOwners.grants.issue(handle, owner.binding, BrowserSafDirection.Share)
            pending = true
            try { sharePicker.launch(arrayOf("*/*")) } catch (failure: Throwable) { BrowserHostLocalOwners.grants.cancel(grant); pending = false; throw failure }
        }.onFailure { error = it.message ?: uiText(UiTextKey.THE_SYSTEM_FILE_PICKER_COULD_NOT_12995) }
    }
    fun pickExport(artifact: NativeHostArtifactRow) {
        runCatching {
            check(artifact.canExport())
            check(!BrowserHostLocalOwners.destinations.hasRetained()) { uiText(UiTextKey.FINISH_OR_CLEAN_UP_THE_PREVIOUS_6F78E) }
            val grant = BrowserHostLocalOwners.grants.issue(handle, owner.binding, BrowserSafDirection.Export, artifact.id, artifact.displayName)
            pending = true
            try { exportPicker.launch(artifact.displayName) } catch (failure: Throwable) { BrowserHostLocalOwners.grants.cancel(grant); pending = false; throw failure }
        }.onFailure { error = it.message ?: uiText(UiTextKey.THE_SYSTEM_SAVE_DIALOG_COULD_NOT_3C890) }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        Text(uiText(UiTextKey.LOCAL_FILES_AND_CLIPBOARD_FOR_BROWSER_B819F), style = MaterialTheme.typography.titleMedium)
        Text(uiText(UiTextKey.CONSENT_APPLIES_ONLY_TO_THE_CURRENT_37E2B), style = MaterialTheme.typography.bodySmall)
        if (data.filesAvailable && (data.fileRead || data.fileWrite)) {
            Text(uiText(UiTextKey.FILES_8_FILES_RESERVED_4_GIB_D3018, files.artifacts.size, formatFileBytes(files.reservedBytes)), style = MaterialTheme.typography.bodySmall)
            if (data.fileRead) OutlinedButton(onClick = { shareConsent = true }, enabled = !busy && !pending && files.artifacts.size < 8) { Text(uiText(UiTextKey.CHOOSE_AND_SHARE_FILES_91AD2)) }
            if (data.fileWrite) OutlinedButton(onClick = {
                if (files.receiveApproved) launchOwned(owner) { NativeSdk.nativeBrowserHostFileApproveReceive(handle, owner.binding.bindingJson, false) }
                else receiveConsent = true
            }, enabled = !busy && !pending) { Text(if (files.receiveApproved) uiText(UiTextKey.STOP_RECEIVING_NEW_FILES_B6905) else uiText(UiTextKey.APPROVE_PRIVATE_RECEIVING_AREA_4E0E0)) }
            files.artifacts.forEach { artifact ->
                Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(artifact.displayName, style = MaterialTheme.typography.titleSmall)
                        Text("${if (artifact.kind == "share") uiText(UiTextKey.SHARED_SNAPSHOT_63B63) else uiText(UiTextKey.RECEIVED_FILE_2B9C2)} · ${hostFilePhaseLabel(artifact.phase)}${artifact.size?.let { " · ${formatFileBytes(it)}" }.orEmpty()}")
                        if (!artifact.ownerStopped || artifact.cleanupPending) Text(uiText(UiTextKey.FILE_PROCESSING_OR_CLEANUP_IS_STILL_08238), style = MaterialTheme.typography.bodySmall)
                        artifact.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        artifact.cleanupError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        val export = files.exports[artifact.id]
                        export?.let {
                            Text(uiText(UiTextKey.SAVE_AS_1B01D, hostFilePhaseLabel(it.phase), formatFileBytes(it.copiedBytes), formatFileBytes(it.totalBytes)))
                            it.error?.let { text -> Text(text, color = MaterialTheme.colorScheme.error) }
                            it.destinationCleanupError?.let { text -> Text(text, color = MaterialTheme.colorScheme.error) }
                            if (it.ownerRetained()) TextButton(onClick = { launchOwned(owner) { NativeSdk.nativeBrowserHostFileExportCancel(handle, owner.binding.bindingJson, it.exportId) } }, enabled = !busy) { Text(uiText(UiTextKey.CANCEL_SAVING_AND_WAIT_FOR_CLEANUP_A276F)) }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (artifact.canExport()) Button(onClick = { pickExport(artifact) }, enabled = !busy && !pending && cleanupTargets.isEmpty() && export?.ownerRetained() != true) { Text(uiText(UiTextKey.SAVE_WITH_SYSTEM_DIALOG_5B981)) }
                            TextButton(onClick = { launchOwned(owner) { NativeSdk.nativeBrowserHostFileDiscard(handle, owner.binding.bindingJson, artifact.id) } }, enabled = !busy && !pending) { Text(if (artifact.kind == "share") uiText(UiTextKey.REVOKE_SHARING_767B9) else uiText(UiTextKey.DELETE_PRIVATE_FILE_BE5BD)) }
                        }
                    }
                }
            }
        }
        if (data.clipboardAvailable && (data.clipboardRead || data.clipboardWrite)) {
            Text(uiText(UiTextKey.CLIPBOARD_ACCESS_REQUIRES_THE_APP_TO_7D0C9), style = MaterialTheme.typography.bodySmall)
            val selected = data.localRead || data.localWrite
            if (!selected && !data.restartRequired) {
                Row { Checkbox(checked = chooseRead, onCheckedChange = { chooseRead = it }, enabled = data.clipboardRead && !busy); Text(uiText(UiTextKey.ALLOW_THE_BROWSER_TO_READ_THE_E46FC)) }
                Row { Checkbox(checked = chooseWrite, onCheckedChange = { chooseWrite = it }, enabled = data.clipboardWrite && !busy); Text(uiText(UiTextKey.ALLOW_THE_BROWSER_TO_WRITE_THE_017CD)) }
                Button(onClick = {
                    val read = chooseRead && data.clipboardRead
                    val write = chooseWrite && data.clipboardWrite
                    launchOwned(owner) {
                        val endpoint = NativeClipboardEndpoint(context, handle, owner.binding, foreground, read, write)
                        BrowserHostLocalOwners.install(owner, endpoint)
                        try { NativeSdk.nativeBrowserClipboardSetDirections(handle, owner.binding.bindingJson, read, write, endpoint) }
                        catch (failure: Throwable) { BrowserHostLocalOwners.discard(owner, endpoint); throw failure }
                    }
                }, enabled = !busy && (chooseRead || chooseWrite)) { Text(uiText(UiTextKey.APPROVE_SELECTED_CLIPBOARD_DIRECTIONS_E18E4)) }
            }
            if (data.localRead) OutlinedButton(onClick = { launchOwned(owner) {
                BrowserHostLocalOwners.endpoint(owner)?.revokeDirections(false, data.localWrite)
                NativeSdk.nativeBrowserClipboardSetDirections(handle, owner.binding.bindingJson, false, data.localWrite, null)
            } }, enabled = !busy) { Text(uiText(UiTextKey.REVOKE_LOCAL_CLIPBOARD_READING_255C8)) }
            if (data.localWrite) OutlinedButton(onClick = { launchOwned(owner) {
                BrowserHostLocalOwners.endpoint(owner)?.revokeDirections(data.localRead, false)
                NativeSdk.nativeBrowserClipboardSetDirections(handle, owner.binding.bindingJson, data.localRead, false, null)
            } }, enabled = !busy) { Text(uiText(UiTextKey.REVOKE_LOCAL_CLIPBOARD_WRITING_036B8)) }
            if (data.restartRequired) Text(uiText(UiTextKey.START_A_NEW_BROWSER_SESSION_TO_7B810), style = MaterialTheme.typography.bodySmall)
        }
        if (busy) Text(uiText(UiTextKey.PROCESSING_LOCAL_CONSENT_OR_FILES_52C2C))
        if (pending) Text(uiText(UiTextKey.FINISH_OR_CANCEL_THE_SYSTEM_FILE_1A641), style = MaterialTheme.typography.bodySmall)
        if (error.isNotBlank()) Text(error, color = MaterialTheme.colorScheme.error)
    }
    if (shareConsent) AlertDialog(
        onDismissRequest = { shareConsent = false }, title = { Text(uiText(UiTextKey.SHARE_THE_SELECTED_FILES_AND_THEIR_07D81)) },
        text = { Text(uiText(UiTextKey.ONLY_READ_ONLY_SNAPSHOTS_AND_NAMES_F6955)) },
        confirmButton = { TextButton(onClick = { shareConsent = false; pickShare() }) { Text(uiText(UiTextKey.CHOOSE_AND_SHARE_016B5)) } }, dismissButton = { TextButton(onClick = { shareConsent = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
    )
    if (receiveConsent) AlertDialog(
        onDismissRequest = { receiveConsent = false }, title = { Text(uiText(UiTextKey.APPROVE_A_PRIVATE_RECEIVING_AREA_FOR_99618)) },
        text = { Text(uiText(UiTextKey.THE_CURRENT_BROWSER_CAN_SEND_REGULAR_3EC69)) },
        confirmButton = { TextButton(onClick = { receiveConsent = false; launchOwned(owner) { NativeSdk.nativeBrowserHostFileApproveReceive(handle, owner.binding.bindingJson, true) } }) { Text(uiText(UiTextKey.APPROVE_RECEIVING_FOR_THIS_SESSION_D0443)) } }, dismissButton = { TextButton(onClick = { receiveConsent = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
    )
}
