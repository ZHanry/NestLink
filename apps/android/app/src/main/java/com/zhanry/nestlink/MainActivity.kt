package com.zhanry.nestlink

import android.app.Activity
import android.app.Application
import android.Manifest
import android.content.ComponentName
import android.content.ContentResolver
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import android.provider.DocumentsContract
import android.system.Os
import android.system.OsConstants
import android.media.projection.MediaProjectionManager
import android.media.projection.MediaProjectionConfig
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.PowerManager
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LocalContentColor
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import android.provider.OpenableColumns
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private val Muted: Color
    @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
private val Danger: Color
    @Composable get() = MaterialTheme.colorScheme.error
private val Warning: Color
    @Composable get() = if (androidx.compose.foundation.isSystemInDarkTheme()) {
        NestLinkUiTokens.darkWarning
    } else {
        NestLinkUiTokens.lightWarning
    }
private val Success: Color
    @Composable get() = if (androidx.compose.foundation.isSystemInDarkTheme()) {
        NestLinkUiTokens.darkSuccess
    } else {
        NestLinkUiTokens.lightSuccess
    }
private val DangerAction: Color
    @Composable get() = if (androidx.compose.foundation.isSystemInDarkTheme()) {
        NestLinkUiTokens.darkDangerAction
    } else {
        NestLinkUiTokens.lightDangerAction
    }
private val DangerActionText: Color
    @Composable get() = if (androidx.compose.foundation.isSystemInDarkTheme()) {
        NestLinkUiTokens.darkDangerActionText
    } else {
        NestLinkUiTokens.lightDangerActionText
    }
private const val NETWORK_OBSERVATION_HEARTBEAT_MS = 750L

private object NativeCloseRecovery {
    private val handle = AtomicLong()

    fun retain(value: Long) {
        if (value > 0L) handle.set(value)
    }

    fun pendingHandle(): Long = handle.get()

    fun clear(value: Long) {
        handle.compareAndSet(value, 0L)
    }
}

internal object NativeSafPickerOwners {
    private val lock = Any()
    private val workers = mutableMapOf<Long, MutableSet<Job>>()
    private val closingHandles = mutableSetOf<Long>()

    fun retain(handle: Long, worker: Job) {
        synchronized(lock) { workers.getOrPut(handle) { mutableSetOf() }.add(worker) }
        worker.invokeOnCompletion {
            synchronized(lock) {
                workers[handle]?.remove(worker)
                if (workers[handle]?.isEmpty() == true) workers.remove(handle)
            }
        }
    }

    fun hasRetainedOwners(): Boolean = synchronized(lock) {
        workers.values.any { jobs -> jobs.any { !it.isCompleted } }
    }

    fun isClosing(handle: Long): Boolean = synchronized(lock) { handle in closingHandles }

    fun beginClose(handle: Long) {
        if (handle > 0L) synchronized(lock) { closingHandles.add(handle) }
    }

    suspend fun awaitAllStopped(timeoutMillis: Long = 5_000L) {
        try {
            withTimeout(timeoutMillis) {
                while (true) {
                    val retained = synchronized(lock) { workers.values.flatMap { jobs -> jobs.filter { !it.isCompleted } } }
                    if (retained.isEmpty()) break
                    retained.forEach { it.join() }
                }
            }
        } catch (_: TimeoutCancellationException) {
            throw IllegalStateException(uiText(UiTextKey.LOCAL_FILE_CLIPBOARD_OR_PLATFORM_CLEANUP_C56BB))
        }
    }

    fun completeClose(handle: Long) {
        synchronized(lock) {
            check(workers.values.all { jobs -> jobs.all { it.isCompleted } }) {
                uiText(UiTextKey.LOCAL_PLATFORM_OPERATIONS_OR_CLEANUP_ARE_D05CD)
            }
            closingHandles.remove(handle)
        }
    }
}

private fun ConnectivityManager.networkFactsJson(network: Network): String? = runCatching {
    readStableDefaultNetworkSnapshot(
        expectedNetworkHandle = network.networkHandle,
        currentDefaultNetworkHandle = { activeNetwork?.networkHandle },
        readSnapshot = { readNetworkFactsJson(network) },
    )
}.getOrNull()

private fun ConnectivityManager.readNetworkFactsJson(network: Network): String? {
    val capabilities = getNetworkCapabilities(network) ?: return null
    val properties = getLinkProperties(network) ?: return null
    val transports = listOf(
        "bluetooth" to NetworkCapabilities.TRANSPORT_BLUETOOTH,
        "cellular" to NetworkCapabilities.TRANSPORT_CELLULAR,
        "ethernet" to NetworkCapabilities.TRANSPORT_ETHERNET,
        "lowpan" to NetworkCapabilities.TRANSPORT_LOWPAN,
        "vpn" to NetworkCapabilities.TRANSPORT_VPN,
        "wifi" to NetworkCapabilities.TRANSPORT_WIFI,
        "wifi_aware" to NetworkCapabilities.TRANSPORT_WIFI_AWARE,
    ).filter { (_, transport) -> capabilities.hasTransport(transport) }
        .map { (name, _) -> name }
        .sorted()

    val addresses = JSONArray().apply {
        properties.linkAddresses
            .map { address ->
                (address.address.hostAddress?.substringBefore('%') ?: return null) to address.prefixLength
            }
            .distinct()
            .sortedWith(compareBy({ it.first }, { it.second }))
            .forEach { (address, prefixLength) ->
                put(JSONObject()
                    .put("address", address)
                    .put("prefix_length", prefixLength))
            }
    }
    val routes = JSONArray().apply {
        properties.routes
            .map { route ->
                val destination = route.destination
                val gateway = route.gateway
                    ?.takeUnless { it.isAnyLocalAddress }
                    ?.hostAddress
                    ?.substringBefore('%')
                Triple(
                    destination.address.hostAddress?.substringBefore('%') ?: return null,
                    destination.prefixLength,
                    gateway,
                )
            }
            .distinct()
            .sortedWith(compareBy({ it.first }, { it.second }, { it.third.orEmpty() }))
            .forEach { (destination, prefixLength, gateway) ->
                put(JSONObject()
                    .put("destination", destination)
                    .put("prefix_length", prefixLength)
                    .put("gateway", gateway ?: JSONObject.NULL))
            }
    }
    val dnsServers = JSONArray().apply {
        properties.dnsServers
            .map { it.hostAddress?.substringBefore('%') ?: return null }
            .distinct()
            .sorted()
            .forEach { server -> put(server) }
    }

    return JSONObject()
        .put("network_handle", network.networkHandle)
        .put("interface_name", properties.interfaceName ?: "")
        .put("link_addresses", addresses)
        .put("routes", routes)
        .put("dns_servers", dnsServers)
        .put("has_internet", capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
        .put("validated", capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
        .put("not_metered", capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
        .put("not_restricted", capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED))
        .put("transports", JSONArray(transports))
        .toString()
}

class MainActivity : ComponentActivity() {
    private val model by viewModels<NestLinkViewModel>()
    private var pendingHostCaptureBindingJson: String? = null
    private var pendingHostCaptureHandle: Long? = null
    private var pendingBrowserHostBindingJson: String? = null
    private var pendingBrowserHostHandle: Long? = null

    private val screenCaptureConsent = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val browserBinding = pendingBrowserHostBindingJson
        val browserHandle = pendingBrowserHostHandle
        if (browserBinding != null || browserHandle != null) {
            pendingBrowserHostBindingJson = null
            pendingBrowserHostHandle = null
            val binding = browserBinding?.let {
                runCatching { HostCaptureBinding.browserHost(it) }.getOrNull()
            }
            val grant = result.data
            when {
                browserBinding == null || binding == null || browserHandle == null ||
                    browserHandle <= 0L || model.state.value.handle != browserHandle -> {
                    browserBinding?.let(BrowserHostCaptureCoordinator::cancelConsent)
                    binding?.let {
                        BrowserHostCaptureStatus.update(
                            "cancelled", uiText(UiTextKey.THE_BROWSER_SHARING_CONSENT_RESULT_HAS_F08C6), browserBinding,
                        )
                    }
                }
                result.resultCode != Activity.RESULT_OK || grant == null -> {
                    BrowserHostCaptureCoordinator.markDenied(browserBinding)
                }
                else -> {
                    HostCaptureService.stageBrowserHostGrant(
                        this, result.resultCode, grant, browserHandle, browserBinding,
                    )
                }
            }
            return@registerForActivityResult
        }
        val expectedBinding = pendingHostCaptureBindingJson
        val expectedHandle = pendingHostCaptureHandle
        pendingHostCaptureBindingJson = null
        pendingHostCaptureHandle = null
        val grant = result.data
        if (result.resultCode != Activity.RESULT_OK || grant == null) {
            HostCaptureStatus.update("stopped", uiText(UiTextKey.ANDROID_SCREEN_CAPTURE_PERMISSION_WAS_NOT_13C02))
        } else if (expectedBinding == null || expectedHandle == null || expectedHandle <= 0L) {
            HostCaptureStatus.update("failed", uiText(UiTextKey.SCREEN_SHARING_CONSENT_IS_NO_LONGER_037DC))
        } else {
            HostCaptureService.start(
                this,
                result.resultCode,
                grant,
                expectedHandle,
                expectedBinding,
            )
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        pendingHostCaptureBindingJson?.let { outState.putString(EXTRA_PENDING_CAPTURE_BINDING, it) }
        pendingHostCaptureHandle?.let { outState.putLong(EXTRA_PENDING_CAPTURE_HANDLE, it) }
        pendingBrowserHostBindingJson?.let { outState.putString(EXTRA_PENDING_BROWSER_BINDING, it) }
        pendingBrowserHostHandle?.let { outState.putLong(EXTRA_PENDING_BROWSER_HANDLE, it) }
        super.onSaveInstanceState(outState)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingHostCaptureBindingJson = savedInstanceState?.getString(EXTRA_PENDING_CAPTURE_BINDING)
        pendingHostCaptureHandle = savedInstanceState?.getLong(EXTRA_PENDING_CAPTURE_HANDLE)?.takeIf { it > 0L }
        pendingBrowserHostBindingJson = savedInstanceState?.getString(EXTRA_PENDING_BROWSER_BINDING)
        pendingBrowserHostHandle = savedInstanceState?.getLong(EXTRA_PENDING_BROWSER_HANDLE)?.takeIf { it > 0L }
        setContent { AppLanguageScope { NestLinkRoot(model, ::requestScreenCapture, ::requestBrowserHostCapture) } }
    }

    override fun onStart() {
        super.onStart()
        model.onForegrounded()
    }

    override fun onResume() {
        super.onResume()
        model.onResumed()
    }

    override fun onPause() {
        model.onClipboardPaused()
        if (!getSystemService(PowerManager::class.java).isInteractive) {
            model.onDeviceSuspending()
        }
        super.onPause()
    }

    override fun onStop() {
        model.onBackgrounded()
        super.onStop()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        model.onClipboardWindowFocus(hasFocus)
    }

    private fun requestScreenCapture() {
        val expectedHandle = model.state.value.handle
        if (expectedHandle <= 0L) {
            HostCaptureStatus.update("failed", uiText(UiTextKey.VERIFY_THE_SERVER_AND_SIGN_IN_C5EE6))
            return
        }
        val captureEligible = runCatching {
            NativeSdk.nativeCanStartHostCapture(expectedHandle)
        }.getOrElse { failure ->
            HostCaptureStatus.update("failed", failure.message ?: uiText(UiTextKey.ENROLL_THIS_DEVICE_AS_A_HOST_64277))
            return
        }
        if (!captureEligible) {
            HostCaptureStatus.update("failed", uiText(UiTextKey.SIGN_IN_AND_ENROLL_THIS_DEVICE_40C4A))
            return
        }
        if (pendingHostCaptureBindingJson != null || pendingBrowserHostBindingJson != null) {
            HostCaptureStatus.update("awaiting_consent", uiText(UiTextKey.ANOTHER_SCREEN_SHARING_CONSENT_REQUEST_IS_E95DA))
            return
        }
        val expectedBinding = runCatching {
            NativeSdk.nativeHostSessionBinding(expectedHandle)
        }.getOrElse { failure ->
            HostCaptureStatus.update("failed", failure.message ?: uiText(UiTextKey.COULD_NOT_READ_THE_CURRENT_HOST_AE3A4))
            return
        }
        if (expectedBinding.isNullOrBlank()) {
            HostCaptureStatus.update("failed", uiText(UiTextKey.ESTABLISH_A_CONNECTED_HOST_VIEW_SESSION_4CD5B))
            return
        }
        val manager = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        pendingHostCaptureBindingJson = expectedBinding
        pendingHostCaptureHandle = expectedHandle
        HostCaptureStatus.update("awaiting_consent", uiText(UiTextKey.CONFIRM_SCREEN_CAPTURE_IN_THE_ANDROID_7F320))
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            manager.createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay())
        } else {
            manager.createScreenCaptureIntent()
        }
        try {
            screenCaptureConsent.launch(intent)
        } catch (failure: Throwable) {
            pendingHostCaptureBindingJson = null
            pendingHostCaptureHandle = null
            HostCaptureStatus.update("failed", failure.message ?: uiText(UiTextKey.COULD_NOT_OPEN_THE_ANDROID_SCREEN_596DB))
        }
    }

    internal fun requestBrowserHostCapture(bindingJson: String) {
        if (BrowserHostCaptureCoordinator.consentState(bindingJson) != "pending") return
        val binding = runCatching { HostCaptureBinding.browserHost(bindingJson) }.getOrNull()
        val expectedHandle = model.state.value.handle
        val nativeCapture = HostCaptureStatus.state.value
        val nativeOwnerBusy = nativeCapture.state in setOf(
            "starting", "awaiting_consent", "waiting_view_authorization", "capturing", "stopping",
        ) || !nativeCapture.cleanupComplete || nativeCapture.audioCleanupPending ||
            nativeCapture.nonAudioCleanupFailed
        if (binding == null || expectedHandle <= 0L || nativeOwnerBusy ||
            pendingHostCaptureBindingJson != null || pendingBrowserHostBindingJson != null
        ) {
            BrowserHostCaptureCoordinator.markDenied(bindingJson)
            return
        }
        pendingBrowserHostBindingJson = bindingJson
        pendingBrowserHostHandle = expectedHandle
        BrowserHostCaptureStatus.update("awaiting_consent", uiText(UiTextKey.CONFIRM_SCREEN_SHARING_IN_THE_ANDROID_F9781), bindingJson)
        val manager = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            manager.createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay())
        } else {
            manager.createScreenCaptureIntent()
        }
        try {
            screenCaptureConsent.launch(intent)
        } catch (failure: Throwable) {
            pendingBrowserHostBindingJson = null
            pendingBrowserHostHandle = null
            BrowserHostCaptureCoordinator.markDenied(bindingJson)
            BrowserHostCaptureStatus.update(
                "failed", failure.message ?: uiText(UiTextKey.COULD_NOT_OPEN_THE_SCREEN_SHARING_23D87), bindingJson,
            )
        }
    }

    private companion object {
        const val EXTRA_PENDING_CAPTURE_BINDING = "nestlink.pending_capture_binding"
        const val EXTRA_PENDING_CAPTURE_HANDLE = "nestlink.pending_capture_handle"
        const val EXTRA_PENDING_BROWSER_BINDING = "nestlink.pending_browser_binding"
        const val EXTRA_PENDING_BROWSER_HANDLE = "nestlink.pending_browser_handle"
    }
}

internal data class DeviceRow(
    val id: String,
    val name: String,
    val platform: String,
    val pathMode: String,
    val capabilities: List<String>,
    val revoked: Boolean,
)

internal data class RemoteRequestRow(
    val id: String,
    val controllerDeviceId: String,
    val hostDeviceId: String,
    val permissions: List<Int>,
    val paths: List<Int>,
    val status: String,
    val nonce: String,
    val policyRevision: Long,
    val expiresAtUnixMs: Long,
    val connectionGeneration: Long,
    val leaseSequence: Long,
)

internal data class TrustedDeviceRow(
    val controllerDeviceId: String,
    val hostKeySha256: String,
    val controllerKeySha256: String,
    val permissions: List<Int>,
    val paths: List<Int>,
    val revision: Long,
    val expiresAtUnixMs: Long,
    val active: Boolean,
)

internal data class TrustedDevicesRow(
    val hostDeviceId: String,
    val devices: List<TrustedDeviceRow>,
)

internal data class NativeSessionRow(
    val requestId: String,
    val connectionGeneration: Long,
    val status: String,
    val hostViewAuthorized: Boolean,
)

internal data class BrowserHostRow(
    val requestId: String,
    val connectionGeneration: Long,
    val status: String,
    val hostViewAuthorized: Boolean,
    val binding: HostCaptureBinding.BrowserHost?,
)

internal data class NativeFileSessionIdentity(
    val identityJson: String,
    val requestId: String,
    val connectionGeneration: Long,
    val coreGeneration: Long,
    val canRead: Boolean,
    val canWrite: Boolean,
    val isHost: Boolean = false,
)

internal data class NativeFileRootRow(val id: String, val displayName: String)
internal data class NativeFileEntryRow(
    val name: String,
    val directory: Boolean,
    val size: Long?,
    val modifiedUnixMs: Long,
)
internal data class NativeFileBrowsePage(
    val requestId: String,
    val connectionGeneration: Long,
    val browseId: String,
    val rootId: String,
    val directory: String,
    val snapshotId: String,
    val offset: Int,
    val totalEntries: Int,
    val hasMore: Boolean,
    val entries: List<NativeFileEntryRow>,
)
internal data class NativeFileTaskRow(
    val taskId: String,
    val kind: String,
    val displayName: String,
    val phase: String,
    val confirmedBytes: Long,
    val totalBytes: Long?,
    val finished: Boolean,
    val error: String?,
    val ownerStopped: Boolean = finished,
)
internal data class NativeSafExportRow(
    val exportId: String,
    val phase: String,
    val copiedBytes: Long,
    val totalBytes: Long,
    val error: String?,
    val privateCleanupComplete: Boolean = false,
    val privateCleanupError: String? = null,
    val destinationCleanupComplete: Boolean = false,
    val destinationCleanupError: String? = null,
    val taskId: String = "",
    val ownerStopped: Boolean = false,
)

internal fun NativeSafExportRow.ownerRetained(): Boolean = phase == "running" || !ownerStopped

internal data class SafDestinationCleanupReceipt(val complete: Boolean, val detail: String)

internal fun cleanupCreatedSafDestination(
    deleteDocument: () -> Boolean,
    clearDocument: () -> Unit,
): SafDestinationCleanupReceipt {
    if (runCatching(deleteDocument).getOrDefault(false)) {
        return SafDestinationCleanupReceipt(true, uiText(UiTextKey.THE_SYSTEM_SAVE_DESTINATION_WAS_DELETED_6EFCB))
    }
    return if (runCatching(clearDocument).isSuccess) {
        SafDestinationCleanupReceipt(true, uiText(UiTextKey.THE_SYSTEM_SAVE_DESTINATION_WAS_TRUNCATED_44F68))
    } else {
        SafDestinationCleanupReceipt(false, uiText(UiTextKey.DESTINATION_CLEANUP_IS_UNCONFIRMED_CHECK_AND_B10CD))
    }
}

private const val MAX_NATIVE_FILE_TASK_HISTORY = 32

private data class PendingSafUpload(
    val handle: Long,
    val identity: NativeFileSessionIdentity,
    val rootId: String,
    val directory: String,
)

private data class PendingSafExport(
    val handle: Long,
    val identity: NativeFileSessionIdentity,
    val taskId: String,
    val suggestedName: String,
)

internal data class MobileState(
    val handle: Long = 0,
    val authGeneration: Long = 0,
    val ownDeviceId: String = "",
    val principal: String = "",
    val accountId: String = "",
    val devices: List<DeviceRow> = emptyList(),
    val services: ServiceManagementRow? = null,
    val networkSettings: NativeNetworkSettingsRow? = null,
    val remoteRequests: List<RemoteRequestRow> = emptyList(),
    val trustedDevices: TrustedDevicesRow? = null,
    val remotePassword: RemotePasswordViewRow? = null,
    val remotePasswordOffer: RemotePasswordOfferRow? = null,
    val nativeSession: NativeSessionRow? = null,
    val browserHost: BrowserHostRow? = null,
    val fileSession: NativeFileSessionIdentity? = null,
    val hostFiles: NativeHostFilesRow = NativeHostFilesRow(),
    val clipboard: NativeClipboardRow? = null,
    val clipboardBusy: Boolean = false,
    val clipboardEndpointActive: Boolean = false,
    val clipboardNotice: String = "",
    val clipboardPlatformOutcome: Int = NativeClipboardOutcome.OK,
    val fileReadRoots: List<NativeFileRootRow> = emptyList(),
    val fileWriteRoots: List<NativeFileRootRow> = emptyList(),
    val fileBrowsePage: NativeFileBrowsePage? = null,
    val fileTask: NativeFileTaskRow? = null,
    val fileTaskName: String = "",
    val safExport: NativeSafExportRow? = null,
    val fileTasks: List<NativeFileTaskRow> = emptyList(),
    val fileExports: Map<String, NativeSafExportRow> = emptyMap(),
    val discardedDownloadTaskIds: Set<String> = emptySet(),
    val localClosePending: Boolean = false,
    val localCloseNotice: String = "",
    val selectedReadRootId: String = "",
    val selectedWriteRootId: String = "",
    val fileLoading: Boolean = false,
    val fileBusy: Boolean = false,
    val filePickerPending: Boolean = false,
    val fileError: String = "",
    val remoteVideoLayout: NativeRemoteVideoLayout? = null,
    val remoteVideoPresentation: RemoteVideoPresentation? = null,
    val nativeInputLayout: NativeRemoteInputLayout? = null,
    val nativeDisplays: NativeDisplays? = null,
    val localDisplaySelection: NativeDisplaySelectionRequest? = null,
    val accessibilityInputEnabled: Boolean = false,
    val inputMethodEnabled: Boolean = false,
    val busy: Boolean = false,
    val error: String = "",
    val message: String = "",
)

internal fun MobileState.withNativeFileTask(task: NativeFileTaskRow, selectLatest: Boolean = false): MobileState {
    val history = (fileTasks.filterNot { it.taskId == task.taskId } + task).toMutableList()
    while (history.size > MAX_NATIVE_FILE_TASK_HISTORY) {
        val expiredUpload = history.indexOfFirst { it.kind != "download" && it.finished }
        val expiredDownload = history.indexOfFirst { candidate ->
            candidate.kind == "download" && candidate.finished &&
                (candidate.taskId in discardedDownloadTaskIds ||
                    fileExports[candidate.taskId]?.privateCleanupComplete == true)
        }
        val expired = if (expiredUpload >= 0) expiredUpload else expiredDownload
        if (expired < 0) break
        history.removeAt(expired)
    }
    val selected = if (selectLatest || fileTask?.taskId == task.taskId || fileTask == null) task else fileTask
    return copy(fileTask = selected, fileTasks = history)
}

private sealed interface NativeInputMessage {
    val handle: Long
    val binding: NativeInputBinding

    data class Action(
        override val handle: Long,
        override val binding: NativeInputBinding,
        val action: NativeInputAction,
        val revision: Long,
    ) : NativeInputMessage

    data class Release(
        override val handle: Long,
        override val binding: NativeInputBinding,
    ) : NativeInputMessage
}

internal class NestLinkViewModel(application: Application) : AndroidViewModel(application) {
    private val identity = AndroidIdentityStore(application)
    private val mutableState = MutableStateFlow(MobileState())
    private val remoteVideoBitmapOwner = RemoteVideoBitmapOwner()
    private val nativeInputDeliveryLock = Any()
    private val nativeInputMessages = Channel<Unit>(Channel.CONFLATED)
    private val nativeInputQueue = java.util.ArrayDeque<NativeInputMessage.Action>()
    private val nativeInputQueueLock = Any()
    private val nativeInputRevision = AtomicLong(0)
    private val inputReleasePending = java.util.concurrent.atomic.AtomicInteger(0)
    @Volatile private var audioPlaybackJob: Job? = null
    private val audioCoordinatorLock = Any()
    private val viewModelCleared = AtomicBoolean(false)
    private val fileRefreshActive = AtomicBoolean(false)
    private val clipboardForeground = NativeClipboardForeground()
    private val clipboardEndpoint = AtomicReference<NativeClipboardEndpoint?>()
    private val clipboardRefreshActive = AtomicBoolean(false)
    private val clipboardOperationActive = AtomicBoolean(false)
    private val clipboardRevocationActive = AtomicBoolean(false)
    private val clipboardRevision = AtomicLong(0)
    private val serviceAuthRevision = AtomicLong(0)
    private val fileBrowseGeneration = AtomicLong(0)
    private val filePickerLock = Any()
    private var pendingSafUpload: PendingSafUpload? = null
    private var pendingSafExport: PendingSafExport? = null
    private var pendingHostShare: Pair<Long, NativeFileSessionIdentity>? = null
    private var pendingHostExport: PendingSafExport? = null
    @Volatile private var fileTaskPollJob: Job? = null
    @Volatile private var fileExportPollJob: Job? = null
    val state = mutableState.asStateFlow()
    internal val browserHostClipboardForeground: NativeClipboardForeground
        get() = clipboardForeground
    private val connectivity = application.getSystemService(ConnectivityManager::class.java)
    private val networkObservationLock = Any()
    private val networkObservation = DefaultNetworkObservation()
    private var networkCallbackRegistered = false
    private var deviceSuspended = false
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            reportNativeNetworkFacts(network)
        }

        override fun onLost(network: Network) {
            reportLostNetwork(network)
        }

        override fun onUnavailable() {
            reportNativeNetworkFacts()
        }

        override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
            reportBlockedStatus(network, blocked)
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            reportNativeNetworkFacts(network)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            reportNativeNetworkFacts(network)
        }
    }

    init {
        NativeCloseRecovery.pendingHandle().takeIf { it > 0L }?.let { handle ->
            mutableState.value = MobileState(
                handle = handle,
                localClosePending = true,
                error = uiText(UiTextKey.LOCAL_RESOURCES_FROM_THE_PREVIOUS_EXIT_D2CA4),
                message = uiText(UiTextKey.THE_CONNECTION_WAS_RECOVERED_FINISH_CLEANUP_EE7B7),
            )
        }
        viewModelScope.launch(Dispatchers.IO) {
            for (wake in nativeInputMessages) {
              while (true) {
                val message = synchronized(nativeInputQueueLock) { nativeInputQueue.pollFirst() } ?: break
                try {
                    synchronized(nativeInputDeliveryLock) {
                        when (message) {
                            is NativeInputMessage.Action -> {
                                val current = mutableState.value
                                if (inputReleasePending.get() == 0 && message.revision == nativeInputRevision.get() && current.handle == message.handle && current.nativeInputLayout?.binding == message.binding) {
                                    NativeSdk.nativeSendInput(message.handle, message.binding.toJson(), message.action.toJson())
                                }
                            }

                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Throwable) {
                    if (message is NativeInputMessage.Action) {
                        updateMobileState { current ->
                            if (current.handle != message.handle ||
                                current.nativeInputLayout?.binding != message.binding
                            ) current else current.copy(
                                error = failure.message ?: uiText(UiTextKey.REMOTE_INPUT_COULD_NOT_BE_DELIVERED_A625B),
                                message = uiText(UiTextKey.CHECK_THE_HOST_ACCESSIBILITY_SERVICE_AND_B1F81),
                                nativeInputLayout = null,
                            )
                        }
                    }
                }
              }
            }
        }
        // Callbacks report changes, but cannot prove the observer stayed alive.
        // Fresh platform facts at a bounded cadence let Rust expire a stale
        // observation if this coroutine or the process stops making progress.
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                reportNativeNetworkFacts()
                delay(NETWORK_OBSERVATION_HEARTBEAT_MS)
            }
        }
        startAudioPlaybackCoordinator()
    }

    private fun startAudioPlaybackCoordinator() {
        synchronized(audioCoordinatorLock) {
            if (viewModelCleared.get() || audioPlaybackJob?.isActive == true) return
            audioPlaybackJob = viewModelScope.launch(Dispatchers.IO) {
                runNativeAudioPlaybackCoordinator()
            }
        }
    }

    private suspend fun stopAudioPlaybackCoordinatorAndReap(handle: Long): NativeAudioCleanupSummary {
        val coordinator = synchronized(audioCoordinatorLock) {
            audioPlaybackJob.also { audioPlaybackJob = null }
        }
        coordinator?.cancelAndJoin()
        return withContext(Dispatchers.IO) { nativeAudioEndpointOwners.reapAllActive(handle) }
    }

    /** Keeps controller playback with the ViewModel across rotation and UI navigation. */
    private suspend fun runNativeAudioPlaybackCoordinator() {
        val retiredBindings = LinkedHashSet<String>()
        try {
            while (currentCoroutineContext().isActive) {
                val current = mutableState.value
                var shouldWait = false
                for (otherHandle in nativeAudioEndpointOwners.activeHandles().filter { it != current.handle }) {
                    val cleanup = nativeAudioEndpointOwners.reapAll(otherHandle)
                    if (!cleanup.cleanupComplete) {
                        publishAudioPlaybackFailure(
                            current.handle,
                            uiText(UiTextKey.AUDIOTRACK_CLEANUP_FOR_THE_PREVIOUS_APP_DDFFA),
                        )
                        shouldWait = true
                    }
                }
                if (shouldWait) {
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }
                val session = current.nativeSession?.takeIf {
                    it.status == "connected" && it.connectionGeneration > 0L
                }
                val bindingJson = if (current.handle > 0L && session != null) {
                    runCatching { NativeSdk.nativeAudioBinding(current.handle) }.getOrNull()
                } else null
                val binding = bindingJson?.let { runCatching { JSONObject(it) }.getOrNull() }
                val matches = binding != null && session != null &&
                    binding.optString("request_id") == session.requestId &&
                    binding.optLong("connection_generation") == session.connectionGeneration &&
                    binding.optString("role") == "ControllerPlayback"

                var owner = if (current.handle > 0L) {
                    nativeAudioEndpointOwners.owner(current.handle, NativeAudioOwnerRole.ControllerPlayback)
                } else null
                var orphanCleanupPending = false
                for (orphan in nativeAudioEndpointOwners.owners(
                    current.handle,
                    NativeAudioOwnerRole.ControllerPlayback,
                )) {
                    if (!orphan.attached && orphan.endpoint !== owner?.endpoint) {
                        val receipt = nativeAudioEndpointOwners.reap(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            orphan.endpoint,
                        )
                        if (receipt?.cleanupComplete != true) orphanCleanupPending = true
                    }
                }
                if (orphanCleanupPending) {
                    publishAudioPlaybackFailure(
                        current.handle,
                        uiText(UiTextKey.CLEANUP_OF_AN_AUDIOTRACK_FROM_AN_C4EA8),
                    )
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }
                if (owner != null && (!matches || owner.bindingJson != bindingJson)) {
                    val receipt = nativeAudioEndpointOwners.reap(
                        current.handle,
                        NativeAudioOwnerRole.ControllerPlayback,
                        owner.endpoint,
                    )
                    if (owner.bindingJson.isNotBlank()) rememberRetiredBinding(retiredBindings, owner.bindingJson)
                    if (receipt?.cleanupComplete != true) {
                        publishAudioPlaybackFailure(
                            current.handle,
                            uiText(UiTextKey.CLEANUP_OF_THE_PREVIOUS_AUDIOTRACK_IS_08887, receipt?.bindingJson ?: owner.bindingJson),
                        )
                        delay(AUDIO_COORDINATOR_POLL_MS)
                        continue
                    }
                    owner = null
                }

                if (!matches) {
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }
                if (bindingJson in retiredBindings) {
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }
                if (owner == null) {
                    val created = try {
                        NativeAudioPlaybackEndpoint.create(
                            binding.getString("request_id"),
                            binding.getLong("connection_generation"),
                        )
                    } catch (failure: Throwable) {
                        runCatching { NativeSdk.nativeFailNativeAudio(current.handle, bindingJson) }
                        rememberRetiredBinding(retiredBindings, bindingJson)
                        publishAudioPlaybackFailure(
                            current.handle,
                            uiText(UiTextKey.ANDROID_AUDIOTRACK_CREATION_FAILED_EA085, failure.message ?: failure.javaClass.simpleName),
                        )
                        delay(AUDIO_COORDINATOR_POLL_MS)
                        continue
                    }
                    if (!nativeAudioEndpointOwners.registerPending(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            bindingJson,
                            created,
                        )
                    ) {
                        check(nativeAudioEndpointOwners.retainRejectedPending(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            bindingJson,
                            created,
                        )) { uiText(UiTextKey.COULD_NOT_RETAIN_THE_REJECTED_ANDROID_05B48) }
                        val cleanupReceipt = nativeAudioEndpointOwners.reap(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            created,
                        )
                        if (cleanupReceipt?.cleanupComplete != true) {
                            publishAudioPlaybackFailure(
                                current.handle,
                                uiText(UiTextKey.THE_ANDROID_AUDIOTRACK_OWNER_SLOT_IS_C41C0, cleanupReceipt?.let { "（${it.bindingJson}）" } ?: ""),
                            )
                        }
                        delay(AUDIO_COORDINATOR_POLL_MS)
                        continue
                    }
                    try {
                        NativeSdk.nativeAttachNativeAudioPlayback(current.handle, bindingJson, created)
                        check(nativeAudioEndpointOwners.markAttached(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            bindingJson,
                            created,
                        )) { "Android AudioTrack owner changed during Core attachment." }
                    } catch (failure: Throwable) {
                        runCatching { NativeSdk.nativeFailNativeAudio(current.handle, bindingJson) }
                        val receipt = nativeAudioEndpointOwners.reap(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            created,
                        )
                        rememberRetiredBinding(retiredBindings, bindingJson)
                        val cleanupText = if (receipt?.cleanupComplete == true) {
                            ""
                        } else uiText(UiTextKey.DEVICE_CLEANUP_IS_STILL_UNCONFIRMED_59A19)
                        publishAudioPlaybackFailure(current.handle, uiText(UiTextKey.ANDROID_AUDIO_PLAYBACK_COULD_NOT_START_6938B, failure.message ?: failure.javaClass.simpleName, cleanupText))
                    }
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }

                if (!owner.attached) {
                    val receipt = nativeAudioEndpointOwners.reap(
                        current.handle,
                        NativeAudioOwnerRole.ControllerPlayback,
                        owner.endpoint,
                    )
                    if (receipt?.cleanupComplete == true) rememberRetiredBinding(retiredBindings, owner.bindingJson)
                    else publishAudioPlaybackFailure(current.handle, uiText(UiTextKey.CLEANUP_OF_AN_UNATTACHED_AUDIOTRACK_IS_13977))
                    delay(AUDIO_COORDINATOR_POLL_MS)
                    continue
                }

                val status = runCatching {
                    NativeSdk.nativeNativeAudioWorkerStatus(current.handle, bindingJson)?.let(::JSONObject)
                }.getOrNull()
                if (status != null) {
                    val workerError = if (status.isNull("error")) "" else status.optString("error")
                    if (status.optBoolean("finished") || status.optBoolean("cleanup_timed_out") || workerError.isNotBlank()) {
                        runCatching { NativeSdk.nativeFailNativeAudio(current.handle, bindingJson) }
                        val receipt = nativeAudioEndpointOwners.reap(
                            current.handle,
                            NativeAudioOwnerRole.ControllerPlayback,
                            owner.endpoint,
                        )
                        rememberRetiredBinding(retiredBindings, bindingJson)
                        if (receipt?.cleanupComplete != true) {
                            publishAudioPlaybackFailure(current.handle, uiText(UiTextKey.AUDIOTRACK_CLEANUP_IS_UNCONFIRMED_THE_PREVIOUS_C9FDA))
                        } else if (workerError.isNotBlank()) {
                            publishAudioPlaybackFailure(current.handle, uiText(UiTextKey.ANDROID_AUDIOTRACK_WAS_CLEANED_UP_BUT_6604A, workerError))
                        }
                    }
                }
                delay(AUDIO_COORDINATOR_POLL_MS)
            }
        } finally {
            for (handle in nativeAudioEndpointOwners.activeHandles()) {
                val cleanup = nativeAudioEndpointOwners.reapAll(handle)
                if (!cleanup.cleanupComplete) {
                    publishAudioPlaybackFailure(handle, uiText(UiTextKey.AUDIOTRACK_CLEANUP_WAS_UNCONFIRMED_WHEN_THE_DDB30))
                }
            }
        }
    }

    private fun rememberRetiredBinding(retired: LinkedHashSet<String>, bindingJson: String) {
        retired.remove(bindingJson)
        retired.add(bindingJson)
        while (retired.size > 64) retired.remove(retired.first())
    }

    private fun publishAudioPlaybackFailure(handle: Long, detail: String) {
        updateMobileState { current ->
            if (current.handle != handle) current else current.copy(error = detail)
        }
    }

    private companion object {
        const val AUDIO_COORDINATOR_POLL_MS = 150L
    }

    fun onForegrounded() {
        synchronized(networkObservationLock) {
            registerNetworkObserverIfNeededLocked()
            reportNativeNetworkFactsLocked()
        }
    }

    fun onResumed() {
        clipboardForeground.resumed(true)
        refreshPlatformInputSettings()
        synchronized(networkObservationLock) {
            deviceSuspended = false
            registerNetworkObserverIfNeededLocked()
            reportNativeNetworkFactsLocked()
        }
    }

    fun onClipboardPaused() { clipboardForeground.resumed(false) }
    fun onClipboardWindowFocus(focused: Boolean) { clipboardForeground.focused(focused) }

    private fun refreshPlatformInputSettings() {
        val context = getApplication<Application>()
        val accessibilityEnabled = AndroidInputBridge.isAccessibilityEnabled(context)
        val inputMethodEnabled = AndroidInputBridge.isInputMethodEnabled(context) &&
            AndroidInputBridge.isInputMethodSelected(context)
        updateMobileState { current ->
            if (current.accessibilityInputEnabled == accessibilityEnabled &&
                current.inputMethodEnabled == inputMethodEnabled
            ) current else current.copy(
                accessibilityInputEnabled = accessibilityEnabled,
                inputMethodEnabled = inputMethodEnabled,
            )
        }
    }

    fun onDeviceSuspending() {
        synchronized(networkObservationLock) {
            deviceSuspended = true
            reportNativeNetworkFactsLocked()
        }
    }

    private fun registerNetworkObserverIfNeededLocked() {
        if (!networkCallbackRegistered) {
            networkCallbackRegistered = runCatching {
                connectivity.registerDefaultNetworkCallback(networkCallback)
                true
            }.getOrDefault(false)
        }
    }

    fun onBackgrounded() {
        // The default-network callback remains registered while the activity is
        // backgrounded. Report the last real snapshot; onResume supplies the
        // second clock sample needed to detect suspend without treating a
        // system consent screen as loss of the network observer.
        reportNativeNetworkFacts()
    }

    fun connect(origin: String) = runTask {
        val materialBox = AtomicReference<IdentityMaterial?>()
        val pendingHandle = AtomicLong()
        var adopted = false
        try {
            if (mutableState.value.handle > 0L || NativeCloseRecovery.pendingHandle() > 0L) {
                error(uiText(UiTextKey.THE_PREVIOUS_LOCAL_CONNECTION_STILL_NEEDS_0BA71))
            }
            withContext(Dispatchers.IO) { NativeSafPickerOwners.awaitAllStopped() }
            val material = withContext(Dispatchers.IO) {
                identity.loadOrCreate().also(materialBox::set)
            }
            val handle = withContext(Dispatchers.IO) {
                NativeSdk.nativeConnect(origin.trim(), "", "", material.deviceId, material.seed)
                    .also(pendingHandle::set)
            }
            val id = withContext(Dispatchers.IO) { NativeSdk.nativeDeviceId(handle) }
            val networkSettings = withContext(Dispatchers.IO) {
                parseNativeNetworkSettings(NativeSdk.nativeConfigureNetworkArea(handle,
                    getApplication<Application>().filesDir.resolve("native-network").absolutePath))
            }
            updateMobileState { MobileState(handle = handle, authGeneration = serviceAuthRevision.get(), ownDeviceId = id, networkSettings = networkSettings) }
            adopted = true
            reportNativeNetworkFacts()
            uiText(UiTextKey.SERVER_IDENTITY_VERIFIED_SIGN_IN_CREDENTIALS_99163)
        } finally {
            materialBox.getAndSet(null)?.seed?.fill(0)
            val orphan = pendingHandle.get()
            if (!adopted && orphan > 0) {
                withContext(NonCancellable + Dispatchers.IO) {
                    val cleanup = runCatching { closeNativeSession(orphan) }.exceptionOrNull()
                    if (cleanup != null) {
                        NativeCloseRecovery.retain(orphan)
                        updateMobileState { current ->
                            current.copy(
                                handle = orphan,
                                busy = false,
                                localClosePending = true,
                                error = uiText(UiTextKey.LOCAL_CLEANUP_AFTER_CONNECTION_INITIALIZATION_FAILED_E94CB, cleanup.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                                message = uiText(UiTextKey.RETRY_LOCAL_CLEANUP_BEFORE_CONNECTING_TO_675E2),
                            )
                        }
                    } else {
                        NativeCloseRecovery.clear(orphan)
                    }
                }
            }
        }
    }

    fun disconnectUnverifiedServer() {
        val old = mutableState.value
        if (old.handle <= 0 || old.busy || old.principal.isNotEmpty()) return
        updateMobileState { it.copy(busy = true, error = "", message = uiText(UiTextKey.CLOSING_THE_SERVER_CONNECTION_15A8D)) }
        viewModelScope.launch(Dispatchers.IO) {
            val error = runCatching { closeNativeSession(old.handle) }.exceptionOrNull()
            updateMobileState { current ->
                if (current.handle != old.handle) current
                else if (error == null) {
                    NativeCloseRecovery.clear(old.handle)
                    MobileState()
                }
                else current.copy(
                    busy = false,
                    localClosePending = true,
                    localCloseNotice = "",
                    error = uiText(UiTextKey.LOCAL_CONNECTION_CLEANUP_IS_STILL_RUNNING_9529E, error.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                    message = uiText(UiTextKey.THE_CONNECTION_IS_RETAINED_A_NEW_CF9AC),
                )
            }
            if (error != null) NativeCloseRecovery.retain(old.handle)
        }
    }

    fun retryPendingNativeClose() {
        val pending = mutableState.value
        if (!pending.localClosePending || pending.handle <= 0L || pending.busy) return
        updateMobileState { current ->
            if (current.handle != pending.handle || !current.localClosePending) current
            else current.copy(busy = true, error = "", message = uiText(UiTextKey.RETRYING_LOCAL_RESOURCE_CLEANUP_CEBE0))
        }
        viewModelScope.launch(Dispatchers.IO) {
            val error = runCatching { closeNativeSession(pending.handle) }.exceptionOrNull()
            updateMobileState { current ->
                if (current.handle != pending.handle) current
                else if (error == null) {
                    NativeCloseRecovery.clear(pending.handle)
                    MobileState(error = current.localCloseNotice)
                }
                else current.copy(
                    busy = false,
                    localClosePending = true,
                    error = uiText(UiTextKey.SOME_LOCAL_RESOURCES_HAVE_NOT_BEEN_CC49E, error.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                    message = uiText(UiTextKey.THE_CONNECTION_REMAINS_RETAINED_YOU_CAN_B094F),
                )
            }
            if (error != null) NativeCloseRecovery.retain(pending.handle)
        }
    }

    fun login(username: String, password: String, factor: String) = runTask {
        val authGeneration = serviceAuthRevision.incrementAndGet()
        updateMobileState { it.copy(
            authGeneration = authGeneration,
            remotePassword = null,
            remotePasswordOffer = null,
            remoteRequests = emptyList(),
        ) }
        val handle = requireHandle()
        val principal = withContext(Dispatchers.IO) {
            NativeSdk.nativeLogin(handle, username.trim(), password, factor.trim().ifEmpty { null })
        }
        val parsed = JSONObject(principal)
        val devices = withContext(Dispatchers.IO) { parseDevices(NativeSdk.nativeDevices(handle)) }
        val networkSettings = withContext(Dispatchers.IO) { parseNativeNetworkSettings(NativeSdk.nativeNetworkSettings(handle)) }
        updateMobileState { current -> current.copy(
            authGeneration = authGeneration,
            principal = parsed.optString("username", username),
            accountId = parsed.optString("account_id"),
            devices = devices,
            networkSettings = networkSettings,
        ) }
        uiText(UiTextKey.SIGNED_IN_ONLINE_STATUS_IS_SHOWN_AE328)
    }

    fun refreshNetworkSettings() {
        val handle = mutableState.value.handle
        if (handle <= 0L) return
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { parseNativeNetworkSettings(NativeSdk.nativeNetworkSettings(handle)) }
                .onSuccess { row -> updateMobileState { if (it.handle == handle) it.copy(networkSettings = row) else it } }
        }
    }

    fun saveNetworkSettings(generation: Long, revision: Long, stun: Boolean, prefixes: String) = runTask {
        val handle = requireHandle()
        val row = withContext(Dispatchers.IO) {
            parseNativeNetworkSettings(NativeSdk.nativeConfigureNetwork(handle, generation, revision, nativeNetworkSettingsJson(stun, prefixes)))
        }
        check(mutableState.value.handle == handle) { AppLanguage.context(getApplication<Application>()).getString(R.string.native_network_stale) }
        updateMobileState { it.copy(networkSettings = row) }
        AppLanguage.context(getApplication<Application>()).getString(
            if (row.durable == false) R.string.native_network_durability else R.string.native_network_saved)
    }

    fun refreshServices(afterId: String? = null) = runServiceCommand(serviceListCommand(afterId))

    fun inspectService(id: String) = runServiceCommand(serviceCommand("inspect_service", JSONObject().put("service_id", id)))

    fun saveService(draft: ServiceEditorDraft) {
        val command = runCatching { draft.command() }.getOrElse { failure ->
            updateMobileState { it.copy(error = failure.message ?: uiText(UiTextKey.CHECK_THE_SERVICE_CONFIGURATION_E61DF), message = "") }
            return
        }
        runServiceCommand(command)
    }

    fun revokeService(row: ServiceRow) = runServiceCommand(serviceCommand("revoke_service",
        JSONObject().put("service_id", row.id).put("expected_revision", row.revision)))

    private fun runServiceCommand(command: JSONObject) {
        val started = mutableState.value
        if (started.busy || started.handle <= 0L || started.principal.isBlank() || started.localClosePending) return
        val authRevision = serviceAuthRevision.get()
        updateMobileState { it.copy(busy = true, error = "", message = "") }
        viewModelScope.launch {
            var binding: ServiceActionBinding? = null
            try {
                val context = withContext(Dispatchers.IO) {
                    parseServiceContext(NativeSdk.nativeServiceContext(started.handle))
                }
                binding = ServiceActionBinding(started.handle, context, authRevision)
                check(context.accountId == started.accountId) { uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B) }
                check(started.services?.context?.let { it == context } != false) {
                    uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_THE_EARLIER_FEBC7)
                }
                check(serviceAuthRevision.get() == authRevision) { uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_THE_SERVICE_397F2) }
                val request = serviceRequest(context, command)
                val (response, liveContext) = withContext(Dispatchers.IO) {
                    val parsed = parseServiceManagement(NativeSdk.nativeServiceAction(started.handle, request))
                    val current = parseServiceContext(NativeSdk.nativeServiceContext(started.handle))
                    parsed to current
                }
                updateMobileState { current ->
                    if (current.handle != started.handle || current.accountId != started.accountId ||
                        current.localClosePending || current.principal.isBlank() ||
                        serviceAuthRevision.get() != authRevision) current
                    else if (!serviceResponseIsCurrent(
                            binding = requireNotNull(binding),
                            responseContext = response.context,
                            liveContext = liveContext,
                            currentHandle = current.handle,
                            currentAccountId = current.accountId,
                            currentUiContext = current.services?.context,
                            currentAuthRevision = serviceAuthRevision.get(),
                        )) current.copy(
                        services = null, busy = false,
                        error = uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_THE_EARLIER_84072), message = "",
                    ) else current.copy(
                        services = response, busy = false,
                        error = if (response.operation.status == "succeeded") "" else response.operation.notice(),
                        message = if (response.operation.status == "succeeded") response.operation.notice() else "",
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState { current ->
                    if (current.handle != started.handle || current.accountId != started.accountId ||
                        current.localClosePending || current.principal.isBlank() ||
                        serviceAuthRevision.get() != authRevision) current
                    else if (binding?.let { current.services?.context?.let { shown -> shown != it.context } } == true) current.copy(
                        services = null, busy = false,
                        error = uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_THE_EARLIER_FEBC7), message = "",
                    )
                    else current.copy(busy = false, error = failure.message ?: uiText(UiTextKey.THE_SERVICE_OPERATION_IS_UNCONFIRMED_KEEP_46F9B), message = "")
                }
            }
        }
    }

    fun refreshDevices() = runTask {
        val rows = withContext(Dispatchers.IO) { parseDevices(NativeSdk.nativeDevices(requireHandle())) }
        updateMobileState { it.copy(devices = rows) }
        uiText(UiTextKey.DEVICE_LIST_UPDATED_BBD55)
    }

    fun enrollController(name: String) = runTask {
        withContext(Dispatchers.IO) { NativeSdk.nativeRegisterController(requireHandle(), name.trim()) }
        val rows = withContext(Dispatchers.IO) { parseDevices(NativeSdk.nativeDevices(requireHandle())) }
        updateMobileState { it.copy(devices = rows) }
        uiText(UiTextKey.THIS_DEVICE_IS_ENROLLED_AS_A_74EA5)
    }

    fun enrollHost(name: String) = runTask {
        withContext(Dispatchers.IO) { NativeSdk.nativeRegisterHost(requireHandle(), name.trim()) }
        val rows = withContext(Dispatchers.IO) { parseDevices(NativeSdk.nativeDevices(requireHandle())) }
        updateMobileState { it.copy(devices = rows) }
        uiText(UiTextKey.THIS_DEVICE_IS_ENROLLED_AS_A_05A51)
    }

    fun stopHostCapture() = HostCaptureService.stop(
        getApplication(),
        handle = mutableState.value.handle,
    )

    fun revokeDevice(id: String) = runTask {
        withContext(Dispatchers.IO) { NativeSdk.nativeRevokeDevice(requireHandle(), id) }
        val rows = withContext(Dispatchers.IO) { parseDevices(NativeSdk.nativeDevices(requireHandle())) }
        updateMobileState { it.copy(devices = rows) }
        uiText(UiTextKey.THE_REVOCATION_REQUEST_COMPLETED_A9AD6)
    }

    fun requestView(hostDeviceId: String, requestInput: Boolean, requestAudio: Boolean, requestFileRead: Boolean = false, requestFileWrite: Boolean = false, requestClipboardRead: Boolean = false, requestClipboardWrite: Boolean = false) = runTask {
        withContext(Dispatchers.IO) {
            NativeSdk.nativeRequestView(requireHandle(), hostDeviceId, requestInput, requestAudio, requestFileRead, requestFileWrite, requestClipboardRead, requestClipboardWrite)
        }
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(requireHandle()))
        }
        val session = withContext(Dispatchers.IO) {
            parseNativeSession(NativeSdk.nativeNativeSessionStatus(requireHandle()))
        }
        updateMobileState { it.copy(remoteRequests = requests).withNativeSession(session) }
        when {
            requestClipboardRead || requestClipboardWrite -> uiText(UiTextKey.SELECTED_CLIPBOARD_DIRECTIONS_REQUESTED_EACH_DEVICE_DD345)
            requestFileRead || requestFileWrite -> uiText(UiTextKey.SELECTED_FILE_DIRECTIONS_REQUESTED_AFTER_THE_68C72)
            requestInput && requestAudio -> uiText(UiTextKey.VIEW_INPUT_AND_SYSTEM_AUDIO_REQUESTED_35387)
            requestInput -> uiText(UiTextKey.VIEW_AND_INPUT_REQUESTED_THE_HOST_AFA88)
            requestAudio -> uiText(UiTextKey.VIEW_AND_SYSTEM_AUDIO_REQUESTED_THE_1196B)
            else -> uiText(UiTextKey.VIEW_ONLY_ACCESS_REQUESTED_AFTER_HOST_323C5)
        }
    }

    suspend fun pollRemoteRequests() {
        val before = mutableState.value
        if (before.handle <= 0 || before.busy) return
        runCatching {
            val requests = withContext(Dispatchers.IO) {
                parseRemoteRequests(NativeSdk.nativeRemoteRequests(before.handle))
            }
            val session = withContext(Dispatchers.IO) {
                parseNativeSession(NativeSdk.nativeNativeSessionStatus(before.handle))
            }
            updateMobileState { current ->
                if (current.handle != before.handle) current
                else current.copy(remoteRequests = requests).withNativeSession(session)
            }
        }
    }

    fun refreshRemoteRequests() = runTask {
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(requireHandle()))
        }
        val session = withContext(Dispatchers.IO) {
            parseNativeSession(NativeSdk.nativeNativeSessionStatus(requireHandle()))
        }
        updateMobileState { it.copy(remoteRequests = requests).withNativeSession(session) }
        if (requests.isEmpty()) uiText(UiTextKey.THERE_ARE_NO_PENDING_OR_RECENT_F794C)
        else uiText(UiTextKey.REMOTE_CONSENT_AND_LOCAL_NATIVE_SESSION_D2B15)
    }

    fun refreshTrustedDevices() = runTask {
        updateMobileState { it.copy(trustedDevices = null) }
        val before = mutableState.value
        val handle = requireHandle()
        check(before.ownDeviceId.isNotBlank()) { uiText(UiTextKey.ENROLL_THIS_DEVICE_AS_A_HOST_64277) }
        val trusted = withContext(Dispatchers.IO) {
            parseTrustedDevices(NativeSdk.nativeTrustedDevices(handle, before.ownDeviceId))
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) {
                current.copy(trustedDevices = trusted)
            } else current
        }
        uiText(UiTextKey.TRUSTED_DEVICES_REFRESHED)
    }

    fun trustRemote(request: RemoteRequestRow) = runTask {
        val before = mutableState.value
        check(request.hostDeviceId == before.ownDeviceId && request.status == "approved" && request.leaseSequence > 0L) {
            uiText(UiTextKey.ONLY_THIS_HOSTS_APPROVED_ACTIVE_REQUEST_CAN_BE_TRUSTED)
        }
        val handle = requireHandle()
        val trusted = before.trustedDevices?.takeIf { it.hostDeviceId == request.hostDeviceId }
            ?: withContext(Dispatchers.IO) {
                parseTrustedDevices(NativeSdk.nativeTrustedDevices(handle, request.hostDeviceId))
            }
        val expectedRevision = trusted.devices
            .firstOrNull { it.controllerDeviceId == request.controllerDeviceId }
            ?.revision ?: 0L
        val expiry = Math.addExact(System.currentTimeMillis(), 3_600_000L)
        val updated = withContext(Dispatchers.IO) {
            parseTrustedDevices(
                NativeSdk.nativeTrustRemote(handle, request.id, expectedRevision, expiry),
            )
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) {
                current.copy(trustedDevices = updated)
            } else current
        }
        uiText(UiTextKey.CONTROLLER_TRUSTED_FOR_ONE_HOUR)
    }

    fun revokeTrustedDevice(device: TrustedDeviceRow) = runTask {
        val before = mutableState.value
        val trusted = before.trustedDevices?.takeIf { it.hostDeviceId == before.ownDeviceId }
            ?: error(uiText(UiTextKey.REFRESH_TRUSTED_DEVICES_BEFORE_REVOKING))
        check(device.active) {
            uiText(UiTextKey.REFRESH_TRUSTED_DEVICES_BEFORE_REVOKING)
        }
        val handle = requireHandle()
        val updated = withContext(Dispatchers.IO) {
            parseTrustedDevices(
                NativeSdk.nativeRevokeDeviceTrust(
                    handle,
                    trusted.hostDeviceId,
                    device.controllerDeviceId,
                    device.revision,
                ),
            )
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) {
                current.copy(trustedDevices = updated)
            } else current
        }
        uiText(UiTextKey.TRUSTED_DEVICE_ACCESS_REVOKED)
    }

    fun refreshRemotePassword() = runTask {
        updateMobileState { it.copy(remotePassword = null) }
        val handle = requireHandle()
        val before = mutableState.value
        check(before.ownDeviceId.isNotBlank()) { uiText(UiTextKey.ENROLL_THIS_DEVICE_AS_A_HOST_64277) }
        val settings = withContext(Dispatchers.IO) {
            parseRemotePasswordView(NativeSdk.nativeRemotePassword(handle, before.ownDeviceId))
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) current.copy(remotePassword = settings)
            else current
        }
        uiText(UiTextKey.REMOTE_PASSWORD_SETTINGS_REFRESHED)
    }

    fun configureRemotePassword(
        expectedRevision: Long,
        permissions: List<Int>,
        paths: List<Int>,
        lifetimeDays: Int,
        password: String,
    ) = runTask {
        check(remotePasswordLengthIsValid(password)) { uiText(UiTextKey.REMOTE_PASSWORD_MUST_BE_12_1024_UTF_8_BYTES) }
        val expiresAtUnixMs = remotePasswordExpiry(System.currentTimeMillis(), lifetimeDays)
            ?: error(uiText(UiTextKey.CHOOSE_AN_EXPIRY_WITHIN_30_DAYS))
        val settingsJson = remotePasswordSettingsJson(expectedRevision, permissions, paths, expiresAtUnixMs)
        val wasActive = mutableState.value.remotePassword?.active == true
        val handle = requireHandle()
        val authGeneration = mutableState.value.authGeneration
        val settings = withContext(Dispatchers.IO) {
            parseRemotePasswordView(
                NativeSdk.nativeConfigureRemotePassword(handle, settingsJson, password),
            )
        }
        check(serviceAuthRevision.get() == authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == authGeneration) current.copy(remotePassword = settings)
            else current
        }
        uiText(if (wasActive) UiTextKey.REMOTE_PASSWORD_ROTATED_ITS_OLD_SESSIONS_WERE_CLOSED else UiTextKey.REMOTE_PASSWORD_CONFIGURED_ITS_OLD_SESSIONS_WERE_CLOSED)
    }

    fun revokeRemotePassword(expectedRevision: Long) = runTask {
        val handle = requireHandle()
        val authGeneration = mutableState.value.authGeneration
        val settings = withContext(Dispatchers.IO) {
            parseRemotePasswordView(NativeSdk.nativeRevokeRemotePassword(handle, expectedRevision))
        }
        check(serviceAuthRevision.get() == authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == authGeneration) current.copy(remotePassword = settings)
            else current
        }
        uiText(UiTextKey.REMOTE_PASSWORD_REVOKED_AND_ITS_SESSIONS_WERE_CLOSED)
    }

    fun refreshRemotePasswordOffer(request: RemoteRequestRow) = runTask {
        updateMobileState { current ->
            current.copy(remotePasswordOffer = current.remotePasswordOffer?.takeUnless { it.requestId == request.id })
        }
        val before = mutableState.value
        check(request.controllerDeviceId == before.ownDeviceId && request.status == "pending") {
            uiText(UiTextKey.ONLY_A_PENDING_OUTGOING_REQUEST_CAN_USE_A_PASSWORD)
        }
        val handle = requireHandle()
        val scope = withContext(Dispatchers.IO) {
            parseRemotePasswordOffer(
                request.id,
                NativeSdk.nativeRemotePasswordOffer(handle, request.id),
            )
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) current.copy(remotePasswordOffer = scope)
            else current
        }
        uiText(UiTextKey.REMOTE_PASSWORD_SCOPE_REFRESHED_FOR_THIS_REQUEST)
    }

    fun authorizeRemotePassword(request: RemoteRequestRow, expectedRevision: Long, password: String) = runTask {
        check(request.status == "pending" && request.controllerDeviceId == mutableState.value.ownDeviceId) {
            uiText(UiTextKey.ONLY_A_PENDING_OUTGOING_REQUEST_CAN_USE_A_PASSWORD)
        }
        check(remotePasswordLengthIsValid(password)) { uiText(UiTextKey.REMOTE_PASSWORD_MUST_BE_12_1024_UTF_8_BYTES) }
        val before = mutableState.value
        val handle = requireHandle()
        val result = withContext(Dispatchers.IO) {
            NativeSdk.nativeAuthorizeRemotePassword(handle, request.id, expectedRevision, password)
        }
        check(serviceAuthRevision.get() == before.authGeneration && mutableState.value.handle == handle) {
            uiText(UiTextKey.THE_ACCOUNT_SESSION_CHANGED_SIGN_IN_6841B)
        }
        val updatedRequest = parseRemoteRequest(result)
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(handle))
        }
        updateMobileState { current ->
            if (current.handle == handle && current.authGeneration == before.authGeneration) current.copy(
                remotePasswordOffer = current.remotePasswordOffer?.takeUnless { it.requestId == request.id },
                remoteRequests = (requests.filterNot { it.id == updatedRequest.id } + updatedRequest),
            ) else current
        }
        uiText(UiTextKey.REMOTE_PASSWORD_AUTHORIZED_THIS_REQUEST_ONLY)
    }

    fun decideRemote(
        request: RemoteRequestRow,
        approved: Boolean,
        approveInput: Boolean = false,
        approveAudio: Boolean = false,
        approveFileRead: Boolean = false,
        approveFileWrite: Boolean = false,
        approveClipboardRead: Boolean = false,
        approveClipboardWrite: Boolean = false,
    ) = runTask {
        withContext(Dispatchers.IO) {
            NativeSdk.nativeApproveRemote(
                requireHandle(), request.id, request.nonce, request.policyRevision, approved, approveInput, approveAudio, approveFileRead, approveFileWrite, approveClipboardRead, approveClipboardWrite,
            )
        }
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(requireHandle()))
        }
        updateMobileState { it.copy(remoteRequests = requests) }
        if (!approved) uiText(UiTextKey.THE_REMOTE_REQUEST_WAS_REJECTED_BCD3C)
        else when {
            approveClipboardRead || approveClipboardWrite -> uiText(UiTextKey.SELECTED_CLIPBOARD_DIRECTIONS_APPROVED_LOCAL_SYSTEM_DC7D7)
            approveFileRead || approveFileWrite -> uiText(UiTextKey.SELECTED_FILE_DIRECTIONS_APPROVED_LOCAL_FILE_E60B7)
            approveInput && approveAudio -> uiText(UiTextKey.VIEW_INPUT_AND_SYSTEM_AUDIO_APPROVED_D1F33)
            approveInput -> uiText(UiTextKey.VIEW_AND_INPUT_APPROVED_INPUT_REMAINS_AC722)
            approveAudio -> uiText(UiTextKey.VIEW_AND_SYSTEM_AUDIO_APPROVED_THE_E02A6)
            else -> uiText(UiTextKey.VIEW_ONLY_ACCESS_APPROVED_THE_LOCAL_9E193)
        }
    }

    fun startNativeSession(request: RemoteRequestRow) = runTask {
        withContext(Dispatchers.IO) {
            NativeSdk.nativeStartNativeSession(requireHandle(), request.id)
        }
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(requireHandle()))
        }
        val session = withContext(Dispatchers.IO) {
            parseNativeSession(NativeSdk.nativeNativeSessionStatus(requireHandle()))
        }
        updateMobileState { it.copy(remoteRequests = requests).withNativeSession(session) }
        uiText(UiTextKey.NATIVE_SESSION_ESTABLISHED_THE_HOST_ENABLES_D60E0)
    }

    fun startBrowserHost(request: RemoteRequestRow) = runTask {
        val handle = requireHandle()
        check(request.status == "approved" && request.hostDeviceId == mutableState.value.ownDeviceId) {
            uiText(UiTextKey.ONLY_A_LOCALLY_APPROVED_REMOTE_REQUEST_871BC)
        }
        check(mutableState.value.nativeSession?.status !in setOf("establishing", "connected", "stopping")) {
            uiText(UiTextKey.STOP_THE_NATIVE_SESSION_BEFORE_STARTING_43E5D)
        }
        updateMobileState {
            it.withBrowserHost(
                BrowserHostRow(request.id, request.connectionGeneration, "establishing", false, null),
            )
        }
        try {
            val raw = withContext(Dispatchers.IO) {
                NativeSdk.nativeStartBrowserHost(handle, request.id)
            }
            val host = parseBrowserHost(raw)
            updateMobileState { current ->
                if (current.handle == handle) current.withBrowserHost(host) else current
            }
        } finally {
            refreshBrowserHostStatus(handle)
        }
        uiText(UiTextKey.BROWSER_SHARING_CONNECTED_AUTHORIZED_MEDIA_STARTS_9A95E)
    }

    fun stopBrowserHost(requestId: String) = runTask {
        val handle = requireHandle()
        val raw = withContext(Dispatchers.IO) {
            NativeSdk.nativeStopBrowserHost(handle, requestId)
        }
        val host = parseBrowserHost(raw)
        updateMobileState { current ->
            if (current.handle == handle) current.withBrowserHost(host) else current
        }
        refreshBrowserHostStatus(handle)
        uiText(UiTextKey.BROWSER_SHARING_STOPPED_F0350)
    }

    suspend fun refreshBrowserHostStatus(handle: Long = mutableState.value.handle) {
        if (handle <= 0L) return
        val host = runCatching {
            withContext(Dispatchers.IO) {
                parseBrowserHost(NativeSdk.nativeBrowserHostStatus(handle))
            }
        }.getOrNull()
        updateMobileState { current ->
            if (current.handle == handle) current.withBrowserHost(host) else current
        }
    }

    fun stopNativeSession(requestId: String) = runTask {
        withContext(Dispatchers.IO) {
            NativeSdk.nativeStopNativeSession(requireHandle(), requestId)
        }
        val session = withContext(Dispatchers.IO) {
            parseNativeSession(NativeSdk.nativeNativeSessionStatus(requireHandle()))
        }
        updateMobileState { it.withNativeSession(session) }
        uiText(UiTextKey.THE_LOCAL_NATIVE_SESSION_STOPPED_503CE)
    }

    fun updateNativeDisplays(handle: Long, requestId: String, generation: Long, reported: NativeDisplays?): Boolean {
        val updated = updateMobileState { current ->
            if (!current.matchesVideoSession(handle, requestId, generation)) current
            else if (reported != null && !reported.matchesSession(requestId, generation)) current
            else if (reported != null && current.localDisplaySelection?.let { !reported.observes(it) } == true) current
            else if (reported?.catalog != null && current.nativeDisplays?.catalog?.let { it.revision > reported.catalog.revision } == true) current
            else {
                val keep = reported != null && current.remoteVideoLayout?.let(reported::accepts) == true
                current.copy(
                    nativeDisplays = reported,
                    remoteVideoLayout = current.remoteVideoLayout.takeIf { keep },
                    remoteVideoPresentation = current.remoteVideoPresentation.takeIf { keep },
                    nativeInputLayout = current.nativeInputLayout.takeIf { keep },
                )
            }
        }
        return updated.matchesVideoSession(handle, requestId, generation)
    }

    fun selectRemoteDisplay(source: Int) {
        val before = mutableState.value
        val request = before.nativeDisplays?.request(source) ?: return
        val session = before.nativeSession ?: return
        val previousInput = before.nativeInputLayout?.binding
        val updated = updateMobileState { current ->
            if (current.handle != before.handle || current.nativeSession != session ||
                current.nativeDisplays != before.nativeDisplays || current.effectiveDisplays()?.confirmed == null
            ) current else current.copy(
                localDisplaySelection = request,
                remoteVideoLayout = null, remoteVideoPresentation = null, nativeInputLayout = null,
                error = "",
            )
        }
        if (updated.localDisplaySelection != request) return
        viewModelScope.launch {
            try {
                val reported = withContext(Dispatchers.IO) {
                    synchronized(nativeInputDeliveryLock) {
                        previousInput?.let { NativeSdk.nativeReleaseInput(before.handle, it.toJson()) }
                        NativeDisplays.parse(NativeSdk.nativeSelectRemoteDisplay(before.handle, request.toJson()))
                            ?: error(uiText(UiTextKey.THE_REMOTE_DISPLAY_SELECTION_RESPONSE_IS_EF124))
                    }
                }
                updateNativeDisplays(before.handle, session.requestId, session.connectionGeneration, reported)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState { current ->
                    if (current.handle != before.handle || current.localDisplaySelection != request) current
                    else current.copy(error = failure.message ?: uiText(UiTextKey.COULD_NOT_SWITCH_THE_REMOTE_DISPLAY_DD2C5))
                }
            }
        }
    }

    fun updateRemoteVideoLayout(
        handle: Long,
        requestId: String,
        sessionGeneration: Long,
        layout: NativeRemoteVideoLayout?,
    ): Boolean {
        val updated = updateMobileState { current ->
            if (!current.matchesVideoSession(handle, requestId, sessionGeneration)) current
            else {
                val validLayout = layout?.takeIf {
                    it.connectionGeneration == sessionGeneration && it.layoutEpoch > 0 &&
                        current.effectiveDisplays()?.accepts(it) == true && it.width in 1..8192 && it.height in 1..8192 &&
                        it.width.toLong() * it.height.toLong() * 4 <= 64L * 1024 * 1024
                }
                if (current.remoteVideoLayout == validLayout &&
                    (validLayout != null || current.remoteVideoPresentation == null)
                ) current
                else current.copy(
                    remoteVideoLayout = validLayout,
                    remoteVideoPresentation = null,
                    nativeInputLayout = current.nativeInputLayout?.takeIf {
                        validLayout != null && it.binding.connectionGeneration == validLayout.connectionGeneration &&
                            it.binding.source == validLayout.source && it.binding.layoutEpoch == validLayout.layoutEpoch
                    },
                )
            }
        }
        return updated.matchesVideoSession(handle, requestId, sessionGeneration)
    }

    fun updateNativeInputLayout(
        handle: Long,
        requestId: String,
        sessionGeneration: Long,
        layout: NativeRemoteInputLayout?,
    ): Boolean {
        val updated = updateMobileState { current ->
            if (!current.matchesVideoSession(handle, requestId, sessionGeneration)) current
            else {
                val valid = layout?.takeIf { input ->
                    input.isValid() && input.binding.requestId == requestId &&
                        input.binding.connectionGeneration == sessionGeneration &&
                        current.remoteVideoLayout?.let(input.binding::matchesVideoLayout) == true
                }
                if (current.nativeInputLayout == valid) current
                else current.copy(nativeInputLayout = valid)
            }
        }
        return updated.matchesVideoSession(handle, requestId, sessionGeneration)
    }

    fun sendNativeInput(binding: NativeInputBinding, action: NativeInputAction) {
        val current = mutableState.value
        if (inputReleasePending.get() > 0 || current.handle <= 0 || current.nativeInputLayout?.binding != binding) return
        val accepted = synchronized(nativeInputQueueLock) {
            val tail = nativeInputQueue.peekLast()
            // Coalesce only consecutive motion. Button/key ordering is preserved.
            if (action is NativeInputAction.Pointer && action.button == null &&
                tail?.action is NativeInputAction.Pointer && tail.action.button == null &&
                tail.handle == current.handle && tail.binding == binding) {
                nativeInputQueue.removeLast()
            }
            if (nativeInputQueue.size >= 64) false else {
                nativeInputQueue.addLast(NativeInputMessage.Action(current.handle, binding, action, nativeInputRevision.get()))
                true
            }
        }
        if (accepted) nativeInputMessages.trySend(Unit) else releaseNativeInput(binding)
    }

    fun releaseNativeInput(binding: NativeInputBinding) {
        val current = mutableState.value
        if (current.handle <= 0 || current.nativeSession?.requestId != binding.requestId ||
            current.nativeSession?.connectionGeneration != binding.connectionGeneration
        ) return
        inputReleasePending.incrementAndGet()
        nativeInputRevision.incrementAndGet()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                synchronized(nativeInputDeliveryLock) {
                    synchronized(nativeInputQueueLock) { nativeInputQueue.clear() }
                    NativeSdk.nativeReleaseInput(current.handle, binding.toJson())
                }
            } finally {
                inputReleasePending.decrementAndGet()
            }
        }
    }

    fun reserveRemoteVideoBitmap(): RemoteVideoBitmapReservation? = remoteVideoBitmapOwner.reserve()

    fun retryRemoteVideoRetirements(barrier: RemoteVideoFrameCommitBarrier) {
        remoteVideoBitmapOwner.retryPendingRetirements(barrier)
    }

    fun cancelRemoteVideoRetirementCallbacks(barrier: RemoteVideoFrameCommitBarrier) {
        remoteVideoBitmapOwner.cancelPendingRetirements(barrier)
    }

    fun presentRemoteVideo(
        handle: Long,
        requestId: String,
        sessionGeneration: Long,
        layout: NativeRemoteVideoLayout,
        frame: NativeDecodedVideoFrame,
        bitmapLease: RemoteVideoBitmapLease,
    ): Boolean {
        val updated = updateMobileState { current ->
            val previous = current.remoteVideoPresentation
            if (current.matchesVideoSession(handle, requestId, sessionGeneration) &&
                current.effectiveDisplays()?.accepts(layout) == true &&
                current.remoteVideoLayout == layout && frame.matches(layout) &&
                (previous == null || previous.sequence < frame.sequence)
            ) {
                current.copy(
                    remoteVideoPresentation = RemoteVideoPresentation(
                        connectionGeneration = frame.connectionGeneration,
                        layoutEpoch = frame.layoutEpoch,
                        source = frame.source,
                        sequence = frame.sequence,
                        width = frame.width,
                        height = frame.height,
                        bitmapLease = bitmapLease,
                    ),
                )
            } else {
                current
            }
        }
        return updated.matchesVideoSession(handle, requestId, sessionGeneration) &&
            updated.remoteVideoLayout == layout &&
            updated.remoteVideoPresentation?.bitmapLease === bitmapLease
    }

    fun clearRemoteVideo(handle: Long? = null, requestId: String? = null, sessionGeneration: Long? = null) {
        updateMobileState { current ->
            val session = current.nativeSession
            val isTarget = (handle == null || current.handle == handle) &&
                (requestId == null || session?.requestId == requestId) &&
                (sessionGeneration == null || session?.connectionGeneration == sessionGeneration)
            if (isTarget && (current.remoteVideoLayout != null || current.remoteVideoPresentation != null || current.nativeInputLayout != null)) {
                current.copy(remoteVideoLayout = null, remoteVideoPresentation = null, nativeInputLayout = null)
            } else {
                current
            }
        }
    }

    fun synchronizeNativeSession(
        handle: Long,
        expected: NativeSessionRow,
        reported: NativeSessionRow?,
    ): Boolean {
        val updated = updateMobileState { current ->
            val currentSession = current.nativeSession
            if (current.handle != handle || currentSession?.requestId != expected.requestId ||
                currentSession?.connectionGeneration != expected.connectionGeneration
            ) current else current.withNativeSession(reported)
        }
        val actual = updated.nativeSession
        return updated.handle == handle && actual?.let {
            it.requestId == expected.requestId && it.connectionGeneration == expected.connectionGeneration &&
                it.status in setOf("establishing", "connected")
        } == true
    }

    fun refreshNativeClipboard() {
        val handle = mutableState.value.handle
        if (handle <= 0L || NativeSafPickerOwners.isClosing(handle) || clipboardOperationActive.get() || !clipboardRefreshActive.compareAndSet(false, true)) return
        val revision = clipboardRevision.get()
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            try {
                if (viewModelCleared.get() || NativeSafPickerOwners.isClosing(handle)) return@launch
                val discovered = parseNativeClipboardStatus(NativeSdk.nativeClipboardStatus(handle))
                if (mutableState.value.handle != handle || clipboardOperationActive.get() || clipboardRevision.get() != revision) return@launch
                val endpoint = clipboardEndpoint.get()
                if (endpoint != null && (discovered == null || !endpoint.matchesBinding(discovered.binding.requestId, discovered.binding.connectionGeneration, discovered.binding.coreGeneration))) {
                    endpoint.close()
                    clipboardEndpoint.compareAndSet(endpoint, null)
                }
                updateMobileState { current ->
                    if (current.handle != handle || clipboardOperationActive.get() || clipboardRevision.get() != revision) current
                    else {
                        val platformOutcome = clipboardEndpoint.get()?.lastOutcome() ?: NativeClipboardOutcome.OK
                        current.copy(clipboard = discovered, clipboardEndpointActive = clipboardEndpoint.get()?.isActive() == true,
                            clipboardPlatformOutcome = platformOutcome,
                            clipboardNotice = when {
                                current.clipboard?.binding != discovered?.binding -> uiText(UiTextKey.THE_LOCAL_SESSION_CHANGED_CLIPBOARD_DIRECTIONS_EC615)
                                platformOutcome != NativeClipboardOutcome.OK -> nativeClipboardOutcomeMessage(platformOutcome)
                                current.clipboardPlatformOutcome != NativeClipboardOutcome.OK -> ""
                                else -> current.clipboardNotice
                            })
                    }
                }
            } catch (_: Exception) {
                updateMobileState { current -> if (current.handle != handle || clipboardOperationActive.get()) current else current.copy(clipboardNotice = uiText(UiTextKey.COULD_NOT_READ_CLIPBOARD_CONSENT_STATUS_5AE90)) }
            } finally { clipboardRefreshActive.set(false) }
        }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    fun setNativeClipboardDirections(binding: NativeClipboardBinding, read: Boolean, write: Boolean) {
        val before = mutableState.value
        val row = before.clipboard ?: return
        val handle = before.handle
        if (row.binding != binding || handle <= 0L || NativeSafPickerOwners.isClosing(handle) ||
            (read && !row.allowedLocalRead) || (write && !row.allowedLocalWrite) || !clipboardOperationActive.compareAndSet(false, true)) return
        val revision = clipboardRevision.incrementAndGet()
        // Revoke the platform gate before waiting on any async Core work.
        clipboardEndpoint.get()?.revokeDirections(read, write)
        updateMobileState { it.copy(clipboardBusy = true, clipboardNotice = "") }
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            var created: NativeClipboardEndpoint? = null
            try {
                if (!clipboardBindingCurrent(handle, binding)) return@launch
                val actual = parseNativeClipboardStatus(NativeSdk.nativeClipboardStatus(handle)) ?: return@launch
                if (actual.binding != binding) return@launch
                if (!actual.ready && (read || write)) {
                    created = NativeClipboardEndpoint(getApplication(), handle, binding, clipboardForeground, read, write)
                    clipboardEndpoint.getAndSet(created)?.close()
                }
                val confirmed = parseNativeClipboardStatus(NativeSdk.nativeClipboardSetDirections(handle, binding.json(), read, write, created))
                if (confirmed?.binding != binding || !clipboardBindingCurrent(handle, binding)) return@launch
                updateMobileState { current ->
                    if (current.handle != handle || current.clipboard?.binding != binding || clipboardRevision.get() != revision) current else current.copy(
                        clipboard = confirmed, clipboardEndpointActive = clipboardEndpoint.get()?.isActive() == true,
                        clipboardNotice = if (read || write) uiText(UiTextKey.SELECTED_LOCAL_DIRECTIONS_CONFIRMED_CONTENT_IS_3540F) else uiText(UiTextKey.LOCAL_CLIPBOARD_CONSENT_REVOKED_A_NEW_4C5B4))
                }
            } catch (_: Exception) {
                created?.let { it.close(); clipboardEndpoint.compareAndSet(it, null) }
                updateMobileState { current -> if (current.handle != handle || current.clipboard?.binding != binding || clipboardRevision.get() != revision) current else current.copy(
                    clipboardEndpointActive = clipboardEndpoint.get()?.isActive() == true,
                    clipboardNotice = uiText(UiTextKey.THE_LOCAL_CLIPBOARD_DIRECTION_WAS_NOT_9F520)) }
            } finally {
                clipboardOperationActive.set(false)
                updateMobileState { current -> if (current.handle != handle) current else current.copy(clipboardBusy = false) }
            }
        }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    fun revokeNativeClipboard(binding: NativeClipboardBinding) {
        val current = mutableState.value
        val handle = current.handle
        if (handle <= 0L || current.clipboard?.binding != binding || NativeSafPickerOwners.isClosing(handle)) return
        // This gate closes even while the original action is blocked. Its
        // actual worker remains retained; a pending write can still be Unknown.
        clipboardEndpoint.get()?.close()
        if (!clipboardRevocationActive.compareAndSet(false, true)) return
        val revision = clipboardRevision.incrementAndGet()
        updateMobileState { it.copy(clipboardEndpointActive = false, clipboardNotice = uiText(UiTextKey.LOCAL_CLIPBOARD_ACCESS_CLOSED_CHECKING_ORIGINAL_F2D41)) }
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            try {
                if (!clipboardBindingCurrent(handle, binding)) return@launch
                val confirmed = parseNativeClipboardStatus(NativeSdk.nativeClipboardSetDirections(handle, binding.json(), false, false, null))
                updateMobileState { state ->
                    if (state.handle != handle || state.clipboard?.binding != binding || confirmed?.binding != binding || clipboardRevision.get() != revision) state
                    else state.copy(clipboard = confirmed, clipboardNotice = uiText(UiTextKey.LOCAL_CLIPBOARD_CONSENT_REVOKED_A_WRITE_A9766))
                }
            } catch (_: Exception) {
                updateMobileState { state -> if (state.handle != handle || state.clipboard?.binding != binding || clipboardRevision.get() != revision) state
                    else state.copy(clipboardNotice = uiText(UiTextKey.LOCAL_CLIPBOARD_ACCESS_CLOSED_ORIGINAL_SESSION_19988)) }
            } finally { clipboardRevocationActive.set(false) }
        }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    fun runNativeClipboardAction(binding: NativeClipboardBinding, sendLocal: Boolean) {
        val before = mutableState.value
        val row = before.clipboard ?: return
        val handle = before.handle
        if (row.binding != binding || !row.canAct(sendLocal) || handle <= 0L || NativeSafPickerOwners.isClosing(handle) || !clipboardOperationActive.compareAndSet(false, true)) return
        val revision = clipboardRevision.incrementAndGet()
        updateMobileState { it.copy(clipboardBusy = true, clipboardNotice = "") }
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            try {
                if (!clipboardBindingCurrent(handle, binding)) return@launch
                val effect = NativeSdk.nativeClipboardAction(handle, binding.json(), sendLocal)
                if (!clipboardBindingCurrent(handle, binding)) return@launch
                val notice = when (effect) {
                    "applied" -> uiText(UiTextKey.THIS_TEXT_CLIPBOARD_TRANSFER_WAS_CONFIRMED_85632)
                    "not_applied" -> uiText(UiTextKey.THIS_WRITE_WAS_NOT_APPLIED_B6A3C)
                    else -> uiText(UiTextKey.THE_WRITE_OUTCOME_IS_UNKNOWN_CHECK_91A60)
                }
                updateMobileState { current -> if (current.handle != handle || current.clipboard?.binding != binding || clipboardRevision.get() != revision) current else current.copy(clipboardNotice = notice) }
            } catch (_: Exception) {
                val code = clipboardEndpoint.get()?.lastOutcome() ?: NativeClipboardOutcome.UNAVAILABLE
                val notice = if (code == NativeClipboardOutcome.OK) uiText(UiTextKey.THE_TRANSFER_WAS_NOT_CONFIRMED_COMPLETE_EE50B) else nativeClipboardOutcomeMessage(code)
                updateMobileState { current -> if (current.handle != handle || current.clipboard?.binding != binding || clipboardRevision.get() != revision) current else current.copy(clipboardNotice = notice) }
            } finally {
                clipboardOperationActive.set(false)
                updateMobileState { current -> if (current.handle != handle) current else current.copy(clipboardBusy = false, clipboardEndpointActive = clipboardEndpoint.get()?.isActive() == true,
                    clipboardPlatformOutcome = clipboardEndpoint.get()?.lastOutcome() ?: NativeClipboardOutcome.OK) }
            }
        }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    private fun clipboardBindingCurrent(handle: Long, binding: NativeClipboardBinding): Boolean {
        val current = mutableState.value
        return !viewModelCleared.get() && current.handle == handle && current.clipboard?.binding == binding && !NativeSafPickerOwners.isClosing(handle) &&
            parseNativeClipboardStatus(NativeSdk.nativeClipboardStatus(handle))?.binding == binding
    }

    fun refreshNativeFiles() {
        val handle = mutableState.value.handle
        if (handle <= 0L || NativeSafPickerOwners.isClosing(handle) || !fileRefreshActive.compareAndSet(false, true)) return
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            try {
                if (NativeSafPickerOwners.isClosing(handle) || mutableState.value.handle != handle) return@launch
                val discovered = parseNativeFileSessionIdentity(NativeSdk.nativeFileSessionIdentity(handle))
                val before = mutableState.value
                if (before.handle != handle) return@launch
                val oldIdentity = before.fileSession
                if (discovered == oldIdentity) {
                    if (discovered?.isHost == true && !NativeSafPickerOwners.isClosing(handle)) refreshNativeHostFiles(handle, discovered)
                    else if (discovered != null && !before.fileBusy && !before.filePickerPending &&
                        before.fileTasks.ifEmpty { listOfNotNull(before.fileTask) }.all { it.finished && it.ownerStopped } &&
                        before.fileExports.values.none { it.ownerRetained() }
                    ) {
                        // Host roots are dynamic local approvals. The session
                        // identity stays unchanged when a host shares a file.
                        val read = if (discovered.canRead) parseNativeFileRoots(NativeSdk.nativeFileRoots(handle, discovered.identityJson, false)) else emptyList()
                        if (NativeSafPickerOwners.isClosing(handle)) return@launch
                        val write = if (discovered.canWrite) parseNativeFileRoots(NativeSdk.nativeFileRoots(handle, discovered.identityJson, true)) else emptyList()
                        updateMobileState { current ->
                            if (current.handle != handle || current.fileSession != discovered) current else current.copy(
                                fileReadRoots = read, fileWriteRoots = write,
                                selectedReadRootId = current.selectedReadRootId.takeIf { id -> read.any { it.id == id } } ?: read.firstOrNull()?.id.orEmpty(),
                                selectedWriteRootId = current.selectedWriteRootId.takeIf { id -> write.any { it.id == id } } ?: write.firstOrNull()?.id.orEmpty(),
                                fileBrowsePage = current.fileBrowsePage?.takeIf { page -> read.any { it.id == page.rootId } },
                            )
                        }
                    }
                    return@launch
                }

                val oldTask = before.fileTask?.takeIf { !it.ownerStopped }
                val oldExport = before.safExport?.takeIf { it.phase == "running" }
                val oldBrowse = before.fileBrowsePage
                if (oldIdentity != null) {
                    if (oldTask != null) {
                        runCatching { NativeSdk.nativeFileTaskControl(handle, oldIdentity.identityJson, oldTask.taskId, 2) }
                    }
                    if (oldExport != null) {
                        runCatching { NativeSdk.nativeFileExportCancel(handle, oldIdentity.identityJson, oldExport.exportId) }
                    }
                    if (oldBrowse != null) {
                        runCatching { NativeSdk.nativeFileBrowseCancel(handle, oldIdentity.identityJson, oldBrowse.browseId) }
                    }
                }
                synchronized(filePickerLock) {
                    if (pendingSafUpload?.handle == handle && pendingSafUpload?.identity == oldIdentity) pendingSafUpload = null
                    if (pendingSafExport?.handle == handle && pendingSafExport?.identity == oldIdentity) pendingSafExport = null
                    if (pendingHostShare?.first == handle && pendingHostShare?.second == oldIdentity) pendingHostShare = null
                    if (pendingHostExport?.handle == handle && pendingHostExport?.identity == oldIdentity) pendingHostExport = null
                }
                fileTaskPollJob?.cancel()
                fileExportPollJob?.cancel()

                val readRoots = if (discovered?.canRead == true && !discovered.isHost) {
                    parseNativeFileRoots(NativeSdk.nativeFileRoots(handle, discovered.identityJson, false))
                } else emptyList()
                val writeRoots = if (discovered?.canWrite == true && !discovered.isHost) {
                    parseNativeFileRoots(NativeSdk.nativeFileRoots(handle, discovered.identityJson, true))
                } else emptyList()
                val current = mutableState.value
                if (current.handle != handle || current.fileSession != oldIdentity) return@launch
                val selectedReadRoot = current.selectedReadRootId.takeIf { id -> readRoots.any { it.id == id } }
                    ?: readRoots.firstOrNull()?.id.orEmpty()
                val selectedWriteRoot = current.selectedWriteRootId.takeIf { id -> writeRoots.any { it.id == id } }
                    ?: writeRoots.firstOrNull()?.id.orEmpty()
                updateMobileState {
                    if (it.handle != handle || it.fileSession != oldIdentity) it else it.copy(
                        fileSession = discovered,
                        hostFiles = NativeHostFilesRow(),
                        fileReadRoots = readRoots,
                        fileWriteRoots = writeRoots,
                        selectedReadRootId = selectedReadRoot,
                        selectedWriteRootId = selectedWriteRoot,
                        fileBrowsePage = null,
                        fileTask = null,
                        fileTaskName = "",
                        safExport = null,
                        fileTasks = emptyList(),
                        fileExports = emptyMap(),
                        discardedDownloadTaskIds = emptySet(),
                        fileLoading = false,
                        fileBusy = false,
                        filePickerPending = false,
                        fileError = "",
                    )
                }
                if (discovered?.isHost == true && !NativeSafPickerOwners.isClosing(handle)) refreshNativeHostFiles(handle, discovered)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState { current ->
                    if (current.handle != handle) current else current.copy(
                        fileLoading = false,
                        fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_READ_THE_CURRENT_FILE_510FB),
                    )
                }
            } finally {
                fileRefreshActive.set(false)
            }
        }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    private fun refreshNativeHostFiles(handle: Long, identity: NativeFileSessionIdentity): NativeHostFilesRow? {
        if (!identity.isHost || !isNativeFileIdentityCurrent(handle, identity)) return null
        NativeSdk.nativeConfigureHostFileArea(handle, getApplication<Application>().filesDir.resolve("host-files").absolutePath)
        if (!isNativeFileIdentityCurrent(handle, identity)) return null
        NativeSdk.nativeHostFilesAttach(handle, identity.identityJson)
        val host = parseNativeHostFiles(NativeSdk.nativeHostFilesStatus(handle, identity.identityJson), identity)
        updateMobileState { if (it.handle != handle || it.fileSession != identity) it else it.copy(hostFiles = host) }
        return host
    }

    fun prepareNativeHostShare(): Boolean {
        val current = mutableState.value
        val session = current.fileSession ?: return false
        if (!session.isHost || !session.canRead || current.fileBusy || current.filePickerPending || !current.canStartAnotherFileTask()) return false
        synchronized(filePickerLock) {
            if (pendingSafUpload != null || pendingSafExport != null || pendingHostShare != null || pendingHostExport != null) return false
            pendingHostShare = current.handle to session
        }
        updateMobileState { if (it.fileSession != session) it else it.copy(filePickerPending = true, fileError = "") }
        return true
    }

    fun finishNativeHostSharePicker(uris: List<Uri>) {
        val pending = synchronized(filePickerLock) { pendingHostShare.also { pendingHostShare = null } } ?: return
        updateMobileState { if (it.fileSession != pending.second) it else it.copy(filePickerPending = false) }
        if (uris.isEmpty()) return
        if (uris.distinct().size > 8) { updateMobileState { it.copy(fileError = uiText(UiTextKey.YOU_CAN_SHARE_UP_TO_8_81711)) }; return }
        updateMobileState { if (it.fileSession != pending.second) it else it.copy(fileBusy = true, fileError = "") }
        launchNativeSafPickerWorker(pending.first) {
            try {
                if (refreshNativeHostFiles(pending.first, pending.second) == null) error(uiText(UiTextKey.THE_SESSION_FOR_THIS_SHARED_FILE_61438))
                val resolver = getApplication<Application>().contentResolver
                for (uri in uris.distinct()) {
                    if (!isNativeFileIdentityCurrent(pending.first, pending.second)) error(uiText(UiTextKey.THE_SESSION_FOR_THIS_SHARED_FILE_61438))
                    val name = readSafDisplayName(resolver, uri)
                    if (!isPortableDocumentName(name)) error(uiText(UiTextKey.THE_SYSTEM_PROVIDER_RETURNED_A_FILE_1E971))
                    val descriptor = resolver.openFileDescriptor(uri, "r") ?: error(uiText(UiTextKey.COULD_NOT_OPEN_THE_SELECTED_SHARED_F64B3))
                    val artifactId = descriptor.use { pfd ->
                        if (!isNativeFileIdentityCurrent(pending.first, pending.second)) error(uiText(UiTextKey.THE_SESSION_FOR_THIS_SHARED_FILE_61438))
                        NativeSdk.nativeHostFileShare(pending.first, pending.second.identityJson, name, pfd.detachFd())
                    }
                    while (true) {
                        if (!isNativeFileIdentityCurrent(pending.first, pending.second)) error(uiText(UiTextKey.THE_SESSION_ENDED_THE_ORIGINAL_SNAPSHOT_9DDCC))
                        val host = parseNativeHostFiles(NativeSdk.nativeHostFilesStatus(pending.first, pending.second.identityJson), pending.second)
                        updateMobileState { if (it.fileSession != pending.second) it else it.copy(hostFiles = host) }
                        val artifact = host.artifacts.firstOrNull { it.id == artifactId } ?: error(uiText(UiTextKey.THE_SNAPSHOT_WAS_NOT_SHARED_SUCCESSFULLY_0E801))
                        if (artifact.ownerStopped) {
                            if (artifact.phase != "shared") error(artifact.error ?: uiText(UiTextKey.THE_SELECTED_FILE_SNAPSHOT_COULD_NOT_47FEB))
                            break
                        }
                        delay(200)
                    }
                }
            } catch (failure: Throwable) {
                updateMobileState { if (it.handle != pending.first || it.fileSession != pending.second) it else it.copy(fileError = failure.message ?: uiText(UiTextKey.SHARED_FILE_PREPARATION_FAILED_9ADBC)) }
            } finally {
                updateMobileState { if (it.handle != pending.first || it.fileSession != pending.second) it else it.copy(fileBusy = false) }
            }
        }
    }

    fun approveNativeHostReceive(approved: Boolean) = nativeHostAction(allowWhileBusy = !approved) { handle, session ->
        NativeSdk.nativeHostFileApproveReceive(handle, session.identityJson, approved)
    }

    fun discardNativeHostFile(id: String) = nativeHostAction(allowWhileBusy = true) { handle, session ->
        NativeSdk.nativeHostFileDiscard(handle, session.identityJson, id)
    }

    fun cancelNativeHostExport(id: String) = nativeHostAction(allowWhileBusy = true) { handle, session ->
        NativeSdk.nativeHostFileExportCancel(handle, session.identityJson, id)
    }

    private fun nativeHostAction(allowWhileBusy: Boolean = false, action: (Long, NativeFileSessionIdentity) -> Unit) {
        val current = mutableState.value
        val session = current.fileSession ?: return
        if (!session.isHost || (current.fileBusy && !allowWhileBusy) || NativeSafPickerOwners.isClosing(current.handle)) return
        updateMobileState { if (it.fileSession != session) it else it.copy(fileBusy = true, fileError = "") }
        launchNativeSafPickerWorker(current.handle) {
            try {
                if (refreshNativeHostFiles(current.handle, session) == null) error(uiText(UiTextKey.THE_LOCAL_FILE_SESSION_HAS_ENDED_01E40))
                action(current.handle, session)
                refreshNativeHostFiles(current.handle, session)
            } catch (failure: Throwable) {
                updateMobileState { if (it.fileSession != session) it else it.copy(fileError = failure.message ?: uiText(UiTextKey.THE_LOCAL_FILE_OPERATION_DID_NOT_82736)) }
            } finally {
                if (!current.fileBusy) updateMobileState { if (it.fileSession != session) it else it.copy(fileBusy = false) }
            }
        }
    }

    fun prepareNativeHostExport(id: String): String? {
        val current = mutableState.value
        val session = current.fileSession ?: return null
        val artifact = current.hostFiles.artifacts.firstOrNull { it.id == id } ?: return null
        if (!session.isHost || !artifact.canExport() || current.fileBusy || current.filePickerPending ||
            current.hostFiles.exports.values.any { it.ownerRetained() } || !current.canStartAnotherFileTask()) return null
        synchronized(filePickerLock) {
            if (pendingSafUpload != null || pendingSafExport != null || pendingHostShare != null || pendingHostExport != null) return null
            pendingHostExport = PendingSafExport(current.handle, session, id, artifact.displayName)
        }
        updateMobileState { if (it.fileSession != session) it else it.copy(filePickerPending = true, fileError = "") }
        return artifact.displayName.takeIf(::isPortableDocumentName) ?: "received-file"
    }

    fun finishNativeHostExportPicker(uri: Uri?) {
        val pending = synchronized(filePickerLock) { pendingHostExport.also { pendingHostExport = null } }
        updateMobileState { it.copy(filePickerPending = false) }
        if (uri == null) return
        val handle = pending?.handle ?: mutableState.value.handle
        launchNativeSafPickerWorker(handle) {
            var handedToRust = false
            try {
                if (pending == null || !isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_LOCAL_SESSION_FOR_THIS_SAVE_96A2A))
                updateMobileState { if (it.fileSession != pending.identity) it else it.copy(fileBusy = true, fileError = "") }
                val descriptor = getApplication<Application>().contentResolver.openFileDescriptor(uri, "rw") ?: error(uiText(UiTextKey.COULD_NOT_OPEN_THE_SYSTEM_SAVE_FCFF3))
                val export = descriptor.use { pfd ->
                    if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_LOCAL_FILE_SESSION_HAS_ENDED_01E40))
                    val fd = pfd.detachFd()
                    handedToRust = true
                    parseNativeSafExport(NativeSdk.nativeHostFileExport(pending.handle, pending.identity.identityJson, pending.taskId, fd), pending.taskId)
                }
                while (true) {
                    if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_SESSION_ENDED_THE_EXPORT_OWNER_FF4C0))
                    val host = parseNativeHostFiles(NativeSdk.nativeHostFilesStatus(pending.handle, pending.identity.identityJson), pending.identity)
                    updateMobileState { if (it.fileSession != pending.identity) it else it.copy(hostFiles = host) }
                    val actual = host.exports[pending.taskId]?.takeIf { it.exportId == export.exportId } ?: error(uiText(UiTextKey.EXPORT_STATUS_IS_UNCONFIRMED_3F365))
                    if (!actual.ownerRetained()) {
                        if (actual.phase != "completed") error(actual.error ?: actual.destinationCleanupError ?: uiText(UiTextKey.EXPORT_DID_NOT_COMPLETE_90862))
                        break
                    }
                    delay(200)
                }
            } catch (failure: Throwable) {
                val cleanup = if (!handedToRust) cleanupPickedSafDestination(uri).detail else ""
                updateMobileState { current ->
                    if (pending != null && (current.handle != pending.handle || current.fileSession != pending.identity)) current
                    else current.copy(fileError = listOfNotNull(failure.message, cleanup.takeIf(String::isNotBlank)).joinToString("；"))
                }
            } finally {
                if (pending != null) updateMobileState { if (it.fileSession != pending.identity) it else it.copy(fileBusy = false) }
            }
        }
    }

    fun selectNativeFileRoot(rootId: String) {
        val current = mutableState.value
        if (current.fileSession == null || current.fileReadRoots.none { it.id == rootId }) return
        if (current.selectedReadRootId == rootId) return
        fileBrowseGeneration.incrementAndGet()
        updateMobileState {
            if (it.fileSession != current.fileSession) it else it.copy(
                selectedReadRootId = rootId,
                fileBrowsePage = null,
                fileLoading = false,
                fileError = "",
            )
        }
    }

    fun selectNativeFileWriteRoot(rootId: String) {
        val current = mutableState.value
        if (current.fileSession == null || current.fileWriteRoots.none { it.id == rootId }) return
        updateMobileState {
            if (it.fileSession != current.fileSession) it else it.copy(selectedWriteRootId = rootId)
        }
    }

    fun browseNativeFiles(rootId: String, directory: String?) {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        if (!identity.canRead || current.fileReadRoots.none { it.id == rootId }) return
        val generation = fileBrowseGeneration.incrementAndGet()
        val previous = current.fileBrowsePage
        updateMobileState {
            if (it.fileSession != identity) it else it.copy(fileLoading = true, fileError = "")
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (previous != null) {
                    runCatching { NativeSdk.nativeFileBrowseCancel(current.handle, identity.identityJson, previous.browseId) }
                }
                val page = parseNativeFileBrowsePage(
                    NativeSdk.nativeFileBrowseBegin(current.handle, identity.identityJson, rootId, directory?.ifEmpty { null }),
                    identity,
                )
                require(page.rootId == rootId && page.directory == directory.orEmpty()) {
                    uiText(UiTextKey.THE_REMOTE_DIRECTORY_RESPONSE_DOES_NOT_6D2B7)
                }
                if (fileBrowseGeneration.get() != generation) return@launch
                if (!isNativeFileIdentityCurrent(current.handle, identity)) return@launch
                updateMobileState {
                    if (it.handle != current.handle || it.fileSession != identity || it.selectedReadRootId != rootId) it
                    else it.copy(fileBrowsePage = page, fileLoading = false, fileError = "")
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                if (fileBrowseGeneration.get() == generation) {
                    updateMobileState {
                        if (it.handle != current.handle || it.fileSession != identity) it
                        else it.copy(fileLoading = false, fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_READ_THE_REMOTE_DIRECTORY_328A1))
                    }
                }
            }
        }
    }

    fun loadMoreNativeFiles() {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        val page = current.fileBrowsePage ?: return
        if (!page.hasMore || current.fileLoading) return
        val generation = fileBrowseGeneration.incrementAndGet()
        updateMobileState { if (it.fileBrowsePage != page) it else it.copy(fileLoading = true, fileError = "") }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val nextJson = NativeSdk.nativeFileBrowseNext(current.handle, identity.identityJson, page.browseId)
                if (fileBrowseGeneration.get() != generation) return@launch
                val next = nextJson?.let { parseNativeFileBrowsePage(it, identity) }
                if (next != null) {
                    require(next.browseId == page.browseId && next.rootId == page.rootId &&
                        next.directory == page.directory && next.snapshotId == page.snapshotId
                    ) { uiText(UiTextKey.THE_REMOTE_PAGE_RESPONSE_DOES_NOT_D62CE) }
                }
                if (!isNativeFileIdentityCurrent(current.handle, identity)) return@launch
                updateMobileState { latest ->
                    val activePage = latest.fileBrowsePage
                    if (activePage == null || latest.handle != current.handle || latest.fileSession != identity ||
                        activePage.browseId != page.browseId || activePage.snapshotId != page.snapshotId
                    ) latest else latest.copy(
                        fileBrowsePage = if (next == null) activePage.copy(hasMore = false) else activePage.copy(
                            entries = activePage.entries + next.entries,
                            offset = next.offset,
                            totalEntries = next.totalEntries,
                            hasMore = next.hasMore,
                        ),
                        fileLoading = false,
                        fileError = "",
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState {
                    if (it.fileSession != identity || it.fileBrowsePage?.browseId != page.browseId) it
                    else it.copy(fileLoading = false, fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_READ_THE_REMOTE_DIRECTORY_328A1))
                }
            }
        }
    }

    fun downloadNativeFile(rootId: String, relativePath: String, displayName: String) {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        if (!identity.canRead || current.fileReadRoots.none { it.id == rootId }) return
        if (!current.canStartAnotherFileTask() || current.fileBusy || current.filePickerPending) return
        updateMobileState { if (it.fileSession != identity) it else it.copy(fileBusy = true, fileError = "") }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (!isNativeFileIdentityCurrent(current.handle, identity)) error(uiText(UiTextKey.THE_FILE_SESSION_HAS_ENDED_REFRESH_2634F))
                val privateArea = getApplication<Application>().filesDir.resolve("verified-downloads")
                if ((!privateArea.isDirectory && !privateArea.mkdirs()) || !privateArea.isDirectory) {
                    error(uiText(UiTextKey.COULD_NOT_CREATE_THE_PRIVATE_APP_50DCF))
                }
                NativeSdk.nativeConfigureFileDownloadArea(current.handle, privateArea.absolutePath)
                val task = parseNativeFileTask(
                    NativeSdk.nativeFileDownload(current.handle, identity.identityJson, rootId, relativePath),
                    displayName,
                )
                updateMobileState {
                    if (it.handle != current.handle || it.fileSession != identity) it else it.copy(
                        fileTask = task,
                        fileTaskName = displayName,
                        safExport = null,
                        fileBusy = false,
                        fileError = "",
                    ).withNativeFileTask(task, selectLatest = true)
                }
                pollNativeFileTask(current.handle, identity, task.taskId, displayName)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState {
                    if (it.fileSession != identity) it else it.copy(
                        fileBusy = false,
                        fileError = failure.message ?: uiText(UiTextKey.THE_DOWNLOAD_COULD_NOT_START_65156),
                    )
                }
            }
        }
    }

    private fun pollNativeFileTask(handle: Long, identity: NativeFileSessionIdentity, taskId: String, displayName: String) {
        fileTaskPollJob?.cancel()
        fileTaskPollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                if (!isNativeFileIdentityCurrent(handle, identity)) return@launch
                val task = try {
                    parseNativeFileTask(NativeSdk.nativeFileTaskStatus(handle, identity.identityJson, taskId), displayName)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Throwable) {
                    updateMobileState { current ->
                        if (current.handle != handle || current.fileSession != identity) current
                        else current.copy(fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_READ_FILE_TASK_STATUS_B6204))
                    }
                    return@launch
                }
                updateMobileState { current ->
                    if (current.handle != handle || current.fileSession != identity || current.fileTask?.taskId != taskId) current
                    else current.withNativeFileTask(task).copy(fileError = "")
                }
                if (task.finished && task.ownerStopped) return@launch
                delay(450)
            }
        }
    }

    fun controlNativeFileTask(taskId: String, action: Int) {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        val task = current.fileTasks.firstOrNull { it.taskId == taskId }
            ?.takeIf { !it.finished } ?: current.fileTask?.takeIf { it.taskId == taskId && !it.finished } ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                NativeSdk.nativeFileTaskControl(current.handle, identity.identityJson, task.taskId, action)
                val refreshed = parseNativeFileTask(
                    NativeSdk.nativeFileTaskStatus(current.handle, identity.identityJson, task.taskId),
                    task.displayName,
                )
                updateMobileState {
                    if (it.fileSession != identity) it
                    else it.withNativeFileTask(refreshed).copy(fileError = "")
                }
            } catch (failure: Throwable) {
                updateMobileState { if (it.fileSession != identity) it else it.copy(fileError = failure.message ?: uiText(UiTextKey.FILE_TASK_CONTROL_FAILED_71B6D)) }
            }
        }
    }

    fun discardNativeFileDownload(taskId: String) {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        val task = current.fileTasks.firstOrNull { it.taskId == taskId }
            ?: current.fileTask?.takeIf { it.taskId == taskId }
            ?: return
        if (task.kind != "download" || !task.finished || !task.ownerStopped || current.fileBusy ||
            NativeSafPickerOwners.hasRetainedOwners()
        ) return
        if (current.fileExports[taskId]?.ownerRetained() == true) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                NativeSdk.nativeFileDownloadDiscard(current.handle, identity.identityJson, taskId)
                updateMobileState { latest ->
                    if (latest.handle != current.handle || latest.fileSession != identity) latest
                    else {
                        val remainingTasks = latest.fileTasks.filterNot { it.taskId == taskId }
                        val selected = if (latest.fileTask?.taskId == taskId) remainingTasks.lastOrNull() else latest.fileTask
                        latest.copy(
                            fileTask = selected,
                            fileTaskName = selected?.displayName.orEmpty(),
                            fileTasks = remainingTasks,
                            fileExports = latest.fileExports - taskId,
                            discardedDownloadTaskIds = latest.discardedDownloadTaskIds + taskId,
                            safExport = latest.safExport?.takeUnless { it.taskId == taskId },
                            fileError = "",
                        )
                    }
                }
            } catch (failure: Throwable) {
                updateMobileState { latest ->
                    if (latest.fileSession != identity) latest
                    else latest.copy(fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_CLEAN_UP_THE_PRIVATE_33638))
                }
            }
        }
    }

    fun prepareNativeFileUpload(rootId: String): Boolean {
        val current = mutableState.value
        val identity = current.fileSession ?: return false
        if (!identity.canWrite || current.fileWriteRoots.none { it.id == rootId } || current.fileBusy ||
            current.filePickerPending || !current.canStartAnotherFileTask()
        ) return false
        val directory = current.fileBrowsePage?.takeIf { it.rootId == rootId }?.directory.orEmpty()
        synchronized(filePickerLock) {
            if (pendingSafUpload != null || pendingSafExport != null) return false
            pendingSafUpload = PendingSafUpload(current.handle, identity, rootId, directory)
        }
        val updated = updateMobileState { if (it.fileSession != identity) it else it.copy(filePickerPending = true, fileError = "") }
        if (updated.fileSession != identity || !updated.filePickerPending) {
            synchronized(filePickerLock) { if (pendingSafUpload?.identity == identity) pendingSafUpload = null }
            return false
        }
        return true
    }

    fun prepareNativeFileExport(taskId: String): String? {
        val current = mutableState.value
        val identity = current.fileSession ?: return null
        val task = current.fileTasks.firstOrNull { it.taskId == taskId }
            ?: current.fileTask?.takeIf { it.taskId == taskId }
            ?: return null
        if (task.kind != "download" || !task.finished || !task.ownerStopped || task.phase != "completed") return null
        val previousExport = current.fileExports[taskId]
        if (previousExport?.phase == "completed" && previousExport.privateCleanupComplete) return null
        if (current.fileBusy || current.filePickerPending || !identity.canRead || !current.canStartAnotherFileTask()
        ) return null
        val suggestedName = task.displayName.takeIf(::isPortableDocumentName) ?: "download"
        synchronized(filePickerLock) {
            if (pendingSafUpload != null || pendingSafExport != null) return null
            pendingSafExport = PendingSafExport(current.handle, identity, task.taskId, suggestedName)
        }
        val updated = updateMobileState { if (it.fileSession != identity) it else it.copy(filePickerPending = true, fileError = "") }
        if (updated.fileSession != identity || !updated.filePickerPending) {
            synchronized(filePickerLock) { if (pendingSafExport?.identity == identity) pendingSafExport = null }
            return null
        }
        return suggestedName
    }

    fun cancelPendingNativeFilePicker() {
        synchronized(filePickerLock) {
            pendingSafUpload = null
            pendingSafExport = null
            pendingHostShare = null
            pendingHostExport = null
        }
        updateMobileState { it.copy(filePickerPending = false) }
    }

    fun finishNativeFileUploadPicker(uri: Uri?) {
        val pending = synchronized(filePickerLock) { pendingSafUpload.also { pendingSafUpload = null } }
        if (pending == null) return
        updateMobileState { it.copy(filePickerPending = false) }
        if (uri == null) return
        launchNativeSafPickerWorker(pending.handle) {
            updateMobileState { if (it.fileSession != pending.identity) it else it.copy(fileBusy = true, fileError = "") }
            try {
                if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_REMOTE_SESSION_FOR_THE_SELECTED_DA750))
                val resolver = getApplication<Application>().contentResolver
                val displayName = readSafDisplayName(resolver, uri)
                if (!isPortableDocumentName(displayName)) error(uiText(UiTextKey.THE_SYSTEM_DOCUMENT_PROVIDER_RETURNED_AN_48BB8))
                if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_REMOTE_SESSION_FOR_THE_SELECTED_DA750))
                val descriptor = try {
                    resolver.openFileDescriptor(uri, "r")
                } catch (_: Throwable) {
                    null
                } ?: error(uiText(UiTextKey.COULD_NOT_OPEN_THE_FILE_SELECTED_7650A))
                val task = descriptor.use { pfd ->
                    if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_REMOTE_SESSION_FOR_THE_SELECTED_DA750))
                    val detachedFd = pfd.detachFd()
                    parseNativeFileTask(
                        NativeSdk.nativeFileUpload(
                            pending.handle,
                            pending.identity.identityJson,
                            pending.rootId,
                            remoteChildPath(pending.directory, displayName),
                            displayName,
                            detachedFd,
                        ),
                        displayName,
                    )
                }
                updateMobileState {
                    if (it.handle != pending.handle || it.fileSession != pending.identity) it else it.copy(
                        fileTask = task,
                        fileTaskName = displayName,
                        safExport = null,
                        fileBusy = false,
                        fileError = "",
                    ).withNativeFileTask(task, selectLatest = true)
                }
                pollNativeFileTask(pending.handle, pending.identity, task.taskId, displayName)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState {
                    if (it.fileSession != pending.identity) it else it.copy(
                        fileBusy = false,
                        fileError = failure.message ?: uiText(UiTextKey.THE_UPLOAD_COULD_NOT_START_036AE),
                    )
                }
            }
        }
    }

    fun finishNativeFileExportPicker(uri: Uri?) {
        val pending = synchronized(filePickerLock) { pendingSafExport.also { pendingSafExport = null } }
        if (pending == null) {
            if (uri != null) launchNativeSafPickerWorker(mutableState.value.handle) {
                val cleanup = cleanupPickedSafDestination(uri)
                val detail = uiText(UiTextKey.THE_FILE_SESSION_FOR_THIS_SAVE_A5EE4, cleanup.detail)
                updateMobileState { if (cleanup.complete) it.copy(fileError = detail) else it.copy(fileError = detail, error = detail) }
            }
            return
        }
        updateMobileState { it.copy(filePickerPending = false) }
        if (uri == null) return
        // Every returned CreateDocument URI must reach either the retained
        // Rust owner or confirmed best-effort cleanup, even as this view model
        // clears. A replaced identity is rejected again before FD handoff.
        launchNativeSafPickerWorker(pending.handle) {
            var nativeOwnsDestination = false
            updateMobileState { if (it.fileSession != pending.identity) it else it.copy(fileBusy = true, fileError = "") }
            try {
                if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_REMOTE_SESSION_FOR_THIS_DOWNLOAD_9B818))
                val descriptor = try {
                    getApplication<Application>().contentResolver.openFileDescriptor(uri, "rwt")
                } catch (_: Throwable) {
                    null
                } ?: error(uiText(UiTextKey.THIS_SAVE_LOCATION_DOES_NOT_SUPPORT_D84DE))
                val status = descriptor.use { pfd ->
                    if (!isNativeFileIdentityCurrent(pending.handle, pending.identity)) error(uiText(UiTextKey.THE_REMOTE_SESSION_FOR_THIS_DOWNLOAD_9B818))
                    val detachedFd = pfd.detachFd()
                    // JNI adopts the FD before parsing any other argument.
                    // Once handed over, Rust alone controls cleanup: an error
                    // while returning/parsing status cannot delete a live target.
                    nativeOwnsDestination = true
                    parseNativeSafExport(
                        NativeSdk.nativeFileExport(pending.handle, pending.identity.identityJson, pending.taskId, detachedFd),
                        pending.taskId,
                    )
                }
                updateMobileState {
                    if (it.handle != pending.handle || it.fileSession != pending.identity) it else it.copy(
                        safExport = status,
                        fileExports = it.fileExports + (pending.taskId to status),
                        fileBusy = false,
                        fileError = "",
                    )
                }
                pollNativeFileExport(pending.handle, pending.identity, pending.taskId, status.exportId)
            } catch (cancelled: CancellationException) {
                if (!nativeOwnsDestination) {
                    val cleanup = cleanupPickedSafDestination(uri)
                    val detail = uiText(UiTextKey.EXPORT_PREPARATION_WAS_CANCELLED_7D559, cleanup.detail)
                    updateMobileState {
                        if (it.fileSession == pending.identity) it.copy(fileBusy = false, fileError = detail)
                        else if (!cleanup.complete) it.copy(error = detail)
                        else it
                    }
                }
                throw cancelled
            } catch (failure: Throwable) {
                val detail = if (nativeOwnsDestination) failure.message ?: uiText(UiTextKey.THE_EXPORT_COULD_NOT_START_1159A)
                    else "${failure.message ?: uiText(UiTextKey.THE_EXPORT_COULD_NOT_START_1159A)}；${cleanupPickedSafDestination(uri).detail}"
                updateMobileState {
                    if (it.fileSession != pending.identity) it.copy(error = detail) else it.copy(
                        fileBusy = false,
                        fileError = detail,
                    )
                }
            }
        }
    }

    private fun cleanupPickedSafDestination(uri: Uri): SafDestinationCleanupReceipt {
        val application = getApplication<Application>()
        val resolver = application.contentResolver
        return cleanupCreatedSafDestination(
            deleteDocument = {
                DocumentsContract.isDocumentUri(application, uri) && DocumentsContract.deleteDocument(resolver, uri)
            },
            clearDocument = {
                val descriptor = resolver.openFileDescriptor(uri, "rw") ?: error(uiText(UiTextKey.THE_SAVE_DESTINATION_COULD_NOT_BE_88DA2))
                descriptor.use { pfd ->
                    val fd = pfd.fileDescriptor
                    if (!OsConstants.S_ISREG(Os.fstat(fd).st_mode)) error(uiText(UiTextKey.THE_SAVE_DESTINATION_IS_NOT_A_E49CB))
                    Os.ftruncate(fd, 0L)
                    Os.fsync(fd)
                    if (Os.fstat(fd).st_size != 0L) error(uiText(UiTextKey.THE_SAVE_DESTINATION_COULD_NOT_BE_680B4))
                }
            },
        )
    }

    private fun launchNativeSafPickerWorker(handle: Long, work: suspend () -> Unit) {
        // Register the real Job before the provider can acquire a descriptor.
        // Lifecycle cancellation cannot detach a blocked provider call; close
        // retains this same Job and waits for its actual completion.
        val worker = viewModelScope.launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) { work() }
        NativeSafPickerOwners.retain(handle, worker)
        worker.start()
    }

    private suspend fun closeNativeSession(handle: Long) {
        NativeSafPickerOwners.beginClose(handle)
        NativeSafPickerOwners.awaitAllStopped()
        NativeSdk.nativeClose(handle)
        NativeSafPickerOwners.completeClose(handle)
    }

    private fun pollNativeFileExport(handle: Long, identity: NativeFileSessionIdentity, taskId: String, exportId: String) {
        fileExportPollJob?.cancel()
        fileExportPollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                if (!isNativeFileIdentityCurrent(handle, identity)) return@launch
                val status = try {
                    parseNativeSafExport(NativeSdk.nativeFileExportStatus(handle, identity.identityJson, exportId), taskId)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Throwable) {
                    updateMobileState { current ->
                        if (current.handle != handle || current.fileSession != identity) current
                        else current.copy(fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_READ_EXPORT_STATUS_760A8))
                    }
                    return@launch
                }
                val associated = status.copy(taskId = taskId)
                updateMobileState { current ->
                    if (current.handle != handle || current.fileSession != identity) current
                    else current.copy(
                        safExport = associated.takeIf { current.safExport?.taskId == taskId || current.safExport?.exportId == exportId }
                            ?: current.safExport,
                        fileExports = current.fileExports + (taskId to associated),
                        fileError = "",
                    )
                }
                if (!status.ownerRetained()) return@launch
                delay(350)
            }
        }
    }

    fun cancelNativeFileExport(taskId: String) {
        val current = mutableState.value
        val identity = current.fileSession ?: return
        val export = current.fileExports[taskId]?.takeIf { it.phase == "running" }
            ?: current.safExport?.takeIf { it.taskId == taskId && it.phase == "running" }
            ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                NativeSdk.nativeFileExportCancel(current.handle, identity.identityJson, export.exportId)
            } catch (failure: Throwable) {
                updateMobileState { if (it.fileSession != identity) it else it.copy(fileError = failure.message ?: uiText(UiTextKey.COULD_NOT_CANCEL_THE_FILE_EXPORT_0C977)) }
            }
        }
    }

    private fun isNativeFileIdentityCurrent(handle: Long, identity: NativeFileSessionIdentity): Boolean {
        val current = mutableState.value
        if (current.handle != handle || current.fileSession != identity || NativeSafPickerOwners.isClosing(handle)) return false
        return parseNativeFileSessionIdentity(NativeSdk.nativeFileSessionIdentity(handle)) == identity
    }

    private fun readSafDisplayName(resolver: ContentResolver, uri: Uri): String {
        val cursor = try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        } catch (_: Throwable) {
            null
        } ?: return "document"
        return runCatching {
            cursor.use {
                if (!it.moveToFirst()) "document"
                else {
                    val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (column < 0) "document" else it.getString(column)?.takeIf(String::isNotBlank) ?: "document"
                }
            }
        }.getOrDefault("document")
    }

    private fun retireNativeFileOwners(snapshot: MobileState) {
        NativeSafPickerOwners.beginClose(snapshot.handle)
        clipboardEndpoint.getAndSet(null)?.close()
        synchronized(filePickerLock) {
            if (pendingSafUpload?.handle == snapshot.handle) pendingSafUpload = null
            if (pendingSafExport?.handle == snapshot.handle) pendingSafExport = null
            if (pendingHostShare?.first == snapshot.handle) pendingHostShare = null
            if (pendingHostExport?.handle == snapshot.handle) pendingHostExport = null
        }
        updateMobileState { current ->
            if (current.handle != snapshot.handle) current else current.copy(filePickerPending = false)
        }
    }

    private fun revokeNativeFileOwners(snapshot: MobileState) {
        val identity = snapshot.fileSession ?: return
        snapshot.fileTask?.takeIf { !it.ownerStopped }?.let { task ->
            runCatching { NativeSdk.nativeFileTaskControl(snapshot.handle, identity.identityJson, task.taskId, 2) }
        }
        snapshot.safExport?.takeIf { it.phase == "running" }?.let { export ->
            runCatching { NativeSdk.nativeFileExportCancel(snapshot.handle, identity.identityJson, export.exportId) }
        }
        snapshot.fileBrowsePage?.let { page ->
            runCatching { NativeSdk.nativeFileBrowseCancel(snapshot.handle, identity.identityJson, page.browseId) }
        }
    }

    fun revokeRemote(id: String) = runTask {
        withContext(Dispatchers.IO) { NativeSdk.nativeCancelRemote(requireHandle(), id) }
        val requests = withContext(Dispatchers.IO) {
            parseRemoteRequests(NativeSdk.nativeRemoteRequests(requireHandle()))
        }
        val session = withContext(Dispatchers.IO) {
            parseNativeSession(NativeSdk.nativeNativeSessionStatus(requireHandle()))
        }
        updateMobileState { it.copy(remoteRequests = requests).withNativeSession(session) }
        uiText(UiTextKey.THE_REMOTE_ACCESS_REQUEST_WAS_REVOKED_AF643)
    }

    fun logout() {
        val old = mutableState.value
        if (old.handle == 0L || old.busy) return
        val authGeneration = serviceAuthRevision.incrementAndGet()
        retireNativeFileOwners(old)
        HostCaptureService.stop(getApplication(), "account_logout", old.handle)
        updateMobileState { it.copy(
            authGeneration = authGeneration,
            remotePassword = null,
            remotePasswordOffer = null,
            remoteRequests = emptyList(),
            busy = true,
            error = "",
            message = uiText(UiTextKey.WAITING_FOR_RUST_APP_CORE_TO_0340C),
        ) }
        viewModelScope.launch(Dispatchers.IO) {
            val audioCleanup = try {
                stopAudioPlaybackCoordinatorAndReap(old.handle)
            } catch (failure: Throwable) {
                updateMobileState { current -> current.copy(
                    busy = false,
                    error = uiText(UiTextKey.ANDROID_AUDIO_OWNER_CLEANUP_IS_INCOMPLETE_B9F2D, failure.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                    message = uiText(UiTextKey.APP_CORE_REMAINS_OPEN_UNTIL_CLEANUP_86BF1),
                ) }
                startAudioPlaybackCoordinator()
                return@launch
            }
            val initialCaptureCleanup = try {
                HostCaptureService.awaitCleanup(old.handle)
            } catch (failure: Throwable) {
                updateMobileState { current -> current.copy(
                    busy = false,
                    error = uiText(UiTextKey.SCREEN_CAPTURE_CLEANUP_IS_INCOMPLETE_THE_CD085, failure.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                    message = uiText(UiTextKey.APP_CORE_REMAINS_OPEN_UNTIL_CLEANUP_86BF1),
                ) }
                startAudioPlaybackCoordinator()
                return@launch
            }
            val captureCleanup = if (initialCaptureCleanup.audioCleanupPending && audioCleanup.cleanupComplete) {
                runCatching { HostCaptureService.awaitCleanup(old.handle) }
                    .getOrElse { initialCaptureCleanup }
            } else initialCaptureCleanup
            if (captureCleanup.nonAudioCleanupFailed || captureCleanup.audioCleanupPending ||
                !audioCleanup.cleanupComplete
            ) {
                updateMobileState { current -> current.copy(
                    busy = false,
                    error = if (!audioCleanup.cleanupComplete) {
                        val pending = audioCleanup.receipts.lastOrNull { !it.cleanupComplete }?.detail
                            ?: uiText(UiTextKey.ANDROID_AUDIO_DEVICE_RELEASE_OR_WORKER_08FCC)
                        uiText(UiTextKey.SCREEN_OR_SYSTEM_AUDIO_DEVICE_CLEANUP_A1870, pending)
                    } else {
                        uiText(UiTextKey.SCREEN_OR_SYSTEM_AUDIO_DEVICE_CLEANUP_A1870, captureCleanup.detail)
                    },
                    message = uiText(UiTextKey.APP_CORE_REMAINS_OPEN_UNTIL_DEVICE_12B77),
                ) }
                startAudioPlaybackCoordinator()
                return@launch
            }
            revokeNativeFileOwners(old)
            var logoutFailed = false
            try { NativeSdk.nativeLogout(old.handle) } catch (_: Throwable) { logoutFailed = true }
            val closeError = runCatching { closeNativeSession(old.handle) }.exceptionOrNull()
            val logoutNotice = if (logoutFailed) {
                uiText(UiTextKey.THE_SERVER_HAS_NOT_CONFIRMED_SIGN_269FA)
            } else ""
            updateMobileState { current ->
                if (current.handle != old.handle) current
                else if (closeError == null) {
                    NativeCloseRecovery.clear(old.handle)
                    MobileState(error = logoutNotice)
                }
                else current.copy(
                    busy = false,
                    localClosePending = true,
                    localCloseNotice = logoutNotice,
                    error = uiText(UiTextKey.A_FILE_OR_LOCAL_WORKER_IS_F42F2, closeError.message ?: uiText(UiTextKey.CLEANUP_IS_INCOMPLETE_9DCEF)),
                    message = uiText(UiTextKey.THE_SYSTEM_FILE_PROVIDER_MAY_STILL_A31F6),
                )
            }
            if (closeError != null) NativeCloseRecovery.retain(old.handle)
        }
    }

    private fun runTask(block: suspend () -> String) {
        if (mutableState.value.busy) return
        updateMobileState { it.copy(busy = true, error = "", message = "") }
        viewModelScope.launch {
            try {
                val message = block()
                updateMobileState { it.copy(busy = false, error = "", message = message) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Throwable) {
                updateMobileState { it.copy(
                    busy = false,
                    error = failure.message ?: uiText(UiTextKey.THE_OPERATION_DID_NOT_COMPLETE_79BE1),
                    message = "",
                ) }
            }
        }
    }

    private fun requireHandle(): Long = mutableState.value.handle.takeIf { it > 0 }
        ?: error(uiText(UiTextKey.VERIFY_THE_SERVER_IDENTITY_FIRST_960A0))

    private fun updateMobileState(transform: (MobileState) -> MobileState): MobileState {
        while (true) {
            val current = mutableState.value
            val updated = transform(current)
            if (current === updated) return current
            if (mutableState.compareAndSet(current, updated)) {
                val oldLease = current.remoteVideoPresentation?.bitmapLease
                val newLease = updated.remoteVideoPresentation?.bitmapLease
                if (oldLease !== newLease) oldLease?.releaseOwner()
                return updated
            }
        }
    }

    private fun MobileState.matchesVideoSession(handle: Long, requestId: String, generation: Long): Boolean {
        val session = nativeSession ?: return false
        return this.handle == handle && session.requestId == requestId &&
            session.connectionGeneration == generation &&
            session.status in setOf("establishing", "connected")
    }

    private fun reportNativeNetworkFacts(network: Network? = null) {
        synchronized(networkObservationLock) {
            reportNativeNetworkFactsLocked(network)
        }
    }

    private fun reportNativeNetworkFactsLocked(network: Network? = null) {
        val handle = mutableState.value.handle
        if (handle <= 0L) return

        runCatching {
            val defaultBeforeRead = connectivity.activeNetwork
            val defaultHandleBeforeRead = defaultBeforeRead?.networkHandle
            networkObservation.observeDefaultNetwork(defaultHandleBeforeRead)

            // A late event for a network that is no longer default must not
            // invalidate a newer default-network observation.
            if (network != null && !networkObservation.isCurrentDefault(network.networkHandle)) {
                return@runCatching
            }

            val target = network ?: defaultBeforeRead
            val factsJson = target?.let { connectivity.networkFactsJson(it) }.orEmpty()
            val defaultAfterRead = connectivity.activeNetwork
            val defaultHandleAfterRead = defaultAfterRead?.networkHandle
            networkObservation.observeDefaultNetwork(defaultHandleAfterRead)

            // If the default changed during collection, discard this event.
            // The replacement network callback or next heartbeat will sample it.
            if (defaultHandleBeforeRead != defaultHandleAfterRead ||
                target?.networkHandle != defaultHandleAfterRead
            ) {
                return@runCatching
            }

            publishNetworkFactsLocked(
                handle = handle,
                factsJson = factsJson,
                observerActive = networkCallbackRegistered && !deviceSuspended &&
                    !networkObservation.isBlocked(defaultHandleAfterRead),
            )
        }
    }

    private fun reportBlockedStatus(network: Network, blocked: Boolean) {
        synchronized(networkObservationLock) {
            val defaultHandle = connectivity.activeNetwork?.networkHandle
            networkObservation.observeDefaultNetwork(defaultHandle)
            if (!networkObservation.observeBlockedStatus(network.networkHandle, blocked)) {
                return@synchronized
            }
            reportNativeNetworkFactsLocked(network)
        }
    }

    private fun reportLostNetwork(network: Network) {
        synchronized(networkObservationLock) {
            val wasDefault = networkObservation.isCurrentDefault(network.networkHandle)
            val defaultBeforeRead = connectivity.activeNetwork
            val defaultHandleBeforeRead = defaultBeforeRead?.networkHandle
            networkObservation.observeDefaultNetwork(defaultHandleBeforeRead)

            if (defaultHandleBeforeRead != null && defaultHandleBeforeRead != network.networkHandle) {
                // A queued loss for the old network may arrive after its
                // replacement became default. Observe the replacement itself.
                reportNativeNetworkFactsLocked(defaultBeforeRead)
                return@synchronized
            }
            if (defaultHandleBeforeRead == null && !wasDefault) {
                return@synchronized
            }

            val defaultAfterRead = connectivity.activeNetwork
            val defaultHandleAfterRead = defaultAfterRead?.networkHandle
            networkObservation.observeDefaultNetwork(defaultHandleAfterRead)
            if (defaultHandleBeforeRead != defaultHandleAfterRead) {
                reportNativeNetworkFactsLocked(defaultAfterRead)
                return@synchronized
            }

            val handle = mutableState.value.handle
            if (handle > 0L) {
                publishNetworkFactsLocked(handle, factsJson = "", observerActive = false)
            }
        }
    }

    private fun publishNetworkFactsLocked(handle: Long, factsJson: String, observerActive: Boolean) {
        NativeSdk.nativeNetworkChanged(
            handle = handle,
            factsJson = factsJson,
            observerActive = observerActive,
            elapsedRealtimeMs = SystemClock.elapsedRealtime(),
            uptimeMs = SystemClock.uptimeMillis(),
        )
    }

    override fun onCleared() {
        viewModelCleared.set(true)
        clipboardForeground.resumed(false)
        clipboardForeground.focused(false)
        val fileSnapshot = mutableState.value
        retireNativeFileOwners(fileSnapshot)
        val audioCoordinator = synchronized(audioCoordinatorLock) {
            audioPlaybackJob.also {
                audioPlaybackJob = null
                it?.cancel()
            }
        }
        val (handle, callbackWasRegistered) = synchronized(networkObservationLock) {
            val handle = mutableState.value.handle
            val callbackWasRegistered = networkCallbackRegistered
            networkCallbackRegistered = false
            deviceSuspended = true
            reportNativeNetworkFactsLocked()
            updateMobileState { MobileState() }
            handle to callbackWasRegistered
        }
        if (handle > 0L) NativeCloseRecovery.retain(handle)
        if (callbackWasRegistered) {
            runCatching { connectivity.unregisterNetworkCallback(networkCallback) }
        }
        remoteVideoBitmapOwner.releaseAll()
        if (handle > 0) {
            HostCaptureService.stop(getApplication(), "activity_cleared", handle)
            Thread({
                revokeNativeFileOwners(fileSnapshot)
                val coordinatorJoin = runCatching { runBlocking { audioCoordinator?.join() } }
                val captureResult = runCatching {
                    HostCaptureService.awaitCleanup(handle)
                }
                val initialCaptureCleanup = captureResult.getOrNull()
                val audioCleanup = nativeAudioEndpointOwners.reapAllActive(handle)
                val captureCleanup = if (initialCaptureCleanup?.audioCleanupPending == true &&
                    audioCleanup.cleanupComplete
                ) {
                    runCatching { HostCaptureService.awaitCleanup(handle) }
                        .getOrNull() ?: initialCaptureCleanup
                } else initialCaptureCleanup
                if (captureResult.isFailure || captureCleanup == null) {
                    val failure = captureResult.exceptionOrNull()
                    HostCaptureStatus.update(
                        "failed",
                        uiText(UiTextKey.SCREEN_CAPTURE_CLEANUP_IS_INCOMPLETE_THE_2592E, failure?.message ?: uiText(UiTextKey.UNKNOWN_CLEANUP_ERROR_6DF42)),
                        captureHandle = handle,
                    )
                    return@Thread
                }
                if (coordinatorJoin.isFailure || captureCleanup.nonAudioCleanupFailed ||
                    captureCleanup.audioCleanupPending || !audioCleanup.cleanupComplete
                ) {
                    HostCaptureStatus.update(
                        "failed",
                        if (coordinatorJoin.isFailure) {
                            uiText(UiTextKey.CONTROLLER_AUDIO_COORDINATOR_EXIT_IS_UNCONFIRMED_FFD9E)
                        } else if (!audioCleanup.cleanupComplete) {
                            uiText(UiTextKey.SCREEN_OR_SYSTEM_AUDIO_CLEANUP_FAILED_6A4BC) +
                                (audioCleanup.receipts.lastOrNull { !it.cleanupComplete }?.detail
                                    ?: uiText(UiTextKey.ANDROID_AUDIO_DEVICE_RELEASE_OR_WORKER_08FCC))
                        } else {
                            uiText(UiTextKey.SCREEN_OR_SYSTEM_AUDIO_CLEANUP_FAILED_A32C7, captureCleanup.detail)
                        },
                        captureHandle = handle,
                    )
                    return@Thread
                }
                val failures = mutableListOf<String>()
                try {
                    NativeSdk.nativeLogout(handle)
                } catch (failure: Throwable) {
                    failures += uiText(UiTextKey.LOCAL_ACCOUNT_SIGN_OUT_FAILED_A7E3F, failure.message ?: failure.javaClass.simpleName)
                }
                try {
                    runBlocking { closeNativeSession(handle) }
                    NativeCloseRecovery.clear(handle)
                } catch (failure: Throwable) {
                    NativeCloseRecovery.retain(handle)
                    failures += uiText(UiTextKey.LOCAL_APP_CORE_CLEANUP_FAILED_284E4, failure.message ?: failure.javaClass.simpleName)
                }
                if (failures.isNotEmpty()) {
                    HostCaptureStatus.update(
                        "failed",
                        failures.joinToString("；"),
                        captureHandle = handle,
                        cleanupComplete = true,
                    )
                }
            }, "nestlink-mobile-session-close").start()
        }
        super.onCleared()
    }
}

private fun parseDevices(json: String): List<DeviceRow> {
    val array = JSONArray(json)
    return List(array.length()) { index ->
        val item = array.getJSONObject(index)
        val device = item.getJSONObject("device")
        DeviceRow(
            id = device.getString("id"),
            name = device.getString("name"),
            platform = device.getString("platform"),
            pathMode = device.getString("path_mode"),
            capabilities = device.getJSONArray("capabilities").let { array ->
                List(array.length()) { array.getString(it) }
            },
            revoked = item.getBoolean("revoked"),
        )
    }
}

private fun parseRemoteRequest(json: String): RemoteRequestRow =
    parseRemoteRequest(JSONObject(json))

private fun parseRemoteRequests(json: String): List<RemoteRequestRow> {
    val array = JSONArray(json)
    return List(array.length()) { index -> parseRemoteRequest(array.getJSONObject(index)) }
}

internal fun parseTrustedDevices(json: String): TrustedDevicesRow {
    val root = JSONObject(json)
    val devicesJson = root.getJSONArray("devices")
    val devices = List(devicesJson.length()) { index ->
        val item = devicesJson.getJSONObject(index)
        TrustedDeviceRow(
            controllerDeviceId = item.getString("controller_device_id"),
            hostKeySha256 = item.getString("host_key_sha256"),
            controllerKeySha256 = item.getString("controller_key_sha256"),
            permissions = item.getJSONArray("permissions").let { values ->
                List(values.length()) { values.getInt(it) }
            },
            paths = item.getJSONArray("paths").let { values ->
                List(values.length()) { values.getInt(it) }
            },
            revision = item.getLong("revision"),
            expiresAtUnixMs = item.getLong("expires_at_unix_ms"),
            active = item.getBoolean("active"),
        )
    }
    require(devices.map { it.controllerDeviceId }.distinct().size == devices.size)
    require(devices.all { device ->
        device.controllerDeviceId.isNotBlank() && device.revision > 0L &&
            device.permissions.all { it in 1..7 } && device.paths.all { it in 1..2 } &&
            device.expiresAtUnixMs >= 0L
    })
    return TrustedDevicesRow(root.getString("host_device_id"), devices)
}

private fun parseRemoteRequest(item: JSONObject): RemoteRequestRow = RemoteRequestRow(
    id = item.getString("id"),
    controllerDeviceId = item.getString("controller_device_id"),
    hostDeviceId = item.getString("host_device_id"),
    permissions = item.getJSONArray("permissions").let { values ->
        List(values.length()) { values.getInt(it) }
    },
    paths = item.getJSONArray("paths").let { values ->
        List(values.length()) { values.getInt(it) }
    },
    status = item.getString("status"),
    nonce = item.getString("nonce"),
    policyRevision = item.getLong("policy_revision"),
    expiresAtUnixMs = item.getLong("expires_at_unix_ms"),
    connectionGeneration = item.getLong("connection_generation"),
    leaseSequence = item.getLong("lease_sequence"),
)

private fun parseNativeSession(json: String): NativeSessionRow? {
    if (json == "null" || json.isBlank()) return null
    val session = JSONObject(json)
    return NativeSessionRow(
        requestId = session.getString("request_id"),
        connectionGeneration = session.getLong("connection_generation"),
        status = session.getString("status"),
        hostViewAuthorized = session.getBoolean("host_view_authorized"),
    )
}

private fun parseBrowserHost(json: String): BrowserHostRow? {
    if (json == "null" || json.isBlank()) return null
    val host = JSONObject(json)
    val bindingJson = host.optJSONObject("binding")?.toString()
    val binding = bindingJson?.let(HostCaptureBinding::browserHost)
    val row = BrowserHostRow(
        requestId = host.getString("request_id"),
        connectionGeneration = host.getLong("connection_generation"),
        status = host.getString("status"),
        hostViewAuthorized = host.getBoolean("host_view_authorized"),
        binding = binding,
    )
    require(row.requestId.isNotBlank() && row.connectionGeneration > 0L)
    require(binding == null || (
        binding.requestId == row.requestId && binding.connectionGeneration == row.connectionGeneration
    ))
    return row
}

internal fun parseNativeFileSessionIdentity(json: String?): NativeFileSessionIdentity? {
    if (json.isNullOrBlank()) return null
    return runCatching {
        val envelope = JSONObject(json)
        val identity = envelope.getJSONObject("identity")
        val binding = identity.getJSONObject("binding")
        val requestId = binding.getString("request_id")
        val connectionGeneration = binding.getLong("connection_generation")
        val coreGeneration = identity.getLong("core_generation")
        if (requestId.isBlank() || connectionGeneration <= 0 || coreGeneration <= 0) null
        else NativeFileSessionIdentity(
                identityJson = identity.toString(),
                requestId = requestId,
                connectionGeneration = connectionGeneration,
                coreGeneration = coreGeneration,
                canRead = envelope.getBoolean("read"),
                canWrite = envelope.getBoolean("write"),
                isHost = envelope.getBoolean("host"),
            )
    }.getOrNull()
}

internal fun parseNativeFileRoots(json: String): List<NativeFileRootRow> = runCatching {
    val roots = JSONObject(json).getJSONArray("roots")
    buildList(roots.length()) {
        repeat(roots.length()) { index ->
            val item = roots.getJSONObject(index)
            val id = item.getString("root_id")
            val name = item.getString("display_name")
            if (id.isNotBlank() && name.isNotBlank()) add(NativeFileRootRow(id, name))
        }
    }
}.getOrElse { throw IllegalArgumentException(uiText(UiTextKey.THE_REMOTE_FILE_ROOT_RESPONSE_IS_D5A58)) }

internal fun parseNativeFileBrowsePage(
    json: String,
    identity: NativeFileSessionIdentity,
): NativeFileBrowsePage {
    val item = JSONObject(json)
    val session = item.getJSONObject("session")
    val requestId = session.getString("request_id")
    val generation = session.getLong("connection_generation")
    require(requestId == identity.requestId && generation == identity.connectionGeneration) {
        uiText(UiTextKey.THE_REMOTE_DIRECTORY_RESPONSE_BELONGS_TO_DA10E)
    }
    val entriesJson = item.getJSONArray("entries")
    val entries = List(entriesJson.length()) { index ->
        val entry = entriesJson.getJSONObject(index)
        val size = if (entry.isNull("size")) null else entry.getLong("size").takeIf { it >= 0 }
        NativeFileEntryRow(
            name = entry.getString("name"),
            directory = entry.getBoolean("directory"),
            size = size,
            modifiedUnixMs = entry.optLong("modified_unix_ms", 0),
        )
    }
    return NativeFileBrowsePage(
        requestId = requestId,
        connectionGeneration = generation,
        browseId = item.getString("browse_id"),
        rootId = item.getString("root_id"),
        directory = item.optString("directory", ""),
        snapshotId = item.getString("snapshot_id"),
        offset = item.getInt("offset"),
        totalEntries = item.getInt("total_entries"),
        hasMore = item.getBoolean("has_more"),
        entries = entries,
    )
}

internal fun parseNativeFileTask(json: String, displayName: String): NativeFileTaskRow {
    val item = JSONObject(json)
    val total = if (item.isNull("total_bytes")) null else item.getLong("total_bytes").takeIf { it >= 0 }
    val error = if (item.isNull("error")) null else item.getString("error")
    return NativeFileTaskRow(
        taskId = item.getString("task_id"),
        kind = item.getString("kind"),
        displayName = displayName,
        phase = item.getString("phase"),
        confirmedBytes = item.getLong("confirmed_bytes").coerceAtLeast(0),
        totalBytes = total,
        finished = item.getBoolean("finished"),
        error = error,
        ownerStopped = item.optBoolean("owner_stopped", item.getBoolean("finished")),
    )
}

internal fun parseNativeSafExport(json: String, taskId: String = ""): NativeSafExportRow {
    val item = JSONObject(json)
    val error = if (item.isNull("error")) null else item.getString("error")
    val privateCleanupError = if (item.isNull("private_cleanup_error")) null else item.getString("private_cleanup_error")
    val destinationCleanupError = if (item.isNull("destination_cleanup_error")) null else item.getString("destination_cleanup_error")
    return NativeSafExportRow(
        exportId = item.getString("export_id"),
        phase = item.getString("phase"),
        copiedBytes = item.getLong("copied_bytes").coerceAtLeast(0),
        totalBytes = item.getLong("total_bytes").coerceAtLeast(0),
        error = error,
        privateCleanupComplete = item.optBoolean("private_cleanup_complete", false),
        privateCleanupError = privateCleanupError,
        destinationCleanupComplete = item.optBoolean("destination_cleanup_complete", false),
        destinationCleanupError = destinationCleanupError,
        taskId = taskId,
        ownerStopped = item.optBoolean("owner_stopped", false),
    )
}

internal fun isPortableDocumentName(name: String): Boolean = name.isNotBlank() && name.length <= 255 &&
    name.toByteArray(Charsets.UTF_8).size <= 255 && name.trim() == name &&
    name.none { it == '/' || it == '\\' || it == '\u0000' }

internal fun formatFileBytes(bytes: Long): String {
    val amount = bytes.coerceAtLeast(0)
    if (amount < 1024) return "${amount} B"
    val units = listOf("KiB", "MiB", "GiB", "TiB")
    var value = amount.toDouble()
    var unit = -1
    do {
        value /= 1024.0
        unit++
    } while (value >= 1024.0 && unit < units.lastIndex)
    return "%.1f %s".format(java.util.Locale.ROOT, value, units[unit])
}

private fun MobileState.effectiveDisplays(): NativeDisplays? = nativeDisplays?.takeIf { displays ->
    localDisplaySelection?.let(displays::observes) != false
}

private fun MobileState.withNativeSession(session: NativeSessionRow?): MobileState {
    val sameSession = nativeSession?.requestId == session?.requestId &&
        nativeSession?.connectionGeneration == session?.connectionGeneration
    val active = session?.status in setOf("establishing", "connected")
    return copy(
        nativeSession = session,
        remoteVideoLayout = remoteVideoLayout.takeIf { sameSession && active },
        remoteVideoPresentation = remoteVideoPresentation.takeIf { sameSession && active },
        nativeInputLayout = nativeInputLayout.takeIf { sameSession && active },
        nativeDisplays = nativeDisplays.takeIf { sameSession && active },
        localDisplaySelection = localDisplaySelection.takeIf { sameSession && active },
    )
}

private fun MobileState.withBrowserHost(host: BrowserHostRow?): MobileState =
    copy(browserHost = host)

private fun parseRemoteVideoLayout(json: String?): NativeRemoteVideoLayout? {
    if (json == null || json.isBlank()) return null
    val item = JSONObject(json)
    return NativeRemoteVideoLayout(
        connectionGeneration = item.getLong("connectionGeneration"),
        layoutEpoch = item.getLong("layoutEpoch"),
        source = item.getInt("source"),
        width = item.getInt("width"),
        height = item.getInt("height"),
    )
}

internal fun NativeDecodedVideoFrame.matches(layout: NativeRemoteVideoLayout): Boolean =
    connectionGeneration == layout.connectionGeneration && layoutEpoch == layout.layoutEpoch &&
        source == layout.source && width == layout.width && height == layout.height

private suspend fun pollRemoteVideo(
    model: NestLinkViewModel,
    handle: Long,
    session: NativeSessionRow,
) {
    var nextSessionStatusCheckAt = 0L
    var nextInputLayoutCheckAt = 0L
    while (currentCoroutineContext().isActive) {
        try {
            if (SystemClock.elapsedRealtime() >= nextSessionStatusCheckAt) {
                val reportedSession = try {
                    withContext(Dispatchers.IO) {
                        parseNativeSession(NativeSdk.nativeNativeSessionStatus(handle))
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    model.synchronizeNativeSession(handle, session, null)
                    return
                }
                if (!model.synchronizeNativeSession(handle, session, reportedSession)) return
                nextSessionStatusCheckAt = SystemClock.elapsedRealtime() + 500
            }

            val displays = withContext(Dispatchers.IO) { NativeDisplays.parse(NativeSdk.nativeNativeDisplays(handle)) }
            if (!model.updateNativeDisplays(handle, session.requestId, session.connectionGeneration, displays)) return
            val reportedLayout = withContext(Dispatchers.IO) {
                parseRemoteVideoLayout(NativeSdk.nativeRemoteVideoLayout(handle))
            }
            val layout = reportedLayout?.takeIf {
                it.connectionGeneration == session.connectionGeneration && displays?.accepts(it) == true
            }
            if (!model.updateRemoteVideoLayout(handle, session.requestId, session.connectionGeneration, layout)) {
                return
            }
            if (layout == null) {
                delay(80)
                continue
            }

            if (SystemClock.elapsedRealtime() >= nextInputLayoutCheckAt) {
                val inputLayout = try {
                    withContext(Dispatchers.IO) {
                        NativeRemoteInputLayout.parse(NativeSdk.nativeInputLayout(handle))
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    null
                }
                if (!model.updateNativeInputLayout(
                        handle,
                        session.requestId,
                        session.connectionGeneration,
                        inputLayout,
                    )
                ) return
                nextInputLayoutCheckAt = SystemClock.elapsedRealtime() + 80
            }

            val frame = withContext(Dispatchers.IO) { NativeSdk.nativePollRemoteVideo(handle) }
            if (frame == null) {
                delay(16)
                continue
            }
            try {
                if (frame.matches(layout)) {
                    val reservation = model.reserveRemoteVideoBitmap()
                    if (reservation == null) {
                        frame.bgra.fill(0)
                        delay(16)
                        continue
                    }
                    var bitmap: android.graphics.Bitmap? = null
                    var lease: RemoteVideoBitmapLease? = null
                    try {
                        bitmap = withContext(NonCancellable + Dispatchers.Default) {
                            RemoteVideoPixels.toBitmap(frame)
                        }
                        currentCoroutineContext().ensureActive()
                        lease = reservation.commit(checkNotNull(bitmap))
                        bitmap = null

                        val verifiedDisplays = withContext(Dispatchers.IO) { NativeDisplays.parse(NativeSdk.nativeNativeDisplays(handle)) }
                        if (!model.updateNativeDisplays(handle, session.requestId, session.connectionGeneration, verifiedDisplays)) return
                        val verifiedLayout = try {
                            withContext(Dispatchers.IO) {
                                parseRemoteVideoLayout(NativeSdk.nativeRemoteVideoLayout(handle))
                            }?.takeIf {
                                it.connectionGeneration == session.connectionGeneration && verifiedDisplays?.accepts(it) == true
                            }
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Throwable) {
                            model.updateRemoteVideoLayout(
                                handle,
                                session.requestId,
                                session.connectionGeneration,
                                null,
                            )
                            throw failure
                        }
                        if (verifiedLayout != layout) {
                            if (!model.updateRemoteVideoLayout(
                                    handle,
                                    session.requestId,
                                    session.connectionGeneration,
                                    verifiedLayout,
                                )
                            ) return
                            delay(16)
                            continue
                        }
                        if (!model.updateRemoteVideoLayout(
                                handle,
                                session.requestId,
                                session.connectionGeneration,
                                verifiedLayout,
                            )
                        ) return

                        currentCoroutineContext().ensureActive()
                        if (model.presentRemoteVideo(
                                handle,
                                session.requestId,
                                session.connectionGeneration,
                                layout,
                                frame,
                                checkNotNull(lease),
                            )
                        ) {
                            lease = null
                        } else {
                            lease?.disposeUnpresented()
                            lease = null
                        }
                    } finally {
                        bitmap?.recycle()
                        lease?.disposeUnpresented()
                        reservation.close()
                    }
                }
            } finally {
                frame.bgra.fill(0)
            }
            delay(16)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            model.clearRemoteVideo(handle, session.requestId, session.connectionGeneration)
            val reportedSession = try {
                withContext(Dispatchers.IO) {
                    parseNativeSession(NativeSdk.nativeNativeSessionStatus(handle))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Throwable) {
                model.synchronizeNativeSession(handle, session, null)
                return
            }
            if (!model.synchronizeNativeSession(handle, session, reportedSession)) return
            nextSessionStatusCheckAt = SystemClock.elapsedRealtime() + 500
            delay(200)
        }
    }
}

@Composable
private fun NestLinkRoot(
    model: NestLinkViewModel,
    onStartCapture: () -> Unit,
    onRequestBrowserHostConsent: (String) -> Unit,
) {
    val state by model.state.collectAsState()
    val captureStatus by HostCaptureStatus.state.collectAsState()
    val browserCaptureStatus by BrowserHostCaptureStatus.state.collectAsState()
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner, state.handle, state.principal) {
        if (state.handle <= 0L || state.principal.isEmpty()) return@LaunchedEffect
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            BrowserHostCaptureCoordinator.consentRequests.collect { bindingJson ->
                if (BrowserHostCaptureCoordinator.consentState(bindingJson) == "pending") {
                    onRequestBrowserHostConsent(bindingJson)
                }
            }
        }
    }
    MaterialTheme(
        colorScheme = if (androidx.compose.foundation.isSystemInDarkTheme()) {
            NestLinkUiTokens.darkColorScheme
        } else {
            NestLinkUiTokens.lightColorScheme
        },
        typography = NestLinkUiTokens.typography,
        shapes = NestLinkUiTokens.shapes,
    ) {
            Surface(
                Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing),
                color = MaterialTheme.colorScheme.background,
            ) {
            Column {
                AppLanguagePicker()
                Box(Modifier.weight(1f)) {
                    when {
                        state.localClosePending -> NativeClosePendingScreen(state, model)
                        state.handle == 0L -> ConnectScreen(state, model)
                        state.principal.isEmpty() -> LoginScreen(state, model)
                        else -> HomeScreen(
                            state, model, captureStatus, browserCaptureStatus,
                            onStartCapture,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NativeClosePendingScreen(state: MobileState, model: NestLinkViewModel) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NestLinkUiTokens.mobileScreenPadding),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(uiText(UiTextKey.CLEANING_UP_THE_LOCAL_CONNECTION_1081F), style = MaterialTheme.typography.headlineMedium)
        Text(uiText(UiTextKey.NESTLINK_RETAINS_THE_ORIGINAL_CONNECTION_WHILE_FA223), color = Muted)
        StateMessage(state)
        Button(
            onClick = model::retryPendingNativeClose,
            enabled = !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.busy) CircularProgressIndicator(Modifier.width(20.dp), strokeWidth = 2.dp)
            else Text(uiText(UiTextKey.RETRY_LOCAL_CLEANUP_FA95E))
        }
    }
}

@Composable
private fun ConnectScreen(state: MobileState, model: NestLinkViewModel) {
    var origin by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NestLinkUiTokens.mobileScreenPadding),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("NestLink", style = MaterialTheme.typography.headlineLarge, color = MaterialTheme.colorScheme.primary)
        Text(uiText(UiTextKey.VERIFY_THE_SERVER_IDENTITY_THEN_SIGN_78C59), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(24.dp))
        Field(uiText(UiTextKey.SERVER_HTTPS_ADDRESS_7764B), origin, { origin = it }, placeholder = "https://control.example.com")


        StateMessage(state)
        Button(
            onClick = { model.connect(origin) },
            enabled = !state.busy && origin.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { if (state.busy) CircularProgressIndicator(Modifier.width(20.dp), strokeWidth = 2.dp) else Text(uiText(UiTextKey.VERIFY_SERVER_1717B)) }
        Text(uiText(UiTextKey.YOUR_ADMINISTRATOR_PROVIDES_THE_TRUST_DETAILS_9752F), style = MaterialTheme.typography.bodySmall, color = Muted, modifier = Modifier.padding(top = 12.dp))
    }
}

@Composable
private fun LoginScreen(state: MobileState, model: NestLinkViewModel) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NestLinkUiTokens.mobileScreenPadding), verticalArrangement = Arrangement.Center) {
        Text(uiText(UiTextKey.SIGN_IN_1E2DF), style = MaterialTheme.typography.headlineMedium)
        Text(uiText(UiTextKey.SERVER_IDENTITY_VERIFIED_AN_AUTHENTICATOR_OR_6F063), color = Muted)
        Spacer(Modifier.height(20.dp))
        Field(uiText(UiTextKey.ACCOUNT_311BB), username, { username = it })
        Field(uiText(UiTextKey.PASSWORD_A621A), password, { password = it }, secret = true)

        StateMessage(state)
        Button(onClick = { model.login(username, password, ""); password = "" }, enabled = !state.busy && username.isNotBlank() && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            if (state.busy) CircularProgressIndicator(Modifier.width(20.dp), strokeWidth = 2.dp) else Text(uiText(UiTextKey.SIGN_IN_1E2DF))
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = model::disconnectUnverifiedServer, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
            Text(uiText(UiTextKey.BACK_TO_SERVER_IDENTITY_SETTINGS_018A3))
        }
    }
}

private enum class MobileSection { Remote, Publish, Devices }
private enum class RemoteSection { Authorization, Password, Capture, Files, Clipboard, BrowserHost }


/** Code-native line icons follow the current Material navigation content color. */
@Composable
private fun MobileNavigationIcon(section: MobileSection) {
    val color = LocalContentColor.current
    Canvas(Modifier.size(24.dp)) {
        val unit = size.minDimension / 24f
        val stroke = Stroke(1.7f * unit)
        fun point(x: Float, y: Float) = Offset(x * unit, y * unit)
        when (section) {
            MobileSection.Remote -> {
                drawRoundRect(color, point(3f, 4f), Size(18f * unit, 12f * unit), CornerRadius(2f * unit), style = stroke)
                drawLine(color, point(12f, 16f), point(12f, 20f), stroke.width)
                drawLine(color, point(7f, 20f), point(17f, 20f), stroke.width)
            }
            MobileSection.Publish -> {
                drawLine(color, point(6f, 12f), point(18f, 5f), stroke.width)
                drawLine(color, point(6f, 12f), point(18f, 19f), stroke.width)
                for ((x, y) in listOf(6f to 12f, 18f to 5f, 18f to 19f)) {
                    drawCircle(color, 2.5f * unit, point(x, y), style = stroke)
                }
            }
            MobileSection.Devices -> {
                drawRoundRect(color, point(3f, 4f), Size(12f * unit, 11f * unit), CornerRadius(1.5f * unit), style = stroke)
                drawLine(color, point(7f, 19f), point(11f, 19f), stroke.width)
                drawLine(color, point(9f, 15f), point(9f, 19f), stroke.width)
                drawRoundRect(color, point(17f, 9f), Size(5f * unit, 11f * unit), CornerRadius(1f * unit), style = stroke)
            }
        }
    }
}

@Composable
private fun HomeScreen(
    state: MobileState,
    model: NestLinkViewModel,
    captureStatus: HostCaptureUiState,
    browserCaptureStatus: BrowserHostCaptureUiState,
    onStartCapture: () -> Unit,
) {
    var section by rememberSaveable { mutableStateOf(MobileSection.Devices) }
    var remoteSection by rememberSaveable { mutableStateOf(RemoteSection.Authorization) }
    var revoke by remember { mutableStateOf<DeviceRow?>(null) }
    val uploadPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        model.finishNativeFileUploadPicker(uri)
    }
    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        model.finishNativeFileExportPicker(uri)
    }
    val hostSharePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        model.finishNativeHostSharePicker(uris)
    }
    val hostExportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        model.finishNativeHostExportPicker(uri)
    }
    val authorizationLifecycle = androidx.lifecycle.compose.LocalLifecycleOwner.current
    LaunchedEffect(state.handle, section, remoteSection, authorizationLifecycle) {
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Authorization && state.handle > 0L) {
            authorizationLifecycle.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (isActive) {
                    model.pollRemoteRequests()
                    delay(2_000)
                }
            }
        }
    }
    LaunchedEffect(section, remoteSection) {
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Authorization) model.refreshRemoteRequests()
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Password) model.refreshRemotePassword()
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Capture) model.refreshNetworkSettings()
        if (section == MobileSection.Publish) model.refreshServices()
    }
    LaunchedEffect(state.handle, section, remoteSection) {
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Files && state.handle > 0L) {
            while (isActive) {
                model.refreshNativeFiles()
                delay(1_000)
            }
        }
    }
    LaunchedEffect(state.handle, section, remoteSection) {
        if (section == MobileSection.Remote && remoteSection == RemoteSection.Clipboard && state.handle > 0L) {
            while (isActive) {
                model.refreshNativeClipboard()
                delay(1_000)
            }
        }
    }
    LaunchedEffect(state.handle, section) {
        if (section == MobileSection.Remote && state.handle > 0L) {
            val status = runCatching {
                JSONObject(withContext(Dispatchers.IO) {
                    NativeSdk.nativePlatformCaptureStatus(state.handle)
                })
            }.getOrNull()
            val current = HostCaptureStatus.state.value
            if (status?.optBoolean("active") == true && current.state !in setOf("starting", "awaiting_consent")) {
                HostCaptureStatus.update("capturing", uiText(UiTextKey.CAPTURE_CONSENT_STATUS_CONFIRMED_20006), current.encodedFrames)
            } else if (status != null && !status.optBoolean("active") && current.state == "capturing") {
                HostCaptureStatus.update("stopped", uiText(UiTextKey.CAPTURE_STOPPED_B9B16), current.encodedFrames)
            }
        }
    }
    LaunchedEffect(state.handle, section, state.browserHost?.requestId, state.browserHost?.status) {
        if (section == MobileSection.Remote && state.handle > 0L &&
            state.browserHost?.status in setOf("establishing", "connected", "stopping")
        ) {
            while (isActive) {
                model.refreshBrowserHostStatus(state.handle)
                delay(500)
            }
        }
    }
    Scaffold(
        topBar = {
            Column(Modifier.fillMaxWidth().padding(horizontal = NestLinkUiTokens.mobileScreenPadding, vertical = 12.dp)) {
                Text("NestLink", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text("${state.principal} · ${state.accountId}", style = MaterialTheme.typography.bodySmall, color = Muted)
            }
        },
        bottomBar = {
            NavigationBar {
                MobileSection.entries.forEach { item ->
                    NavigationBarItem(
                        selected = section == item,
                        onClick = { section = item },
                        icon = { MobileNavigationIcon(item) },
                        label = { Text(when (item) { MobileSection.Remote -> uiText(UiTextKey.REMOTE_CONTROL_3FF77); MobileSection.Publish -> uiText(UiTextKey.SERVICE_PUBLISHING_6E26D); MobileSection.Devices -> uiText(UiTextKey.DEVICES_E1506) }) },
                    )
                }
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = NestLinkUiTokens.mobileScreenPadding)) {
            when (section) {
                MobileSection.Devices -> DeviceScreen(state, model, { revoke = it }) { device, requestInput, requestAudio, requestFileRead, requestFileWrite, requestClipboardRead, requestClipboardWrite ->
                    model.requestView(device.id, requestInput, requestAudio, requestFileRead, requestFileWrite, requestClipboardRead, requestClipboardWrite)
                    remoteSection = RemoteSection.Authorization
                    section = MobileSection.Remote
                }
                MobileSection.Remote -> {
                    Row(
                        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        RemoteSection.entries.forEach { item ->
                            FilterChip(
                                selected = remoteSection == item,
                                onClick = { remoteSection = item },
                                label = {
                                    Text(when (item) {
                                        RemoteSection.Authorization -> uiText(UiTextKey.CONNECTIONS_AND_CONSENT_4819B)
                                        RemoteSection.Password -> uiText(UiTextKey.ONE_TIME_PASSWORD)
                                        RemoteSection.Capture -> uiText(UiTextKey.LOCAL_SHARING_SETTINGS_4C8FE)
                                        RemoteSection.Files -> uiText(UiTextKey.FILES_39932)
                                        RemoteSection.Clipboard -> uiText(UiTextKey.CLIPBOARD_8C10E)
                                        RemoteSection.BrowserHost -> uiText(UiTextKey.BROWSER_SHARING_F2DAC)
                                    })
                                },
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    when (remoteSection) {
                        RemoteSection.Authorization -> RemoteScreen(state, model)
                        RemoteSection.Password -> RemotePasswordHostScreen(state, model)
                        RemoteSection.Capture -> Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                            HostCaptureScreen(state, model, captureStatus, browserCaptureStatus, onStartCapture)
                            NativeNetworkSettingsPanel(state.networkSettings, state.busy, model::saveNetworkSettings)
                        }
                        RemoteSection.Clipboard -> Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                            NativeClipboardPanel(state, model)
                        }
                        RemoteSection.BrowserHost -> {
                            Text(uiText(UiTextKey.BROWSER_SHARING_F2DAC), style = MaterialTheme.typography.headlineSmall)
                            Text(uiText(UiTextKey.MANAGE_LOCAL_FILES_AND_CLIPBOARD_FOR_0BFB5), color = Muted, style = MaterialTheme.typography.bodySmall)
                        }
                        RemoteSection.Files -> if (state.fileSession?.isHost == true) HostFilesScreen(
                            state, model,
                            onPickShare = {
                                if (model.prepareNativeHostShare()) runCatching { hostSharePicker.launch(arrayOf("*/*")) }.onFailure { model.cancelPendingNativeFilePicker() }
                            },
                            onPickExport = { artifactId ->
                                model.prepareNativeHostExport(artifactId)?.let { name ->
                                    runCatching { hostExportPicker.launch(name) }.onFailure { model.cancelPendingNativeFilePicker() }
                                }
                            },
                        ) else FilesScreen(
                            state,
                            model,
                            onPickUpload = { rootId ->
                                if (model.prepareNativeFileUpload(rootId)) {
                                    runCatching { uploadPicker.launch(arrayOf("*/*")) }
                                        .onFailure { model.cancelPendingNativeFilePicker() }
                                }
                            },
                            onPickExport = { taskId ->
                                val name = model.prepareNativeFileExport(taskId)
                                if (name != null) {
                                    runCatching { exportPicker.launch(name) }
                                        .onFailure { model.cancelPendingNativeFilePicker() }
                                }
                            },
                        )
                    }
                }
                MobileSection.Publish -> ServicesScreen(state, model)
            }
            val showBrowserHostData = section == MobileSection.Remote && remoteSection == RemoteSection.BrowserHost
            Column(
                Modifier.fillMaxWidth().then(
                    if (showBrowserHostData) {
                        Modifier.weight(1f).verticalScroll(rememberScrollState())
                    } else {
                        Modifier.height(0.dp)
                    },
                ),
            ) {
                BrowserHostDataPanel(
                    handle = state.handle,
                    binding = state.browserHost?.binding,
                    foreground = model.browserHostClipboardForeground,
                    visible = showBrowserHostData,
                )
            }
            Spacer(Modifier.height(12.dp))
            StateMessage(state)
            OutlinedButton(onClick = model::logout, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.SIGN_OUT_E7677)) }
        }
    }
    revoke?.let { device ->
        AlertDialog(
            onDismissRequest = { revoke = null },
            title = { Text(uiText(UiTextKey.REVOKE_DEVICE_CADF7)) },
            text = { Text(uiText(UiTextKey.WILL_NO_LONGER_BE_ABLE_TO_DAE9E, device.name)) },
            confirmButton = { TextButton(onClick = { model.revokeDevice(device.id); revoke = null }) { Text(uiText(UiTextKey.REVOKE_926A5), color = Danger) } },
            dismissButton = { TextButton(onClick = { revoke = null }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
        )
    }
}

@Composable
private fun ColumnScope.FilesScreen(
    state: MobileState,
    model: NestLinkViewModel,
    onPickUpload: (String) -> Unit,
    onPickExport: (String) -> Unit,
) {
    val identity = state.fileSession
    LaunchedEffect(identity?.identityJson, state.selectedReadRootId) {
        if (identity?.canRead == true && state.selectedReadRootId.isNotEmpty() && state.fileBrowsePage == null) {
            model.browseNativeFiles(state.selectedReadRootId, null)
        }
    }

    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.weight(1f)) {
            Text(uiText(UiTextKey.REMOTE_FILES_9ED48), style = MaterialTheme.typography.headlineSmall)
            Text(uiText(UiTextKey.BROWSE_FOLDERS_IN_THE_CURRENT_AUTHORIZED_A5FC6), color = Muted, style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = model::refreshNativeFiles, enabled = !state.fileBusy) { Text(uiText(UiTextKey.REFRESH_AEE88)) }
    }
    Spacer(Modifier.height(8.dp))

    if (identity == null) {
        Text(uiText(UiTextKey.NO_NATIVE_REMOTE_FILE_SESSION_IS_F8A58), color = Muted)
        Spacer(Modifier.weight(1f))
    } else {
        if (!identity.canRead && !identity.canWrite) {
            Text(uiText(UiTextKey.THE_CURRENT_REMOTE_SESSION_HAS_NO_89967), color = Muted)
        }

        if (identity.canRead) {
            Text(uiText(UiTextKey.DOWNLOAD_SOURCE_E2F01), style = MaterialTheme.typography.titleSmall)
            if (state.fileReadRoots.isEmpty()) {
                Text(uiText(UiTextKey.THE_HOST_HAS_NOT_PROVIDED_READABLE_228DE), color = Muted, style = MaterialTheme.typography.bodySmall)
            } else {
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                    state.fileReadRoots.forEach { root ->
                        TextButton(
                            onClick = { model.selectNativeFileRoot(root.id) },
                            enabled = !state.fileBusy && !state.filePickerPending,
                        ) {
                            Text(if (state.selectedReadRootId == root.id) "● ${root.displayName}" else root.displayName)
                        }
                    }
                }
            }
        }

        if (identity.canWrite) {
            Text(uiText(UiTextKey.UPLOAD_DESTINATION_874CB), style = MaterialTheme.typography.titleSmall)
            if (state.fileWriteRoots.isEmpty()) {
                Text(uiText(UiTextKey.THE_HOST_HAS_NOT_PROVIDED_WRITABLE_5D87B), color = Muted, style = MaterialTheme.typography.bodySmall)
            } else {
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                    state.fileWriteRoots.forEach { root ->
                        TextButton(
                            onClick = { model.selectNativeFileWriteRoot(root.id) },
                            enabled = !state.fileBusy && !state.filePickerPending,
                        ) {
                            Text(if (state.selectedWriteRootId == root.id) "● ${root.displayName}" else root.displayName)
                        }
                    }
                }
                OutlinedButton(
                    onClick = { onPickUpload(state.selectedWriteRootId) },
                    enabled = state.selectedWriteRootId.isNotEmpty() && !state.fileBusy && !state.filePickerPending &&
                        state.canStartAnotherFileTask(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (state.filePickerPending) uiText(UiTextKey.WAITING_FOR_THE_SYSTEM_FILE_PICKER_AE152) else uiText(UiTextKey.CHOOSE_FILES_TO_UPLOAD_TO_THIS_01219)) }
            }
        }

        val page = state.fileBrowsePage?.takeIf { it.rootId == state.selectedReadRootId }
        if (identity.canRead && page != null) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text(page.rootId, style = MaterialTheme.typography.labelSmall, color = Muted)
                    Text(if (page.directory.isEmpty()) "/" else "/${page.directory}", style = MaterialTheme.typography.bodySmall)
                }
                if (page.directory.isNotEmpty()) {
                    TextButton(
                        onClick = { model.browseNativeFiles(page.rootId, parentRemoteDirectory(page.directory)) },
                        enabled = !state.fileLoading,
                    ) { Text(uiText(UiTextKey.PARENT_FOLDER_8E784)) }
                }
            }
        }

        if (state.fileLoading) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(Modifier.width(22.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text(uiText(UiTextKey.READING_THE_REMOTE_FOLDER_28E72), color = Muted)
            }
        }

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (identity.canRead && page != null) {
                items(page.entries, key = { "${page.rootId}:${page.directory}:${it.directory}:${it.name}" }) { entry ->
                    val child = remoteChildPath(page.directory, entry.name)
                    Surface(shape = MaterialTheme.shapes.small, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 7.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(if (entry.directory) "📁 ${entry.name}" else entry.name, style = MaterialTheme.typography.bodyMedium)
                                if (!entry.directory) Text(entry.size?.let(::formatFileBytes) ?: uiText(UiTextKey.UNKNOWN_SIZE_F8F5F), color = Muted, style = MaterialTheme.typography.labelSmall)
                            }
                            if (entry.directory) {
                                TextButton(onClick = { model.browseNativeFiles(page.rootId, child) }, enabled = !state.fileLoading) { Text(uiText(UiTextKey.OPEN_C7712)) }
                            } else {
                                TextButton(
                                    onClick = { model.downloadNativeFile(page.rootId, child, entry.name) },
                                    enabled = !state.fileBusy && !state.filePickerPending && state.canStartAnotherFileTask(),
                                ) { Text(uiText(UiTextKey.DOWNLOAD_4673A)) }
                            }
                        }
                    }
                }
                if (page.hasMore) {
                    item {
                        OutlinedButton(onClick = model::loadMoreNativeFiles, enabled = !state.fileLoading, modifier = Modifier.fillMaxWidth()) {
                            Text(uiText(UiTextKey.LOAD_MORE_5FA8A, page.offset, page.totalEntries))
                        }
                    }
                }
                if (page.entries.isEmpty() && !page.hasMore) {
                    item { Text(uiText(UiTextKey.THIS_FOLDER_IS_EMPTY_B372A), color = Muted, modifier = Modifier.padding(vertical = 12.dp)) }
                }
            }
            if (state.fileTasks.isNotEmpty()) {
                item(key = "transfer-history-heading") {
                    Text(uiText(UiTextKey.TRANSFER_HISTORY_589DE), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
                }
                items(state.fileTasks.asReversed(), key = { "task:${it.taskId}" }) { task ->
                    NativeFileTaskCard(
                        task = task,
                        export = state.fileExports[task.taskId],
                        state = state,
                        model = model,
                        onPickExport = onPickExport,
                    )
                }
            }
        }
        if (state.fileBusy) Text(uiText(UiTextKey.PREPARING_FILE_TASKS_9A505), color = Muted, style = MaterialTheme.typography.bodySmall)
        Text(uiText(UiTextKey.DOWNLOADS_ARE_STAGED_IN_PRIVATE_APP_7D3AF), color = Muted, style = MaterialTheme.typography.bodySmall)
    }

    if (state.fileError.isNotBlank()) {
        Text(state.fileError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun NativeFileTaskCard(
    task: NativeFileTaskRow,
    export: NativeSafExportRow?,
    state: MobileState,
    model: NestLinkViewModel,
    onPickExport: (String) -> Unit,
) {
    Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(if (task.kind == "download") uiText(UiTextKey.DOWNLOAD_79EC2, task.displayName) else uiText(UiTextKey.UPLOAD_A8567, task.displayName), style = MaterialTheme.typography.titleSmall)
            Text(uiText(UiTextKey.STATUS_F7B4A, nativeFilePhaseLabel(task.phase)), color = Muted)
            Text(
                task.totalBytes?.let { "${formatFileBytes(task.confirmedBytes)} / ${formatFileBytes(it)}" }
                    ?: uiText(UiTextKey.CONFIRMED_31680, formatFileBytes(task.confirmedBytes)),
                color = Muted,
                style = MaterialTheme.typography.bodySmall,
            )
            task.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            if (!task.finished) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (task.phase == "paused") {
                        OutlinedButton(onClick = { model.controlNativeFileTask(task.taskId, 1) }, enabled = !state.fileBusy) { Text(uiText(UiTextKey.RESUME_7C969)) }
                    } else if (task.phase !in setOf("cancelling")) {
                        OutlinedButton(onClick = { model.controlNativeFileTask(task.taskId, 0) }, enabled = !state.fileBusy) { Text(uiText(UiTextKey.PAUSE_8D12F)) }
                    }
                    if (task.phase != "cancelling") {
                        TextButton(onClick = { model.controlNativeFileTask(task.taskId, 2) }, enabled = !state.fileBusy) { Text(uiText(UiTextKey.CANCEL_2CD0F), color = Danger) }
                    }
                }
            } else if (!task.ownerStopped) {
                Text(uiText(UiTextKey.LOCAL_FILE_WORKER_SHUTDOWN_IS_UNCONFIRMED_3C1D0), color = Muted, style = MaterialTheme.typography.bodySmall)
            }

            if (task.kind == "download" && task.finished && task.ownerStopped) {
                if (task.phase == "completed") {
                    if (export?.phase == "completed") {
                        Text(uiText(UiTextKey.THE_EXPORT_DESTINATION_WAS_READ_BACK_20F98), color = Success, style = MaterialTheme.typography.bodySmall)
                    } else {
                        Text(uiText(UiTextKey.VERIFIED_AND_STAGED_IN_PRIVATE_APP_AA81F), color = Success, style = MaterialTheme.typography.bodySmall)
                    }
                    export?.let { currentExport ->
                        Text(uiText(UiTextKey.EXPORT_4D606, nativeFilePhaseLabel(currentExport.phase), formatFileBytes(currentExport.copiedBytes), formatFileBytes(currentExport.totalBytes)), color = Muted, style = MaterialTheme.typography.bodySmall)
                        currentExport.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                        currentExport.destinationCleanupError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                        currentExport.privateCleanupError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                        if (currentExport.phase != "running" && currentExport.ownerRetained()) {
                            Text(uiText(UiTextKey.EXPORT_WORKER_EXIT_IS_UNCONFIRMED_ITS_D1BE7), color = Muted, style = MaterialTheme.typography.bodySmall)
                        }
                        if (currentExport.phase == "running") {
                            TextButton(onClick = { model.cancelNativeFileExport(task.taskId) }) { Text(uiText(UiTextKey.CANCEL_EXPORT_7EEFA), color = Danger) }
                        }
                    }
                    if (export?.privateCleanupComplete != true) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onPickExport(task.taskId) },
                                enabled = !state.fileBusy && !state.filePickerPending &&
                                    state.canStartAnotherFileTask(),
                                modifier = Modifier.weight(1f),
                            ) { Text(if (export?.phase == "failed" || export?.phase == "cancelled") uiText(UiTextKey.RETRY_EXPORT_0A07F) else uiText(UiTextKey.CHOOSE_SAVE_LOCATION_EDFA3)) }
                            TextButton(
                                onClick = { model.discardNativeFileDownload(task.taskId) },
                                enabled = !state.fileBusy && !NativeSafPickerOwners.hasRetainedOwners() && export?.ownerRetained() != true,
                            ) { Text(if (export?.privateCleanupError != null) uiText(UiTextKey.RETRY_STAGING_CLEANUP_75BDC) else uiText(UiTextKey.DELETE_STAGED_COPY_C4FE0), color = Danger) }
                        }
                    } else {
                        Text(uiText(UiTextKey.THE_PRIVATE_APP_COPY_WAS_CLEANED_AFF4E), color = Muted, style = MaterialTheme.typography.bodySmall)
                        TextButton(
                            onClick = { model.discardNativeFileDownload(task.taskId) },
                            enabled = !state.fileBusy && !NativeSafPickerOwners.hasRetainedOwners(),
                        ) { Text(uiText(UiTextKey.DELETE_RECORD_F2CF9), color = Danger) }
                    }
                } else {
                    Text(uiText(UiTextKey.THE_FAILED_OR_CANCELLED_TASK_HAS_64483), color = Muted, style = MaterialTheme.typography.bodySmall)
                    TextButton(
                        onClick = { model.discardNativeFileDownload(task.taskId) },
                        enabled = !state.fileBusy && !NativeSafPickerOwners.hasRetainedOwners(),
                    ) { Text(uiText(UiTextKey.DELETE_REMAINING_COPY_AND_RECORD_75D11), color = Danger) }
                }
            }
        }
    }
}

internal fun parentRemoteDirectory(directory: String): String {
    if (directory.isEmpty()) return ""
    val lastSeparator = directory.lastIndexOf('/')
    return if (lastSeparator < 0) "" else directory.substring(0, lastSeparator)
}

internal fun remoteChildPath(directory: String, name: String): String =
    if (directory.isEmpty()) name else "${directory}/${name}"

private fun nativeFilePhaseLabel(phase: String): String = when (phase) {
    "queued" -> uiText(UiTextKey.QUEUED_D6F76)
    "running" -> uiText(UiTextKey.IN_PROGRESS_DC959)
    "paused" -> uiText(UiTextKey.PAUSED_EB0C3)
    "cancelling" -> uiText(UiTextKey.CANCELLING_0B58E)
    "completed" -> uiText(UiTextKey.COMPLETED_F2846)
    "cancelled" -> uiText(UiTextKey.CANCELLED_A3777)
    "failed" -> uiText(UiTextKey.FAILED_28384)
    else -> phase
}

internal fun MobileState.canStartAnotherFileTask(): Boolean {
    val tasks = fileTasks.ifEmpty { listOfNotNull(fileTask) }
    return !NativeSafPickerOwners.isClosing(handle) && !NativeSafPickerOwners.hasRetainedOwners() &&
        tasks.none { !it.finished || !it.ownerStopped } &&
        safExport?.ownerRetained() != true &&
        fileExports.values.none { it.ownerRetained() }
}

@Composable
private fun ColumnScope.DeviceScreen(
    state: MobileState,
    model: NestLinkViewModel,
    onRevoke: (DeviceRow) -> Unit,
    onRequestView: (DeviceRow, Boolean, Boolean, Boolean, Boolean, Boolean, Boolean) -> Unit,
) {
    var ownName by remember { mutableStateOf(android.os.Build.MODEL.ifBlank { uiText(UiTextKey.ANDROID_CONTROLLER_F6A25) }) }
    val ownRegistered = state.devices.any { it.id == state.ownDeviceId && !it.revoked }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.weight(1f)) {
            Text(uiText(UiTextKey.DEVICES_E1506), style = MaterialTheme.typography.headlineSmall)
            Text(uiText(UiTextKey.ONLINE_STATUS_IS_SHOWN_ONLY_WHEN_735AF), color = Muted, style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = model::refreshDevices, enabled = !state.busy) { Text(uiText(UiTextKey.REFRESH_AEE88)) }
    }
    Spacer(Modifier.height(12.dp))
    if (!ownRegistered) {
        Field(uiText(UiTextKey.LOCAL_DISPLAY_NAME_1B651), ownName, { ownName = it })
        Button(onClick = { model.enrollController(ownName) }, enabled = !state.busy && ownName.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            Text(uiText(UiTextKey.ENROLL_AS_CONTROLLER_BDAF9))
        }
    }
    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.weight(1f)) {
        items(state.devices, key = { it.id }) { device ->
            Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(device.name, style = MaterialTheme.typography.titleMedium)
                        Text(if (device.revoked) uiText(UiTextKey.REVOKED_FEF96) else uiText(UiTextKey.ENROLLED_5F2F3), color = if (device.revoked) Danger else Muted)
                    }
                    Text("${device.platform} · ${device.pathMode}", color = Muted, style = MaterialTheme.typography.bodySmall)
                    if (device.capabilities.isNotEmpty()) Text(uiText(UiTextKey.CAPABILITIES_90002, device.capabilities.joinToString()), color = Muted, style = MaterialTheme.typography.bodySmall)
                    Text(device.id, color = Muted, style = MaterialTheme.typography.bodySmall)
                    if (!device.revoked && device.id != state.ownDeviceId && "host" in device.capabilities) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            var requestInput by remember(device.id) { mutableStateOf(false) }
                            var requestAudio by remember(device.id) { mutableStateOf(false) }
                            PermissionChoice(requestInput, { requestInput = it }, !state.busy, uiText(UiTextKey.REQUEST_VIEW_AND_INPUT_E183F))
                            PermissionChoice(requestAudio, { requestAudio = it }, !state.busy, uiText(UiTextKey.REQUEST_VIEW_AND_SYSTEM_AUDIO_3B155))
                            var fileRead by remember(device.id) { mutableStateOf(false) }
                            var fileWrite by remember(device.id) { mutableStateOf(false) }
                            var clipboardRead by remember(device.id) { mutableStateOf(false) }
                            var clipboardWrite by remember(device.id) { mutableStateOf(false) }
                            PermissionChoice(fileRead, { fileRead = it }, !state.busy, uiText(UiTextKey.READ_FILES_CHOSEN_BY_THE_HOST_47D34))
                            PermissionChoice(fileWrite, { fileWrite = it }, !state.busy, uiText(UiTextKey.SEND_FILES_TO_THE_HOST_4CD61))
                            PermissionChoice(clipboardRead, { clipboardRead = it }, !state.busy, uiText(UiTextKey.READ_THE_HOST_TEXT_CLIPBOARD_55683))
                            PermissionChoice(clipboardWrite, { clipboardWrite = it }, !state.busy, uiText(UiTextKey.WRITE_THE_HOST_TEXT_CLIPBOARD_DBE0B))
                            OutlinedButton(onClick = { onRequestView(device, requestInput, requestAudio, fileRead, fileWrite, clipboardRead, clipboardWrite) }, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
                                Text(uiText(UiTextKey.REQUEST_VIEW_AND_SELECTED_DATA_DIRECTIONS_E5AE2))
                            }
                        }
                    }
                    if (!device.revoked) TextButton(onClick = { onRevoke(device) }, enabled = !state.busy) { Text(uiText(UiTextKey.REVOKE_DEVICE_3BBA1), color = Danger) }
                }
            }
        }
    }
}

@Composable
private fun RemoteDisplayPicker(state: MobileState, onSelect: (Int) -> Unit) {
    val displays = state.nativeDisplays ?: return
    if (displays.catalog == null) return
    val confirmed = state.effectiveDisplays()?.confirmed
    val waiting = confirmed == null
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        displays.displays.forEach { display ->
            OutlinedButton(
                onClick = { onSelect(display.source) },
                enabled = !waiting && display.source != confirmed?.source,
            ) { Text(if (display.source == confirmed?.source) uiText(UiTextKey.CURRENT_87FC9, display.label) else display.label) }
        }
    }
    if (waiting) Text(uiText(UiTextKey.CONFIRMING_THE_REMOTE_SHARED_DISPLAY_96971), color = Muted, style = MaterialTheme.typography.bodySmall)
    Spacer(Modifier.height(8.dp))
}

private fun remotePasswordExpiryLabel(expiresAtUnixMs: Long): String =
    java.text.DateFormat.getDateTimeInstance(
        java.text.DateFormat.MEDIUM,
        java.text.DateFormat.SHORT,
        UiLanguage.locale,
    ).format(java.util.Date(expiresAtUnixMs))

@Composable
private fun RemotePasswordHostScreen(state: MobileState, model: NestLinkViewModel) {
    val localHost = state.devices.firstOrNull {
        it.id == state.ownDeviceId && !it.revoked && "host" in it.capabilities
    }
    val current = state.remotePassword
    var permissions by remember(state.handle, state.authGeneration, current?.revision) {
        mutableStateOf(current?.permissions?.toSet()?.takeIf { it.isNotEmpty() } ?: setOf(1))
    }
    var paths by remember(state.handle, state.authGeneration, current?.revision) {
        mutableStateOf(current?.paths?.toSet()?.takeIf { it.isNotEmpty() } ?: setOf(1))
    }
    var lifetimeDays by remember(state.handle, state.authGeneration, current?.revision) {
        mutableStateOf(7)
    }
    // These inputs are intentionally not saveable: rotation, process recreation and navigation clear them.
    var password by remember(state.handle, state.authGeneration, current?.revision) { mutableStateOf("") }
    var confirmation by remember(state.handle, state.authGeneration, current?.revision) { mutableStateOf("") }
    var confirmingRevoke by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(uiText(UiTextKey.ONE_TIME_PASSWORD_ACCESS_FOR_THIS_HOST), style = MaterialTheme.typography.headlineSmall)
        Text(uiText(UiTextKey.ONE_TIME_PASSWORD_HOST_EXPLANATION), color = Muted, style = MaterialTheme.typography.bodySmall)
        if (localHost == null) {
            Text(uiText(UiTextKey.ENROLL_THIS_DEVICE_AS_A_HOST_64277), color = Muted)
            return@Column
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = model::refreshRemotePassword, enabled = !state.busy) {
                Text(uiText(if (current == null) UiTextKey.LOAD_REMOTE_PASSWORD_SETTINGS else UiTextKey.REFRESH_REMOTE_PASSWORD_SETTINGS))
            }
        }
        current?.let { settings ->
            Text(uiText(UiTextKey.REMOTE_PASSWORD_REVISION_STATUS, settings.revision, if (settings.active) uiText(UiTextKey.ACTIVE_3A7A7) else uiText(UiTextKey.INACTIVE_8D02D)))
            if (settings.active) {
                Text(uiText(UiTextKey.REMOTE_PASSWORD_SCOPE, remotePermissionsLabel(settings.permissions), remotePathsLabel(settings.paths)))
                Text(uiText(UiTextKey.REMOTE_PASSWORD_EXPIRES, remotePasswordExpiryLabel(settings.expiresAtUnixMs)), color = Muted)
                OutlinedButton(
                    onClick = { confirmingRevoke = true },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger),
                ) {
                    Text(uiText(UiTextKey.REVOKE_PASSWORD_AND_CLOSE_ITS_SESSIONS))
                }
            } else {
                Text(uiText(UiTextKey.NO_ACTIVE_REMOTE_PASSWORD), color = Muted)
            }
        } ?: Text(uiText(UiTextKey.LOAD_CURRENT_REMOTE_PASSWORD_BEFORE_CONFIGURING), color = Muted)

        if (current != null) {
            Text(uiText(UiTextKey.ALLOWED_PERMISSIONS_VIEW_IS_REQUIRED), style = MaterialTheme.typography.titleMedium)
            (1..7).forEach { permission ->
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Checkbox(
                        checked = permission == 1 || permission in permissions,
                        enabled = !state.busy && permission != 1,
                        onCheckedChange = { checked ->
                            permissions = if (checked) permissions + permission else permissions - permission
                        },
                    )
                    Text(remotePermissionLabel(permission))
                }
            }
            Text(uiText(UiTextKey.ALLOWED_CONNECTION_PATHS), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = 1 in paths, onClick = { paths = if (1 in paths) paths - 1 else paths + 1 }, label = { Text(uiText(UiTextKey.DIRECT_B0632)) }, enabled = !state.busy)
                FilterChip(selected = 2 in paths, onClick = { paths = if (2 in paths) paths - 2 else paths + 2 }, label = { Text(uiText(UiTextKey.RELAY_715CE)) }, enabled = !state.busy)
            }
            Text(uiText(UiTextKey.REMOTE_PASSWORD_LIFETIME_MAXIMUM_30_DAYS), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(1, 7, 30).forEach { days ->
                    FilterChip(selected = lifetimeDays == days, onClick = { lifetimeDays = days }, label = { Text(uiText(UiTextKey.DAYS_COUNT, days)) }, enabled = !state.busy)
                }
            }
            Text(uiText(UiTextKey.NEW_REMOTE_PASSWORD_UTF8_LIMIT), color = Muted, style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = password,
                onValueChange = { if (it.length <= 1_024) password = it },
                label = { Text(uiText(UiTextKey.NEW_PASSWORD_8645B)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirmation,
                onValueChange = { if (it.length <= 1_024) confirmation = it },
                label = { Text(uiText(UiTextKey.CONFIRM_NEW_PASSWORD)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            )
            val passwordValid = remotePasswordLengthIsValid(password)
            val passwordsMatch = password == confirmation
            if (password.isNotEmpty() && !passwordValid) Text(uiText(UiTextKey.REMOTE_PASSWORD_MUST_BE_12_1024_UTF_8_BYTES), color = Danger)
            else if (confirmation.isNotEmpty() && !passwordsMatch) Text(uiText(UiTextKey.PASSWORDS_DO_NOT_MATCH), color = Danger)
            Button(
                onClick = {
                    val submitted = password
                    password = ""
                    confirmation = ""
                    model.configureRemotePassword(current.revision, permissions.sorted(), paths.sorted(), lifetimeDays, submitted)
                },
                enabled = !state.busy && 1 in permissions && paths.isNotEmpty() && passwordValid && passwordsMatch,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(uiText(if (current.active) UiTextKey.ROTATE_PASSWORD_CLOSE_OLD_SESSIONS else UiTextKey.ENABLE_ONE_TIME_PASSWORD))
            }
        }
    }

    if (confirmingRevoke) {
        AlertDialog(
            onDismissRequest = { confirmingRevoke = false },
            title = { Text(uiText(UiTextKey.REVOKE_REMOTE_PASSWORD_TITLE)) },
            text = { Text(uiText(UiTextKey.REVOKE_REMOTE_PASSWORD_BODY)) },
            confirmButton = {
                Button(
                    onClick = {
                        confirmingRevoke = false
                        password = ""
                        confirmation = ""
                        current?.let { model.revokeRemotePassword(it.revision) }
                    },
                    enabled = !state.busy,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = DangerAction,
                        contentColor = DangerActionText,
                    ),
                ) { Text(uiText(UiTextKey.REVOKE_926A5)) }
            },
            dismissButton = { TextButton(onClick = { confirmingRevoke = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) } },
        )
    }
}

private fun remotePermissionLabel(permission: Int): String = when (permission) {
    1 -> uiText(UiTextKey.VIEW_ONLY_39395)
    2 -> uiText(UiTextKey.INPUT_2087C)
    3 -> uiText(UiTextKey.SYSTEM_AUDIO_1DBF5)
    4 -> uiText(UiTextKey.READ_FILES_CHOSEN_BY_THE_HOST_47D34)
    5 -> uiText(UiTextKey.SEND_FILES_TO_THE_HOST_PRIVATE_79A77)
    6 -> uiText(UiTextKey.READ_THE_HOST_TEXT_CLIPBOARD_55683)
    7 -> uiText(UiTextKey.WRITE_THE_HOST_TEXT_CLIPBOARD_DBE0B)
    else -> uiText(UiTextKey.PERMISSION_FE1EC, permission)
}

private fun remotePermissionsLabel(permissions: List<Int>): String =
    permissions.joinToString { remotePermissionLabel(it) }

private fun remotePathsLabel(paths: List<Int>): String = paths.joinToString {
    when (it) {
        1 -> uiText(UiTextKey.DIRECT_B0632)
        2 -> uiText(UiTextKey.RELAY_715CE)
        else -> uiText(UiTextKey.PATH_6023E, it)
    }
}

@Composable
private fun RemotePasswordUsePanel(state: MobileState, model: NestLinkViewModel, request: RemoteRequestRow) {
    val scope = state.remotePasswordOffer?.takeIf { it.requestId == request.id }?.settings
    var password by remember(state.handle, state.authGeneration, request.id, request.nonce, request.policyRevision, scope?.revision) {
        mutableStateOf("")
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(uiText(UiTextKey.ONE_TIME_PASSWORD_AUTHORIZATION), style = MaterialTheme.typography.titleMedium)
        Text(uiText(UiTextKey.ONE_TIME_PASSWORD_CONTROLLER_EXPLANATION), color = Muted, style = MaterialTheme.typography.bodySmall)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = { model.refreshRemotePasswordOffer(request) }, enabled = !state.busy) {
                Text(uiText(if (scope == null) UiTextKey.VIEW_REMOTE_PASSWORD_SCOPE else UiTextKey.REFRESH_REMOTE_PASSWORD_SCOPE))
            }
        }
        if (scope == null) {
            Text(uiText(UiTextKey.LOAD_REMOTE_PASSWORD_SCOPE_BEFORE_ENTERING), color = Muted, style = MaterialTheme.typography.bodySmall)
        } else if (!scope.active) {
            Text(uiText(UiTextKey.HOST_HAS_NO_ACTIVE_REMOTE_PASSWORD), color = Muted)
        } else {
            Text(uiText(UiTextKey.ONE_TIME_PASSWORD_SCOPE_REVISION, scope.revision), color = Muted, style = MaterialTheme.typography.bodySmall)
            Text(uiText(UiTextKey.HOST_PASSWORD_SCOPE, remotePermissionsLabel(scope.permissions), remotePathsLabel(scope.paths)))
            Text(uiText(UiTextKey.REMOTE_PASSWORD_EXPIRES, remotePasswordExpiryLabel(scope.expiresAtUnixMs)), color = Muted, style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = password,
                onValueChange = { if (it.length <= 1_024) password = it },
                label = { Text(uiText(UiTextKey.ONE_TIME_AUTHORIZATION_PASSWORD)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            )
            if (password.isNotEmpty() && !remotePasswordLengthIsValid(password)) {
                Text(uiText(UiTextKey.REMOTE_PASSWORD_MUST_BE_12_1024_UTF_8_BYTES), color = Danger)
            }
            Button(
                onClick = {
                    val submitted = password
                    password = ""
                    model.authorizeRemotePassword(request, scope.revision, submitted)
                },
                enabled = !state.busy && request.status == "pending" &&
                    System.currentTimeMillis() < request.expiresAtUnixMs &&
                    System.currentTimeMillis() < scope.expiresAtUnixMs &&
                    remotePasswordLengthIsValid(password),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(uiText(UiTextKey.AUTHORIZE_THIS_REQUEST_ONLY)) }
        }
    }
}

private data class AudioApproval(val request: RemoteRequestRow, val input: Boolean, val fileRead: Boolean = false, val fileWrite: Boolean = false, val clipboardRead: Boolean = false, val clipboardWrite: Boolean = false)

@Composable
private fun ColumnScope.RemoteScreen(state: MobileState, model: NestLinkViewModel) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val context = LocalContext.current
    LaunchedEffect(state.handle, state.ownDeviceId) {
        if (state.handle > 0L && state.ownDeviceId.isNotBlank()) model.refreshTrustedDevices()
    }
    var pendingAudioApproval by remember { mutableStateOf<AudioApproval?>(null) }
    val audioPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val pending = pendingAudioApproval
        pendingAudioApproval = null
        if (granted && pending != null) {
            model.decideRemote(pending.request, true, approveInput = pending.input, approveAudio = true, approveFileRead = pending.fileRead, approveFileWrite = pending.fileWrite, approveClipboardRead = pending.clipboardRead, approveClipboardWrite = pending.clipboardWrite)
        }
    }
    val approveWithAudio: (AudioApproval) -> Unit = { selected ->
        val request = selected.request
        val approveInput = selected.input
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            model.decideRemote(request, true, approveInput = approveInput, approveAudio = true, approveFileRead = selected.fileRead, approveFileWrite = selected.fileWrite, approveClipboardRead = selected.clipboardRead, approveClipboardWrite = selected.clipboardWrite)
        } else {
            pendingAudioApproval = selected
            audioPermission.launch(Manifest.permission.RECORD_AUDIO)
        }
    }
    val session = state.nativeSession
    val sessionActive = session?.status in setOf("establishing", "connected")
    LaunchedEffect(state.handle, session?.requestId, session?.connectionGeneration, sessionActive, lifecycleOwner) {
        if (state.handle <= 0L || session == null || !sessionActive) {
            model.clearRemoteVideo()
            return@LaunchedEffect
        }
        try {
            lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                try {
                    pollRemoteVideo(model, state.handle, session)
                } finally {
                    model.clearRemoteVideo(state.handle, session.requestId, session.connectionGeneration)
                }
            }
        } finally {
            model.clearRemoteVideo(state.handle, session.requestId, session.connectionGeneration)
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.weight(1f)) {
            Text(uiText(UiTextKey.REMOTE_ACCESS_CONSENT_2FABF), style = MaterialTheme.typography.headlineSmall)
            Text(uiText(UiTextKey.VIEW_AND_INPUT_ARE_REQUESTED_AND_259C5), color = Muted, style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = model::refreshRemoteRequests, enabled = !state.busy) { Text(uiText(UiTextKey.REFRESH_AEE88)) }
    }
    Spacer(Modifier.height(12.dp))
    if (sessionActive) {
        val retryRetirements = remember(model) {
            { barrier: RemoteVideoFrameCommitBarrier -> model.retryRemoteVideoRetirements(barrier) }
        }
        val cancelRetirements = remember(model) {
            { barrier: RemoteVideoFrameCommitBarrier -> model.cancelRemoteVideoRetirementCallbacks(barrier) }
        }
        var immersive by remember(session?.requestId) { mutableStateOf(session?.hostViewAuthorized == false) }
        val canvas: @Composable () -> Unit = {
        RemoteDisplayPicker(state, model::selectRemoteDisplay)
        RemoteVideoCanvas(
            presentation = state.remoteVideoPresentation,
            sessionConnected = session?.status == "connected",
            onFrameCommitBarrierAvailable = retryRetirements,
            onFrameCommitBarrierUnavailable = cancelRetirements,
            inputLayout = state.nativeInputLayout,
            onInputAction = model::sendNativeInput,
            onReleaseInput = model::releaseNativeInput,
            modifier = Modifier.fillMaxWidth(),
        )

        }
        if (immersive) {
            androidx.compose.ui.window.Dialog(onDismissRequest = { immersive = false }, properties = androidx.compose.ui.window.DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column(Modifier.fillMaxSize().padding(16.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            TextButton(onClick = { immersive = false }) { Text(uiText(UiTextKey.REMOTE_MINIMIZE)) }
                            Button(onClick = { session?.let { model.stopNativeSession(it.requestId) } }) { Text(uiText(UiTextKey.REMOTE_DISCONNECT)) }
                        }
                        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                            canvas()
                        }
                    }
                }
            }
        } else {
            TextButton(onClick = { immersive = true }) { Text(uiText(UiTextKey.REMOTE_FULLSCREEN)) }
            canvas()
        }
        Spacer(Modifier.height(12.dp))
    }
    if (state.remoteRequests.isEmpty()) {
        Text(uiText(UiTextKey.THERE_ARE_NO_PENDING_OR_RECENT_F794C), color = Muted)
    }
    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.weight(1f)) {
        items(state.remoteRequests, key = { it.id }) { request ->
            val outgoing = request.controllerDeviceId == state.ownDeviceId
            Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp)) {
                    Text(if (outgoing) uiText(UiTextKey.OUTGOING_REQUEST_A732C) else uiText(UiTextKey.INCOMING_REQUEST_4EE22), style = MaterialTheme.typography.titleMedium)
                    Text(uiText(UiTextKey.STATUS_F7B4A, remoteRequestStatusLabel(request.status)), color = Muted)
                    Text(uiText(UiTextKey.HOST_04166, request.hostDeviceId), color = Muted, style = MaterialTheme.typography.bodySmall)
                    Text(uiText(UiTextKey.CONTROLLER_F8456, request.controllerDeviceId), color = Muted, style = MaterialTheme.typography.bodySmall)
                    val permissions = request.permissions.joinToString { permission ->
                        when (permission) {
                            1 -> uiText(UiTextKey.VIEW_ONLY_39395)
                            2 -> uiText(UiTextKey.INPUT_2087C)
                            3 -> uiText(UiTextKey.SYSTEM_AUDIO_1DBF5)
                            4 -> uiText(UiTextKey.READ_FILES_CHOSEN_BY_THE_HOST_47D34)
                            5 -> uiText(UiTextKey.SEND_FILES_TO_THE_HOST_PRIVATE_79A77)
                            6 -> uiText(UiTextKey.READ_THE_HOST_TEXT_CLIPBOARD_55683)
                            7 -> uiText(UiTextKey.WRITE_THE_HOST_TEXT_CLIPBOARD_DBE0B)
                            else -> uiText(UiTextKey.PERMISSION_FE1EC, permission)
                        }
                    }
                    Text(uiText(UiTextKey.REQUESTED_PERMISSIONS_8909C, permissions), color = Muted, style = MaterialTheme.typography.bodySmall)
                    val paths = request.paths.joinToString { path -> if (path == 1) uiText(UiTextKey.DIRECT_B0632) else if (path == 2) uiText(UiTextKey.RELAY_715CE) else uiText(UiTextKey.PATH_6023E, path) }
                    if (paths.isNotEmpty()) Text(uiText(UiTextKey.ALLOWED_PATHS_3A109, paths), color = Muted, style = MaterialTheme.typography.bodySmall)
                    Text(uiText(UiTextKey.LEASE_CONNECTION_83536, request.leaseSequence, request.connectionGeneration), color = Muted, style = MaterialTheme.typography.bodySmall)
                    Text(request.id, color = Muted, style = MaterialTheme.typography.bodySmall)
                    val ownHostRequest = !outgoing && request.hostDeviceId == state.ownDeviceId
                    if (ownHostRequest && request.status == "pending") {
                        var approveInput by remember(request.id, request.nonce) { mutableStateOf(false) }
                        var approveAudio by remember(request.id, request.nonce) { mutableStateOf(false) }
                        if (2 in request.permissions) PermissionChoice(approveInput, { approveInput = it }, !state.busy && state.accessibilityInputEnabled, uiText(UiTextKey.APPROVE_VIEW_AND_INPUT_939DB))
                        if (3 in request.permissions) PermissionChoice(approveAudio, { approveAudio = it }, !state.busy, uiText(UiTextKey.APPROVE_VIEW_AND_SYSTEM_AUDIO_7E251))
                        var approveFileRead by remember(request.id, request.nonce, request.policyRevision) { mutableStateOf(false) }
                        var approveFileWrite by remember(request.id, request.nonce, request.policyRevision) { mutableStateOf(false) }
                        var approveClipboardRead by remember(request.id, request.nonce, request.policyRevision) { mutableStateOf(false) }
                        var approveClipboardWrite by remember(request.id, request.nonce, request.policyRevision) { mutableStateOf(false) }
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { model.decideRemote(request, true) },
                                enabled = !state.busy && 1 in request.permissions && request.paths.isNotEmpty(),
                                modifier = Modifier.weight(1f),
                            ) { Text(uiText(UiTextKey.APPROVE_VIEW_ONLY_8194F)) }
                            OutlinedButton(
                                onClick = { model.decideRemote(request, false) },
                                enabled = !state.busy,
                                modifier = Modifier.weight(1f),
                            ) { Text(uiText(UiTextKey.REJECT_136DE)) }
                        }
                        if (request.permissions.any { it in 2..7 }) {
                            if (4 in request.permissions) PermissionChoice(approveFileRead, { approveFileRead = it }, !state.busy, uiText(UiTextKey.ALLOW_READING_FILES_EXPLICITLY_CHOSEN_LATER_2C227))
                            if (5 in request.permissions) PermissionChoice(approveFileWrite, { approveFileWrite = it }, !state.busy, uiText(UiTextKey.ALLOW_SENDING_TO_A_PRIVATE_AREA_5B4E3))
                            if (6 in request.permissions) PermissionChoice(approveClipboardRead, { approveClipboardRead = it }, !state.busy, uiText(UiTextKey.ALLOW_READING_THE_HOST_TEXT_CLIPBOARD_EE309))
                            if (7 in request.permissions) PermissionChoice(approveClipboardWrite, { approveClipboardWrite = it }, !state.busy, uiText(UiTextKey.ALLOW_WRITING_THE_HOST_TEXT_CLIPBOARD_082E7))
                            OutlinedButton(
                                onClick = { if (approveAudio) approveWithAudio(AudioApproval(request, approveInput, approveFileRead, approveFileWrite, approveClipboardRead, approveClipboardWrite)) else model.decideRemote(request, true, approveInput = approveInput, approveFileRead = approveFileRead, approveFileWrite = approveFileWrite, approveClipboardRead = approveClipboardRead, approveClipboardWrite = approveClipboardWrite) },
                                enabled = !state.busy && (approveInput || approveAudio || approveFileRead || approveFileWrite || approveClipboardRead || approveClipboardWrite) && 1 in request.permissions && request.paths.isNotEmpty(), modifier = Modifier.fillMaxWidth(),
                            ) { Text(uiText(UiTextKey.APPROVE_VIEW_AND_SELECTED_DATA_DIRECTIONS_98E45)) }
                            Text(uiText(UiTextKey.LOCAL_FILE_SHARING_PRIVATE_RECEIVING_AND_3CCA0), color = Muted, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    if (ownHostRequest && request.status == "approved" && request.leaseSequence > 0L) {
                        TrustRemoteButton(state, model, request)
                    }
                    if (outgoing && request.status == "pending") {
                        Spacer(Modifier.height(8.dp))
                        RemotePasswordUsePanel(state, model, request)
                    }
                    val activeSession = state.nativeSession
                    val thisSessionActive = activeSession?.requestId == request.id &&
                        activeSession.status in setOf("establishing", "connected", "stopping")
                    val browserSession = state.browserHost
                    val browserSessionActive = browserSession?.status in setOf("establishing", "connected", "stopping")
                    val thisBrowserSessionActive = browserSession?.requestId == request.id && browserSessionActive
                    if (request.status == "approved" && !thisSessionActive &&
                        (activeSession == null || activeSession.status !in setOf("establishing", "connected", "stopping")) &&
                        !browserSessionActive
                    ) {
                        Button(
                            onClick = { model.startNativeSession(request) },
                            enabled = !state.busy,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(uiText(UiTextKey.START_NATIVE_SESSION_1BAF9)) }
                    }
                    if (ownHostRequest && request.status == "approved" && !thisBrowserSessionActive &&
                        !thisSessionActive && !browserSessionActive &&
                        (activeSession == null || activeSession.status !in setOf("establishing", "connected", "stopping"))
                    ) {
                        OutlinedButton(
                            onClick = { model.startBrowserHost(request) },
                            enabled = !state.busy,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(uiText(UiTextKey.START_BROWSER_SHARING_SESSION_482DC)) }
                    }
                    if (thisSessionActive) {
                        Text(uiText(UiTextKey.LOCAL_NATIVE_SESSION_9E026, nativeSessionStatusLabel(activeSession?.status)), color = if (activeSession?.hostViewAuthorized == true) MaterialTheme.colorScheme.primary else Muted)
                        if (activeSession?.status == "connected") {
                            OutlinedButton(
                                onClick = { model.stopNativeSession(request.id) },
                                enabled = !state.busy,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(uiText(UiTextKey.STOP_NATIVE_SESSION_7D0DA)) }
                        }
                    }
                    if (thisBrowserSessionActive) {
                        Text(
                            uiText(UiTextKey.LOCAL_BROWSER_SESSION_C0B83, if (browserSession.status == "connected") uiText(UiTextKey.CONNECTED_5BE03) else uiText(UiTextKey.STARTING_08773), if (browserSession.hostViewAuthorized) uiText(UiTextKey.VIEW_AUTHORIZED_44843) else uiText(UiTextKey.AWAITING_CONSENT_27CAB)),
                            color = if (browserSession.hostViewAuthorized) MaterialTheme.colorScheme.primary else Muted,
                        )
                        if (browserSession.status in setOf("establishing", "connected")) {
                            OutlinedButton(
                                onClick = { model.stopBrowserHost(request.id) },
                                enabled = !state.busy,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(uiText(UiTextKey.STOP_BROWSER_SHARING_FC61E)) }
                        }
                    }
                    if (outgoing && request.status !in setOf("revoked", "rejected", "expired")) {
                        TextButton(onClick = { model.revokeRemote(request.id) }, enabled = !state.busy) {
                            Text(uiText(UiTextKey.REVOKE_REQUEST_17F67), color = Danger)
                        }
                    }
                }
            }
        }
        item(key = "trusted-devices") {
            TrustedDevicesPanel(state, model)
        }
    }
}

@Composable
private fun TrustRemoteButton(state: MobileState, model: NestLinkViewModel, request: RemoteRequestRow) {
    var confirmationOpen by remember(request.id, request.policyRevision) { mutableStateOf(false) }
    OutlinedButton(
        onClick = { confirmationOpen = true },
        enabled = !state.busy && System.currentTimeMillis() < request.expiresAtUnixMs,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(uiText(UiTextKey.TRUST_CONTROLLER_FOR_ONE_HOUR))
    }
    if (confirmationOpen) {
        AlertDialog(
            onDismissRequest = { confirmationOpen = false },
            title = { Text(uiText(UiTextKey.TRUST_CONTROLLER_CONFIRM_TITLE)) },
            text = { Text(uiText(UiTextKey.TRUST_CONTROLLER_CONFIRM_BODY)) },
            confirmButton = {
                Button(
                    onClick = {
                        confirmationOpen = false
                        model.trustRemote(request)
                    },
                    enabled = !state.busy && System.currentTimeMillis() < request.expiresAtUnixMs,
                ) { Text(uiText(UiTextKey.TRUST_CONTROLLER_FOR_ONE_HOUR_CONFIRM)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmationOpen = false }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) }
            },
        )
    }
}

@Composable
private fun TrustedDevicesPanel(state: MobileState, model: NestLinkViewModel) {
    var pendingRevoke by remember { mutableStateOf<TrustedDeviceRow?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Text(uiText(UiTextKey.TRUSTED_DEVICES_FOR_THIS_HOST), style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = model::refreshTrustedDevices, enabled = !state.busy) {
                Text(uiText(UiTextKey.REFRESH_TRUSTED_DEVICES))
            }
        }
        val trusted = state.trustedDevices?.takeIf { it.hostDeviceId == state.ownDeviceId }
        when {
            trusted == null -> Text(uiText(UiTextKey.REFRESH_TRUSTED_DEVICES), color = Muted, style = MaterialTheme.typography.bodySmall)
            trusted.devices.isEmpty() -> Text(uiText(UiTextKey.TRUSTED_DEVICES_EMPTY), color = Muted)
            else -> trusted.devices.forEach { device ->
                Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(device.controllerDeviceId, style = MaterialTheme.typography.titleSmall)
                        Text(
                            "revision ${device.revision} · ${remotePasswordExpiryLabel(device.expiresAtUnixMs)} · ${if (device.active) uiText(UiTextKey.ACTIVE_3A7A7) else uiText(UiTextKey.INACTIVE_8D02D)}",
                            color = Muted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Text(uiText(UiTextKey.ALLOWED_PERMISSIONS_VIEW_IS_REQUIRED) + ": " + remotePermissionsLabel(device.permissions), color = Muted, style = MaterialTheme.typography.bodySmall)
                        Text(uiText(UiTextKey.ALLOWED_CONNECTION_PATHS) + ": " + remotePathsLabel(device.paths), color = Muted, style = MaterialTheme.typography.bodySmall)
                        if (device.active) {
                            TextButton(onClick = { pendingRevoke = device }, enabled = !state.busy) {
                                Text(uiText(UiTextKey.REVOKE_TRUSTED_DEVICE), color = Danger)
                            }
                        }
                    }
                }
            }
        }
    }
    pendingRevoke?.let { device ->
        AlertDialog(
            onDismissRequest = { pendingRevoke = null },
            title = { Text(uiText(UiTextKey.REVOKE_TRUSTED_DEVICE_TITLE)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(uiText(UiTextKey.REVOKE_TRUSTED_DEVICE_BODY))
                    Text(device.controllerDeviceId, style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        pendingRevoke = null
                        model.revokeTrustedDevice(device)
                    },
                    enabled = !state.busy,
                    colors = ButtonDefaults.buttonColors(containerColor = DangerAction, contentColor = DangerActionText),
                ) { Text(uiText(UiTextKey.REVOKE_TRUSTED_DEVICE)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRevoke = null }) { Text(uiText(UiTextKey.CANCEL_2CD0F)) }
            },
        )
    }
}

@Composable
private fun UnsupportedScreen(title: String, detail: String) {
    Column(Modifier.fillMaxWidth().padding(top = 20.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(detail, color = Muted)
    }
}

@Composable
private fun HostCaptureScreen(
    state: MobileState,
    model: NestLinkViewModel,
    capture: HostCaptureUiState,
    browserCapture: BrowserHostCaptureUiState,
    onStartCapture: () -> Unit,
) {
    var hostName by remember { mutableStateOf(android.os.Build.MODEL.ifBlank { uiText(UiTextKey.ANDROID_HOST_81D33) }) }
    val context = LocalContext.current
    val ownDevice = state.devices.firstOrNull { it.id == state.ownDeviceId && !it.revoked }
    val hostRegistered = ownDevice?.capabilities?.contains("host") == true
    val captureServiceActive = capture.state in setOf(
        "starting", "awaiting_consent", "waiting_view_authorization", "capturing",
    )
    val busyCapture = capture.state == "starting" || capture.state == "awaiting_consent"
    Column(Modifier.fillMaxWidth().padding(top = 20.dp)) {
        Text(uiText(UiTextKey.SCREEN_CAPTURE_C71B1), style = MaterialTheme.typography.headlineSmall)
        Text(
            uiText(UiTextKey.MEDIAPROJECTION_REQUIRES_SYSTEM_CONFIRMATION_EACH_TIME_87DE0),
            color = Muted,
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            uiText(UiTextKey.TOUCH_SERVICE_NESTLINK_KEYBOARD_TEXT_AND_7C2D0, if (state.accessibilityInputEnabled) uiText(UiTextKey.ENABLED_DFB80) else uiText(UiTextKey.NOT_ENABLED_F95EA), if (state.inputMethodEnabled) uiText(UiTextKey.SELECTED_A737F) else uiText(UiTextKey.NOT_ENABLED_OR_SELECTED_3F9C0)),
            color = Muted,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
        OutlinedButton(
            onClick = { context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (state.accessibilityInputEnabled) uiText(UiTextKey.MANAGE_ACCESSIBILITY_SERVICE_7976B) else uiText(UiTextKey.ENABLE_NESTLINK_TOUCH_SERVICE_0B16A)) }
        OutlinedButton(
            onClick = { context.startActivity(Intent(Settings.ACTION_INPUT_METHOD_SETTINGS)) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(uiText(UiTextKey.MANAGE_NESTLINK_KEYBOARD_05034)) }
        OutlinedButton(
            onClick = {
                context.getSystemService(InputMethodManager::class.java)?.showInputMethodPicker()
            },
            enabled = state.inputMethodEnabled,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(uiText(UiTextKey.SELECT_NESTLINK_KEYBOARD_42B84)) }
        Spacer(Modifier.height(16.dp))
        if (!hostRegistered) {
            Field(uiText(UiTextKey.HOST_DISPLAY_NAME_5F41D), hostName, { hostName = it })
            Button(
                onClick = { model.enrollHost(hostName) },
                enabled = !state.busy && hostName.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(uiText(UiTextKey.ENROLL_THIS_DEVICE_AS_A_HOST_480EE)) }
        } else {
            Text(uiText(UiTextKey.HOST_DEVICE_24DB6, ownDevice?.name ?: android.os.Build.MODEL), color = Success)
        }
        Spacer(Modifier.height(12.dp))
        Text(
            when (capture.state) {
                "idle" -> uiText(UiTextKey.SCREEN_CAPTURE_HAS_NOT_STARTED_7E799)
                "awaiting_consent" -> uiText(UiTextKey.WAITING_FOR_ANDROID_SYSTEM_CONSENT_31BE1)
                "starting" -> uiText(UiTextKey.STARTING_THE_CAPTURE_SERVICE_CDCA7)
                "waiting_view_authorization" -> uiText(UiTextKey.SYSTEM_CONSENT_IS_READY_WAITING_FOR_2536A)
                "capturing" -> uiText(UiTextKey.CAPTURE_SERVICE_RUNNING_FRAMES_ENCODED_48FFA, capture.encodedFrames)
                "stopped" -> uiText(UiTextKey.CAPTURE_SERVICE_STOPPED_AD4BB)
                "failed" -> uiText(UiTextKey.CAPTURE_SERVICE_STARTUP_OR_ENCODING_FAILED_57596)
                else -> uiText(UiTextKey.CAPTURE_STATUS_C88CE, capture.state)
            },
            color = when (capture.state) {
                "failed" -> Danger
                "awaiting_consent" -> Warning
                "capturing" -> Success
                else -> Muted
            },
        )
        if (capture.detail.isNotBlank()) Text(capture.detail, color = Muted, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onStartCapture,
            enabled = hostRegistered && !state.busy && !captureServiceActive,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (busyCapture) uiText(UiTextKey.WAITING_FOR_SYSTEM_CONSENT_855CC) else uiText(UiTextKey.REQUEST_SCREEN_CAPTURE_CONSENT_C23EB)) }
        if (captureServiceActive) {
            OutlinedButton(
                onClick = model::stopHostCapture,
                enabled = true,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(uiText(UiTextKey.STOP_SCREEN_CAPTURE_EE03B)) }
        }
        Spacer(Modifier.height(18.dp))
        Text(uiText(UiTextKey.BROWSER_SHARING_F2DAC), style = MaterialTheme.typography.titleMedium)
        val browserHost = state.browserHost
        val browserHostActive = browserHost?.status in setOf("establishing", "connected", "stopping")
        Text(
            when {
                browserHostActive -> uiText(UiTextKey.BROWSER_SESSION_523D1, if (browserHost?.status == "connected") uiText(UiTextKey.CONNECTED_5BE03) else uiText(UiTextKey.STARTING_08773), if (browserHost?.hostViewAuthorized == true) uiText(UiTextKey.VIEW_AUTHORIZED_DB301) else uiText(UiTextKey.AWAITING_SESSION_CONSENT_4CF9A))
                browserCapture.state == "awaiting_consent" -> uiText(UiTextKey.WAITING_FOR_ANDROID_SCREEN_SHARING_CONFIRMATION_80226)
                browserCapture.state == "staging" -> uiText(UiTextKey.PREPARING_SCREEN_SHARING_CONSENT_6C805)
                browserCapture.state == "awaiting_proof" -> uiText(UiTextKey.SCREEN_SHARING_CONSENT_IS_RETAINED_FRAMES_20263)
                browserCapture.state == "active" -> uiText(UiTextKey.THE_BROWSER_CONNECTION_IS_VERIFIED_AND_0FF20)
                browserCapture.state == "denied" -> uiText(UiTextKey.ANDROID_SCREEN_SHARING_CONSENT_WAS_DENIED_F55AA)
                browserCapture.state == "failed" -> uiText(UiTextKey.SCREEN_SHARING_CONSENT_OR_CAPTURE_STARTUP_98BBC)
                browserCapture.state == "cancelled" -> uiText(UiTextKey.BROWSER_SHARING_CONSENT_OR_THE_SESSION_D0D34)
                else -> uiText(UiTextKey.NO_SCREEN_SHARING_REQUEST_IS_AWAITING_12EEA)
            },
            color = when (browserCapture.state) {
                "failed" -> Danger
                "awaiting_consent" -> Warning
                "capturing" -> Success
                else -> Muted
            },
        )
        if (browserCapture.detail.isNotBlank()) {
            Text(browserCapture.detail, color = Muted, style = MaterialTheme.typography.bodySmall)
        }
        if (browserHostActive && browserHost != null && browserHost.status != "stopping") {
            OutlinedButton(
                onClick = { model.stopBrowserHost(browserHost.requestId) },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(uiText(UiTextKey.STOP_BROWSER_SHARING_FC61E)) }
        }
    }
}

@Composable
private fun Field(label: String, value: String, onValueChange: (String) -> Unit, placeholder: String = "", secret: Boolean = false) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = { if (placeholder.isNotEmpty()) Text(placeholder) },
        modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp),
        singleLine = true,
        visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
    )
}

@Composable
private fun StateMessage(state: MobileState) {
    if (state.error.isNotEmpty()) Text(state.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(vertical = 8.dp))
    if (state.message.isNotEmpty()) Text(state.message, color = Success, modifier = Modifier.padding(vertical = 8.dp))
}

@Composable
private fun PermissionChoice(checked: Boolean, onCheckedChange: (Boolean) -> Unit, enabled: Boolean, label: String) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp)
        .toggleable(value = checked, enabled = enabled, role = androidx.compose.ui.semantics.Role.Checkbox, onValueChange = onCheckedChange),
        verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
        Text(label, modifier = Modifier.weight(1f).padding(start = 8.dp))
    }
}
