package com.zhanry.nestlink

import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.os.PowerManager
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.CharacterCodingException
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

internal const val NATIVE_CLIPBOARD_TEXT_BYTES = 64 * 1024

internal data class NativeClipboardBinding(
    val requestId: String,
    val connectionGeneration: Long,
    val coreGeneration: Long,
) {
    fun json(): String = JSONObject().put("request_id", requestId)
        .put("connection_generation", connectionGeneration).put("core_generation", coreGeneration).toString()
}

internal data class NativeClipboardRow(
    val binding: NativeClipboardBinding,
    val isHost: Boolean,
    val permittedRead: Boolean,
    val permittedWrite: Boolean,
    val localRead: Boolean = false,
    val localWrite: Boolean = false,
    val ready: Boolean = false,
    val restartRequired: Boolean = false,
) {
    val allowedLocalRead: Boolean get() = if (isHost) permittedRead else permittedWrite
    val allowedLocalWrite: Boolean get() = if (isHost) permittedWrite else permittedRead
    fun canAct(sendLocal: Boolean): Boolean = !isHost && ready && !restartRequired &&
        (if (sendLocal) permittedWrite && localRead else permittedRead && localWrite)
}

internal fun parseNativeClipboardStatus(json: String?): NativeClipboardRow? {
    if (json == null || json == "null") return null
    require(json.length <= 4_096)
    val root = JSONObject(json)
    val value = root.getJSONObject("binding")
    val binding = NativeClipboardBinding(value.getString("request_id"), value.getLong("connection_generation"), value.getLong("core_generation"))
    require(binding.requestId.isNotEmpty() && binding.requestId.length <= 128 && binding.connectionGeneration > 0 && binding.coreGeneration > 0)
    val endpoint = root.getString("endpoint")
    require(endpoint == "host" || endpoint == "controller")
    val row = NativeClipboardRow(binding, endpoint == "host", root.getBoolean("permitted_read"), root.getBoolean("permitted_write"),
        root.optBoolean("local_read", false), root.optBoolean("local_write", false), root.optBoolean("ready", false), root.optBoolean("session_restart_required", false))
    require((!row.localRead || row.allowedLocalRead) && (!row.localWrite || row.allowedLocalWrite))
    return row
}

/** No listener or clipboard value is retained in lifecycle or UI state. */
internal class NativeClipboardForeground {
    private val resumed = AtomicBoolean(false)
    private val focused = AtomicBoolean(false)
    fun resumed(value: Boolean) { resumed.set(value) }
    fun focused(value: Boolean) { focused.set(value) }
    fun available(): Boolean = resumed.get() && focused.get()
}

/** A local approval can only lose directions for the lifetime of one token. */
internal class NativeClipboardLocalConsent(read: Boolean = false, write: Boolean = false) {
    private val active = AtomicBoolean(true)
    private val readApproved = AtomicBoolean(read)
    private val writeApproved = AtomicBoolean(write)
    fun isActive(): Boolean = active.get()
    fun allows(read: Boolean): Boolean = active.get() && (if (read) readApproved.get() else writeApproved.get())
    fun reduce(read: Boolean, write: Boolean) {
        if (!read) readApproved.set(false)
        if (!write) writeApproved.set(false)
    }
    fun close() { active.set(false); reduce(false, false) }
}

internal object NativeClipboardOutcome {
    const val OK = 0
    const val FOREGROUND = 1
    const val REVOKED = 2
    const val NO_TEXT = 3
    const val UNSUPPORTED = 4
    const val INVALID_TEXT = 5
    const val DENIED = 6
    const val UNAVAILABLE = 7
    const val DEADLINE = 8
    const val WRITE_UNKNOWN = 9
}

/** A direct JNI reply, never placed in MobileState or converted to JSON. */
internal class NativeClipboardResult(@JvmField val status: Int, @JvmField val data: ByteArray? = null) {
    fun clear() { data?.fill(0) }
}

internal fun encodeNativeClipboardText(text: CharSequence): ByteArray {
    require(text.length <= NATIVE_CLIPBOARD_TEXT_BYTES)
    val plain = text.toString()
    require(plain.length <= NATIVE_CLIPBOARD_TEXT_BYTES)
    var utf8Bytes = 0
    var index = 0
    while (index < plain.length) {
        val value = plain[index]
        require(value != '\u0000')
        utf8Bytes += when {
            value.code < 0x80 -> 1
            value.code < 0x800 -> 2
            Character.isHighSurrogate(value) -> {
                require(index + 1 < plain.length && Character.isLowSurrogate(plain[index + 1]))
                index++
                4
            }
            Character.isLowSurrogate(value) -> throw IllegalArgumentException("invalid_clipboard_text")
            else -> 3
        }
        require(utf8Bytes <= NATIVE_CLIPBOARD_TEXT_BYTES)
        index++
    }
    return plain.toByteArray(StandardCharsets.UTF_8)
}

internal fun decodeNativeClipboardText(bytes: ByteArray): String {
    require(bytes.size <= NATIVE_CLIPBOARD_TEXT_BYTES && bytes.none { it == 0.toByte() })
    return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
}

/** ClipboardManager calls run synchronously on the retained Rust worker. */
internal class NativeClipboardEndpoint private constructor(
    context: Context,
    private val handle: Long,
    private val binding: NativeClipboardBinding?,
    private val browserBinding: HostCaptureBinding.BrowserHost?,
    private val foreground: NativeClipboardForeground,
    read: Boolean,
    write: Boolean,
) {
    constructor(context: Context, handle: Long, binding: NativeClipboardBinding, foreground: NativeClipboardForeground, read: Boolean, write: Boolean) :
        this(context, handle, binding, null, foreground, read, write)
    constructor(context: Context, handle: Long, binding: HostCaptureBinding.BrowserHost, foreground: NativeClipboardForeground, read: Boolean, write: Boolean) :
        this(context, handle, null, binding, foreground, read, write)
    init {
        require((binding == null) != (browserBinding == null))
        require(browserBinding == null || browserBinding.hasExactProof())
    }
    private val context = context.applicationContext
    private val consent = NativeClipboardLocalConsent(read, write)
    private val lastOutcome = AtomicInteger(NativeClipboardOutcome.OK)
    private val bindingJson = binding?.json() ?: requireNotNull(browserBinding).bindingJson

    fun matchesBinding(requestId: String, connectionGeneration: Long, coreGeneration: Long): Boolean =
        consent.isActive() && browserBinding == null && binding == NativeClipboardBinding(requestId, connectionGeneration, coreGeneration)

    fun matchesBrowserBinding(exactBindingJson: String): Boolean =
        consent.isActive() && binding == null && browserBinding?.let { sameBrowserProofJson(it.bindingJson, exactBindingJson) } == true

    fun checkActive(): Int = if (consent.isActive() && !NativeSafPickerOwners.isClosing(handle)) NativeClipboardOutcome.OK else NativeClipboardOutcome.REVOKED
    fun lastOutcome(): Int = lastOutcome.get()
    fun isActive(): Boolean = checkActive() == NativeClipboardOutcome.OK

    /** This method can only reduce the initial, explicit local selection. */
    fun revokeDirections(read: Boolean, write: Boolean) {
        consent.reduce(read, write)
    }

    private fun access(read: Boolean, deadline: Long): Int {
        if (checkActive() != NativeClipboardOutcome.OK || !consent.allows(read)) return NativeClipboardOutcome.REVOKED
        if (System.nanoTime() >= deadline) return NativeClipboardOutcome.DEADLINE
        if (!foreground.available()) return NativeClipboardOutcome.FOREGROUND
        val power = context.getSystemService(PowerManager::class.java) ?: return NativeClipboardOutcome.UNAVAILABLE
        val keyguard = context.getSystemService(KeyguardManager::class.java) ?: return NativeClipboardOutcome.UNAVAILABLE
        if (!power.isInteractive || keyguard.isDeviceLocked) return NativeClipboardOutcome.FOREGROUND
        val platformAllowed = runCatching {
            if (browserBinding != null) NativeSdk.nativeBrowserClipboardPlatformAllowed(handle, bindingJson, read)
            else NativeSdk.nativeClipboardPlatformAllowed(handle, bindingJson, read)
        }.getOrDefault(false)
        if (!platformAllowed) return NativeClipboardOutcome.REVOKED
        if (checkActive() != NativeClipboardOutcome.OK || !consent.allows(read)) return NativeClipboardOutcome.REVOKED
        if (System.nanoTime() >= deadline) return NativeClipboardOutcome.DEADLINE
        return if (foreground.available()) NativeClipboardOutcome.OK else NativeClipboardOutcome.FOREGROUND
    }

    private fun deadline(budgetMillis: Long): Long {
        require(budgetMillis in 1..2_000)
        return System.nanoTime() + budgetMillis * 1_000_000L
    }

    private fun outcome(code: Int, bytes: ByteArray? = null): NativeClipboardResult {
        lastOutcome.set(code)
        return NativeClipboardResult(code, bytes)
    }

    fun readText(budgetMillis: Long): NativeClipboardResult {
        var bytes: ByteArray? = null
        try {
            val until = deadline(budgetMillis)
            var allowed = access(true, until)
            if (allowed != NativeClipboardOutcome.OK) return outcome(allowed)
            val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return outcome(NativeClipboardOutcome.UNAVAILABLE)
            val clip = clipboard.primaryClip
            allowed = access(true, until)
            if (allowed != NativeClipboardOutcome.OK) return outcome(allowed)
            if (clip == null) return outcome(NativeClipboardOutcome.NO_TEXT)
            if (clip.itemCount != 1 || !clip.description.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) return outcome(NativeClipboardOutcome.UNSUPPORTED)
            val item = clip.getItemAt(0)
            if (item.uri != null || item.intent != null || item.text == null) return outcome(NativeClipboardOutcome.UNSUPPORTED)
            // Never coerce a URI or Intent into text and never resolve a provider.
            bytes = encodeNativeClipboardText(requireNotNull(item.text))
            allowed = access(true, until)
            if (allowed != NativeClipboardOutcome.OK) return outcome(allowed)
            val result = outcome(NativeClipboardOutcome.OK, bytes)
            bytes = null // The direct JNI caller now owns and clears this array.
            return result
        } catch (_: SecurityException) {
            return outcome(NativeClipboardOutcome.DENIED)
        } catch (_: IllegalArgumentException) {
            return outcome(NativeClipboardOutcome.INVALID_TEXT)
        } catch (_: Exception) {
            return outcome(NativeClipboardOutcome.UNAVAILABLE)
        } finally {
            bytes?.fill(0)
        }
    }

    fun writeText(bytes: ByteArray, budgetMillis: Long): Int {
        var attempted = false
        val code = try {
            val until = deadline(budgetMillis)
            var allowed = access(false, until)
            if (allowed != NativeClipboardOutcome.OK) return writeOutcome(allowed)
            val text = decodeNativeClipboardText(bytes)
            val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return writeOutcome(NativeClipboardOutcome.UNAVAILABLE)
            val clip = ClipData.newPlainText("NestLink", text)
            if (Build.VERSION.SDK_INT >= 33) clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
            allowed = access(false, until)
            if (allowed != NativeClipboardOutcome.OK) return writeOutcome(allowed)
            attempted = true
            clipboard.setPrimaryClip(clip)
            if (access(false, until) == NativeClipboardOutcome.OK) NativeClipboardOutcome.OK else NativeClipboardOutcome.WRITE_UNKNOWN
        } catch (_: SecurityException) {
            if (attempted) NativeClipboardOutcome.WRITE_UNKNOWN else NativeClipboardOutcome.DENIED
        } catch (_: CharacterCodingException) {
            if (attempted) NativeClipboardOutcome.WRITE_UNKNOWN else NativeClipboardOutcome.INVALID_TEXT
        } catch (_: IllegalArgumentException) {
            if (attempted) NativeClipboardOutcome.WRITE_UNKNOWN else NativeClipboardOutcome.INVALID_TEXT
        } catch (_: Exception) {
            if (attempted) NativeClipboardOutcome.WRITE_UNKNOWN else NativeClipboardOutcome.UNAVAILABLE
        } finally {
            bytes.fill(0)
        }
        return writeOutcome(code)
    }

    private fun writeOutcome(code: Int): Int { lastOutcome.set(code); return code }

    fun close() {
        consent.close()
    }
}

internal fun nativeClipboardOutcomeMessage(code: Int): String = when (code) {
    NativeClipboardOutcome.FOREGROUND -> uiText(UiTextKey.CLIPBOARD_ACTIONS_REQUIRE_NESTLINK_IN_THE_39355)
    NativeClipboardOutcome.REVOKED -> uiText(UiTextKey.THE_CURRENT_CLIPBOARD_SESSION_OR_LOCAL_4C86E)
    NativeClipboardOutcome.NO_TEXT -> uiText(UiTextKey.ANDROID_DID_NOT_PROVIDE_READABLE_CLIPBOARD_294C1)
    NativeClipboardOutcome.UNSUPPORTED -> uiText(UiTextKey.ONLY_A_SINGLE_PLAIN_TEXT_CLIPBOARD_C04F4)
    NativeClipboardOutcome.INVALID_TEXT -> uiText(UiTextKey.CLIPBOARD_TEXT_MUST_BE_VALID_UTF_DCC1F)
    NativeClipboardOutcome.DENIED -> uiText(UiTextKey.ANDROID_DENIED_CLIPBOARD_ACCESS_READING_OR_69FC0)
    NativeClipboardOutcome.DEADLINE -> uiText(UiTextKey.THE_CLIPBOARD_ACTION_TIMED_OUT_THE_50FF6)
    NativeClipboardOutcome.WRITE_UNKNOWN -> uiText(UiTextKey.THE_CLIPBOARD_WRITE_OUTCOME_IS_UNKNOWN_ACAD3)
    else -> uiText(UiTextKey.THE_PLATFORM_CLIPBOARD_ACTION_FAILED_CHECK_C9843)
}

@Composable
internal fun NativeClipboardPanel(state: MobileState, model: NestLinkViewModel) {
    Column(Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
        Text(uiText(UiTextKey.TEXT_CLIPBOARD_793C9), style = MaterialTheme.typography.headlineSmall)
        Text(uiText(UiTextKey.BOTH_DEVICES_APPROVE_LOCAL_READING_AND_BC87F))
        val row = state.clipboard
        if (row == null) {
            Text(uiText(UiTextKey.REQUEST_AND_APPROVE_THE_REQUIRED_CLIPBOARD_9C948))
        } else {
            var read by remember(row.binding) { mutableStateOf(false) }
            var write by remember(row.binding) { mutableStateOf(false) }
            Text(if (row.isHost) uiText(UiTextKey.THIS_DEVICE_IS_THE_HOST_AND_4FE49) else uiText(UiTextKey.THIS_DEVICE_IS_THE_CONTROLLER_EXPLICITLY_94393))
            Row {
                Checkbox(if (row.ready) row.localRead else read, { chosen ->
                    if (row.ready) model.setNativeClipboardDirections(row.binding, false, row.localWrite) else read = chosen
                }, enabled = !state.clipboardBusy && row.allowedLocalRead && (!row.ready || row.localRead))
                Text(uiText(UiTextKey.ALLOW_READING_THE_LOCAL_CLIPBOARD_CA000), Modifier.padding(top = 12.dp))
            }
            Row {
                Checkbox(if (row.ready) row.localWrite else write, { chosen ->
                    if (row.ready) model.setNativeClipboardDirections(row.binding, row.localRead, false) else write = chosen
                }, enabled = !state.clipboardBusy && row.allowedLocalWrite && (!row.ready || row.localWrite))
                Text(uiText(UiTextKey.ALLOW_WRITING_THE_LOCAL_CLIPBOARD_733D1), Modifier.padding(top = 12.dp))
            }
            if (!row.ready) Button(onClick = { model.setNativeClipboardDirections(row.binding, read, write) }, enabled = !state.clipboardBusy && (read || write)) { Text(uiText(UiTextKey.CONFIRM_LOCAL_DIRECTIONS_FOR_THIS_SESSION_BC874)) }
            if (row.localRead || row.localWrite) OutlinedButton(onClick = { model.revokeNativeClipboard(row.binding) }) { Text(uiText(UiTextKey.REVOKE_LOCAL_CLIPBOARD_CONSENT_38509)) }
            Text(uiText(UiTextKey.A_NEW_SESSION_IS_REQUIRED_TO_514BE))
            if (!row.isHost) {
                Button(onClick = { model.runNativeClipboardAction(row.binding, false) }, enabled = !state.clipboardBusy && state.clipboardEndpointActive && row.canAct(false), modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.COPY_REMOTE_TEXT_TO_THIS_DEVICE_375FD)) }
                OutlinedButton(onClick = { model.runNativeClipboardAction(row.binding, true) }, enabled = !state.clipboardBusy && state.clipboardEndpointActive && row.canAct(true), modifier = Modifier.fillMaxWidth()) { Text(uiText(UiTextKey.SEND_LOCAL_TEXT_TO_THE_REMOTE_82E49)) }
            }
        }
        if (state.clipboardNotice.isNotBlank()) Text(state.clipboardNotice)
        OutlinedButton(onClick = model::refreshNativeClipboard, enabled = !state.clipboardBusy) { Text(uiText(UiTextKey.REFRESH_CONSENT_STATUS_F9870)) }
    }
}
