package com.zhanry.nestlink

import androidx.annotation.Keep
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Transfers a proof-bound MediaProjection consent result from the resumed
 * Activity to the Rust capture provider. The one-use grant remains staged in
 * HostCaptureService until the Rust media factory invokes activation after
 * mutual endpoint proof.
 */
@Keep
internal object BrowserHostCaptureCoordinator {
    private val requests = BrowserHostConsentRequests()

    /** Activity consumes challenges while resumed; a bounded queue buffers while it is backgrounded. */
    val consentRequests = requests.asFlow()

    /** Rust advertises input only while the platform AccessibilityService is live. */
    @JvmStatic
    fun supportsInput(): Boolean = AndroidInputBridge.accessibility?.get() != null

    @JvmStatic
    fun requestConsent(bindingJson: String): Boolean {
        runCatching { HostCaptureBinding.browserHost(bindingJson) }.getOrElse { return false }
        return requests.request(
            bindingJson,
            onPending = {
                BrowserHostCaptureStatus.update(
                    "awaiting_consent", uiText(UiTextKey.WAITING_FOR_ANDROID_SCREEN_SHARING_CONSENT_6CCCE), bindingJson,
                )
            },
            onCapacityFailure = {
                BrowserHostCaptureStatus.update(
                    "failed", uiText(UiTextKey.COULD_NOT_REQUEST_ANDROID_SCREEN_SHARING_6882B), bindingJson,
                )
            },
        )
    }

    @JvmStatic
    fun consentState(bindingJson: String): String = requests.state(bindingJson)

    /** Called only after the Android system consent ActivityResult was accepted and staged. */
    @JvmStatic
    fun markGranted(bindingJson: String): Boolean {
        if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
        return requests.markGranted(bindingJson)
    }

    /** A denial cancels only this exact proof binding. */
    @JvmStatic
    fun markDenied(bindingJson: String): Boolean {
        if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
        return requests.markDenied(bindingJson) {
            BrowserHostCaptureStatus.update("denied", uiText(UiTextKey.ANDROID_SCREEN_SHARING_CONSENT_WAS_DENIED_F55AA), bindingJson)
        }
    }

    @JvmStatic
    fun takeEndpoint(bindingJson: String): AndroidBrowserRawCaptureEndpoint? {
        return requests.takeGranted(bindingJson) {
            HostCaptureService.reserveBrowserHostEndpoint(bindingJson)
        }
    }

    @JvmStatic
    fun cancelConsent(bindingJson: String): Boolean {
        if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
        requests.cancel(bindingJson) {
            BrowserHostCaptureStatus.update("cancelled", uiText(UiTextKey.BROWSER_SHARING_CONSENT_OR_THE_SESSION_D0D34), bindingJson)
        }
        return HostCaptureService.cancelStagedBrowserHost(bindingJson)
    }

    internal fun resetForTests() {
        requests.clear()
    }
}

internal data class BrowserHostCaptureUiState(
    val state: String = "idle",
    val detail: String = "",
    val requestId: String? = null,
    val connectionGeneration: Long = 0L,
)

/** Public UI status deliberately omits the permit and proof digests in the binding. */
internal object BrowserHostCaptureStatus {
    private val mutable = MutableStateFlow(BrowserHostCaptureUiState())
    val state = mutable.asStateFlow()

    fun update(state: String, detail: String, bindingJson: String?) {
        val parsed = bindingJson?.let { runCatching { HostCaptureBinding.browserHost(it) }.getOrNull() }
        mutable.value = BrowserHostCaptureUiState(
            state = state,
            detail = detail,
            requestId = parsed?.requestId,
            connectionGeneration = parsed?.connectionGeneration ?: 0L,
        )
    }
}
