package com.zhanry.nestlink

import android.content.Context
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Base64
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.ViewModelProvider
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NestLinkSmokeTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val hostSessionBindingJson =
        """{"request_id":"00000000-0000-4000-8000-000000000001","connection_generation":1}"""

    @Test
    fun startsOnServerIdentityVerificationScreen() {
        compose.onNodeWithText(uiText(UiTextKey.VERIFY_THE_SERVER_IDENTITY_THEN_SIGN_78C59)).assertIsDisplayed()
        compose.onNodeWithText(uiText(UiTextKey.VERIFY_SERVER_1717B)).assertIsDisplayed()
    }

    @Test
    fun languageSwitchKeepsActivityDraftSessionAndPendingConsentThenReloadsPreference() {
        val originalChoice = UiLanguage.choice
        val activity = compose.activity
        val context = activity.applicationContext
        val model = ViewModelProvider(activity)[NestLinkViewModel::class.java]
        val binding = browserHostBindingJson()
        val originalBrowserCapture = BrowserHostCaptureStatus.state.value
        try {
            compose.runOnIdle {
                assertTrue(AppLanguage.select(context, DisplayLanguage.Chinese))
                // Retain a one-use binding in the actual coordinator. This test
                // does not create a MediaProjection grant or start capture.
                assertTrue(BrowserHostCaptureCoordinator.requestConsent(binding))
                assertTrue(BrowserHostCaptureCoordinator.markGranted(binding))
            }
            compose.onNodeWithText(uiText(UiTextKey.SERVER_HTTPS_ADDRESS_7764B))
                .performTextInput("https://draft.example.invalid")
            Espresso.closeSoftKeyboard()
            val state = model.state.value
            val capture = HostCaptureStatus.state.value
            val browserCapture = BrowserHostCaptureStatus.state.value

            compose.onNodeWithText("English").performScrollTo().performClick()
            compose.onNodeWithText("Verify the server identity, then sign in.").assertIsDisplayed()
            compose.onNodeWithText("https://draft.example.invalid").assertIsDisplayed()
            compose.runOnIdle {
                assertSame(activity, compose.activity)
                assertSame(model, ViewModelProvider(compose.activity)[NestLinkViewModel::class.java])
                assertEquals(state, model.state.value)
                assertEquals(capture, HostCaptureStatus.state.value)
                assertEquals(browserCapture, BrowserHostCaptureStatus.state.value)
                assertEquals("granted", BrowserHostCaptureCoordinator.consentState(binding))
                assertEquals(
                    "Local direct connections",
                    AppLanguage.context(activity).getString(R.string.native_network_title),
                )
                // The next Application initialization reads the persisted choice.
                UiLanguage.update(DisplayLanguage.Chinese, "zh")
                AppLanguage.initialize(context)
                assertEquals(DisplayLanguage.English, UiLanguage.choice)
            }
            compose.onNodeWithText("Verify server").assertIsDisplayed()
        } finally {
            compose.runOnIdle {
                BrowserHostCaptureCoordinator.resetForTests()
                BrowserHostCaptureStatus.update(originalBrowserCapture.state, originalBrowserCapture.detail, null)
                assertTrue(AppLanguage.select(context, originalChoice))
            }
        }
    }

    @Test
    fun installationSeedSurvivesReopenOnlyAsKeystoreProtectedCiphertext() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefsName = "nestlink_identity_instrumentation_test"
        val alias = "nestlink.installation.identity.instrumentation-test"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        context.deleteSharedPreferences(prefsName)
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }

        var expectedSeed: ByteArray? = null
        try {
            val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
            val store = AndroidIdentityStore(context, prefsName, alias)
            val first = store.loadOrCreate()
            val expected = first.seed.copyOf()
            expectedSeed = expected
            first.seed.fill(0)
            val reopened = store.loadOrCreate()
            try {
                assertEquals(first.deviceId, reopened.deviceId)
                assertArrayEquals(expected, reopened.seed)
                assertEquals(setOf("seed_ciphertext", "device_id"), prefs.all.keys)

                val ciphertext = prefs.getString("seed_ciphertext", null)
                    ?: throw AssertionError("Encrypted installation seed was not saved")
                val encryptedBytes = Base64.decode(ciphertext, Base64.NO_WRAP)
                assertEquals(60, encryptedBytes.size)
                assertFalse(prefs.all.values.any { it is ByteArray })
                assertTrue(prefs.getString("device_id", null).orEmpty().isNotBlank())
                encryptedBytes.fill(0)
            } finally {
                reopened.seed.fill(0)
            }
        } finally {
            expectedSeed?.fill(0)
            context.deleteSharedPreferences(prefsName)
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }

    @Test
    fun remoteRequestListReachesNativeBridgeAndRejectsInvalidHandle() {
        val error = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeRemoteRequests(0L)
        }

        assertEquals("Android SDK handle is invalid", error.message)
    }

    @Test
    fun hostCaptureAuthorizationBridgeRejectsInvalidHandles() {
        val eligibleError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeCanStartHostCapture(0L)
        }
        assertEquals("Android SDK handle is invalid", eligibleError.message)

        val sessionError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeHostSessionBinding(0L)
        }
        assertEquals("Android SDK handle is invalid", sessionError.message)

        val configureError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeConfigureHostVideoStream(0L, hostSessionBindingJson, 0, 32, 24, 1L)
        }
        assertEquals("Android SDK handle is invalid", configureError.message)

        val ptsError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeHostCapturePts(0L, hostSessionBindingJson, 0L)
        }
        assertEquals("Android SDK handle is invalid", ptsError.message)

        val displayError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeHostDisplayReady(0L, hostSessionBindingJson)
        }
        assertEquals("Android SDK handle is invalid", displayError.message)
    }

    @Test
    fun hostVideoKeyframeFeedbackBridgeRejectsInvalidHandle() {
        val error = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeHostVideoKeyframeNeeded(
                handle = 0L,
                sessionBindingJson = hostSessionBindingJson,
                source = 0,
                layoutEpoch = 1L,
                width = 32,
                height = 24,
            )
        }

        assertEquals("Android SDK handle is invalid", error.message)
    }

    @Test
    fun platformNetworkFactsBridgeRejectsInvalidHandle() {
        val error = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeNetworkChanged(
                handle = 0L,
                factsJson = "{}",
                observerActive = true,
                elapsedRealtimeMs = 1_000L,
                uptimeMs = 900L,
            )
        }

        assertEquals("Android SDK handle is invalid", error.message)
    }

    @Test
    fun remoteVideoBitmapWaitsForRemovalCommitAndIgnoresLateDetachedCommit() {
        // Wait for MainActivity's first composition to be registered with this
        // rule before replacing its content, including on slower API 31 boots.
        compose.onNodeWithText(uiText(UiTextKey.VERIFY_THE_SERVER_IDENTITY_THEN_SIGN_78C59)).assertIsDisplayed()
        val bitmap = Bitmap.createBitmap(16, 16, Bitmap.Config.ARGB_8888)
        val owner = RemoteVideoBitmapOwner()
        val lease = owner.reserve()!!.commit(bitmap)
        val presentation = RemoteVideoPresentation(
            connectionGeneration = 1L,
            layoutEpoch = 1L,
            source = 0,
            sequence = 1L,
            width = 16,
            height = 16,
            bitmapLease = lease,
        )
        val currentPresentation = mutableStateOf<RemoteVideoPresentation?>(presentation)
        val contentRoot = compose.activity.findViewById<android.view.View>(android.R.id.content)
        val barrier = HeldFrameCommitBarrier(AndroidViewFrameCommitBarrier(contentRoot))
        val markBarrierAvailable: (RemoteVideoFrameCommitBarrier) -> Unit = {
            lease.retryRetirement(it)
        }
        val markBarrierUnavailable: (RemoteVideoFrameCommitBarrier) -> Unit = {
            lease.cancelPendingRetirement(it)
        }

        // MainActivity already owns its ComposeView. Replace that view's content
        // on the UI thread; the test rule must not create a second root.
        compose.runOnIdle {
            compose.activity.setContent {
                RemoteVideoCanvas(
                    presentation = currentPresentation.value,
                    sessionConnected = false,
                    onFrameCommitBarrierAvailable = markBarrierAvailable,
                    onFrameCommitBarrierUnavailable = markBarrierUnavailable,
                    frameCommitBarrierOverride = barrier,
                )
            }
        }

        compose.onNodeWithContentDescription(uiText(UiTextKey.NESTLINK_AUTHORIZED_REMOTE_SCREEN_ED93E)).assertIsDisplayed()
        assertFalse(bitmap.isRecycled)

        compose.runOnIdle {
            lease.releaseOwner()
            currentPresentation.value = null
        }
        // The Compose test clock advances pending recomposition only while its
        // synchronization APIs run. A latch alone cannot remove the Image or
        // invoke its DisposableEffect retirement callback.
        compose.waitForIdle()
        compose.onNodeWithContentDescription(uiText(UiTextKey.NESTLINK_AUTHORIZED_REMOTE_SCREEN_ED93E)).assertDoesNotExist()

        // The delegated ViewTreeObserver callback proves that the removal reached a real
        // hardware-rendered frame. Hold lease retirement so this test can examine both the
        // detached callback and the fresh callback registered after reattachment.
        barrier.awaitFirstCommit()
        assertFalse(bitmap.isRecycled)

        markBarrierUnavailable(barrier)
        markBarrierAvailable(barrier)
        barrier.awaitSecondCommit()
        assertFalse(bitmap.isRecycled)

        barrier.deliverNext()
        assertFalse(bitmap.isRecycled)
        barrier.deliverNext()
        compose.waitForIdle()
        assertTrue(bitmap.isRecycled)
        assertEquals(0, owner.outstandingCount)
    }

    @Test
    fun hostVideoBridgeRejectsInvalidHandleWithExplicitLayoutBinding() {
        val error = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeSendHostVideo(
                handle = 0L,
                sessionBindingJson = hostSessionBindingJson,
                source = 0,
                layoutEpoch = 1L,
                width = 32,
                height = 24,
                pts90Khz = 0L,
                keyframe = true,
                payload = byteArrayOf(1),
            )
        }

        assertEquals("Android SDK handle is invalid", error.message)
    }

    @Test
    fun remoteVideoBridgeRejectsInvalidHandles() {
        val layoutError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeRemoteVideoLayout(0L)
        }
        assertEquals("Android SDK handle is invalid", layoutError.message)

        val frameError = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativePollRemoteVideo(0L)
        }
        assertEquals("Android SDK handle is invalid", frameError.message)
    }

    @Test
    fun vp8JniBoundaryEncodesRealFramesAndReleasesItsContext() {
        val handle = NativeSdk.nativeVp8EncoderCreate(32, 24, 15, 1200)
        assertTrue(handle > 0L)
        try {
            val first = NativeSdk.nativeVp8Encode(handle, testFrame(0), 0L, true)
            assertEquals(0L, first.pts90Khz)
            assertTrue(first.keyframe)
            assertTrue(first.data.isNotEmpty())
            first.data.fill(0)

            val second = NativeSdk.nativeVp8Encode(handle, testFrame(1), 6_000L, false)
            assertEquals(6_000L, second.pts90Khz)
            assertTrue(second.data.isNotEmpty())
            second.data.fill(0)
        } finally {
            NativeSdk.nativeVp8EncoderDestroy(handle)
        }
        val error = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeVp8EncoderDestroy(handle)
        }
        assertEquals("Android VP8 encoder handle is invalid", error.message)
    }

    @Test
    fun imageReaderRowsAreRepackedFromRgbaWithStridePadding() {
        val source = byteArrayOf(
            1, 2, 3, 4, 5, 6, 7, 8, 99, 99, 99, 99,
            9, 10, 11, 12, 13, 14, 15, 16,
        )
        assertArrayEquals(
            byteArrayOf(3, 2, 1, 4, 7, 6, 5, 8, 11, 10, 9, 12, 15, 14, 13, 16),
            CaptureFramePacker.rgbaToBgra(source, 2, 2, rowStride = 12, pixelStride = 4),
        )
        assertEquals(1080 to 1920, CaptureFramePacker.scaledSize(1440, 2560))
        assertEquals(1280 to 720, CaptureFramePacker.scaledSize(1280, 720))
    }

    @Test
    fun imageReaderRejectsTruncatedOrInvalidPlaneLayouts() {
        assertThrows(IllegalArgumentException::class.java) {
            CaptureFramePacker.rgbaToBgra(byteArrayOf(1, 2, 3), 1, 1, rowStride = 4, pixelStride = 4)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CaptureFramePacker.rgbaToBgra(ByteArray(4), 1, 1, rowStride = 4, pixelStride = 3)
        }
    }


    @Test
    fun browserHostLifecycleAndDataJniRejectUnownedBindings() {
        assertFalse(AndroidBrowserMulticastOwner.stage(
            InstrumentationRegistry.getInstrumentation().targetContext,
            hostSessionBindingJson,
        ))
        val requestId = "00000000-0000-4000-8000-000000000001"
        for (operation in listOf<() -> Unit>(
            { NativeSdk.nativeStartBrowserHost(0L, requestId) },
            { NativeSdk.nativeStopBrowserHost(0L, requestId) },
            { NativeSdk.nativeBrowserHostStatus(0L) },
            { NativeSdk.nativeBrowserHostDataStatus(0L, browserHostBindingJson()) },
            { NativeSdk.nativeBrowserHostFilesStatus(0L, browserHostBindingJson()) },
        )) {
            val error = assertThrows(IllegalStateException::class.java) { operation() }
            assertEquals("Android SDK handle is invalid", error.message)
        }
        val wrongKind = assertThrows(IllegalStateException::class.java) {
            NativeSdk.nativeBrowserHostDataStatus(0L, hostSessionBindingJson)
        }
        assertEquals("stale_browser_binding", wrongKind.message)
        for (binding in listOf(hostSessionBindingJson, browserHostBindingJson())) {
            for (direction in listOf(false, true)) {
                assertFalse(NativeSdk.nativeBrowserHostFilePlatformAllowed(0L, binding, direction))
                assertFalse(NativeSdk.nativeBrowserClipboardPlatformAllowed(0L, binding, direction))
            }
        }
    }

    @Test
    fun browserHostSelectedSourceDescriptorClosesOnRejection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Exercise parsing failure as well as a complete, but unowned, binding.
        for (binding in listOf(hostSessionBindingJson, browserHostBindingJson())) {
            val selected = java.io.File.createTempFile("nestlink-browser-source-", ".bin", context.cacheDir)
            val expected = byteArrayOf(4, 8, 15, 16, 23, 42)
            var detached = -1
            try {
                selected.writeBytes(expected)
                ParcelFileDescriptor.open(selected, ParcelFileDescriptor.MODE_READ_ONLY).use { descriptor ->
                    detached = descriptor.detachFd()
                    assertTrue(Os.readlink("/proc/self/fd/$detached").endsWith(selected.name))
                    val error = assertThrows(IllegalStateException::class.java) {
                        NativeSdk.nativeBrowserHostFileShare(
                            0L, binding, "00000000-0000-4000-8000-000000000005",
                            "selected.bin", detached,
                        )
                    }
                    assertEquals(
                        if (binding == hostSessionBindingJson) "stale_browser_binding" else "Android SDK handle is invalid",
                        error.message,
                    )
                    assertFixtureDescriptorsReleased(selected)
                    detached = -1
                }
                assertArrayEquals(expected, selected.readBytes())
            } finally {
                closeRetainedTestDescriptor(detached, selected)
                expected.fill(0)
                check(selected.delete()) { "Could not reclaim the owned selected-source fixture" }
            }
        }
    }

    @Test
    fun browserHostExportRejectionClearsDestinationAndClosesDescriptor() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        for (binding in listOf(hostSessionBindingJson, browserHostBindingJson())) {
            val destination = java.io.File.createTempFile("nestlink-browser-export-", ".bin", context.cacheDir)
            var detached = -1
            try {
                destination.writeBytes(byteArrayOf(1, 3, 3, 7))
                ParcelFileDescriptor.open(destination, ParcelFileDescriptor.MODE_READ_WRITE).use { descriptor ->
                    detached = descriptor.detachFd()
                    val error = assertThrows(IllegalStateException::class.java) {
                        NativeSdk.nativeBrowserHostFileExport(
                            0L, binding, "00000000-0000-4000-8000-000000000005",
                            "00000000-0000-4000-8000-000000000006", detached,
                        )
                    }
                    assertEquals(
                        (if (binding == hostSessionBindingJson) "stale_browser_binding" else "Android SDK handle is invalid") +
                            "; SAF destination was cleared",
                        error.message,
                    )
                    assertFixtureDescriptorsReleased(destination)
                    detached = -1
                }
                assertEquals(0L, destination.length())
            } finally {
                closeRetainedTestDescriptor(detached, destination)
                check(destination.delete()) { "Could not reclaim the owned export fixture" }
            }
        }
    }

    @Test
    fun failedConnectInitializesBrowserProviderAndReleasesCore() {
        // A local HTTP origin is rejected before any network request. Native
        // connect resolves the app's coordinator class and constructs its real
        // runtime first. Repeating this catches leaked handles and failed cleanup.
        repeat(2) {
            val seed = ByteArray(32) { 0x5a.toByte() }
            try {
                val error = assertThrows(IllegalStateException::class.java) {
                    NativeSdk.nativeConnect(
                        "http://127.0.0.1:9",
                        "00000000-0000-4000-8000-000000000010",
                        Base64.encodeToString(ByteArray(32) { 1 }, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
                        "00000000-0000-4000-8000-000000000011",
                        seed,
                    )
                }
                assertTrue("Unexpected connect failure: ${error.message}", error.message.orEmpty().contains("\"kind\":\"invalid\""))
            } finally {
                seed.fill(0)
            }
        }
        val statusError = assertThrows(IllegalStateException::class.java) { NativeSdk.nativeBrowserHostStatus(0L) }
        assertEquals("Android SDK handle is invalid", statusError.message)
    }

    private fun browserHostBindingJson(): String = org.json.JSONObject()
        .put("request_id", "00000000-0000-4000-8000-000000000001")
        .put("session_id", "00000000-0000-4000-8000-000000000002")
        .put("controller_device_id", "00000000-0000-4000-8000-000000000003")
        .put("host_device_id", "00000000-0000-4000-8000-000000000004")
        .put("controller_key_sha256", org.json.JSONArray(List(32) { 1 }))
        .put("host_key_sha256", org.json.JSONArray(List(32) { 2 }))
        .put("permit_sha256", org.json.JSONArray(List(32) { 3 }))
        .put("connection_generation", 1L)
        .toString()

    private fun assertFixtureDescriptorsReleased(ownedFile: java.io.File) {
        // Native ownership ends before JNI returns, but another app thread may
        // immediately reuse that integer. Check the fixture's resource identity,
        // including a leaked cleanup duplicate, instead of demanding a vacant slot.
        val path = ownedFile.canonicalPath
        val descriptors = checkNotNull(java.io.File("/proc/self/fd").list())
        val retained = descriptors.filter { descriptor ->
            val target = try {
                Os.readlink("/proc/self/fd/$descriptor")
            } catch (error: ErrnoException) {
                if (error.errno != OsConstants.ENOENT) throw error
                null
            }
            target == path || target == "$path (deleted)"
        }
        assertTrue("JNI retained ${retained.size} descriptors for its fixture", retained.isEmpty())
    }

    private fun closeRetainedTestDescriptor(descriptor: Int, ownedFile: java.io.File) {
        if (descriptor < 0) return
        // Reclaim only an exact descriptor still referring to this test file if
        // the JNI call failed before it could adopt ownership (e.g. a link error).
        val target = runCatching { Os.readlink("/proc/self/fd/$descriptor") }.getOrNull()
        if (target == ownedFile.canonicalPath) ParcelFileDescriptor.adoptFd(descriptor).close()
    }

    private fun testFrame(phase: Int): ByteArray = ByteArray(32 * 24 * 4).also { frame ->
        for (pixel in 0 until 32 * 24) {
            val offset = pixel * 4
            frame[offset] = (pixel + phase * 3).toByte()
            frame[offset + 1] = (pixel / 2 + phase * 5).toByte()
            frame[offset + 2] = (pixel / 3 + phase * 7).toByte()
            frame[offset + 3] = 0xff.toByte()
        }
    }

    private class HeldFrameCommitBarrier(
        private val delegate: RemoteVideoFrameCommitBarrier,
    ) : RemoteVideoFrameCommitBarrier {
        private val callbacks = mutableListOf<() -> Unit>()
        private val commitCount = AtomicInteger()
        private val firstCommit = CountDownLatch(1)
        private val secondCommit = CountDownLatch(1)

        override fun afterNextFrameCommit(callback: () -> Unit, onUnavailable: () -> Unit): Boolean =
            delegate.afterNextFrameCommit(
                callback = {
                    synchronized(callbacks) { callbacks += callback }
                    when (commitCount.incrementAndGet()) {
                        1 -> firstCommit.countDown()
                        2 -> secondCommit.countDown()
                    }
                },
                onUnavailable = onUnavailable,
            )

        fun awaitFirstCommit() = assertTrue(
            "No hardware frame commit arrived after removing the image",
            firstCommit.await(10, TimeUnit.SECONDS),
        )

        fun awaitSecondCommit() = assertTrue(
            "No fresh hardware frame commit arrived after the retirement retry",
            secondCommit.await(10, TimeUnit.SECONDS),
        )

        fun deliverNext() {
            val callback = synchronized(callbacks) { callbacks.removeAt(0) }
            InstrumentationRegistry.getInstrumentation().runOnMainSync(callback)
        }
    }
}
