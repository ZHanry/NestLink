package com.zhanry.nestlink

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.content.pm.PackageManager
import android.view.Display
import android.view.WindowManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import kotlin.math.max

internal data class HostCaptureUiState(
    val state: String = "idle",
    val detail: String = "",
    val encodedFrames: Long = 0,
    val captureHandle: Long = 0,
    val cleanupComplete: Boolean = true,
    val audioCleanupPending: Boolean = false,
    val audioCleanupFailureObserved: Boolean = false,
    val nonAudioCleanupFailed: Boolean = false,
)

internal object HostCaptureStatus {
    private val mutable = MutableStateFlow(HostCaptureUiState())
    private val perHandle = ConcurrentHashMap<Long, HostCaptureUiState>()
    private val cleanupWaiters = ConcurrentHashMap<Long, CompletableFuture<HostCaptureUiState>>()
    val state = mutable.asStateFlow()

    fun update(
        state: String,
        detail: String = "",
        encodedFrames: Long = 0,
        captureHandle: Long = 0,
        cleanupComplete: Boolean = false,
        audioCleanupPending: Boolean? = null,
        audioCleanupFailureObserved: Boolean = false,
        nonAudioCleanupFailed: Boolean? = null,
    ): HostCaptureUiState {
        val previous = if (captureHandle > 0L) perHandle[captureHandle] else null
        val updated = HostCaptureUiState(
            state = state,
            detail = detail,
            encodedFrames = encodedFrames,
            captureHandle = captureHandle,
            cleanupComplete = cleanupComplete,
            audioCleanupPending = audioCleanupPending ?: previous?.audioCleanupPending ?: false,
            audioCleanupFailureObserved = audioCleanupFailureObserved ||
                previous?.audioCleanupFailureObserved == true,
            nonAudioCleanupFailed = nonAudioCleanupFailed ?: previous?.nonAudioCleanupFailed ?: false,
        )
        if (captureHandle > 0) {
            perHandle[captureHandle] = updated
            if (cleanupComplete) cleanupWaiters.remove(captureHandle)?.complete(updated)
        }
        val visible = mutable.value
        if (captureHandle == 0L || visible.captureHandle == 0L || visible.captureHandle == captureHandle) {
            mutable.value = updated
        }
        return updated
    }

    fun forHandle(captureHandle: Long): HostCaptureUiState? = perHandle[captureHandle]

    fun markAudioCleanupRecovered(captureHandle: Long): HostCaptureUiState? {
        val current = perHandle[captureHandle] ?: return null
        if (!current.cleanupComplete || !current.audioCleanupPending || current.nonAudioCleanupFailed) {
            return current
        }
        val recovered = current.copy(
            state = "stopped",
            detail = listOfNotNull(
                current.detail.takeIf(String::isNotBlank),
                uiText(UiTextKey.A_LATER_AUDIORECORD_CLEANUP_RETRY_CONFIRMED_DD95A),
            ).joinToString("；"),
            audioCleanupPending = false,
            audioCleanupFailureObserved = true,
        )
        perHandle[captureHandle] = recovered
        val visible = mutable.value
        if (visible.captureHandle == 0L || visible.captureHandle == captureHandle) mutable.value = recovered
        return recovered
    }

    fun awaitCleanup(captureHandle: Long): HostCaptureUiState {
        require(captureHandle > 0) { "Android capture cleanup requires a valid native handle" }
        val existing = perHandle[captureHandle] ?: return HostCaptureUiState(captureHandle = captureHandle)
        if (existing.cleanupComplete) return existing
        val completion = cleanupWaiters.computeIfAbsent(captureHandle) { CompletableFuture() }
        val latest = perHandle[captureHandle]
        if (latest == null || latest.cleanupComplete) {
            completion.complete(latest ?: HostCaptureUiState(captureHandle = captureHandle))
        }
        return try {
            completion.get()
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IllegalStateException("Android capture cleanup wait was interrupted", interrupted)
        } catch (failure: ExecutionException) {
            throw IllegalStateException("Android capture cleanup completion failed", failure.cause)
        }
    }
}

/** Owns the one-use MediaProjection grant, exactly one VirtualDisplay and its VP8 worker. */
internal class HostCaptureService : Service() {
    private var languageObservation: AutoCloseable? = null
    @Volatile private var notificationStarted = false
    /** Set as soon as shutdown is requested, before cleanup is queued on the worker. */
    private val stopRequested = AtomicBoolean(false)
    private val cleanupStarted = AtomicBoolean(false)
    private val serviceDestroyed = AtomicBoolean(false)
    private val browserHostActivationLeaseGate = BrowserHostActivationLeaseGate { bindingJson ->
        NativeSdk.nativeBrowserHostActivationLeaseActive(bindingJson)
    }
    /** Serializes frame work with fallback cleanup if the worker looper has already quit. */
    private val captureGate = Any()
    @Volatile private var captureHandle = 0L
    private var projection: MediaProjection? = null
    private var projectionCallback: MediaProjection.Callback? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var displayCreated = false
    private var displayManager: DisplayManager? = null
    private val captureLayouts = CaptureLayoutTracker()
    private var densityDpi = 0
    private var imageReader: ImageReader? = null
    private var workerThread: HandlerThread? = null
    private var worker: Handler? = null
    private var encoderHandle = 0L
    private var captureWasReported = false
    private var hostViewAuthorized = false
    /** Immutable request/generation owner pinned to this one-use Projection grant. */
    private var hostSessionBindingJson: String? = null
    /** BrowserHost owns the same process-wide Projection slot but is a distinct tagged owner. */
    private var browserHostBindingJson: String? = null
    private var browserHostRequestId: String? = null
    private var browserHostGeneration = 0L
    private var browserHostGrantResultCode = 0
    private var browserHostGrant: Intent? = null
    private var browserHostGrantClaimed = false
    private var browserHostQueue: AndroidBrowserRawFrameQueue? = null
    private var browserHostEndpoint: AndroidBrowserRawCaptureEndpoint? = null
    private var browserHostAudioEndpoint: BrowserHostAudioCaptureEndpoint? = null
    private var browserHostInputActive = false
    private var browserHostActive = false
    private var browserHostFailureDetail: String? = null
    private var browserHostWidth = 0
    private var browserHostHeight = 0
    private var lastBrowserFrameNanos = 0L
    private var inputDeviceAttached = false
    /** Retained until app-core reports the owning Input session stopped. */
    private var inputRequestId: String? = null
    private var audioEndpoint: NativeAudioCaptureEndpoint? = null
    private var audioRequestId: String? = null
    private var audioConnectionGeneration = 0L
    private var audioBindingJson: String? = null
    private var lastPts90Khz = -1L
    private var lastEncodedTimestampNanos = 0L
    private var encodedFrames = 0L
    private var framesInEncoder = 0L
    /** Last geometry generation accepted by the native source, retained across pauses. */
    private var configuredLayoutEpoch = 0L
    /** Network generations advance only after the previous catalogue ACK. */
    private var configuredWireLayoutEpoch = 0L
    private val cleanupCompletion = CompletableFuture<HostCaptureUiState>()
    private val authorizationPoll = object : Runnable {
        override fun run() {
            pollHostViewAuthorization()
        }
    }
    private val browserDiscoveryPoll = object : Runnable {
        override fun run() {
            synchronized(captureGate) {
                if (stopRequested.get()) return
                val binding = browserHostBindingJson ?: return
                val current = runCatching {
                    AndroidBrowserMulticastOwner.poll(binding, browserHostActivationLeaseGate.isActive(binding))
                }.getOrDefault(false)
                if (!current) {
                    browserHostFailureDetail = uiText(UiTextKey.BROWSER_DISCOVERY_CONSENT_EXPIRED_OR_WI_65DD4)
                    postStop(REASON_SETUP_FAILED)
                } else if (worker?.postDelayed(this, 1_000L) != true) {
                    postStop(REASON_SETUP_FAILED)
                }
            }
        }
    }
    private val displayResizeListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = Unit
        override fun onDisplayRemoved(displayId: Int) = Unit

        override fun onDisplayChanged(displayId: Int) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
                displayId != Display.DEFAULT_DISPLAY
            ) return
            val bounds = (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
            val handler = worker ?: return
            val resize = if (browserHostBindingJson != null) {
                Runnable { resizeBrowserHostLocked(bounds.width(), bounds.height()) }
            } else {
                Runnable { resizeCapturedContent(bounds.width(), bounds.height()) }
            }
            if (!handler.post(resize)) {
                postStop(REASON_RESIZE_FAILED)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        cleanupOwner = this
        languageObservation = UiLanguage.observe {
            if (notificationStarted && !stopRequested.get() && !serviceDestroyed.get()) {
                // Update copy only. Do not reopen Projection, consent or media.
                runCatching {
                    createNotificationChannel()
                    refreshForegroundNotification()
                }
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                if (captureHandle <= 0L) {
                    captureHandle = intent.getLongExtra(EXTRA_HANDLE, 0L)
                }
                postStop(intent.getStringExtra(EXTRA_REASON) ?: REASON_LOCAL_STOP)
                return START_NOT_STICKY
            }
            ACTION_STAGE_BROWSER -> stageBrowserHostGrant(intent, startId)
            ACTION_START -> startCapture(intent, startId)
            else -> stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    private fun startCapture(intent: Intent, startId: Int) {
        val requestedHandle = intent.getLongExtra(EXTRA_HANDLE, 0L)
        if (projection != null || browserHostBindingJson != null) {
            HostCaptureStatus.update(
                "failed",
                uiText(UiTextKey.ANOTHER_SCREEN_CAPTURE_OWNER_IS_STILL_E0458),
                captureHandle = requestedHandle,
                cleanupComplete = requestedHandle != captureHandle,
            )
            return
        }
        if (displayCreated || stopRequested.get()) {
            HostCaptureStatus.update(
                "failed",
                uiText(UiTextKey.THIS_SYSTEM_GRANT_HAS_ALREADY_BEEN_A21F3),
                captureHandle = requestedHandle,
                cleanupComplete = requestedHandle != captureHandle || cleanupCompletion.isDone,
            )
            return
        }
        captureHandle = requestedHandle
        hostSessionBindingJson = intent.getStringExtra(EXTRA_SESSION_BINDING)
        val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, 0)
        val grant = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_GRANT, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(EXTRA_GRANT)
        }
        if (captureHandle <= 0L || hostSessionBindingJson.isNullOrBlank() ||
            resultCode != Activity.RESULT_OK || grant == null
        ) {
            updateCaptureStatus("failed", uiText(UiTextKey.THE_SYSTEM_SCREEN_SHARING_GRANT_OR_D5BC6))
            stopSelf(startId)
            return
        }

        try {
            check(NativeSdk.nativeHostSessionBinding(captureHandle) == hostSessionBindingJson) {
                uiText(UiTextKey.THE_ORIGINAL_HOST_VIEW_SESSION_ENDED_26A50)
            }
            createNotificationChannel()
            startForegroundCaptureNotification()
            check(NativeSdk.nativeCanStartHostCapture(captureHandle)) {
                uiText(UiTextKey.SIGN_IN_AND_ENROLL_THIS_DEVICE_40C4A)
            }
            val manager = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
            val activeProjection = manager.getMediaProjection(resultCode, grant)
                ?: error("Android did not provide a MediaProjection")
            projection = activeProjection

            val bounds = (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
            captureLayouts.initialize(bounds.width(), bounds.height())
            densityDpi = resources.displayMetrics.densityDpi
            val thread = HandlerThread("nestlink-screen-vp8").apply { start() }
            workerThread = thread
            val handler = Handler(thread.looper)
            worker = handler
            val displays = getSystemService(DISPLAY_SERVICE) as DisplayManager
            displayManager = displays
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                displays.registerDisplayListener(displayResizeListener, Handler(Looper.getMainLooper()))
            }

            val callback = object : MediaProjection.Callback() {
                override fun onStop() {
                    postStop(REASON_SYSTEM_REVOKED)
                }

                override fun onCapturedContentResize(width: Int, height: Int) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        if (!handler.post { resizeCapturedContent(width, height) }) {
                            postStop(REASON_RESIZE_FAILED)
                        }
                    }
                }
            }
            projectionCallback = callback
            activeProjection.registerCallback(callback, Handler(Looper.getMainLooper()))
            updateCaptureStatus(
                "waiting_view_authorization",
                uiText(UiTextKey.ANDROID_CONSENT_IS_READY_WAITING_FOR_3F3A4),
            )
            handler.post(authorizationPoll)
        } catch (failure: Throwable) {
            val detail = failure.message ?: uiText(UiTextKey.SCREEN_CAPTURE_INITIALIZATION_FAILED_5DD63)
            if (!stopRequested.get()) updateCaptureStatus("failed", detail)
            postStop(REASON_SETUP_FAILED)
        }
    }

    /** Holds a user-approved one-use Intent only; no MediaProjection API is touched here. */
    private fun stageBrowserHostGrant(intent: Intent, startId: Int) {
        val handle = intent.getLongExtra(EXTRA_HANDLE, 0L)
        val bindingJson = intent.getStringExtra(EXTRA_BROWSER_BINDING)
        val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, 0)
        val grant = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_GRANT, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(EXTRA_GRANT)
        }
        val binding = bindingJson?.let { runCatching { HostCaptureBinding.browserHost(it) }.getOrNull() }
        if (handle <= 0L || bindingJson.isNullOrBlank() || binding == null ||
            resultCode != Activity.RESULT_OK || grant == null || projection != null ||
            hostSessionBindingJson != null || browserHostBindingJson != null || stopRequested.get() ||
            nativeAudioEndpointOwners.owners(handle, NativeAudioOwnerRole.HostCapture).isNotEmpty()
        ) {
            val detail = uiText(UiTextKey.SCREEN_SHARING_CONSENT_IS_INVALID_OR_83DE7)
            BrowserHostCaptureStatus.update("failed", detail, bindingJson)
            bindingJson?.takeIf { binding != null }?.let(BrowserHostCaptureCoordinator::markDenied)
            // This is a started-service singleton. A rejected BrowserHost request
            // must not stop an existing NativeSession owner.
            if (projection == null && hostSessionBindingJson == null && browserHostBindingJson == null) {
                stopSelf(startId)
            }
            return
        }
        captureHandle = handle
        browserHostBindingJson = bindingJson
        browserHostRequestId = binding.requestId
        browserHostGeneration = binding.connectionGeneration
        browserHostGrantResultCode = resultCode
        browserHostGrant = grant
        browserHostGrantClaimed = false
        try {
            createNotificationChannel()
            startForegroundCaptureNotification()
            check(AndroidBrowserMulticastOwner.stage(applicationContext, bindingJson)) {
                "Previous browser discovery owner still needs cleanup"
            }
            val thread = HandlerThread("nestlink-browser-host-capture").apply { start() }
            workerThread = thread
            worker = Handler(thread.looper)
            BrowserHostCaptureStatus.update("awaiting_proof", uiText(UiTextKey.SYSTEM_CONSENT_IS_RETAINED_SCREEN_READING_FFB49), bindingJson)
            check(worker?.postDelayed(browserDiscoveryPoll, 1_000L) == true) {
                "Browser discovery watchdog could not start"
            }
            check(BrowserHostCaptureCoordinator.markGranted(bindingJson)) {
                "BrowserHost consent was cancelled before its system grant could be staged"
            }
        } catch (failure: Throwable) {
            val detail = failure.message ?: uiText(UiTextKey.COULD_NOT_PREPARE_BROWSER_SHARING_CONSENT_CDA88)
            browserHostFailureDetail = detail
            BrowserHostCaptureStatus.update("failed", detail, bindingJson)
            bindingJson?.let(BrowserHostCaptureCoordinator::markDenied)
            browserHostGrant = null
            postStop(REASON_SETUP_FAILED)
        }
    }

    private fun reserveBrowserHostEndpoint(bindingJson: String): AndroidBrowserRawCaptureEndpoint? =
        synchronized(captureGate) {
            if (browserHostBindingJson != bindingJson || browserHostGrant == null ||
                browserHostGrantClaimed || stopRequested.get()
            ) return@synchronized null
            val binding = runCatching { HostCaptureBinding.browserHost(bindingJson) }.getOrNull()
                ?: return@synchronized null
            // Geometry only: the one-use system grant is still staged. No
            // MediaProjection, VirtualDisplay or pixel read happens here.
            val preparedBounds = (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
            val preparedSize = CaptureFramePacker.scaledSize(preparedBounds.width(), preparedBounds.height())
            val queue = AndroidBrowserRawFrameQueue()
            val endpoint = AndroidBrowserRawCaptureEndpoint(
                bindingJson = bindingJson,
                boundRequestId = binding.requestId,
                boundGeneration = binding.connectionGeneration,
                queue = queue,
                activateOwner = ::activateBrowserHostOwner,
                stopOwner = ::stopBrowserHostAndAwait,
                displaySize = {
                    synchronized(captureGate) {
                        if (browserHostActive) browserHostWidth to browserHostHeight
                        else preparedSize
                    }
                },
                audioOwner = { expected ->
                    synchronized(captureGate) {
                        browserHostAudioEndpoint.takeIf {
                            browserHostBindingJson == expected && browserHostActive
                        }?.also { endpoint ->
                            nativeAudioEndpointOwners.markAttached(
                                captureHandle,
                                NativeAudioOwnerRole.HostCapture,
                                expected,
                                endpoint.nativeEndpointForCleanup(),
                            )
                        }
                    }
                },
                stopInputOwner = ::stopBrowserHostInputOwnerAndAwait,
            )
            browserHostQueue = queue
            browserHostEndpoint = endpoint
            browserHostGrantClaimed = true
            endpoint
        }

    private fun activateBrowserHostOwner(
        bindingJson: String,
        audio: Boolean,
        input: Boolean,
    ): Boolean {
        val handler = worker ?: return false
        val completion = CompletableFuture<Boolean>()
        val task = Runnable {
            val activation = runCatching {
                synchronized(captureGate) {
                    activateBrowserHostLocked(bindingJson, audio, input)
                }
            }
            val result = activation.getOrElse { failure ->
                val detail = failure.message ?: uiText(UiTextKey.BROWSER_SHARING_MEDIA_COULD_NOT_START_67386)
                browserHostFailureDetail = detail
                BrowserHostCaptureStatus.update("failed", detail, bindingJson)
                postStop(REASON_SETUP_FAILED)
                false
            }
            completion.complete(result)
        }
        if (Looper.myLooper() == handler.looper) task.run()
        else if (!handler.post(task)) return false
        return try {
            completion.get(10, java.util.concurrent.TimeUnit.SECONDS)
        } catch (_: Throwable) {
            false
        }
    }

    /** All projection/display/audio/input activation is behind endpoint proof. */
    private fun activateBrowserHostLocked(bindingJson: String, audio: Boolean, input: Boolean): Boolean {
        if (browserHostBindingJson != bindingJson || !browserHostGrantClaimed ||
            browserHostGrant == null || projection != null || stopRequested.get()
        ) return false
        val resultCode = browserHostGrantResultCode
        val grant = browserHostGrant ?: return false
        var acquiredProjection: MediaProjection? = null
        if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                val manager = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
                acquiredProjection = manager.getMediaProjection(resultCode, grant)
            }
        ) return false
        val activeProjection = acquiredProjection
            ?: error("Android did not provide a BrowserHost MediaProjection")
        projection = activeProjection
        val bounds = (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
        densityDpi = resources.displayMetrics.densityDpi
        val threadHandler = checkNotNull(worker)
        val displays = getSystemService(DISPLAY_SERVICE) as DisplayManager
        displayManager = displays
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            displays.registerDisplayListener(displayResizeListener, Handler(Looper.getMainLooper()))
        }
        val callback = object : MediaProjection.Callback() {
            override fun onStop() {
                postStop(REASON_SYSTEM_REVOKED)
            }

            override fun onCapturedContentResize(width: Int, height: Int) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
                    !threadHandler.post { resizeBrowserHostLocked(width, height) }
                ) postStop(REASON_RESIZE_FAILED)
            }
        }
        projectionCallback = callback
        activeProjection.registerCallback(callback, Handler(Looper.getMainLooper()))
        if (!configureBrowserHostReaderLocked(bounds.width(), bounds.height(), initial = true)) return false
        if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                check(!displayCreated) { "MediaProjection token already created a VirtualDisplay" }
                displayCreated = true
                virtualDisplay = activeProjection.createVirtualDisplay(
                    "NestLink BrowserHost screen capture",
                    browserHostWidth,
                    browserHostHeight,
                    densityDpi,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    checkNotNull(imageReader).surface,
                    null,
                    threadHandler,
                ) ?: error("Android could not create the BrowserHost capture display")
            }
        ) return false

        if (audio) {
            check(checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                "BrowserHost system audio requires the Android RECORD_AUDIO runtime grant"
            }
            val oldAudioOwners = nativeAudioEndpointOwners.owners(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
            )
            if (oldAudioOwners.isNotEmpty()) {
                val cleanup = nativeAudioEndpointOwners.reapAll(
                    captureHandle,
                    NativeAudioOwnerRole.HostCapture,
                )
                check(cleanup.cleanupComplete) {
                    uiText(UiTextKey.THE_PREVIOUS_ANDROID_AUDIORECORD_HAS_NOT_A27C7)
                }
            }
            var createdAudioEndpoint: BrowserHostAudioCaptureEndpoint? = null
            if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                    createdAudioEndpoint = BrowserHostAudioCaptureEndpoint.create(
                        activeProjection,
                        bindingJson,
                        captureLeaseActive = {
                            browserHostActivationLeaseGate.isActive(bindingJson)
                        },
                    )
                }
            ) return false
            val audioEndpoint = checkNotNull(createdAudioEndpoint)
            browserHostAudioEndpoint = audioEndpoint
            val nativeAudioEndpoint = audioEndpoint.nativeEndpointForCleanup()
            val registered = nativeAudioEndpointOwners.registerPending(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
                bindingJson,
                nativeAudioEndpoint,
            )
            if (!registered) {
                check(nativeAudioEndpointOwners.retainRejectedPending(
                    captureHandle,
                    NativeAudioOwnerRole.HostCapture,
                    bindingJson,
                    nativeAudioEndpoint,
                )) { uiText(UiTextKey.COULD_NOT_RETAIN_THE_REJECTED_BROWSERHOST_109BC) }
                error(uiText(UiTextKey.ANOTHER_ANDROID_AUDIORECORD_OWNER_HAS_NOT_1AE77))
            }
        }
        if (input) {
            var inputEnabled = false
            if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                    check(AndroidInputBridge.accessibility?.get() != null) {
                        "BrowserHost input requires the NestLink AccessibilityService"
                    }
                    inputEnabled = AndroidInputBridge.enableForVerifiedLayout(
                        VerifiedPointerLayout(
                            browserHostWidth,
                            browserHostHeight,
                            bounds.left,
                            bounds.top,
                            bounds.width(),
                            bounds.height(),
                        ),
                    )
                }
            ) return false
            check(inputEnabled) { "BrowserHost AccessibilityService could not activate input" }
            browserHostInputActive = true
        }
        check(!stopRequested.get()) { "BrowserHost capture was stopped during activation" }
        browserHostGrant = null
        browserHostActive = true
        lastBrowserFrameNanos = 0L
        BrowserHostCaptureStatus.update("active", uiText(UiTextKey.THE_BROWSER_CONNECTION_IS_VERIFIED_AND_0FF20), bindingJson)
        refreshForegroundNotification()
        return true
    }

    private fun configureBrowserHostReaderLocked(
        contentWidth: Int,
        contentHeight: Int,
        initial: Boolean,
    ): Boolean {
        val bindingJson = checkNotNull(browserHostBindingJson)
        val queue = checkNotNull(browserHostQueue)
        val (width, height) = CaptureFramePacker.scaledSize(contentWidth, contentHeight)
        var reader: ImageReader? = null
        if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                if (!initial) queue.clearPending()
                imageReader?.setOnImageAvailableListener(null, null)
                imageReader?.close()
                val created = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
                reader = created
                imageReader = created
                browserHostWidth = width
                browserHostHeight = height
                created.setOnImageAvailableListener(
                    { source -> offerBrowserHostImage(source, bindingJson) },
                    checkNotNull(worker),
                )
            }
        ) return false
        val activeReader = checkNotNull(reader)
        if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                val currentDisplay = virtualDisplay
                if (!initial && currentDisplay != null) currentDisplay.setSurface(activeReader.surface)
                if (browserHostInputActive) {
                    val bounds = (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
                    check(AndroidInputBridge.enableForVerifiedLayout(
                        VerifiedPointerLayout(width, height, bounds.left, bounds.top, bounds.width(), bounds.height()),
                    )) { "BrowserHost AccessibilityService was lost during resize" }
                }
            }
        ) return false
        return true
    }

    private fun resizeBrowserHostLocked(contentWidth: Int, contentHeight: Int) {
        synchronized(captureGate) {
            if (!browserHostActive || stopRequested.get()) return
            runCatching {
                if (!configureBrowserHostReaderLocked(contentWidth, contentHeight, initial = false)) {
                    postStop(REASON_RESIZE_FAILED)
                }
            }
                .onFailure { postStop(REASON_RESIZE_FAILED) }
        }
    }

    /** Releases BrowserHost input and waits for the AccessibilityService gesture owner. */
    private fun stopBrowserHostInputOwnerAndAwait(bindingJson: String): Boolean = synchronized(captureGate) {
        if (browserHostBindingJson != bindingJson) return@synchronized false
        if (!browserHostInputActive) return@synchronized true
        val stopped = AndroidInputBridge.disableAndAwait()
        if (stopped) browserHostInputActive = false
        stopped
    }

    /** An old Kotlin endpoint must not release a pointer owned by a replacement binding. */
    private fun releasePointerForBrowserHostOwner(bindingJson: String): Boolean = synchronized(captureGate) {
        withBrowserHostInputOwnerLocked(bindingJson) { AndroidInputBridge.releasePointer() }
    }

    private fun withBrowserHostInputOwnerLocked(bindingJson: String, action: () -> Boolean): Boolean {
        if (browserHostBindingJson != bindingJson || !browserHostActive || !browserHostInputActive ||
            stopRequested.get() || !AndroidInputBridge.isAccessibilityRunning()
        ) return false
        return action()
    }

    private fun isBrowserHostInputActiveForOwner(bindingJson: String): Boolean = synchronized(captureGate) {
        withBrowserHostInputOwnerLocked(bindingJson) { true }
    }

    private fun selectBrowserHostInputSourceForOwner(
        bindingJson: String,
        source: Int,
        left: Int,
        top: Int,
        width: Int,
        height: Int,
    ): Boolean = synchronized(captureGate) {
        withBrowserHostInputOwnerLocked(bindingJson) {
            AndroidInputBridge.selectSource(source, left, top, width, height)
        }
    }

    private fun sendBrowserHostHidKeyForOwner(bindingJson: String, usage: Int, down: Boolean): Boolean =
        synchronized(captureGate) {
            withBrowserHostInputOwnerLocked(bindingJson) { AndroidInputBridge.sendHidKey(usage, down) }
        }

    private fun dispatchBrowserHostPointerForOwner(
        bindingJson: String,
        x: Int,
        y: Int,
        phase: Int,
    ): Boolean = synchronized(captureGate) {
        withBrowserHostInputOwnerLocked(bindingJson) { AndroidInputBridge.dispatchPointer(x, y, phase) }
    }

    private fun commitBrowserHostTextForOwner(bindingJson: String, text: String): Boolean =
        synchronized(captureGate) {
            withBrowserHostInputOwnerLocked(bindingJson) { AndroidInputBridge.commitRemoteText(text) }
        }

    /** Resets the BrowserHost AudioRecord and retains it until its worker exits. */
    private fun stopBrowserHostAudioLocked() {
        val endpoint = browserHostAudioEndpoint ?: return
        val owners = nativeAudioEndpointOwners.owners(captureHandle, NativeAudioOwnerRole.HostCapture)
        if (owners.none { it.endpoint === endpoint.nativeEndpointForCleanup() }) {
            check(nativeAudioEndpointOwners.retainRejectedPending(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
                checkNotNull(browserHostBindingJson),
                endpoint.nativeEndpointForCleanup(),
            )) { uiText(UiTextKey.COULD_NOT_RETAIN_THE_BROWSERHOST_AUDIORECORD_86745) }
        }
        val cleanup = nativeAudioEndpointOwners.reapAll(captureHandle, NativeAudioOwnerRole.HostCapture)
        check(cleanup.cleanupComplete) {
            cleanup.receipts.lastOrNull()?.detail ?: "BrowserHost AudioRecord cleanup did not finish"
        }
        browserHostAudioEndpoint = null
    }

    /** Stops only the exact BrowserHost binding and waits for all platform owners. */
    private fun stopBrowserHostAndAwait(bindingJson: String): Boolean {
        if (browserHostBindingJson != bindingJson) return false
        if (Looper.myLooper() == worker?.looper) {
            stopCapture(REASON_LOCAL_STOP)
        } else {
            postStop(REASON_LOCAL_STOP)
        }
        val result = awaitCleanupCompletion()
        return result.cleanupComplete && result.state != "failed" &&
            BrowserHostCaptureStatus.state.value.state != "failed"
    }

    private fun offerBrowserHostImage(source: ImageReader, bindingJson: String) {
        synchronized(captureGate) {
            val queue = browserHostQueue ?: return
            if (!browserHostActive || stopRequested.get() || source !== imageReader ||
                browserHostBindingJson != bindingJson
            ) return
            var rgba: ByteArray? = null
            var bgra: ByteArray? = null
            var acquiredImage: Image? = null
            try {
                if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                        acquiredImage = source.acquireLatestImage()
                    }
                ) {
                    queue.clearPending()
                    postStop(REASON_SESSION_BINDING_CHANGED)
                    return
                }
                val image = acquiredImage ?: return
                image.use {
                    if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {}) {
                        queue.clearPending()
                        postStop(REASON_SESSION_BINDING_CHANGED)
                        return@use
                    }
                    val timestamp = it.timestamp.takeIf { value -> value > 0L } ?: System.nanoTime()
                    if (timestamp <= lastBrowserFrameNanos) return
                    val age = System.nanoTime() - timestamp
                    if (age < 0L || age > 250_000_000L) return
                    val plane = it.planes.singleOrNull() ?: error("Android returned an invalid BrowserHost capture plane")
                    val buffer = plane.buffer.asReadOnlyBuffer()
                    rgba = ByteArray(buffer.remaining()).also(buffer::get)
                    bgra = CaptureFramePacker.rgbaToBgra(
                        checkNotNull(rgba), it.width, it.height, plane.rowStride, plane.pixelStride,
                    )
                    if (!browserHostActivationLeaseGate.runIfActive(bindingJson) {
                            if (browserHostActive && source === imageReader && browserHostBindingJson == bindingJson) {
                                queue.offer(it.width, it.height, timestamp, checkNotNull(bgra))
                                lastBrowserFrameNanos = timestamp
                            }
                        }
                    ) {
                        queue.clearPending()
                        postStop(REASON_SESSION_BINDING_CHANGED)
                    }
                }
            } catch (failure: Throwable) {
                postStop(REASON_RESIZE_FAILED)
            } finally {
                rgba?.fill(0)
                bgra?.fill(0)
            }
        }
    }

    private fun updateCaptureStatus(
        state: String,
        detail: String = "",
        encodedFrames: Long = 0,
        cleanupComplete: Boolean = false,
        audioCleanupPending: Boolean? = null,
        audioCleanupFailureObserved: Boolean = false,
        nonAudioCleanupFailed: Boolean? = null,
    ): HostCaptureUiState = HostCaptureStatus.update(
        state,
        detail,
        encodedFrames,
        captureHandle,
        cleanupComplete,
        audioCleanupPending,
        audioCleanupFailureObserved,
        nonAudioCleanupFailed,
    )

    private fun awaitCleanupCompletion(): HostCaptureUiState = try {
        cleanupCompletion.get()
    } catch (interrupted: InterruptedException) {
        Thread.currentThread().interrupt()
        throw IllegalStateException("Android capture cleanup wait was interrupted", interrupted)
    } catch (failure: ExecutionException) {
        throw IllegalStateException("Android capture cleanup completion failed", failure.cause)
    }

    private fun encodeLatestImage(source: ImageReader, layoutEpoch: Long) {
        synchronized(captureGate) {
            val layout = captureLayouts.current ?: return
            if (stopRequested.get() || !hostViewAuthorized ||
                source !== imageReader || !captureLayouts.accepts(layoutEpoch)
            ) return
            encodeLatestImageLocked(source, layout)
        }
    }

    /** Must run under [captureGate] so no callback can race encoder teardown. */
    private fun encodeLatestImageLocked(source: ImageReader, layout: CaptureLayout) {
        if (stopRequested.get() || !hostViewAuthorized || source !== imageReader ||
            captureLayouts.current?.epoch != layout.epoch
        ) return
        var bgra: ByteArray? = null
        try {
            val sessionBinding = hostSessionBindingJson ?: return
            if (NativeSdk.nativeHostSessionBinding(captureHandle) != sessionBinding) {
                suspendAuthorizedOutputLocked(REASON_VIEW_SESSION_ENDED)
                return
            }
            val wireLayoutEpoch = NativeSdk.nativeHostDisplayReady(captureHandle, sessionBinding)
            if (wireLayoutEpoch == 0L) {
                source.acquireLatestImage()?.close()
                return
            }
            configuredWireLayoutEpoch = wireLayoutEpoch
            val image = source.acquireLatestImage() ?: return
            var authorizationLost = false
            image.use {
                val timestamp = it.timestamp.takeIf { value -> value > 0L }
                    ?: System.nanoTime()
                check(lastEncodedTimestampNanos == 0L || timestamp > lastEncodedTimestampNanos) {
                    "Android capture timestamps did not increase"
                }
                if (lastEncodedTimestampNanos > 0L &&
                    timestamp - lastEncodedTimestampNanos < FRAME_INTERVAL_NANOS
                ) {
                    return
                }
                lastEncodedTimestampNanos = timestamp
                val plane = it.planes.singleOrNull() ?: error("Android returned an invalid capture plane")
                val buffer = plane.buffer.asReadOnlyBuffer()
                val rgba = ByteArray(buffer.remaining())
                buffer.get(rgba)
                try {
                    bgra = CaptureFramePacker.rgbaToBgra(
                        rgba,
                        it.width,
                        it.height,
                        plane.rowStride,
                        plane.pixelStride,
                    )
                } finally {
                    rgba.fill(0)
                }
                if (stopRequested.get()) return
                if (NativeSdk.nativeHostSessionBinding(captureHandle) != sessionBinding) {
                    authorizationLost = true
                    return@use
                }

                check(timestamp >= 0L) { "Android capture timestamp was negative" }
                val captureAgeNanos = Math.subtractExact(System.nanoTime(), timestamp)
                check(captureAgeNanos >= 0L) { "Android projection timestamp is outside the monotonic clock domain" }
                // A delayed callback drops its stale pixels while retaining the
                // original OS grant. It must never turn into a fresh wire PTS.
                if (captureAgeNanos > 100_000_000L) return@use
                val candidate = NativeSdk.nativeHostCapturePts(captureHandle, sessionBinding, captureAgeNanos)
                check(lastPts90Khz < Long.MAX_VALUE) { "Android capture timestamp limit reached" }
                val pts = max(candidate, lastPts90Khz + 1L)
                if (stopRequested.get()) return
                if (NativeSdk.nativeHostSessionBinding(captureHandle) != sessionBinding) {
                    authorizationLost = true
                    return@use
                }
                val feedbackNeedsKeyframe = NativeSdk.nativeHostVideoKeyframeNeeded(
                    captureHandle,
                    sessionBinding,
                    VIDEO_SOURCE_ID,
                    wireLayoutEpoch,
                    layout.width,
                    layout.height,
                )
                val frame = NativeSdk.nativeVp8Encode(
                    encoderHandle,
                    checkNotNull(bgra),
                    pts,
                    forceKeyframe = framesInEncoder == 0L || feedbackNeedsKeyframe,
                )
                try {
                    // A stop may arrive during the JNI call. Discard its output and
                    // leave all state publication to the serialized cleanup path.
                    if (stopRequested.get()) return
                    // Reject callbacks and encoder output from a retired layout even
                    // if Android had already queued them before its surface changed.
                    if (source !== imageReader || !captureLayouts.accepts(layout.epoch)) return
                    if (NativeSdk.nativeHostSessionBinding(captureHandle) != sessionBinding) {
                        authorizationLost = true
                        return@use
                    }
                    check(frame.pts90Khz == pts && frame.data.isNotEmpty()) {
                        "VP8 encoder returned an invalid frame"
                    }
                    check(
                        NativeSdk.nativeSendHostVideo(
                            captureHandle,
                            sessionBinding,
                            VIDEO_SOURCE_ID,
                            wireLayoutEpoch,
                            layout.width,
                            layout.height,
                            frame.pts90Khz,
                            frame.keyframe,
                            frame.data,
                        ),
                    ) { "authorized host video channel did not accept the encoded frame" }
                    lastPts90Khz = pts
                    encodedFrames = Math.addExact(encodedFrames, 1L)
                    framesInEncoder = Math.addExact(framesInEncoder, 1L)
                    if (!stopRequested.get()) {
                        updateCaptureStatus(
                            "capturing",
                            uiText(UiTextKey.THE_HOST_VIEW_SESSION_IS_AUTHORIZED_49BC1, encodedFrames),
                            encodedFrames,
                        )
                    }
                } finally {
                    frame.data.fill(0)
                }
            }
            if (authorizationLost) {
                suspendAuthorizedOutputLocked(REASON_VIEW_SESSION_ENDED)
                return
            }
        } catch (failure: Throwable) {
            if (!stopRequested.get() && hostViewAuthorized) {
                updateCaptureStatus("failed", failure.message ?: uiText(UiTextKey.SCREEN_FRAME_ENCODING_FAILED_16F09), encodedFrames)
                postStop(REASON_ENCODER_FAILED)
            }
        } finally {
            bgra?.fill(0)
        }
    }

    private fun pollHostViewAuthorization() {
        if (stopRequested.get()) return
        try {
            val currentBinding = NativeSdk.nativeHostSessionBinding(captureHandle)
            synchronized(captureGate) {
                if (stopRequested.get()) return
                if (hostSessionBindingJson == null || currentBinding != hostSessionBindingJson) {
                    postStop(REASON_SESSION_BINDING_CHANGED)
                    return
                }
                val authorized = true
                when {
                    authorized && !hostViewAuthorized -> activateAuthorizedOutputLocked()
                    !authorized && hostViewAuthorized -> {
                        suspendAuthorizedOutputLocked(REASON_VIEW_SESSION_ENDED)
                    }
                }
                if (hostViewAuthorized) NativeSdk.nativeHostDisplayReady(captureHandle, checkNotNull(hostSessionBindingJson))
                synchronizeHostAudioSafelyLocked()
            }
        } catch (failure: Throwable) {
            if (!stopRequested.get()) {
                updateCaptureStatus(
                    "failed",
                    failure.message ?: uiText(UiTextKey.COULD_NOT_VERIFY_HOST_VIEW_SESSION_BC855),
                    encodedFrames,
                )
                postStop(REASON_AUTHORIZATION_CHECK_FAILED)
            }
        } finally {
            if (!stopRequested.get()) {
                worker?.postDelayed(authorizationPoll, AUTHORIZATION_POLL_INTERVAL_MILLIS)
            }
        }
    }

    /** Keeps a local audio device failure from affecting the independent video capture path. */
    private fun synchronizeHostAudioSafelyLocked() {
        try {
            synchronizeHostAudioLocked()
        } catch (failure: Throwable) {
            val binding = audioBindingJson ?: runCatching {
                NativeSdk.nativeAudioBinding(captureHandle)
            }.getOrNull()
            if (binding != null) runCatching { NativeSdk.nativeFailNativeAudio(captureHandle, binding) }
            val cleanup = runCatching { stopHostAudioLocked(failRoute = false) }.exceptionOrNull()
            val detail = listOfNotNull(
                uiText(UiTextKey.REMOTE_SYSTEM_AUDIO_IS_UNAVAILABLE_FB733, failure.message ?: failure.javaClass.simpleName),
                cleanup?.let { uiText(UiTextKey.AUDIORECORD_CLEANUP_FAILED_5E4FE, it.message ?: it.javaClass.simpleName) },
            ).joinToString("；")
            updateCaptureStatus("capturing", detail, encodedFrames)
        }
    }

    /** Opens playback capture only for the current Core-issued host Audio binding. */
    private fun synchronizeHostAudioLocked() {
        val projection = projection ?: return
        if (stopRequested.get()) return
        val bindingJson = NativeSdk.nativeAudioBinding(captureHandle)
        val binding = bindingJson?.let(::JSONObject)
        val requestId = binding?.optString("request_id")?.takeIf(String::isNotBlank)
        val generation = binding?.optLong("connection_generation", 0L) ?: 0L
        val role = binding?.optString("role")
        val hostBinding = hostSessionBindingJson?.let(::JSONObject)
        val sameSession = hostBinding != null &&
            hostBinding.optString("request_id") == requestId &&
            hostBinding.optLong("connection_generation", 0L) == generation
        if (requestId == null || generation <= 0L || role != "HostCapture" || !sameSession) {
            if (audioEndpoint != null) stopHostAudioLocked(failRoute = false)
            return
        }
        if (audioEndpoint != null && audioRequestId == requestId && audioConnectionGeneration == generation) {
            val status = bindingJson?.let { NativeSdk.nativeNativeAudioWorkerStatus(captureHandle, it) }?.let(::JSONObject)
            if (status != null) {
                val failed = !status.isNull("error") && status.optString("error").isNotBlank()
                if (status.optBoolean("finished") || status.optBoolean("cleanup_timed_out") || failed) {
                    stopHostAudioLocked(failRoute = true)
                }
            }
            return
        }
        if (audioEndpoint != null) stopHostAudioLocked(failRoute = false)
        val priorOwners = nativeAudioEndpointOwners.owners(captureHandle, NativeAudioOwnerRole.HostCapture)
        if (priorOwners.isNotEmpty()) {
            val cleanup = nativeAudioEndpointOwners.reapAll(captureHandle, NativeAudioOwnerRole.HostCapture)
            check(cleanup.cleanupComplete) {
                uiText(UiTextKey.THE_PREVIOUS_ANDROID_AUDIORECORD_HAS_NOT_280DA)
            }
        }
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            checkNotNull(bindingJson)
            NativeSdk.nativeFailNativeAudio(captureHandle, bindingJson)
            updateCaptureStatus(
                "capturing",
                uiText(UiTextKey.SYSTEM_AUDIO_IS_AUTHORIZED_BUT_ANDROID_87A92),
                encodedFrames,
            )
            return
        }
        val endpoint = try {
            NativeAudioCaptureEndpoint.create(projection, requestId, generation)
        } catch (failure: Throwable) {
            checkNotNull(bindingJson)
            runCatching { NativeSdk.nativeFailNativeAudio(captureHandle, bindingJson) }
            updateCaptureStatus("capturing", uiText(UiTextKey.SYSTEM_PLAYBACK_CAPTURE_COULD_NOT_START_B413E, failure.message ?: failure.javaClass.simpleName), encodedFrames)
            return
        }
        try {
            checkNotNull(bindingJson)
            val registered = nativeAudioEndpointOwners.registerPending(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
                bindingJson,
                endpoint,
            )
            if (!registered) {
                check(nativeAudioEndpointOwners.retainRejectedPending(
                    captureHandle,
                    NativeAudioOwnerRole.HostCapture,
                    bindingJson,
                    endpoint,
                )) { uiText(UiTextKey.COULD_NOT_RETAIN_THE_REJECTED_ANDROID_C4623) }
                error(uiText(UiTextKey.ANOTHER_ANDROID_AUDIORECORD_OWNER_HAS_NOT_1AE77))
            }
            // Pin the owner before JNI: Core may reject and synchronously call
            // reset, whose failure must still leave a strong Kotlin reference.
            audioEndpoint = endpoint
            audioRequestId = requestId
            audioConnectionGeneration = generation
            audioBindingJson = bindingJson
            NativeSdk.nativeAttachNativeAudioCapture(captureHandle, bindingJson, endpoint)
            check(nativeAudioEndpointOwners.markAttached(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
                bindingJson,
                endpoint,
            )) { "Android AudioRecord owner changed during Core attachment." }
        } catch (failure: Throwable) {
            runCatching { bindingJson?.let { NativeSdk.nativeFailNativeAudio(captureHandle, it) } }
            val receipt = nativeAudioEndpointOwners.reap(
                captureHandle,
                NativeAudioOwnerRole.HostCapture,
                endpoint,
            )
            if (receipt?.cleanupComplete == true) {
                clearHostAudioOwner(endpoint)
            } else throw IllegalStateException(
                "Android AudioRecord attach failed and device cleanup did not finish: ${failure.message}",
                failure,
            )
            throw failure
        }
    }

    /** Stop the platform recorder and wait for its reader thread before Core can close. */
    private fun stopHostAudioLocked(failRoute: Boolean) {
        val role = NativeAudioOwnerRole.HostCapture
        var owners = nativeAudioEndpointOwners.owners(captureHandle, role)
        val localEndpoint = audioEndpoint
        if (localEndpoint != null && owners.none { it.endpoint === localEndpoint }) {
            check(nativeAudioEndpointOwners.retainRejectedPending(
                captureHandle,
                role,
                checkNotNull(audioBindingJson) { uiText(UiTextKey.THE_LOCAL_ANDROID_AUDIORECORD_OWNER_LOST_E8083) },
                localEndpoint,
            )) { uiText(UiTextKey.COULD_NOT_RETAIN_THE_LOCAL_ANDROID_6C4E6) }
            owners = nativeAudioEndpointOwners.owners(captureHandle, role)
        }

        var failure: Throwable? = null
        val bindings = (owners.map { it.bindingJson } + listOfNotNull(audioBindingJson))
            .distinct()
        for (owner in owners) {
            val receipt = nativeAudioEndpointOwners.reap(captureHandle, role, owner.endpoint)
            if (receipt?.cleanupComplete == true) {
                (owner.endpoint as? NativeAudioCaptureEndpoint)?.let(::clearHostAudioOwner)
            } else {
                val cleanupFailure = IllegalStateException(
                    receipt?.detail ?: "Android AudioRecord cleanup did not finish",
                )
                if (failure == null) failure = cleanupFailure else failure?.addSuppressed(cleanupFailure)
            }
        }
        if (failRoute) {
            val currentBinding = runCatching { NativeSdk.nativeAudioBinding(captureHandle) }
                .onFailure { error -> if (failure == null) failure = error else failure?.addSuppressed(error) }
                .getOrNull()
            for (bindingJson in bindings.filter { it == currentBinding }) {
                runCatching { NativeSdk.nativeFailNativeAudio(captureHandle, bindingJson) }
                    .onFailure { error -> if (failure == null) failure = error else failure?.addSuppressed(error) }
            }
        }
        failure?.let { throw it }
    }

    private fun clearHostAudioOwner(endpoint: NativeAudioCaptureEndpoint) {
        if (audioEndpoint === endpoint) {
            audioEndpoint = null
            audioRequestId = null
            audioConnectionGeneration = 0L
            audioBindingJson = null
        }
    }


    /** Applies a system content-size change on the same worker that owns frame delivery. */
    private fun resizeCapturedContent(contentWidth: Int, contentHeight: Int) {
        synchronized(captureGate) {
            if (stopRequested.get()) return
            try {
                val update = captureLayouts.resize(contentWidth, contentHeight)
                if (!update.contentSizeChanged) return

                if (inputDeviceAttached || inputRequestId != null) {
                    stopInputSessionForLayoutChange()
                    suspendAuthorizedOutputLocked(REASON_INPUT_LAYOUT_CHANGED)
                    return
                }

                // Close the old native delivery gate before retiring its surface,
                // encoder and queued frames. Source callbacks carry this epoch too.
                hostSessionBindingJson?.let {
                    NativeSdk.nativeClearHostVideoStreamFor(captureHandle, it)
                }
                val resumeOutput = hostViewAuthorized
                hostViewAuthorized = false
                imageReader?.setOnImageAvailableListener(null, null)
                virtualDisplay?.setSurface(null)
                imageReader?.close()
                imageReader = null
                if (encoderHandle > 0L) {
                    NativeSdk.nativeVp8EncoderDestroy(encoderHandle)
                    encoderHandle = 0L
                }

                // MediaProjection requires one VirtualDisplay per grant. Resize
                // only when the encoded surface geometry changes; when the raw
                // content changes but rounds to the same output size, replace
                // the reader/encoder generation above while retaining the display.
                if (update.outputSizeChanged) {
                    virtualDisplay?.resize(update.layout.width, update.layout.height, densityDpi)
                }

                if (resumeOutput) {
                    val sessionBinding = hostSessionBindingJson
                    if (sessionBinding == null || NativeSdk.nativeHostSessionBinding(captureHandle) != sessionBinding) {
                        suspendAuthorizedOutputLocked(REASON_VIEW_SESSION_ENDED)
                        return
                    }
                    activateAuthorizedOutputLocked()
                } else if (!stopRequested.get()) {
                    updateCaptureStatus(
                        "waiting_view_authorization",
                        uiText(UiTextKey.SHARED_CONTENT_DIMENSIONS_CHANGED_WAITING_FOR_4F657),
                        encodedFrames,
                    )
                }
            } catch (failure: Throwable) {
                if (!stopRequested.get()) {
                    updateCaptureStatus(
                        "failed",
                        failure.message ?: uiText(UiTextKey.COULD_NOT_APPLY_THE_SCREEN_SHARING_32052),
                        encodedFrames,
                    )
                    postStop(REASON_RESIZE_FAILED)
                }
            }
        }
    }

    /** All calls run on the capture worker and under [captureGate]. */
    private fun activateAuthorizedOutputLocked() {
        if (stopRequested.get()) return
        val sessionBinding = checkNotNull(hostSessionBindingJson) {
            "host capture has no pinned NativeSessionBinding"
        }
        check(NativeSdk.nativeHostSessionBinding(captureHandle) == sessionBinding) {
            "host View session authorization ended before capture started"
        }
        // Multiple OS callbacks may arrive before a network ACK. Keep the
        // latest local geometry and finish the old handshake before publishing
        // one next revision. The same VirtualDisplay and grant remain owned.
        if (configuredWireLayoutEpoch > 0L) {
            val confirmedEpoch = NativeSdk.nativeHostDisplayReady(captureHandle, sessionBinding)
            if (confirmedEpoch == 0L) return
            configuredWireLayoutEpoch = confirmedEpoch
        }
        val nextWireLayoutEpoch = Math.addExact(configuredWireLayoutEpoch, 1L)
        val currentLayout = checkNotNull(captureLayouts.current)
        val layout = if (configuredLayoutEpoch >= currentLayout.epoch) {
            // A paused source may resume at identical dimensions. Retire its
            // prior generation so no delayed frame can masquerade as current.
            captureLayouts.advanceEpoch()
        } else currentLayout
        check(!displayCreated || virtualDisplay != null) {
            "MediaProjection token already consumed its VirtualDisplay"
        }
        val reader = ImageReader.newInstance(layout.width, layout.height, PixelFormat.RGBA_8888, 2)
        val encoder = try {
            NativeSdk.nativeVp8EncoderCreate(layout.width, layout.height, CAPTURE_FPS, BITRATE_KBPS)
        } catch (failure: Throwable) {
            reader.close()
            throw failure
        }
        if (encoder <= 0L) {
            reader.close()
            error("VP8 encoder could not be created")
        }
        imageReader = reader
        encoderHandle = encoder
        framesInEncoder = 0L
        reader.setOnImageAvailableListener(
            { source -> encodeLatestImage(source, layout.epoch) },
            checkNotNull(worker),
        )

        try {
            val currentDisplay = virtualDisplay
            if (currentDisplay == null) {
                check(!displayCreated) { "MediaProjection token already created a VirtualDisplay" }
                displayCreated = true
                virtualDisplay = checkNotNull(projection).createVirtualDisplay(
                    "NestLink screen capture",
                    layout.width,
                    layout.height,
                    densityDpi,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    reader.surface,
                    null,
                    checkNotNull(worker),
                ) ?: error("Android could not create the capture display")
            } else {
                currentDisplay.setSurface(reader.surface)
            }

            if (!captureWasReported) {
                val status = JSONObject(
                    NativeSdk.nativeReportPlatformCapture(
                        captureHandle,
                        true,
                        sessionBinding,
                        "projection_active",
                    ),
                )
                check(status.optBoolean("active")) {
                    "Rust Android bridge did not accept the authorized platform capture state"
                }
                // Remember externally visible state before any later setup call can fail.
                captureWasReported = true
            }
            NativeSdk.nativeClearHostVideoStreamFor(captureHandle, sessionBinding)
            NativeSdk.nativeConfigureHostVideoStream(
                captureHandle,
                sessionBinding,
                VIDEO_SOURCE_ID,
                layout.width,
                layout.height,
                nextWireLayoutEpoch,
            )
            configuredLayoutEpoch = layout.epoch
            configuredWireLayoutEpoch = nextWireLayoutEpoch
            hostViewAuthorized = true
            attachHostInputIfProvenLocked(layout)
            NativeSdk.nativeHostDisplayReady(captureHandle, sessionBinding)
            if (!stopRequested.get()) {
                updateCaptureStatus(
                    "capturing",
                    uiText(UiTextKey.RUST_APP_CORE_VERIFIED_THE_HOST_FEC6E),
                    encodedFrames,
                )
                refreshForegroundNotification()
            }
        } catch (failure: Throwable) {
            // Permit revocation can race display attachment. Leave the token and
            // the one display idle, then wait for a fresh authorized View session.
            val stillAuthorized = runCatching {
                NativeSdk.nativeHostSessionBinding(captureHandle) == sessionBinding
            }.getOrDefault(false)
            if (!stillAuthorized) {
                suspendAuthorizedOutputLocked(REASON_VIEW_SESSION_ENDED)
                return
            }
            throw failure
        }
    }

    /** Attach input only when the captured source is the whole default display. */
    private fun attachHostInputIfProvenLocked(layout: CaptureLayout) {
        if (inputDeviceAttached || inputRequestId != null || captureHandle <= 0L) return
        val bounds = runCatching {
            (getSystemService(WINDOW_SERVICE) as WindowManager).maximumWindowMetrics.bounds
        }.getOrNull() ?: return
        if (layout.contentWidth != bounds.width() || layout.contentHeight != bounds.height()) return
        if (!NestLinkAccessibilityService.isEnabled(this)) return

        val bindingJson = hostSessionBindingJson ?: return
        val session = runCatching { JSONObject(bindingJson) }.getOrNull() ?: return
        val generation = session.optLong("connection_generation", 0L)
        val requestId = session.optString("request_id").takeIf(String::isNotBlank) ?: return
        if (generation <= 0L || !runCatching {
                NativeSdk.nativeHostInputAuthorized(captureHandle, bindingJson)
            }.getOrDefault(false)
        ) return
        if (!AndroidInputBridge.enableForVerifiedLayout(
                VerifiedPointerLayout(layout.width, layout.height, bounds.left, bounds.top, bounds.width(), bounds.height()),
            )) return

        val attached = runCatching {
            NativeSdk.nativeAttachHostInput(
                captureHandle,
                bindingJson,
                VIDEO_SOURCE_ID,
                configuredWireLayoutEpoch,
                0,
                0,
                layout.width,
                layout.height,
            )
        }.isSuccess
        inputDeviceAttached = attached
        if (attached) inputRequestId = requestId
        if (!attached) AndroidInputBridge.disableForLayoutChange()
    }

    /** Retires the old input owner and waits for its platform cleanup to finish. */
    private fun stopInputSessionForLayoutChange() {
        if (!inputDeviceAttached && inputRequestId == null) return
        AndroidInputBridge.disableForLayoutChange()
        inputDeviceAttached = false
        val requestId = checkNotNull(inputRequestId) {
            "Android Input cleanup lost its owning native session"
        }
        var status = readNativeSessionForInputCleanup(requestId)
        when (status.optString("status")) {
            "stopped" -> {
                requireSuccessfulInputCleanup(status)
                inputRequestId = null
                return
            }
            "failed" -> error(nativeInputCleanupFailure(status))
            "stopping" -> Unit
            "establishing", "connected" -> {
                try {
                    NativeSdk.nativeStopNativeSession(captureHandle, requestId)
                } catch (stopFailure: Throwable) {
                    status = runCatching {
                        readNativeSessionForInputCleanup(requestId)
                    }.getOrElse { throw stopFailure }
                    if (status.optString("status") !in setOf("stopping", "stopped", "failed")) {
                        throw stopFailure
                    }
                }
            }
            else -> error("Android Input session has an unknown cleanup state")
        }

        while (true) {
            status = readNativeSessionForInputCleanup(requestId)
            when (status.optString("status")) {
                "stopped" -> {
                    requireSuccessfulInputCleanup(status)
                    inputRequestId = null
                    return
                }
                "failed" -> error(nativeInputCleanupFailure(status))
                "establishing", "connected", "stopping" -> SystemClock.sleep(INPUT_CLEANUP_POLL_MILLIS)
                else -> error("Android Input session has an unknown cleanup state")
            }
        }
    }

    private fun readNativeSessionForInputCleanup(requestId: String): JSONObject {
        val json = NativeSdk.nativeNativeSessionStatus(captureHandle)
        val session = json.takeUnless { it.isBlank() || it == "null" }
            ?.let(::JSONObject)
            ?: error("Android Input cleanup lost its native session")
        check(session.optString("request_id") == requestId) {
            "Android Input cleanup session identity changed"
        }
        return session
    }

    private fun nativeInputCleanupFailure(status: JSONObject): String =
        status.optJSONObject("failure")?.let { failure ->
            val kind = failure.optString("kind").takeIf(String::isNotBlank)
            val code = failure.optString("code").takeIf(String::isNotBlank)
            val details = listOfNotNull(kind, code)
            if (details.isEmpty()) null else " (${details.joinToString(", ")})"
        }?.let { detail -> "app-core reported that Android Input cleanup failed${detail}" }
            ?: "app-core reported that Android Input cleanup failed"

    private fun requireSuccessfulInputCleanup(status: JSONObject) {
        check(status.optString("cleanup") != "failed") {
            nativeInputCleanupFailure(status)
        }
    }

    /** Detaches the only display surface before releasing the per-session encoder. */
    private fun suspendAuthorizedOutputLocked(reason: String) {
        hostViewAuthorized = false
        if (inputDeviceAttached || inputRequestId != null) stopInputSessionForLayoutChange()
        if (captureHandle > 0L) {
            hostSessionBindingJson?.let { binding ->
                runCatching { NativeSdk.nativeClearHostVideoStreamFor(captureHandle, binding) }
            }
        }
        imageReader?.setOnImageAvailableListener(null, null)
        runCatching { virtualDisplay?.setSurface(null) }
        runCatching { imageReader?.close() }
        imageReader = null
        if (encoderHandle > 0L) {
            runCatching { NativeSdk.nativeVp8EncoderDestroy(encoderHandle) }
            encoderHandle = 0L
        }
        if (captureWasReported && captureHandle > 0L) {
            runCatching {
                NativeSdk.nativeReportPlatformCapture(
                    captureHandle,
                    false,
                    hostSessionBindingJson,
                    reason,
                )
            }
            captureWasReported = false
        }
        if (!stopRequested.get()) {
            updateCaptureStatus(
                "waiting_view_authorization",
                uiText(UiTextKey.THE_HOST_VIEW_SESSION_ENDED_FRAME_2A72E),
                encodedFrames,
            )
            refreshForegroundNotification()
        }
    }

    private fun refreshForegroundNotification() {
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIFICATION_ID, buildNotification())
    }

    private fun startForegroundCaptureNotification() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        notificationStarted = true
    }

    private fun buildNotification(): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, HostCaptureService::class.java)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_REASON, REASON_LOCAL_STOP)
                .putExtra(EXTRA_HANDLE, captureHandle),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle(uiText(UiTextKey.NESTLINK_SCREEN_CAPTURE_FC39D))
            .setContentText(
                when {
                    browserHostBindingJson != null && browserHostActive -> uiText(UiTextKey.BROWSER_CONNECTION_VERIFIED_SCREEN_SHARING_IS_A4805)
                    browserHostBindingJson != null -> uiText(UiTextKey.SYSTEM_CONSENT_RETAINED_WAITING_FOR_BROWSER_AFD9C)
                    hostViewAuthorized -> uiText(UiTextKey.AUTHORIZED_SCREEN_SHARING_IS_ACTIVE_26E17)
                    else -> uiText(UiTextKey.SYSTEM_CONSENT_READY_WAITING_FOR_A_F3464)
                },
            )
            .setContentIntent(openApp)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, uiText(UiTextKey.STOP_CA4D9), stop).build())
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                uiText(UiTextKey.SCREEN_CAPTURE_C71B1),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = uiText(UiTextKey.SHOWS_THE_ACTIVE_LOCAL_SCREEN_CAPTURE_B424F) }
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun postStop(reason: String) {
        stopRequested.set(true)
        // New callbacks see the flag and exit. The worker's FIFO queue places
        // cleanup after any frame/JNI callback already in flight, without
        // blocking the main thread that may have requested the stop.
        val handler = worker
        handler?.removeCallbacks(authorizationPoll)
        handler?.removeCallbacks(browserDiscoveryPoll)
        if (handler == null) {
            scheduleCleanup(reason, null)
        } else if (!handler.post { stopCapture(reason) }) {
            scheduleCleanup(reason, null)
        }
    }

    /** Keeps this service and all of its native/platform owners reachable until cleanup returns. */
    private fun scheduleCleanup(reason: String, handler: Handler?) {
        val cleanup = Runnable { stopCapture(reason) }
        if (handler?.post(cleanup) == true) return
        Thread(cleanup, "nestlink-capture-cleanup").start()
    }

    private fun stopCapture(reason: String) {
        stopRequested.set(true)
        if (!cleanupStarted.compareAndSet(false, true)) return
        worker?.removeCallbacks(authorizationPoll)
        worker?.removeCallbacks(browserDiscoveryPoll)
        val cleanupFailures = mutableListOf<String>()
        var audioCleanupFailure: String? = null
        fun attemptCleanup(label: String, action: () -> Unit) {
            runCatching(action).onFailure { failure ->
                cleanupFailures += "${label}: ${failure.message ?: failure.javaClass.simpleName}"
            }
        }
        synchronized(captureGate) {
            browserHostBindingJson?.let { binding ->
                attemptCleanup(uiText(UiTextKey.COULD_NOT_RELEASE_BROWSER_WI_FI_716B6)) {
                    check(AndroidBrowserMulticastOwner.stop(binding)) {
                        "Browser discovery owner did not match"
                    }
                }
            }
            displayManager?.let { manager ->
                attemptCleanup(uiText(UiTextKey.COULD_NOT_UNREGISTER_THE_DISPLAY_LISTENER_20746)) {
                    manager.unregisterDisplayListener(displayResizeListener)
                }
            }
            displayManager = null
            if (audioEndpoint != null || nativeAudioEndpointOwners.owners(
                    captureHandle,
                    NativeAudioOwnerRole.HostCapture,
                ).isNotEmpty() && browserHostBindingJson == null
            ) {
                runCatching { stopHostAudioLocked(failRoute = true) }
                    .onFailure { failure ->
                        audioCleanupFailure = failure.message
                            ?: failure.javaClass.simpleName
                    }
            }
            if (browserHostBindingJson != null && browserHostAudioEndpoint != null) {
                runCatching { stopBrowserHostAudioLocked() }
                    .onFailure { failure ->
                        audioCleanupFailure = failure.message ?: failure.javaClass.simpleName
                    }
            }
            if (browserHostInputActive) {
                attemptCleanup(uiText(UiTextKey.BROWSERHOST_INPUT_SESSION_CLEANUP_FAILED_F4E7E)) {
                    check(AndroidInputBridge.disableAndAwait()) {
                        "BrowserHost AccessibilityService did not confirm pointer release"
                    }
                    browserHostInputActive = false
                }
            }
            attemptCleanup(uiText(UiTextKey.COULD_NOT_CLEAN_UP_BROWSERHOST_RAW_3AA12)) {
                browserHostEndpoint?.retireFromOwner()
                browserHostQueue?.stopAndClear()
            }
            if (inputDeviceAttached || inputRequestId != null) {
                attemptCleanup(uiText(UiTextKey.ANDROID_INPUT_SESSION_CLEANUP_FAILED_AD9D2), ::stopInputSessionForLayoutChange)
            }
            if (captureHandle > 0L) {
                hostSessionBindingJson?.let { binding -> attemptCleanup(uiText(UiTextKey.COULD_NOT_CLOSE_THE_LOCAL_VIDEO_832AA)) {
                    NativeSdk.nativeClearHostVideoStreamFor(captureHandle, binding)
                }
                }
            }
            attemptCleanup(uiText(UiTextKey.COULD_NOT_DISABLE_IMAGE_READING_CALLBACKS_32DF4)) {
                imageReader?.setOnImageAvailableListener(null, null)
            }
            attemptCleanup(uiText(UiTextKey.COULD_NOT_RELEASE_THE_VIRTUAL_DISPLAY_55EA9)) { virtualDisplay?.release() }
            virtualDisplay = null
            projectionCallback?.let { callback ->
                attemptCleanup(uiText(UiTextKey.COULD_NOT_UNREGISTER_THE_MEDIAPROJECTION_CALLBACK_D2633)) {
                    projection?.unregisterCallback(callback)
                }
            }
            attemptCleanup(uiText(UiTextKey.COULD_NOT_STOP_MEDIAPROJECTION_ED6B9)) { projection?.stop() }
            projection = null
            projectionCallback = null
            attemptCleanup(uiText(UiTextKey.COULD_NOT_CLOSE_THE_IMAGE_READER_25A37)) { imageReader?.close() }
            imageReader = null
            if (encoderHandle > 0L) {
                val encoder = encoderHandle
                attemptCleanup(uiText(UiTextKey.COULD_NOT_DESTROY_THE_VP8_ENCODER_6004E)) {
                    NativeSdk.nativeVp8EncoderDestroy(encoder)
                }
                encoderHandle = 0L
            }
            if (captureWasReported && captureHandle > 0L) {
                attemptCleanup(uiText(UiTextKey.COULD_NOT_REPORT_THAT_SCREEN_CAPTURE_29BE4)) {
                    NativeSdk.nativeReportPlatformCapture(
                        captureHandle,
                        false,
                        hostSessionBindingJson,
                        reason,
                    )
                }
                captureWasReported = false
            }
            hostViewAuthorized = false
            browserHostActive = false
            browserHostGrant = null
        }
        attemptCleanup(uiText(UiTextKey.COULD_NOT_STOP_THE_SCREEN_CAPTURE_F034A)) { workerThread?.quitSafely() }
        workerThread = null
        worker = null
        if (!serviceDestroyed.get()) {
            attemptCleanup(uiText(UiTextKey.COULD_NOT_REMOVE_THE_SCREEN_CAPTURE_671C9)) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            }
            attemptCleanup(uiText(UiTextKey.COULD_NOT_STOP_THE_SCREEN_CAPTURE_83113)) { stopSelf() }
        } else {
            attemptCleanup(uiText(UiTextKey.COULD_NOT_REMOVE_THE_SCREEN_CAPTURE_671C9)) {
                (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                    .cancel(NOTIFICATION_ID)
            }
        }
        val priorFailure = if (browserHostBindingJson == null) {
            HostCaptureStatus.forHandle(captureHandle)
                ?.takeIf { it.state == "failed" }
                ?.detail
                ?.takeIf(String::isNotBlank)
        } else {
            null
        }
        val nonAudioCleanupFailed = cleanupFailures.isNotEmpty()
        val audioCleanupPending = nativeAudioEndpointOwners.owners(
            captureHandle,
            NativeAudioOwnerRole.HostCapture,
        ).isNotEmpty()
        val audioCleanupFailureObserved = nativeAudioEndpointOwners
            .receipts(captureHandle)
            .any { it.role == NativeAudioOwnerRole.HostCapture && it.failureObserved }
        val finalStatus = if (nonAudioCleanupFailed || audioCleanupFailure != null || audioCleanupPending ||
            priorFailure != null || browserHostFailureDetail != null
        ) {
            val details = listOfNotNull(
                priorFailure,
                browserHostFailureDetail,
                cleanupFailures.joinToString("；").takeIf(String::isNotEmpty),
                audioCleanupFailure?.let { uiText(UiTextKey.ANDROID_AUDIO_CAPTURE_CLEANUP_FAILED_6B318, it) },
            )
            updateCaptureStatus(
                "failed",
                details.joinToString("；"),
                encodedFrames,
                cleanupComplete = true,
                audioCleanupPending = audioCleanupPending,
                audioCleanupFailureObserved = audioCleanupFailureObserved,
                nonAudioCleanupFailed = nonAudioCleanupFailed,
            )
        } else {
            val detail = if (reason == REASON_SYSTEM_REVOKED) {
                uiText(UiTextKey.ANDROID_REVOKED_SCREEN_CAPTURE_CONSENT_THE_71523)
            } else {
                uiText(UiTextKey.THE_SCREEN_CAPTURE_SERVICE_HAS_STOPPED_6063E)
            }
            updateCaptureStatus(
                "stopped",
                detail,
                encodedFrames,
                cleanupComplete = true,
                audioCleanupPending = false,
                audioCleanupFailureObserved = audioCleanupFailureObserved,
                nonAudioCleanupFailed = false,
            )
        }
        if (browserHostBindingJson != null) {
            val detail = when {
                finalStatus.state == "failed" -> finalStatus.detail
                reason == REASON_SYSTEM_REVOKED -> uiText(UiTextKey.ANDROID_REVOKED_SCREEN_SHARING_CONSENT_MEDIA_44878)
                else -> uiText(UiTextKey.BROWSER_SHARING_MEDIA_AND_INPUT_HAVE_AC641)
            }
            BrowserHostCaptureStatus.update(
                if (finalStatus.state == "failed") "failed" else "stopped",
                detail,
                browserHostBindingJson,
            )
        }
        cleanupCompletion.complete(finalStatus)
        if (cleanupOwner === this) cleanupOwner = null
    }

    override fun onDestroy() {
        languageObservation?.close()
        languageObservation = null
        serviceDestroyed.set(true)
        if (!cleanupStarted.get()) {
            stopRequested.set(true)
            worker?.removeCallbacks(authorizationPoll)
            scheduleCleanup(REASON_SERVICE_DESTROYED, worker)
        }
        super.onDestroy()
    }

    companion object {
        @Volatile
        private var cleanupOwner: HostCaptureService? = null

        private const val ACTION_START = "com.zhanry.nestlink.action.START_CAPTURE"
        private const val ACTION_STOP = "com.zhanry.nestlink.action.STOP_CAPTURE"
        private const val ACTION_STAGE_BROWSER = "com.zhanry.nestlink.action.STAGE_BROWSER_HOST_CAPTURE"
        private const val EXTRA_HANDLE = "capture.handle"
        private const val EXTRA_SESSION_BINDING = "capture.session_binding"
        private const val EXTRA_BROWSER_BINDING = "capture.browser_host_binding"
        private const val EXTRA_RESULT_CODE = "capture.result_code"
        private const val EXTRA_GRANT = "capture.grant"
        private const val EXTRA_REASON = "capture.stop_reason"
        private const val CHANNEL_ID = "nestlink_screen_capture"
        private const val NOTIFICATION_ID = 1501
        private const val CAPTURE_FPS = 15
        private const val BITRATE_KBPS = 2_000
        private const val AUTHORIZATION_POLL_INTERVAL_MILLIS = 250L
        private const val INPUT_CLEANUP_POLL_MILLIS = 25L
        private const val VIDEO_SOURCE_ID = 0
        private const val NANOS_PER_SECOND = 1_000_000_000L
        private const val FRAME_INTERVAL_NANOS = NANOS_PER_SECOND / CAPTURE_FPS
        private const val REASON_LOCAL_STOP = "local_stop"
        private const val REASON_SYSTEM_REVOKED = "system_revoked"
        private const val REASON_SETUP_FAILED = "setup_failed"
        private const val REASON_ENCODER_FAILED = "encoder_failed"
        private const val REASON_VIEW_SESSION_ENDED = "view_session_ended"
        private const val REASON_SESSION_BINDING_CHANGED = "session_binding_changed"
        private const val REASON_AUTHORIZATION_CHECK_FAILED = "authorization_check_failed"
        private const val REASON_RESIZE_FAILED = "resize_failed"
        private const val REASON_INPUT_LAYOUT_CHANGED = "input_layout_changed"
        private const val REASON_SERVICE_DESTROYED = "service_destroyed"

        fun start(
            context: Context,
            resultCode: Int,
            grant: Intent,
            handle: Long,
            sessionBindingJson: String,
        ) {
            require(sessionBindingJson.isNotBlank()) { "Android capture requires its original host View session binding" }
            HostCaptureStatus.update(
                "starting",
                uiText(UiTextKey.STARTING_THE_ANDROID_SCREEN_CAPTURE_SERVICE_7C9E2),
                captureHandle = handle,
            )
            val intent = Intent(context, HostCaptureService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_RESULT_CODE, resultCode)
                .putExtra(EXTRA_GRANT, grant)
                .putExtra(EXTRA_HANDLE, handle)
                .putExtra(EXTRA_SESSION_BINDING, sessionBindingJson)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Starts the service with a one-use system grant pinned to a complete
         * BrowserHost binding. The service stages it and publishes the grant to
         * the waiting Rust provider only after it has accepted the exact owner.
         */
        fun stageBrowserHostGrant(
            context: Context,
            resultCode: Int,
            grant: Intent,
            handle: Long,
            bindingJson: String,
        ): Boolean {
            require(handle > 0L) { "BrowserHost capture requires a valid native handle" }
            HostCaptureBinding.browserHost(bindingJson)
            BrowserHostCaptureStatus.update("staging", uiText(UiTextKey.PREPARING_A_ONE_TIME_SYSTEM_GRANT_4CFCC), bindingJson)
            val intent = Intent(context, HostCaptureService::class.java)
                .setAction(ACTION_STAGE_BROWSER)
                .putExtra(EXTRA_RESULT_CODE, resultCode)
                .putExtra(EXTRA_GRANT, grant)
                .putExtra(EXTRA_HANDLE, handle)
                .putExtra(EXTRA_BROWSER_BINDING, bindingJson)
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            } catch (failure: Throwable) {
                val detail = failure.message ?: uiText(UiTextKey.COULD_NOT_START_THE_SCREEN_SHARING_4BED1)
                BrowserHostCaptureStatus.update("failed", detail, bindingJson)
                BrowserHostCaptureCoordinator.markDenied(bindingJson)
                false
            }
        }

        /** The Rust provider can reserve the staged grant once for this exact binding. */
        fun reserveBrowserHostEndpoint(bindingJson: String): AndroidBrowserRawCaptureEndpoint? {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return null
            val owner = cleanupOwner ?: return null
            return owner.reserveBrowserHostEndpoint(bindingJson)
        }

        /** Binding-scoped input callback used by retained JNI endpoint objects. */
        @JvmStatic
        fun releaseBrowserHostPointer(bindingJson: String): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            val owner = cleanupOwner ?: return false
            return owner.releasePointerForBrowserHostOwner(bindingJson)
        }

        @JvmStatic
        fun isBrowserHostInputActive(bindingJson: String): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            return cleanupOwner?.isBrowserHostInputActiveForOwner(bindingJson) == true
        }

        @JvmStatic
        fun selectBrowserHostInputSource(
            bindingJson: String,
            source: Int,
            left: Int,
            top: Int,
            width: Int,
            height: Int,
        ): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            return cleanupOwner?.selectBrowserHostInputSourceForOwner(
                bindingJson, source, left, top, width, height,
            ) == true
        }

        @JvmStatic
        fun sendBrowserHostHidKey(bindingJson: String, usage: Int, down: Boolean): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            return cleanupOwner?.sendBrowserHostHidKeyForOwner(bindingJson, usage, down) == true
        }

        @JvmStatic
        fun dispatchBrowserHostPointer(bindingJson: String, x: Int, y: Int, phase: Int): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            return cleanupOwner?.dispatchBrowserHostPointerForOwner(bindingJson, x, y, phase) == true
        }

        @JvmStatic
        fun commitBrowserHostText(bindingJson: String, text: String): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            return cleanupOwner?.commitBrowserHostTextForOwner(bindingJson, text) == true
        }

        /** Cancellation is binding-scoped so stale Rust owners cannot stop a replacement. */
        fun cancelStagedBrowserHost(bindingJson: String): Boolean {
            if (runCatching { HostCaptureBinding.browserHost(bindingJson) }.isFailure) return false
            val owner = cleanupOwner ?: return true
            if (owner.browserHostBindingJson != bindingJson) return true
            BrowserHostCaptureStatus.update("cancelled", uiText(UiTextKey.BROWSER_SHARING_CONSENT_OR_THE_SESSION_D0D34), bindingJson)
            if (!owner.stopBrowserHostAndAwait(bindingJson)) {
                BrowserHostCaptureStatus.update(
                    "failed",
                    uiText(UiTextKey.BROWSER_SHARING_WAS_CANCELLED_ANDROID_MEDIA_381D0),
                    bindingJson,
                )
                return false
            }
            return true
        }

        fun stop(
            context: Context,
            reason: String = REASON_LOCAL_STOP,
            handle: Long = HostCaptureStatus.state.value.captureHandle,
        ) {
            val owner = cleanupOwner
            if (owner != null) {
                if (handle <= 0L || owner.captureHandle == 0L || owner.captureHandle == handle) {
                    if (owner.captureHandle <= 0L && handle > 0L) owner.captureHandle = handle
                    owner.postStop(reason)
                }
                return
            }
            val intent = Intent(context, HostCaptureService::class.java)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_REASON, reason)
                .putExtra(EXTRA_HANDLE, handle)
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }.onFailure {
                val stopped = runCatching {
                    context.stopService(Intent(context, HostCaptureService::class.java))
                }.getOrDefault(false)
                if (!stopped && handle > 0L && HostCaptureStatus.forHandle(handle)?.cleanupComplete == false) {
                    HostCaptureStatus.update(
                        "failed",
                        uiText(UiTextKey.COULD_NOT_START_THE_SCREEN_CAPTURE_43D62, it.message ?: it.javaClass.simpleName),
                        captureHandle = handle,
                        cleanupComplete = true,
                    )
                }
            }
        }

        fun awaitCleanup(handle: Long): HostCaptureUiState {
            require(handle > 0L) { "Android capture cleanup requires a valid native handle" }
            val owner = cleanupOwner
            val captureCleanup = if (owner != null && (owner.captureHandle == handle || owner.captureHandle <= 0L)) {
                if (owner.captureHandle <= 0L) owner.captureHandle = handle
                owner.awaitCleanupCompletion()
            } else {
                HostCaptureStatus.awaitCleanup(handle)
            }
            if (captureCleanup.audioCleanupPending && !captureCleanup.nonAudioCleanupFailed) {
                val cleanup = nativeAudioEndpointOwners.reapAll(handle, NativeAudioOwnerRole.HostCapture)
                if (cleanup.cleanupComplete) {
                    return HostCaptureStatus.markAudioCleanupRecovered(handle) ?: captureCleanup
                }
            }
            return captureCleanup
        }
    }
}
