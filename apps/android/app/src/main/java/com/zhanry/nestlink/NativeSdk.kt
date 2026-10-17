package com.zhanry.nestlink

internal data class NativeEncodedVideoFrame(
    val pts90Khz: Long,
    val keyframe: Boolean,
    val data: ByteArray,
)

internal data class NativeRemoteVideoLayout(
    val connectionGeneration: Long,
    val layoutEpoch: Long,
    val source: Int,
    val width: Int,
    val height: Int,
)

internal data class NativeDecodedVideoFrame(
    val connectionGeneration: Long,
    val layoutEpoch: Long,
    val source: Int,
    val sequence: Long,
    val pts90Khz: Long,
    val width: Int,
    val height: Int,
    /** Packed BGRA pixels copied from the Rust decoder. Clear after presentation. */
    val bgra: ByteArray,
)

internal object NativeSdk {
    init { System.loadLibrary("nestlink_android") }

    external fun nativeConnect(
        origin: String,
        deploymentId: String,
        issuerKey: String,
        deviceId: String,
        seed: ByteArray,
    ): Long
    external fun nativeLogin(handle: Long, username: String, password: String, factor: String?): String
    external fun nativeMe(handle: Long): String
    /** Local-only dialing consent. Rust validates, persists and fences every change. */
    external fun nativeConfigureNetworkArea(handle: Long, privateDirectory: String): String
    external fun nativeNetworkSettings(handle: Long): String
    external fun nativeConfigureNetwork(handle: Long, expectedGeneration: Long, expectedRevision: Long, settingsJson: String): String
    external fun nativeDevices(handle: Long): String
    /** Current app-core authentication context for stale-response rejection. */
    external fun nativeServiceContext(handle: Long): String
    /** Service metadata commands only; Rust owns validation, authorization and outcomes. */
    external fun nativeServiceAction(handle: Long, requestJson: String): String
    external fun nativeRemoteRequest(handle: Long, requestId: String): String
    external fun nativeRemoteRequests(handle: Long): String
    external fun nativeTrustedDevices(handle: Long, hostDeviceId: String): String
    external fun nativeTrustRemote(handle: Long, requestId: String, expectedRevision: Long, expiresAtUnixMs: Long): String
    external fun nativeRevokeDeviceTrust(handle: Long, hostDeviceId: String, controllerDeviceId: String, expectedRevision: Long): String
    /** Current host-owned password scope; the verifier is never returned. */
    external fun nativeRemotePassword(handle: Long, hostDeviceId: String): String
    /** Secret is passed only to Rust and is never included in the settings JSON. */
    external fun nativeConfigureRemotePassword(handle: Long, settingsJson: String, password: String): String
    external fun nativeRevokeRemotePassword(handle: Long, expectedRevision: Long): String
    /** Reads the host's current scope for this exact pending request. */
    external fun nativeRemotePasswordOffer(handle: Long, requestId: String): String
    /** Uses the password for this pending request only; it does not create device trust. */
    external fun nativeAuthorizeRemotePassword(handle: Long, requestId: String, expectedRevision: Long, password: String): String
    external fun nativeRequestView(
        handle: Long,
        hostDeviceId: String,
        requestInput: Boolean,
        requestAudio: Boolean,
        requestFileRead: Boolean,
        requestFileWrite: Boolean,
        requestClipboardRead: Boolean,
        requestClipboardWrite: Boolean,
    ): String
    external fun nativeApproveRemote(
        handle: Long,
        requestId: String,
        expectedNonce: String,
        expectedPolicyRevision: Long,
        approved: Boolean,
        approveInput: Boolean,
        approveAudio: Boolean,
        approveFileRead: Boolean,
        approveFileWrite: Boolean,
        approveClipboardRead: Boolean,
        approveClipboardWrite: Boolean,
    ): String
    external fun nativeCancelRemote(handle: Long, requestId: String)
    external fun nativeStartNativeSession(handle: Long, requestId: String): String
    external fun nativeStopNativeSession(handle: Long, requestId: String): String
    external fun nativeNativeSessionStatus(handle: Long): String
    external fun nativeStartBrowserHost(handle: Long, requestId: String): String
    external fun nativeStopBrowserHost(handle: Long, requestId: String): String
    external fun nativeBrowserHostStatus(handle: Long): String
    /** Uses the retained Rust LeaseControl for the exact BrowserHost activation binding. */
    external fun nativeBrowserHostActivationLeaseActive(bindingJson: String): Boolean
    external fun nativeClipboardStatus(handle: Long): String?
    external fun nativeClipboardSetDirections(
        handle: Long,
        bindingJson: String,
        read: Boolean,
        write: Boolean,
        endpoint: NativeClipboardEndpoint?,
    ): String
    /** One explicit operation. Clipboard bytes never enter a JSON reply. */
    external fun nativeClipboardAction(handle: Long, bindingJson: String, sendLocal: Boolean): String
    external fun nativeClipboardPlatformAllowed(handle: Long, bindingJson: String, read: Boolean): Boolean
    external fun nativeBrowserHostDataStatus(handle: Long, bindingJson: String): String
    external fun nativeBrowserHostFilesStatus(handle: Long, bindingJson: String): String
    external fun nativeBrowserHostFilePlatformAllowed(handle: Long, bindingJson: String, write: Boolean): Boolean
    external fun nativeBrowserHostFileShare(handle: Long, bindingJson: String, grantId: String, displayName: String, sourceFd: Int): String
    external fun nativeBrowserHostFileApproveReceive(handle: Long, bindingJson: String, approved: Boolean)
    external fun nativeBrowserHostFileDiscard(handle: Long, bindingJson: String, artifactId: String)
    external fun nativeBrowserHostFileExport(handle: Long, bindingJson: String, grantId: String, artifactId: String, destinationFd: Int): String
    external fun nativeBrowserHostFileExportCancel(handle: Long, bindingJson: String, exportId: String)
    /** Cleanup-only status remains readable for the exact original picker grant after stop. */
    external fun nativeBrowserHostFileExportStatus(handle: Long, bindingJson: String, grantId: String): String
    external fun nativeBrowserClipboardSetDirections(handle: Long, bindingJson: String, read: Boolean, write: Boolean, endpoint: NativeClipboardEndpoint?): String
    external fun nativeBrowserClipboardPlatformAllowed(handle: Long, bindingJson: String, read: Boolean): Boolean
    external fun nativeFileSessionIdentity(handle: Long): String?
    external fun nativeConfigureHostFileArea(handle: Long, privateArea: String)
    external fun nativeHostFilesAttach(handle: Long, identityJson: String)
    external fun nativeHostFilesStatus(handle: Long, identityJson: String): String
    external fun nativeHostFileShare(handle: Long, identityJson: String, displayName: String, sourceFd: Int): String
    external fun nativeHostFileApproveReceive(handle: Long, identityJson: String, approved: Boolean)
    external fun nativeHostFileDiscard(handle: Long, identityJson: String, artifactId: String)
    external fun nativeHostFileExport(handle: Long, identityJson: String, artifactId: String, destinationFd: Int): String
    external fun nativeHostFileExportCancel(handle: Long, identityJson: String, exportId: String)
    external fun nativeFileRoots(handle: Long, identityJson: String, write: Boolean): String
    external fun nativeFileBrowseBegin(
        handle: Long,
        identityJson: String,
        rootId: String,
        directory: String?,
    ): String
    external fun nativeFileBrowseNext(handle: Long, identityJson: String, browseId: String): String?
    external fun nativeFileBrowseCancel(handle: Long, identityJson: String, browseId: String)
    external fun nativeFileDownload(
        handle: Long,
        identityJson: String,
        rootId: String,
        relativePath: String,
    ): String
    external fun nativeFileUpload(
        handle: Long,
        identityJson: String,
        rootId: String,
        relativePath: String,
        displayName: String,
        sourceFd: Int,
    ): String
    external fun nativeFileTaskStatus(handle: Long, identityJson: String, taskId: String): String
    /** action: 0 pause, 1 resume, 2 cancel */
    external fun nativeFileTaskControl(
        handle: Long,
        identityJson: String,
        taskId: String,
        action: Int,
    )
    external fun nativeFileDownloadDiscard(handle: Long, identityJson: String, taskId: String)
    external fun nativeConfigureFileDownloadArea(handle: Long, privateArea: String)
    external fun nativeFileExport(
        handle: Long,
        identityJson: String,
        taskId: String,
        destinationFd: Int,
    ): String
    external fun nativeFileExportStatus(handle: Long, identityJson: String, exportId: String): String
    external fun nativeFileExportCancel(handle: Long, identityJson: String, exportId: String)
    external fun nativeAudioBinding(handle: Long): String?
    external fun nativeAttachNativeAudioCapture(
        handle: Long,
        bindingJson: String,
        endpoint: NativeAudioEndpoint,
    )
    external fun nativeAttachNativeAudioPlayback(
        handle: Long,
        bindingJson: String,
        endpoint: NativeAudioEndpoint,
    )
    external fun nativeNativeAudioWorkerStatus(handle: Long, bindingJson: String): String?
    external fun nativeFailNativeAudio(handle: Long, bindingJson: String)
    external fun nativeDeviceId(handle: Long): String
    external fun nativeRegisterController(handle: Long, name: String)
    external fun nativeRegisterHost(handle: Long, name: String)
    external fun nativeRevokeDevice(handle: Long, deviceId: String)
    external fun nativeReportPlatformCapture(
        handle: Long,
        active: Boolean,
        sessionBindingJson: String?,
        reason: String,
    ): String
    external fun nativePlatformCaptureStatus(handle: Long): String
    external fun nativeCanStartHostCapture(handle: Long): Boolean
    external fun nativeHostSessionBinding(handle: Long): String?
    external fun nativeConfigureHostVideoStream(
        handle: Long,
        sessionBindingJson: String,
        source: Int,
        width: Int,
        height: Int,
        layoutEpoch: Long,
    )
    external fun nativeHostCapturePts(handle: Long, sessionBindingJson: String, captureAgeNanos: Long): Long
    external fun nativeHostDisplayReady(handle: Long, sessionBindingJson: String): Long
    external fun nativeNativeDisplays(handle: Long): String?
    external fun nativeSelectRemoteDisplay(handle: Long, requestJson: String): String
    external fun nativeClearHostVideoStreamFor(handle: Long, sessionBindingJson: String)
    external fun nativeHostVideoKeyframeNeeded(
        handle: Long,
        sessionBindingJson: String,
        source: Int,
        layoutEpoch: Long,
        width: Int,
        height: Int,
    ): Boolean
    external fun nativeSendHostVideo(
        handle: Long,
        sessionBindingJson: String,
        source: Int,
        layoutEpoch: Long,
        width: Int,
        height: Int,
        pts90Khz: Long,
        keyframe: Boolean,
        payload: ByteArray,
    ): Boolean
    external fun nativeRemoteVideoLayout(handle: Long): String?
    external fun nativePollRemoteVideo(handle: Long): NativeDecodedVideoFrame?
    external fun nativeHostInputAuthorized(handle: Long, sessionBindingJson: String): Boolean
    external fun nativeAttachHostInput(
        handle: Long,
        sessionBindingJson: String,
        source: Int,
        layoutEpoch: Long,
        left: Int,
        top: Int,
        width: Int,
        height: Int,
    )
    external fun nativeInputLayout(handle: Long): String?
    external fun nativeSendInput(handle: Long, bindingJson: String, actionJson: String)
    external fun nativeReleaseInput(handle: Long, bindingJson: String)
    external fun nativeNetworkChanged(
        handle: Long,
        factsJson: String,
        observerActive: Boolean,
        elapsedRealtimeMs: Long,
        uptimeMs: Long,
    )
    external fun nativeVp8EncoderCreate(width: Int, height: Int, fps: Int, bitrateKbps: Int): Long
    external fun nativeVp8Encode(
        handle: Long,
        bgra: ByteArray,
        pts90Khz: Long,
        forceKeyframe: Boolean,
    ): NativeEncodedVideoFrame
    external fun nativeVp8EncoderDestroy(handle: Long)
    external fun nativeLogout(handle: Long)
    external fun nativeClose(handle: Long)
}
