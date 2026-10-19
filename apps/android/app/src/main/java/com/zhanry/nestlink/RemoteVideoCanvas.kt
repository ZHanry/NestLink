package com.zhanry.nestlink

import android.graphics.Bitmap
import android.view.KeyEvent as AndroidKeyEvent
import android.view.View
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.focusable
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.geometry.Offset
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChanged
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.dp

internal data class RemoteVideoPresentation(
    val connectionGeneration: Long,
    val layoutEpoch: Long,
    val source: Int,
    val sequence: Long,
    val width: Int,
    val height: Int,
    val bitmapLease: RemoteVideoBitmapLease,
) {
    val bitmap: Bitmap get() = bitmapLease.bitmap
}

@Composable
internal fun RemoteVideoCanvas(
    presentation: RemoteVideoPresentation?,
    sessionConnected: Boolean,
    onFrameCommitBarrierAvailable: (RemoteVideoFrameCommitBarrier) -> Unit,
    onFrameCommitBarrierUnavailable: (RemoteVideoFrameCommitBarrier) -> Unit,
    frameCommitBarrierOverride: RemoteVideoFrameCommitBarrier? = null,
    inputLayout: NativeRemoteInputLayout? = null,
    onInputAction: (NativeInputBinding, NativeInputAction) -> Unit = { _, _ -> },
    onReleaseInput: (NativeInputBinding) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val view = LocalView.current
    val retirementBarrier = remember(view, frameCommitBarrierOverride) {
        frameCommitBarrierOverride ?: AndroidViewFrameCommitBarrier(view)
    }
    SideEffect { onFrameCommitBarrierAvailable(retirementBarrier) }
    DisposableEffect(view, retirementBarrier, onFrameCommitBarrierAvailable) {
        val attachListener = object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(attachedView: View) {
                onFrameCommitBarrierAvailable(retirementBarrier)
            }

            override fun onViewDetachedFromWindow(detachedView: View) {
                onFrameCommitBarrierUnavailable(retirementBarrier)
            }
        }
        view.addOnAttachStateChangeListener(attachListener)
        if (view.isAttachedToWindow) onFrameCommitBarrierAvailable(retirementBarrier)
        onDispose { view.removeOnAttachStateChangeListener(attachListener) }
    }

    val activeInputLayout = inputLayout?.takeIf { layout ->
        sessionConnected && presentation != null && layout.isValid() &&
            layout.binding.connectionGeneration == presentation.connectionGeneration &&
            layout.binding.source == presentation.source &&
            layout.binding.layoutEpoch == presentation.layoutEpoch
    }
    val latestReleaseInput = rememberUpdatedState(onReleaseInput)
    DisposableEffect(activeInputLayout?.binding) {
        val binding = activeInputLayout?.binding
        onDispose { if (binding != null) latestReleaseInput.value(binding) }
    }

    var viewScale by remember(activeInputLayout?.binding) { mutableStateOf(1f) }
    var viewPan by remember(activeInputLayout?.binding) { mutableStateOf(Offset.Zero) }
    Column(modifier) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(uiText(UiTextKey.REMOTE_SCREEN_CD57D), modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = { viewScale = (viewScale / 1.5f).coerceAtLeast(1f); if (viewScale == 1f) viewPan = Offset.Zero }) { Text("−") }
            TextButton(onClick = { viewScale = (viewScale * 1.5f).coerceAtMost(4f) }) { Text("+") }
            TextButton(onClick = { viewScale = 1f; viewPan = Offset.Zero }) { Text(uiText(UiTextKey.REMOTE_FIT)) }
        }
        if (presentation == null) {
            Surface(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                shape = MaterialTheme.shapes.large,
                color = NestLinkUiTokens.mediaCanvas,
            ) {
                Box(
                    Modifier.fillMaxWidth().height(112.dp).padding(16.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (sessionConnected) uiText(UiTextKey.THE_SESSION_IS_CONNECTED_WAITING_FOR_75371)
                        else uiText(UiTextKey.THE_REMOTE_SCREEN_APPEARS_AFTER_CONNECTING_82A5E),
                        color = NestLinkUiTokens.mediaForeground,
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        } else {
            val acquired = remember(presentation.bitmapLease) { mutableStateOf(false) }
            DisposableEffect(presentation.bitmapLease, retirementBarrier) {
                val hasLease = presentation.bitmapLease.acquireForDisplay()
                acquired.value = hasLease
                onDispose {
                    if (hasLease) presentation.bitmapLease.releaseFromDisplay(retirementBarrier)
                }
            }
            if (acquired.value) {
                val image = remember(presentation.bitmapLease) { presentation.bitmap.asImageBitmap() }
                val focusRequester = remember(activeInputLayout?.binding) { FocusRequester() }
                val videoHasFocus = remember(activeInputLayout?.binding) { mutableStateOf(false) }
                val focusColor = if (androidx.compose.foundation.isSystemInDarkTheme()) {
                    NestLinkUiTokens.darkFocus
                } else {
                    NestLinkUiTokens.lightFocus
                }
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .heightIn(max = 360.dp)
                        .aspectRatio(
                            presentation.width.toFloat() / presentation.height.toFloat(),
                            matchHeightConstraintsFirst = true,
                        )
                        .then(if (videoHasFocus.value) Modifier.border(2.dp, focusColor, MaterialTheme.shapes.large) else Modifier),
                    shape = MaterialTheme.shapes.large,
                    color = NestLinkUiTokens.mediaCanvas,
                ) {
                    Image(
                        bitmap = image,
                        contentDescription = uiText(UiTextKey.NESTLINK_AUTHORIZED_REMOTE_SCREEN_ED93E),
                        modifier = Modifier.fillMaxSize().graphicsLayer { scaleX = viewScale; scaleY = viewScale; translationX = viewPan.x; translationY = viewPan.y }.clip(MaterialTheme.shapes.large).then(
                            if (activeInputLayout == null) Modifier else Modifier.pointerInput(
                                activeInputLayout,
                                presentation.width,
                                presentation.height,
                                onInputAction,
                            ) {
                                awaitEachGesture {
                                    val down = awaitFirstDown(requireUnconsumed = false)
                                    focusRequester.requestFocus()
                                    var lastPoint = mapVideoPointToInput(
                                        down.position.x,
                                        down.position.y,
                                        size.width.toFloat(),
                                        size.height.toFloat(),
                                        activeInputLayout,
                                    )
                                    var pointerHeld = lastPoint != null
                                    lastPoint?.let { (x, y) ->
                                        onInputAction(
                                            activeInputLayout.binding,
                                            NativeInputAction.Pointer(1, true, x, y),
                                        )
                                    }
                                    try {
                                        while (true) {
                                            val event = awaitPointerEvent()
                                            if (event.changes.count { it.pressed } >= 2) {
                                                if (pointerHeld) { onReleaseInput(activeInputLayout.binding); pointerHeld = false }
                                                viewScale = (viewScale * event.calculateZoom()).coerceIn(1f, 4f)
                                                val pan = viewPan + event.calculatePan()
                                                val maxX = size.width * (viewScale - 1f) / 2f
                                                val maxY = size.height * (viewScale - 1f) / 2f
                                                viewPan = Offset(pan.x.coerceIn(-maxX, maxX), pan.y.coerceIn(-maxY, maxY))
                                                event.changes.forEach { it.consume() }
                                                continue
                                            }
                                            val change = event.changes.firstOrNull { it.id == down.id } ?: break
                                            val point = mapVideoPointToInput(
                                                change.position.x,
                                                change.position.y,
                                                size.width.toFloat(),
                                                size.height.toFloat(),
                                                activeInputLayout,
                                            )
                                            if (pointerHeld && point != null && point != lastPoint && change.pressed) {
                                                onInputAction(
                                                    activeInputLayout.binding,
                                                    NativeInputAction.Pointer(null, false, point.first, point.second),
                                                )
                                                lastPoint = point
                                            }
                                            if (!change.pressed) {
                                                if (pointerHeld) {
                                                    val releasePoint = point ?: lastPoint
                                                    if (releasePoint != null) {
                                                        onInputAction(
                                                            activeInputLayout.binding,
                                                            NativeInputAction.Pointer(1, false, releasePoint.first, releasePoint.second),
                                                        )
                                                    }
                                                    pointerHeld = false
                                                }
                                                change.consume()
                                                break
                                            }
                                            if (change.positionChanged()) change.consume()
                                        }
                                    } finally {
                                        if (pointerHeld) {
                                            lastPoint?.let { (x, y) ->
                                                onInputAction(
                                                    activeInputLayout.binding,
                                                    NativeInputAction.Pointer(1, false, x, y),
                                                )
                                            }
                                        }
                                    }
                                }
                            }.focusRequester(focusRequester).focusable().onFocusChanged {
                                if (videoHasFocus.value && !it.isFocused) onReleaseInput(activeInputLayout.binding)
                                videoHasFocus.value = it.isFocused
                            }.onPreviewKeyEvent { event ->
                                val usage = event.nativeKeyEvent.keyCode.toHidUsage() ?: return@onPreviewKeyEvent false
                                if (event.nativeKeyEvent.repeatCount > 0) return@onPreviewKeyEvent true
                                when (event.nativeKeyEvent.action) {
                                    AndroidKeyEvent.ACTION_DOWN -> onInputAction(
                                        activeInputLayout.binding,
                                        NativeInputAction.Key(usage, true),
                                    )
                                    AndroidKeyEvent.ACTION_UP -> onInputAction(
                                        activeInputLayout.binding,
                                        NativeInputAction.Key(usage, false),
                                    )
                                    else -> return@onPreviewKeyEvent false
                                }
                                true
                            },
                        ),
                        contentScale = ContentScale.Fit,
                    )
                }
            } else {
                Surface(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    shape = MaterialTheme.shapes.large,
                    color = NestLinkUiTokens.mediaCanvas,
                ) {
                    Box(
                        Modifier.fillMaxWidth().height(112.dp).padding(16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(uiText(UiTextKey.PREPARING_THE_REMOTE_SCREEN_C687C), color = NestLinkUiTokens.mediaForeground, textAlign = TextAlign.Center)
                    }
                }
            }
            Text(
                "${presentation.width} × ${presentation.height}",
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (activeInputLayout?.scrollSupported == true) {
                Row(Modifier.fillMaxWidth()) {
                    TextButton(onClick = { onInputAction(activeInputLayout.binding, NativeInputAction.Scroll(0, 120)) }) { Text("↑") }
                    TextButton(onClick = { onInputAction(activeInputLayout.binding, NativeInputAction.Scroll(0, -120)) }) { Text("↓") }
                    TextButton(onClick = { onInputAction(activeInputLayout.binding, NativeInputAction.Scroll(-120, 0)) }) { Text("←") }
                    TextButton(onClick = { onInputAction(activeInputLayout.binding, NativeInputAction.Scroll(120, 0)) }) { Text("→") }
                }
            }
            if (activeInputLayout != null) {
                Row(Modifier.fillMaxWidth()) {
                    TextButton(onClick = {
                        val x = activeInputLayout.left + activeInputLayout.width / 2
                        val y = activeInputLayout.top + activeInputLayout.height / 2
                        onInputAction(activeInputLayout.binding, NativeInputAction.Pointer(2, true, x, y))
                        onInputAction(activeInputLayout.binding, NativeInputAction.Pointer(2, false, x, y))
                    }) { Text(uiText(UiTextKey.REMOTE_RIGHT_CLICK)) }
                    for ((label, usage) in listOf("Esc" to 0x29, "Enter" to 0x28, "Tab" to 0x2b)) {
                        TextButton(onClick = {
                            onInputAction(activeInputLayout.binding, NativeInputAction.Key(usage, true))
                            onInputAction(activeInputLayout.binding, NativeInputAction.Key(usage, false))
                        }) { Text(label) }
                    }
                }
                RemoteInputComposer(
                    binding = activeInputLayout.binding,
                    onCommit = { text ->
                        onInputAction(activeInputLayout.binding, NativeInputAction.Text(text))
                    },
                )
            } else {
                Text(
                    uiText(UiTextKey.THIS_SESSION_IS_VIEW_ONLY_OR_1B4F0),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RemoteInputComposer(binding: NativeInputBinding, onCommit: (String) -> Unit) {
    var text by remember(binding) { mutableStateOf("") }
    fun commit() {
        val value = text
        if (value.isNotBlank() && value.toByteArray(Charsets.UTF_8).size <= 1800) {
            onCommit(value)
            text = ""
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = text,
            onValueChange = { candidate ->
                if (candidate.toByteArray(Charsets.UTF_8).size <= 1800) text = candidate
            },
            modifier = Modifier.weight(1f),
            label = { Text(uiText(UiTextKey.SEND_TEXT_TO_THE_REMOTE_INPUT_21216)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { commit() }),
        )
        TextButton(onClick = ::commit, enabled = text.isNotBlank()) { Text(uiText(UiTextKey.SEND_EDECF)) }
    }
}

private fun Int.toHidUsage(): Int? = when (this) {
    in AndroidKeyEvent.KEYCODE_A..AndroidKeyEvent.KEYCODE_Z -> 0x04 + this - AndroidKeyEvent.KEYCODE_A
    in AndroidKeyEvent.KEYCODE_1..AndroidKeyEvent.KEYCODE_9 -> 0x1e + this - AndroidKeyEvent.KEYCODE_1
    AndroidKeyEvent.KEYCODE_0 -> 0x27
    AndroidKeyEvent.KEYCODE_ENTER -> 0x28
    AndroidKeyEvent.KEYCODE_ESCAPE -> 0x29
    AndroidKeyEvent.KEYCODE_DEL -> 0x2a
    AndroidKeyEvent.KEYCODE_TAB -> 0x2b
    AndroidKeyEvent.KEYCODE_SPACE -> 0x2c
    AndroidKeyEvent.KEYCODE_MINUS -> 0x2d
    AndroidKeyEvent.KEYCODE_EQUALS -> 0x2e
    AndroidKeyEvent.KEYCODE_LEFT_BRACKET -> 0x2f
    AndroidKeyEvent.KEYCODE_RIGHT_BRACKET -> 0x30
    AndroidKeyEvent.KEYCODE_BACKSLASH -> 0x31
    AndroidKeyEvent.KEYCODE_SEMICOLON -> 0x33
    AndroidKeyEvent.KEYCODE_APOSTROPHE -> 0x34
    AndroidKeyEvent.KEYCODE_GRAVE -> 0x35
    AndroidKeyEvent.KEYCODE_COMMA -> 0x36
    AndroidKeyEvent.KEYCODE_PERIOD -> 0x37
    AndroidKeyEvent.KEYCODE_SLASH -> 0x38
    AndroidKeyEvent.KEYCODE_CAPS_LOCK -> 0x39
    in AndroidKeyEvent.KEYCODE_F1..AndroidKeyEvent.KEYCODE_F12 -> 0x3a + this - AndroidKeyEvent.KEYCODE_F1
    AndroidKeyEvent.KEYCODE_SYSRQ -> 0x46
    AndroidKeyEvent.KEYCODE_SCROLL_LOCK -> 0x47
    AndroidKeyEvent.KEYCODE_BREAK -> 0x48
    AndroidKeyEvent.KEYCODE_INSERT -> 0x49
    AndroidKeyEvent.KEYCODE_MOVE_HOME -> 0x4a
    AndroidKeyEvent.KEYCODE_PAGE_UP -> 0x4b
    AndroidKeyEvent.KEYCODE_FORWARD_DEL -> 0x4c
    AndroidKeyEvent.KEYCODE_MOVE_END -> 0x4d
    AndroidKeyEvent.KEYCODE_PAGE_DOWN -> 0x4e
    AndroidKeyEvent.KEYCODE_DPAD_RIGHT -> 0x4f
    AndroidKeyEvent.KEYCODE_DPAD_LEFT -> 0x50
    AndroidKeyEvent.KEYCODE_DPAD_DOWN -> 0x51
    AndroidKeyEvent.KEYCODE_DPAD_UP -> 0x52
    AndroidKeyEvent.KEYCODE_CTRL_LEFT -> 0xe0
    AndroidKeyEvent.KEYCODE_SHIFT_LEFT -> 0xe1
    AndroidKeyEvent.KEYCODE_ALT_LEFT -> 0xe2
    AndroidKeyEvent.KEYCODE_META_LEFT -> 0xe3
    AndroidKeyEvent.KEYCODE_CTRL_RIGHT -> 0xe4
    AndroidKeyEvent.KEYCODE_SHIFT_RIGHT -> 0xe5
    AndroidKeyEvent.KEYCODE_ALT_RIGHT -> 0xe6
    AndroidKeyEvent.KEYCODE_META_RIGHT -> 0xe7
    else -> null
}
