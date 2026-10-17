package com.zhanry.nestlink

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.ComponentName
import android.content.Context
import android.view.inputmethod.InputMethodManager
import android.graphics.Path
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.KeyEvent
import android.view.inputmethod.InputConnection
import android.inputmethodservice.InputMethodService
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Accessibility gestures are used for touch injection; window contents are never inspected. */
internal class NestLinkAccessibilityService : AccessibilityService() {
    private var pointerStroke: GestureDescription.StrokeDescription? = null
    private var pointerX = 0
    private var pointerY = 0

    override fun onServiceConnected() {
        super.onServiceConnected()
        AndroidInputBridge.accessibility = WeakReference(this)
    }

    override fun onAccessibilityEvent(event: android.view.accessibility.AccessibilityEvent?) = Unit
    override fun onInterrupt() {
        pointerStroke = null
    }

    override fun onDestroy() {
        if (AndroidInputBridge.accessibility?.get() === this) AndroidInputBridge.accessibility = null
        pointerStroke = null
        super.onDestroy()
    }

    private fun pointerGestureOnMain(x: Int, y: Int, phase: Int, request: GestureRequest) {
        if (request.cancelled.get()) {
            request.finish(false)
            return
        }
        val next = when (phase) {
            POINTER_DOWN -> {
                if (pointerStroke != null) {
                    pointerStroke = null
                    request.finish(false)
                    return
                }
                val path = Path().apply {
                    moveTo(x.toFloat(), y.toFloat())
                    lineTo(x.toFloat(), y.toFloat())
                }
                GestureDescription.StrokeDescription(path, 0, GESTURE_SEGMENT_MS, true)
            }
            POINTER_MOVE, POINTER_UP -> {
                val previous = pointerStroke
                if (previous == null) {
                    request.finish(false)
                    return
                }
                val path = Path().apply {
                    moveTo(pointerX.toFloat(), pointerY.toFloat())
                    lineTo(x.toFloat(), y.toFloat())
                }
                previous.continueStroke(
                    path,
                    0,
                    GESTURE_SEGMENT_MS,
                    phase != POINTER_UP,
                )
            }
            else -> {
                request.finish(false)
                return
            }
        }
        val builder = GestureDescription.Builder().addStroke(next).build()
        val accepted = synchronized(request) {
            if (request.cancelled.get()) false else dispatchGesture(
                builder,
                object : GestureResultCallback() {
                    override fun onCompleted(gestureDescription: GestureDescription?) {
                        if (!request.cancelled.get()) {
                            if (phase == POINTER_UP) pointerStroke = null
                            else pointerStroke = next
                            pointerX = x
                            pointerY = y
                            request.finish(true)
                        }
                    }

                    override fun onCancelled(gestureDescription: GestureDescription?) {
                        pointerStroke = null
                        request.finish(false)
                    }
                },
                mainHandler,
            )
        }
        if (!accepted) {
            if (!request.cancelled.get()) pointerStroke = null
            request.finish(false)
        } else {
            if (phase == POINTER_UP) pointerStroke = null else pointerStroke = next
            pointerX = x
            pointerY = y
        }
    }

    private fun releasePointerOnMain(request: GestureRequest) {
        if (request.cancelled.get()) {
            request.finish(false)
            return
        }
        val previous = pointerStroke
        if (previous == null) {
            request.finish(true)
            return
        }
        val path = Path().apply {
            moveTo(pointerX.toFloat(), pointerY.toFloat())
            lineTo(pointerX.toFloat(), pointerY.toFloat())
        }
        val ending = previous.continueStroke(path, 0, GESTURE_SEGMENT_MS, false)
        val accepted = synchronized(request) {
            if (request.cancelled.get()) false else dispatchGesture(
                GestureDescription.Builder().addStroke(ending).build(),
                object : GestureResultCallback() {
                    override fun onCompleted(gestureDescription: GestureDescription?) {
                        pointerStroke = null
                        request.finish(!request.cancelled.get())
                    }

                    override fun onCancelled(gestureDescription: GestureDescription?) {
                        pointerStroke = null
                        request.finish(false)
                    }
                },
                mainHandler,
            )
        }
        if (!accepted) {
            if (!request.cancelled.get()) pointerStroke = null
            request.finish(false)
        } else {
            pointerStroke = null
        }
    }

    internal companion object {
        private const val POINTER_DOWN = 1
        private const val POINTER_MOVE = 2
        private const val POINTER_UP = 3
        private const val GESTURE_SEGMENT_MS = 32L
        private const val GESTURE_TIMEOUT_MS = 2_000L
        private val mainHandler = Handler(Looper.getMainLooper())

        private class GestureRequest {
            val cancelled = AtomicBoolean(false)
            private val completed = AtomicBoolean(false)
            private val latch = CountDownLatch(1)
            private val result = AtomicBoolean(false)

            fun finish(success: Boolean) {
                if (completed.compareAndSet(false, true)) {
                    result.set(success)
                    latch.countDown()
                }
            }

            fun await(): Boolean {
                if (!latch.await(GESTURE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    synchronized(this) { cancelled.set(true) }
                    completed.set(true)
                    return false
                }
                return result.get()
            }
        }

        @Volatile
        internal var accessibility: WeakReference<NestLinkAccessibilityService>? = null

        @JvmStatic
        fun isEnabled(context: Context): Boolean {
            val component = ComponentName(context, NestLinkAccessibilityService::class.java)
                .flattenToString()
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: return false
            return enabled.split(':').any { it.equals(component, ignoreCase = true) }
        }

        @JvmStatic
        fun dispatchPointer(x: Int, y: Int, phase: Int): Boolean {
            val service = accessibility?.get() ?: return false
            return awaitGesture { request ->
                if (!mainHandler.post { service.pointerGestureOnMain(x, y, phase, request) }) {
                    request.finish(false)
                }
            }
        }

        @JvmStatic
        fun releasePointer(): Boolean {
            val service = accessibility?.get() ?: return true
            return awaitGesture { request ->
                if (!mainHandler.post { service.releasePointerOnMain(request) }) request.finish(false)
            }
        }

        @JvmStatic
        fun isRunning(): Boolean = accessibility?.get() != null

        private fun awaitGesture(schedule: (GestureRequest) -> Unit): Boolean {
            if (Looper.myLooper() == Looper.getMainLooper()) return false
            val request = GestureRequest()
            schedule(request)
            return request.await()
        }
    }
}

/** A deliberately small opt-in IME used only for focused text and key delivery. */
internal class NestLinkInputMethod : InputMethodService() {
    override fun onCreate() {
        super.onCreate()
        AndroidInputBridge.inputMethod = WeakReference(this)
    }

    override fun onDestroy() {
        if (AndroidInputBridge.inputMethod?.get() === this) AndroidInputBridge.inputMethod = null
        super.onDestroy()
    }

    override fun onStartInput(attribute: android.view.inputmethod.EditorInfo?, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        AndroidInputBridge.hasInputTarget = attribute != null
    }

    override fun onFinishInput() {
        AndroidInputBridge.hasInputTarget = false
        super.onFinishInput()
    }

    internal companion object {
        @JvmStatic
        fun commitRemoteText(text: String): Boolean {
            if (text.isEmpty() || text.toByteArray(Charsets.UTF_8).size > 1800) return false
            val service = AndroidInputBridge.inputMethod?.get() ?: return false
            if (!AndroidInputBridge.hasInputTarget) return false
            val connection: InputConnection = service.currentInputConnection ?: return false
            return connection.commitText(text, 1)
        }

        @JvmStatic
        fun sendHidKey(usage: Int, down: Boolean): Boolean {
            val service = AndroidInputBridge.inputMethod?.get() ?: return false
            if (!AndroidInputBridge.hasInputTarget) return false
            val connection = service.currentInputConnection ?: return false
            val keyCode = androidKeyCode(usage) ?: return false
            val action = if (down) KeyEvent.ACTION_DOWN else KeyEvent.ACTION_UP
            return connection.sendKeyEvent(KeyEvent(action, keyCode))
        }

        private fun androidKeyCode(usage: Int): Int? = when (usage) {
            in 0x04..0x1d -> KeyEvent.KEYCODE_A + usage - 0x04
            in 0x1e..0x26 -> KeyEvent.KEYCODE_1 + usage - 0x1e
            0x27 -> KeyEvent.KEYCODE_0
            0x28 -> KeyEvent.KEYCODE_ENTER
            0x29 -> KeyEvent.KEYCODE_ESCAPE
            0x2a -> KeyEvent.KEYCODE_DEL
            0x2b -> KeyEvent.KEYCODE_TAB
            0x2c -> KeyEvent.KEYCODE_SPACE
            0x2d -> KeyEvent.KEYCODE_MINUS
            0x2e -> KeyEvent.KEYCODE_EQUALS
            0x2f -> KeyEvent.KEYCODE_LEFT_BRACKET
            0x30 -> KeyEvent.KEYCODE_RIGHT_BRACKET
            0x31 -> KeyEvent.KEYCODE_BACKSLASH
            0x33 -> KeyEvent.KEYCODE_SEMICOLON
            0x34 -> KeyEvent.KEYCODE_APOSTROPHE
            0x35 -> KeyEvent.KEYCODE_GRAVE
            0x36 -> KeyEvent.KEYCODE_COMMA
            0x37 -> KeyEvent.KEYCODE_PERIOD
            0x38 -> KeyEvent.KEYCODE_SLASH
            0x39 -> KeyEvent.KEYCODE_CAPS_LOCK
            in 0x3a..0x45 -> KeyEvent.KEYCODE_F1 + usage - 0x3a
            0x46 -> KeyEvent.KEYCODE_SYSRQ
            0x47 -> KeyEvent.KEYCODE_SCROLL_LOCK
            0x48 -> KeyEvent.KEYCODE_BREAK
            0x49 -> KeyEvent.KEYCODE_INSERT
            0x4a -> KeyEvent.KEYCODE_MOVE_HOME
            0x4b -> KeyEvent.KEYCODE_PAGE_UP
            0x4c -> KeyEvent.KEYCODE_FORWARD_DEL
            0x4d -> KeyEvent.KEYCODE_MOVE_END
            0x4e -> KeyEvent.KEYCODE_PAGE_DOWN
            0x4f -> KeyEvent.KEYCODE_DPAD_RIGHT
            0x50 -> KeyEvent.KEYCODE_DPAD_LEFT
            0x51 -> KeyEvent.KEYCODE_DPAD_DOWN
            0x52 -> KeyEvent.KEYCODE_DPAD_UP
            0xe0 -> KeyEvent.KEYCODE_CTRL_LEFT
            0xe1 -> KeyEvent.KEYCODE_SHIFT_LEFT
            0xe2 -> KeyEvent.KEYCODE_ALT_LEFT
            0xe3 -> KeyEvent.KEYCODE_META_LEFT
            0xe4 -> KeyEvent.KEYCODE_CTRL_RIGHT
            0xe5 -> KeyEvent.KEYCODE_SHIFT_RIGHT
            0xe6 -> KeyEvent.KEYCODE_ALT_RIGHT
            0xe7 -> KeyEvent.KEYCODE_META_RIGHT
            else -> null
        }
    }
}

internal object AndroidInputBridge {
    @Volatile
    var accessibility: WeakReference<NestLinkAccessibilityService>? = null
    @Volatile
    var inputMethod: WeakReference<NestLinkInputMethod>? = null
    @Volatile
    var hasInputTarget: Boolean = false

    @Volatile
    private var acceptingInput: Boolean = false

    fun isAccessibilityRunning(): Boolean = acceptingInput && accessibility?.get() != null

    @Volatile private var pointerLayout: VerifiedPointerLayout? = null

    fun dispatchPointer(x: Int, y: Int, phase: Int): Boolean {
        if (!acceptingInput) return false
        val mapped = pointerLayout?.map(x, y) ?: return false
        return NestLinkAccessibilityService.dispatchPointer(mapped.first, mapped.second, phase)
    }

    fun selectSource(source: Int, left: Int, top: Int, width: Int, height: Int): Boolean =
        acceptingInput && pointerLayout?.matchesSource(source, left, top, width, height) == true

    fun releasePointer(): Boolean = NestLinkAccessibilityService.releasePointer()

    fun commitRemoteText(text: String): Boolean = NestLinkInputMethod.commitRemoteText(text)

    fun sendHidKey(usage: Int, down: Boolean): Boolean = NestLinkInputMethod.sendHidKey(usage, down)

    fun isAccessibilityEnabled(context: Context): Boolean =
        NestLinkAccessibilityService.isEnabled(context)

    fun isInputMethodEnabled(context: Context): Boolean {
        val expected = ComponentName(context, NestLinkInputMethod::class.java).flattenToString()
        return context.getSystemService(InputMethodManager::class.java)
            ?.enabledInputMethodList
            ?.any { it.id == expected } == true
    }

    fun isInputMethodSelected(context: Context): Boolean {
        val expected = ComponentName(context, NestLinkInputMethod::class.java).flattenToString()
        return Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
        ) == expected
    }

    fun enableForVerifiedLayout(layout: VerifiedPointerLayout): Boolean {
        val ready = accessibility?.get() != null
        pointerLayout = layout.takeIf { ready }
        acceptingInput = ready
        return ready
    }

    fun disableForLayoutChange() {
        acceptingInput = false
        pointerLayout = null
        NestLinkAccessibilityService.releasePointer()
    }

    /** Revokes the source and synchronously confirms the current gesture was released. */
    fun disableAndAwait(): Boolean {
        acceptingInput = false
        pointerLayout = null
        return NestLinkAccessibilityService.releasePointer()
    }
}
