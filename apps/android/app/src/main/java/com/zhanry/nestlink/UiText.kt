package com.zhanry.nestlink

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.Locale
import java.util.concurrent.CopyOnWriteArraySet

internal enum class DisplayLanguage(val storedValue: String) {
    System("system"), Chinese("zh-Hans"), English("en");

    companion object {
        fun parse(value: String?): DisplayLanguage = entries.firstOrNull { it.storedValue == value } ?: System
    }
}

/** UI-only state. It never enters a native command, proof or consent binding. */
internal object UiLanguage {
    var choice by mutableStateOf(DisplayLanguage.System)
        private set
    private var systemLanguage by mutableStateOf("zh")
    private val listeners = CopyOnWriteArraySet<() -> Unit>()

    val english: Boolean
        get() = when (choice) {
            DisplayLanguage.System -> systemLanguage != "zh"
            DisplayLanguage.Chinese -> false
            DisplayLanguage.English -> true
        }
    val locale: Locale get() = if (english) Locale.ENGLISH else Locale.SIMPLIFIED_CHINESE

    fun update(selected: DisplayLanguage, system: String) {
        choice = selected
        systemLanguage = system.lowercase(Locale.ROOT)
        // Display observers refresh copy only; their platform failures must not
        // roll back the selected language or interrupt a live capture owner.
        listeners.forEach { listener -> runCatching { listener() } }
    }

    fun observe(listener: () -> Unit): AutoCloseable {
        listeners.add(listener)
        return AutoCloseable { listeners.remove(listener) }
    }
}

internal fun UiTextKey.render(english: Boolean, vararg arguments: Any?): String {
    val template = if (english) this.english else chinese
    return if (arguments.isEmpty()) template else String.format(
        if (english) Locale.ENGLISH else Locale.SIMPLIFIED_CHINESE,
        template,
        *arguments,
    )
}

/** Only explicit catalog keys are translated. Arguments remain exact values. */
internal fun uiText(key: UiTextKey, vararg arguments: Any?): String = key.render(UiLanguage.english, *arguments)

/** Presentation only. Serialized protocol values and unknown future states stay intact. */
internal fun remoteRequestStatusLabel(status: String): String = when (status) {
    "pending" -> uiText(UiTextKey.REQUEST_PENDING)
    "approved" -> uiText(UiTextKey.REQUEST_APPROVED)
    "rejected" -> uiText(UiTextKey.REQUEST_REJECTED)
    "revoked" -> uiText(UiTextKey.REVOKED_FEF96)
    "expired" -> uiText(UiTextKey.REQUEST_EXPIRED)
    else -> status
}

internal fun nativeSessionStatusLabel(status: String?): String = when (status) {
    "establishing" -> uiText(UiTextKey.SESSION_CONNECTING)
    "connected" -> uiText(UiTextKey.CONNECTED_5BE03)
    "stopping" -> uiText(UiTextKey.SESSION_STOPPING)
    "stopped" -> uiText(UiTextKey.SESSION_STOPPED)
    "failed" -> uiText(UiTextKey.FAILED_28384)
    else -> status.orEmpty()
}
