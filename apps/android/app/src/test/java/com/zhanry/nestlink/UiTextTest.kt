package com.zhanry.nestlink

import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class UiTextTest {
    @After fun restoreLanguage() { UiLanguage.update(DisplayLanguage.System, "zh") }

    @Test fun everyLocalCopyHasEnglishAndMatchingFormatArguments() {
        val placeholders = Regex("%(\\d+)\\\$s")
        val han = Regex("[\\u3400-\\u9fff]")
        assertTrue(UiTextKey.entries.size >= 570)
        UiTextKey.entries.forEach { key ->
            assertTrue(key.name, key.chinese.isNotBlank())
            assertTrue(key.name, key.english.isNotBlank())
            assertFalse(key.name, han.containsMatchIn(key.english))
            val chinese = placeholders.findAll(key.chinese).map { it.groupValues[1] }.sorted().toList()
            val english = placeholders.findAll(key.english).map { it.groupValues[1] }.sorted().toList()
            assertEquals(key.name, chinese, english)
            val count = english.map(String::toInt).maxOrNull() ?: 0
            val arguments = Array<Any?>(count) { "literal argument ${it + 1}: /目录/100% \"device\"" }
            for (useEnglish in listOf(false, true)) {
                val rendered = key.render(useEnglish, *arguments)
                arguments.forEach { assertTrue(key.name, rendered.contains(it.toString())) }
            }
        }
    }

    @Test fun selectionAndSystemFallbackChooseCopyWithoutChangingProtocolValues() {
        val key = UiTextKey.HOST_04166
        // Use an explicit template: dynamic device names remain byte-for-byte.
        val host = "设备/host:443?x=direct_only"
        UiLanguage.update(DisplayLanguage.English, "zh")
        assertTrue(UiLanguage.english)
        assertEquals("Host: $host", uiText(key, host))
        assertEquals("future_session_state/原值", nativeSessionStatusLabel("future_session_state/原值"))
        assertEquals("future_request_state/原值", remoteRequestStatusLabel("future_request_state/原值"))
        UiLanguage.update(DisplayLanguage.Chinese, "en")
        assertFalse(UiLanguage.english)
        assertEquals("主机：$host", uiText(key, host))
        UiLanguage.update(DisplayLanguage.System, "zh")
        assertFalse(UiLanguage.english)
        UiLanguage.update(DisplayLanguage.System, "fr")
        assertTrue(UiLanguage.english)
        assertEquals(DisplayLanguage.System, DisplayLanguage.parse("unexpected"))
    }

    @Test fun formattingCanReorderArgumentsWithoutReinterpretingTheirContent() {
        val key = UiTextKey.REVOKE_REVISION_OF_THE_SERVER_CHECKS_FB567
        val service = "service%2\$s/中文"
        val rendered = key.render(true, service, 17)
        assertTrue(rendered.contains("revision 17"))
        assertTrue(rendered.contains(service))
    }

    @Test fun languageObserversCanRefreshCopyAndDetachWithoutAnActivityRestart() {
        var notifications = 0
        val observation = UiLanguage.observe { notifications++ }
        UiLanguage.update(DisplayLanguage.English, "zh")
        assertEquals(1, notifications)
        observation.close()
        UiLanguage.update(DisplayLanguage.Chinese, "en")
        assertEquals(1, notifications)
    }

    @Test fun failingCopyObserverCannotInterruptSelectionOrOtherOwners() {
        var notifications = 0
        val failed = UiLanguage.observe { error("Notification service unavailable") }
        val healthy = UiLanguage.observe { notifications++ }
        try {
            UiLanguage.update(DisplayLanguage.English, "zh")
            assertTrue(UiLanguage.english)
            assertEquals(1, notifications)
        } finally {
            failed.close()
            healthy.close()
        }
    }
}
