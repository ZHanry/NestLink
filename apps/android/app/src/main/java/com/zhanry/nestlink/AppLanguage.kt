package com.zhanry.nestlink

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import android.view.ContextThemeWrapper
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

class NestLinkApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppLanguage.initialize(this)
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        AppLanguage.initialize(this)
    }
}

internal object AppLanguage {
    private const val PREFERENCES = "display-language"
    private const val CHOICE = "choice"

    fun initialize(context: Context) {
        val selected = DisplayLanguage.parse(context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getString(CHOICE, null))
        UiLanguage.update(selected, context.resources.configuration.locales[0].language)
    }

    fun select(context: Context, selected: DisplayLanguage): Boolean {
        // Persist first. Failure keeps the current display language intact.
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val previous = preferences.getString(CHOICE, null)
        if (!preferences.edit().putString(CHOICE, selected.storedValue).commit()) {
            // SharedPreferences updates its in-memory map even if commit fails.
            // Restore it so a configuration callback cannot publish that choice.
            preferences.edit().apply {
                if (previous == null) remove(CHOICE) else putString(CHOICE, previous)
            }.apply()
            return false
        }
        UiLanguage.update(selected, context.resources.configuration.locales[0].language)
        return true
    }

    fun context(base: Context): Context {
        val configuration = Configuration(base.resources.configuration)
        configuration.setLocales(LocaleList(UiLanguage.locale))
        // Preserve the Activity in the wrapper chain for ActivityResult owners.
        return ContextThemeWrapper(base, base.theme).apply { applyOverrideConfiguration(configuration) }
    }
}

/** A resource context change only: no Activity recreation or capture restart. */
@Composable
internal fun AppLanguageScope(content: @Composable () -> Unit) {
    val base = LocalContext.current
    val configuration = LocalConfiguration.current
    val locale = UiLanguage.locale
    val localized = remember(base, configuration, locale) { AppLanguage.context(base) }
    CompositionLocalProvider(
        LocalContext provides localized,
        LocalConfiguration provides localized.resources.configuration,
        content = content,
    )
}

@Composable
internal fun AppLanguagePicker() {
    val context = LocalContext.current.applicationContext
    val choice = UiLanguage.choice
    var saveFailed by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp)) {
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.display_language), style = MaterialTheme.typography.labelMedium)
            DisplayLanguage.entries.forEach { language ->
                FilterChip(
                    selected = choice == language,
                    onClick = { saveFailed = !AppLanguage.select(context, language) },
                    label = { Text(when (language) {
                        DisplayLanguage.System -> stringResource(R.string.display_language_system)
                        DisplayLanguage.Chinese -> "中文"
                        DisplayLanguage.English -> "English"
                    }) },
                )
            }
        }
        if (saveFailed) Text(stringResource(R.string.display_language_save_failed), color = MaterialTheme.colorScheme.error)
    }
}
