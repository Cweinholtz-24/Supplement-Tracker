
package com.supplementtracker.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import com.google.gson.Gson
import com.supplementtracker.data.model.AppSettings
import com.supplementtracker.data.model.User
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "user_preferences")

@Singleton
class UserPreferences @Inject constructor(
    @ApplicationContext private val context: Context,
    private val gson: Gson = Gson()
) {
    
    private object PreferencesKeys {
        val IS_LOGGED_IN = booleanPreferencesKey("is_logged_in")
        val USER_DATA = stringPreferencesKey("user_data")
        val APP_SETTINGS = stringPreferencesKey("app_settings")
    }
    
    fun isLoggedIn(): Flow<Boolean> = context.dataStore.data.map { preferences ->
        preferences[PreferencesKeys.IS_LOGGED_IN] ?: false
    }
    
    suspend fun setLoggedIn(isLoggedIn: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[PreferencesKeys.IS_LOGGED_IN] = isLoggedIn
        }
    }
    
    fun getUser(): Flow<User?> = context.dataStore.data.map { preferences ->
        preferences[PreferencesKeys.USER_DATA]?.let { userJson ->
            try {
                gson.fromJson(userJson, User::class.java)
            } catch (e: Exception) {
                null
            }
        }
    }
    
    suspend fun saveUser(user: User) {
        context.dataStore.edit { preferences ->
            preferences[PreferencesKeys.USER_DATA] = gson.toJson(user)
        }
    }
    
    fun getAppSettings(): Flow<AppSettings> = context.dataStore.data.map { preferences ->
        preferences[PreferencesKeys.APP_SETTINGS]?.let { settingsJson ->
            try {
                gson.fromJson(settingsJson, AppSettings::class.java)
            } catch (e: Exception) {
                AppSettings()
            }
        } ?: AppSettings()
    }
    
    suspend fun saveAppSettings(settings: AppSettings) {
        context.dataStore.edit { preferences ->
            preferences[PreferencesKeys.APP_SETTINGS] = gson.toJson(settings)
        }
    }
    
    suspend fun clear() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }
}
