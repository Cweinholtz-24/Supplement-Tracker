
package com.supplementtracker.data.model

import kotlinx.datetime.LocalDate
import kotlinx.datetime.Clock
import kotlinx.datetime.TimeZone
import kotlinx.datetime.todayIn
import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class User(
    val id: String,
    val username: String,
    val email: String? = null
) : Parcelable

@Parcelize
data class Protocol(
    val id: String,
    val name: String,
    val compounds: List<String>,
    val frequency: String = "Daily",
    val description: String? = null,
    val isActive: Boolean = true,
    val createdAt: String
) : Parcelable

@Parcelize
data class ProtocolLog(
    val id: String,
    val protocolId: String,
    val date: String,
    val compounds: Map<String, CompoundEntry>,
    val mood: String? = null,
    val energy: String? = null,
    val sideEffects: String? = null,
    val weight: String? = null,
    val generalNotes: String? = null
) : Parcelable

@Parcelize
data class CompoundEntry(
    val taken: Boolean,
    val note: String? = null
) : Parcelable

@Parcelize
data class Analytics(
    val totalDays: Int,
    val adherence: Double,
    val streak: Int,
    val missedDays: Int,
    val compoundStats: Map<String, CompoundStats>
) : Parcelable

@Parcelize
data class CompoundStats(
    val taken: Int,
    val missed: Int,
    val percentage: Double
) : Parcelable

@Parcelize
data class Notification(
    val id: String,
    val title: String,
    val message: String,
    val type: String = "info",
    val isRead: Boolean = false,
    val createdAt: String
) : Parcelable

// API Request/Response models
data class LoginRequest(
    val username: String,
    val password: String
)

data class LoginResponse(
    val success: Boolean? = null,
    val requires2FA: Boolean? = null,
    val message: String,
    val user: User? = null,
    val token: String? = null
)

data class TwoFARequest(
    val code: String
)

data class CreateProtocolRequest(
    val name: String,
    val compounds: List<String>
)

data class ProtocolLogRequest(
    val compounds: Map<String, Boolean>,
    val notes: Map<String, String>
)

// UI State models
data class UiState<T>(
    val data: T? = null,
    val loading: Boolean = false,
    val error: String? = null
) {
    val isSuccess: Boolean get() = data != null && !loading && error == null
    val isError: Boolean get() = error != null
    val isLoading: Boolean get() = loading
}

// Settings
data class AppSettings(
    val notificationsEnabled: Boolean = true,
    val reminderTime: String = "09:00",
    val darkMode: Boolean = false,
    val healthConnectEnabled: Boolean = false
)

// Calendar data
data class CalendarEvent(
    val date: String,
    val taken: Int,
    val total: Int,
    val missed: Int,
    val completed: Boolean,
    val entries: Map<String, CompoundEntry>
)
