package com.supplementtracker.data.repository

import com.supplementtracker.data.model.*
import com.supplementtracker.data.network.ApiService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ProtocolRepository @Inject constructor(
    private val apiService: ApiService
) {

    fun getProtocols(): Flow<Result<List<Protocol>>> = flow {
        try {
            val response = apiService.getProtocols()
            if (response.isSuccessful) {
                response.body()?.let { protocols ->
                    emit(Result.success(protocols))
                } ?: emit(Result.failure(Exception("Empty response")))
            } else {
                emit(Result.failure(Exception("Failed to fetch protocols: ${response.message()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    suspend fun getAvailableCompounds(): List<String> {
        return apiService.getAvailableCompounds().compounds
    }

    suspend fun addCustomCompound(name: String) {
        apiService.addCustomCompound(AddCompoundRequest(name))
    }

    suspend fun createProtocol(name: String, compounds: List<CompoundDetail>): Protocol {
        return apiService.createProtocol(CreateProtocolRequest(name, compounds))
    }

    fun saveProtocolLog(
        protocolId: String, 
        compounds: Map<String, Boolean>, 
        notes: Map<String, String>
    ): Flow<Result<Unit>> = flow {
        try {
            val response = apiService.saveProtocolLog(
                protocolId, 
                ProtocolLogRequest(compounds, notes)
            )
            if (response.isSuccessful) {
                emit(Result.success(Unit))
            } else {
                emit(Result.failure(Exception("Failed to save log: ${response.message()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getProtocolAnalytics(protocolId: String): Flow<Result<Analytics>> = flow {
        try {
            val response = apiService.getProtocolAnalytics(protocolId)
            if (response.isSuccessful) {
                response.body()?.let { analytics ->
                    emit(Result.success(analytics))
                } ?: emit(Result.failure(Exception("Empty response")))
            } else {
                emit(Result.failure(Exception("Failed to fetch analytics: ${response.message()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getProtocolCalendar(protocolId: String): Flow<Result<List<CalendarEvent>>> = flow {
        try {
            val response = apiService.getProtocolCalendar(protocolId)
            if (response.isSuccessful) {
                response.body()?.let { calendar ->
                    emit(Result.success(calendar))
                } ?: emit(Result.failure(Exception("Empty response")))
            } else {
                emit(Result.failure(Exception("Failed to fetch calendar: ${response.message()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
}