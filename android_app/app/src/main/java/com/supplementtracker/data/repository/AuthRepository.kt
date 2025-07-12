
package com.supplementtracker.data.repository

import com.supplementtracker.data.local.UserPreferences
import com.supplementtracker.data.model.*
import com.supplementtracker.data.network.ApiService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuthRepository @Inject constructor(
    private val apiService: ApiService,
    private val userPreferences: UserPreferences
) {
    
    fun login(username: String, password: String): Flow<Result<LoginResponse>> = flow {
        try {
            val response = apiService.login(LoginRequest(username, password))
            if (response.isSuccessful) {
                response.body()?.let { loginResponse ->
                    if (loginResponse.requires2FA != true) {
                        // Save user data if login is complete
                        loginResponse.user?.let { user ->
                            userPreferences.saveUser(user)
                        }
                        userPreferences.setLoggedIn(true)
                    }
                    emit(Result.success(loginResponse))
                } ?: emit(Result.failure(Exception("Empty response")))
            } else {
                emit(Result.failure(Exception("Login failed: ${response.message()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
    
    fun verify2FA(code: String): Flow<Result<Unit>> = flow {
        try {
            val response = apiService.verify2FA(TwoFARequest(code))
            if (response.isSuccessful) {
                response.body()?.let { loginResponse ->
                    loginResponse.user?.let { user ->
                        userPreferences.saveUser(user)
                    }
                    userPreferences.setLoggedIn(true)
                    emit(Result.success(Unit))
                } ?: emit(Result.failure(Exception("Empty response")))
            } else {
                emit(Result.failure(Exception("2FA verification failed")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
    
    suspend fun logout() {
        userPreferences.clear()
    }
    
    fun isLoggedIn(): Flow<Boolean> = userPreferences.isLoggedIn()
    
    fun getCurrentUser(): Flow<User?> = userPreferences.getUser()
}
