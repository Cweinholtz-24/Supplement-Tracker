
package com.supplementtracker.ui.auth

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.supplementtracker.data.model.UiState
import com.supplementtracker.data.repository.AuthRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(UiState<Unit>())
    val uiState: StateFlow<UiState<Unit>> = _uiState.asStateFlow()
    
    private val _requires2FA = MutableStateFlow(false)
    val requires2FA: StateFlow<Boolean> = _requires2FA.asStateFlow()
    
    val isLoggedIn: StateFlow<Boolean> = authRepository.isLoggedIn()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = false
        )
    
    fun login(username: String, password: String) {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            authRepository.login(username, password)
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "Login failed")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = { loginResponse ->
                            if (loginResponse.requires2FA == true) {
                                _requires2FA.value = true
                                _uiState.value = UiState(data = Unit)
                            } else {
                                _uiState.value = UiState(data = Unit)
                            }
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "Login failed")
                        }
                    )
                }
        }
    }
    
    fun verify2FA(code: String) {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            authRepository.verify2FA(code)
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "2FA verification failed")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = {
                            _requires2FA.value = false
                            _uiState.value = UiState(data = Unit)
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "2FA verification failed")
                        }
                    )
                }
        }
    }
    
    fun resetLogin() {
        _requires2FA.value = false
        _uiState.value = UiState()
    }
}
