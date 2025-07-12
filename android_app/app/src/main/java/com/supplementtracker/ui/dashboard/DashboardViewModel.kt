
package com.supplementtracker.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.supplementtracker.data.model.Protocol
import com.supplementtracker.data.model.UiState
import com.supplementtracker.data.model.User
import com.supplementtracker.data.repository.AuthRepository
import com.supplementtracker.data.repository.ProtocolRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val protocolRepository: ProtocolRepository,
    private val authRepository: AuthRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(UiState<List<Protocol>>())
    val uiState: StateFlow<UiState<List<Protocol>>> = _uiState.asStateFlow()
    
    val currentUser: StateFlow<User?> = authRepository.getCurrentUser()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = null
        )
    
    fun loadProtocols() {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            protocolRepository.getProtocols()
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "Failed to load protocols")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = { protocols ->
                            _uiState.value = UiState(data = protocols)
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "Failed to load protocols")
                        }
                    )
                }
        }
    }
    
    fun logout() {
        viewModelScope.launch {
            authRepository.logout()
        }
    }
}
