
package com.supplementtracker.ui.protocol

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.supplementtracker.data.model.Protocol
import com.supplementtracker.data.model.UiState
import com.supplementtracker.data.repository.ProtocolRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CreateProtocolViewModel @Inject constructor(
    private val protocolRepository: ProtocolRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(UiState<Protocol>())
    val uiState: StateFlow<UiState<Protocol>> = _uiState.asStateFlow()
    
    fun createProtocol(name: String, compounds: List<String>) {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            protocolRepository.createProtocol(name, compounds)
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "Failed to create protocol")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = { protocol ->
                            _uiState.value = UiState(data = protocol)
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "Failed to create protocol")
                        }
                    )
                }
        }
    }
}
