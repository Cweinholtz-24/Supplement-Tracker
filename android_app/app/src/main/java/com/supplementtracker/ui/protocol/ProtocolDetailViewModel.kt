
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
class ProtocolDetailViewModel @Inject constructor(
    private val protocolRepository: ProtocolRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(UiState<Protocol>())
    val uiState: StateFlow<UiState<Protocol>> = _uiState.asStateFlow()
    
    private val _saveState = MutableStateFlow(UiState<Unit>())
    val saveState: StateFlow<UiState<Unit>> = _saveState.asStateFlow()
    
    fun loadProtocol(protocolId: String) {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            protocolRepository.getProtocols()
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "Failed to load protocol")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = { protocols ->
                            val protocol = protocols.find { it.id == protocolId }
                            if (protocol != null) {
                                _uiState.value = UiState(data = protocol)
                            } else {
                                _uiState.value = UiState(error = "Protocol not found")
                            }
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "Failed to load protocol")
                        }
                    )
                }
        }
    }
    
    fun saveLog(
        protocolId: String,
        compounds: Map<String, Boolean>,
        notes: Map<String, String>
    ) {
        viewModelScope.launch {
            _saveState.value = UiState(loading = true)
            
            protocolRepository.saveProtocolLog(protocolId, compounds, notes)
                .catch { e ->
                    _saveState.value = UiState(error = e.message ?: "Failed to save log")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = {
                            _saveState.value = UiState(data = Unit)
                        },
                        onFailure = { e ->
                            _saveState.value = UiState(error = e.message ?: "Failed to save log")
                        }
                    )
                }
        }
    }
}
