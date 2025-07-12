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

    private val _uiState = MutableStateFlow(CreateProtocolUiState())
    val uiState: StateFlow<CreateProtocolUiState> = _uiState.asStateFlow()

    private val _availableCompounds = MutableStateFlow<List<String>>(emptyList())
    val availableCompounds: StateFlow<List<String>> = _availableCompounds.asStateFlow()

    fun loadAvailableCompounds() {
        viewModelScope.launch {
            try {
                val compounds = protocolRepository.getAvailableCompounds()
                _availableCompounds.value = compounds
            } catch (e: Exception) {
                // Handle error silently for now
            }
        }
    }

    fun addCustomCompound(name: String) {
        viewModelScope.launch {
            try {
                protocolRepository.addCustomCompound(name)
                loadAvailableCompounds()
            } catch (e: Exception) {
                // Handle error
            }
        }
    }

    fun createProtocol(name: String, compounds: List<CompoundDetail>) {
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