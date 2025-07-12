
package com.supplementtracker.ui.analytics

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.supplementtracker.data.model.Analytics
import com.supplementtracker.data.model.UiState
import com.supplementtracker.data.repository.ProtocolRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AnalyticsViewModel @Inject constructor(
    private val protocolRepository: ProtocolRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(UiState<Analytics>())
    val uiState: StateFlow<UiState<Analytics>> = _uiState.asStateFlow()
    
    fun loadAnalytics(protocolId: String) {
        viewModelScope.launch {
            _uiState.value = UiState(loading = true)
            
            protocolRepository.getProtocolAnalytics(protocolId)
                .catch { e ->
                    _uiState.value = UiState(error = e.message ?: "Failed to load analytics")
                }
                .collect { result ->
                    result.fold(
                        onSuccess = { analytics ->
                            _uiState.value = UiState(data = analytics)
                        },
                        onFailure = { e ->
                            _uiState.value = UiState(error = e.message ?: "Failed to load analytics")
                        }
                    )
                }
        }
    }
}
