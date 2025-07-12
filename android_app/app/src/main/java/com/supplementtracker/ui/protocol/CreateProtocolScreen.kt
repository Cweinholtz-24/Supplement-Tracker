
package com.supplementtracker.ui.protocol

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsState
import com.supplementtracker.data.model.CompoundDetail

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateProtocolScreen(
    onProtocolCreated: () -> Unit,
    onBackClick: () -> Unit,
    viewModel: CreateProtocolViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val availableCompounds by viewModel.availableCompounds.collectAsState()
    
    var protocolName by remember { mutableStateOf("") }
    var compounds by remember { mutableStateOf(listOf<CompoundDetail>()) }
    var selectedCompound by remember { mutableStateOf("") }
    var dailyDosage by remember { mutableStateOf("1") }
    var timesPerDay by remember { mutableStateOf(1) }
    var unit by remember { mutableStateOf("capsule") }
    var showAddCustom by remember { mutableStateOf(false) }
    var newCompoundName by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf(false) }
    
    LaunchedEffect(Unit) {
        viewModel.loadAvailableCompounds()
    }
    
    LaunchedEffect(uiState.isSuccess) {
        if (uiState.isSuccess) {
            onProtocolCreated()
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { 
                    Text(
                        text = "Create Protocol",
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                OutlinedTextField(
                    value = protocolName,
                    onValueChange = { protocolName = it },
                    label = { Text("Protocol Name") },
                    placeholder = { Text("Enter protocol name...") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
            
            item {
                Text(
                    text = "Add Compounds",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )
            }
            
            item {
                Card {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp)
                    ) {
                        // Compound dropdown
                        ExposedDropdownMenuBox(
                            expanded = expanded,
                            onExpandedChange = { expanded = !expanded }
                        ) {
                            OutlinedTextField(
                                value = selectedCompound,
                                onValueChange = { },
                                readOnly = true,
                                label = { Text("Select Compound") },
                                trailingIcon = {
                                    ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded)
                                },
                                modifier = Modifier
                                    .menuAnchor()
                                    .fillMaxWidth()
                            )
                            
                            ExposedDropdownMenu(
                                expanded = expanded,
                                onDismissRequest = { expanded = false }
                            ) {
                                availableCompounds.forEach { compound ->
                                    DropdownMenuItem(
                                        text = { Text(compound) },
                                        onClick = {
                                            selectedCompound = compound
                                            expanded = false
                                        }
                                    )
                                }
                                
                                Divider()
                                
                                DropdownMenuItem(
                                    text = { Text("Add Custom Compound...") },
                                    onClick = {
                                        showAddCustom = true
                                        expanded = false
                                    },
                                    leadingIcon = {
                                        Icon(Icons.Default.Add, contentDescription = null)
                                    }
                                )
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = dailyDosage,
                                onValueChange = { dailyDosage = it },
                                label = { Text("Dosage") },
                                modifier = Modifier.weight(1f)
                            )
                            
                            OutlinedTextField(
                                value = timesPerDay.toString(),
                                onValueChange = { 
                                    timesPerDay = it.toIntOrNull() ?: 1
                                },
                                label = { Text("Times/Day") },
                                modifier = Modifier.weight(1f)
                            )
                        }
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        OutlinedTextField(
                            value = unit,
                            onValueChange = { unit = it },
                            label = { Text("Unit") },
                            placeholder = { Text("capsule, mg, ml, etc.") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Button(
                            onClick = {
                                if (selectedCompound.isNotBlank()) {
                                    val newCompound = CompoundDetail(
                                        name = selectedCompound,
                                        dailyDosage = dailyDosage,
                                        timesPerDay = timesPerDay,
                                        unit = unit
                                    )
                                    compounds = compounds + newCompound
                                    selectedCompound = ""
                                    dailyDosage = "1"
                                    timesPerDay = 1
                                    unit = "capsule"
                                }
                            },
                            enabled = selectedCompound.isNotBlank(),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Add Compound")
                        }
                    }
                }
            }
            
            item {
                Text(
                    text = "Protocol Compounds",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )
            }
            
            items(compounds) { compound ->
                Card {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = compound.name,
                                    style = MaterialTheme.typography.bodyLarge,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    text = "${compound.dailyDosage} ${compound.unit}, ${compound.timesPerDay}x daily",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            
                            IconButton(
                                onClick = {
                                    compounds = compounds.filterNot { it == compound }
                                }
                            ) {
                                Icon(
                                    Icons.Default.Delete,
                                    contentDescription = "Remove compound",
                                    tint = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                    }
                }
            }
            
            item {
                Button(
                    onClick = { viewModel.createProtocol(protocolName, compounds) },
                    enabled = protocolName.isNotBlank() && compounds.isNotEmpty() && !uiState.isLoading,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text("Create Protocol")
                }
            }
            
            if (uiState.isError) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            text = uiState.errorMessage,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }
            }
        }
    }
    
    // Add Custom Compound Dialog
    if (showAddCustom) {
        AlertDialog(
            onDismissRequest = { showAddCustom = false },
            title = { Text("Add Custom Compound") },
            text = {
                OutlinedTextField(
                    value = newCompoundName,
                    onValueChange = { newCompoundName = it },
                    label = { Text("Compound Name") },
                    placeholder = { Text("Enter compound name...") },
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (newCompoundName.isNotBlank()) {
                            viewModel.addCustomCompound(newCompoundName)
                            selectedCompound = newCompoundName
                            newCompoundName = ""
                            showAddCustom = false
                        }
                    },
                    enabled = newCompoundName.isNotBlank()
                ) {
                    Text("Add")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddCustom = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}
