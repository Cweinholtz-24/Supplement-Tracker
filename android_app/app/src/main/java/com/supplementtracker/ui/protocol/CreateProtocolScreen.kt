
package com.supplementtracker.ui.protocol

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateProtocolScreen(
    onProtocolCreated: () -> Unit,
    onBackClick: () -> Unit,
    viewModel: CreateProtocolViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    
    var protocolName by remember { mutableStateOf("") }
    var compounds by remember { mutableStateOf(listOf("FOXO4-DRI", "Fisetin", "Quercetin")) }
    var newCompound by remember { mutableStateOf("") }
    
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
                    text = "Compounds",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )
            }
            
            itemsIndexed(compounds) { index, compound ->
                Card {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Medication,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = compound,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyLarge
                        )
                        if (compounds.size > 1) {
                            IconButton(
                                onClick = {
                                    compounds = compounds.toMutableList().apply {
                                        removeAt(index)
                                    }
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
                            OutlinedTextField(
                                value = newCompound,
                                onValueChange = { newCompound = it },
                                label = { Text("Add Compound") },
                                placeholder = { Text("Enter compound name...") },
                                modifier = Modifier.weight(1f),
                                singleLine = true
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            IconButton(
                                onClick = {
                                    if (newCompound.isNotBlank()) {
                                        compounds = compounds + newCompound
                                        newCompound = ""
                                    }
                                },
                                enabled = newCompound.isNotBlank()
                            ) {
                                Icon(Icons.Default.Add, contentDescription = "Add compound")
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
                            text = uiState.error ?: "Failed to create protocol",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }
            }
        }
    }
}
