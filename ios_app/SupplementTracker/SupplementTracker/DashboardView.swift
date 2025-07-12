struct DashboardView: View {
    @StateObject private var apiService = APIService.shared
    @State private var protocols: [ProtocolModel] = []
    @State private var isLoading = true
    @State private var errorMessage = ""
    @State private var showingError = false
    @State private var showingCreateProtocol = false
    @State private var searchText = ""
    @State private var selectedStats: ProtocolStats?

    var filteredProtocols: [ProtocolModel] {
        if searchText.isEmpty {
            return protocols
        } else {
            return protocols.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
        }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                LazyVStack(spacing: 16) {
                    // Quick Stats Card
                    if !protocols.isEmpty {
                        QuickStatsView(protocols: protocols)
                            .padding(.horizontal)
                    }

                    // Search Bar
                    SearchBar(text: $searchText)
                        .padding(.horizontal)

                    // Quick Actions
                    QuickActionsView(showingCreateProtocol: $showingCreateProtocol)
                        .padding(.horizontal)

                    // Protocols List
                    if isLoading {
                        ProgressView("Loading protocols...")
                            .frame(maxWidth: .infinity, minHeight: 200)
                    } else if filteredProtocols.isEmpty {
                        EmptyStateView(showingCreateProtocol: $showingCreateProtocol)
                    } else {
                        LazyVStack(spacing: 12) {
                            ForEach(filteredProtocols) { protocol in
                                ProtocolCardView(protocol: protocol, onStatsRequested: { stats in
                                    selectedStats = stats
                                })
                                .padding(.horizontal)
                            }
                        }
                    }
                }
                .padding(.vertical)
            }
            .navigationTitle("My Protocols")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        showingCreateProtocol = true
                    }) {
                        Image(systemName: "plus.circle.fill")
                            .font(.title2)
                    }
                }

                ToolbarItem(placement: .navigationBarLeading) {
                    NavigationLink(destination: SettingsView()) {
                        Image(systemName: "person.circle")
                            .font(.title2)
                    }
                }
            }
            .refreshable {
                await loadProtocols()
            }
        }
        .sheet(isPresented: $showingCreateProtocol) {
            CreateProtocolView { newProtocol in
                protocols.append(newProtocol)
            }
        }
        .sheet(item: $selectedStats) { stats in
            ProtocolStatsDetailView(stats: stats)
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
        .task {
            await loadProtocols()
        }
    }

    private func loadProtocols() async {
        isLoading = true
        do {
            protocols = try await apiService.getProtocols()
        } catch {
            errorMessage = error.localizedDescription
            showingError = true
        }
        isLoading = false
    }
}

struct QuickStatsView: View {
    let protocols: [ProtocolModel]

    private var totalProtocols: Int {
        protocols.count
    }

    private var activeProtocols: Int {
        protocols.filter { $0.displayIsActive }.count
    }

    private var totalCompounds: Int {
        protocols.reduce(0) { $0 + $1.compounds.count }
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Quick Stats")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)

            HStack(spacing: 16) {
                StatCardView(title: "Total Protocols", value: "\(totalProtocols)", color: .blue)
                StatCardView(title: "Active", value: "\(activeProtocols)", color: .green)
                StatCardView(title: "Compounds", value: "\(totalCompounds)", color: .purple)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct StatCardView: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(color)

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(.systemBackground))
        .cornerRadius(8)
    }
}

struct SearchBar: View {
    @Binding var text: String

    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass")
                .foregroundColor(.secondary)

            TextField("Search protocols...", text: $text)
                .textFieldStyle(PlainTextFieldStyle())

            if !text.isEmpty {
                Button(action: {
                    text = ""
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

struct QuickActionsView: View {
    @Binding var showingCreateProtocol: Bool

    var body: some View {
        VStack(spacing: 12) {
            Text("Quick Actions")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    QuickActionButton(
                        icon: "plus.circle",
                        title: "New Protocol",
                        color: .blue
                    ) {
                        showingCreateProtocol = true
                    }

                    QuickActionButton(
                        icon: "chart.bar",
                        title: "Analytics",
                        color: .green
                    ) {
                        // Navigate to analytics
                    }

                    QuickActionButton(
                        icon: "bell",
                        title: "Reminders",
                        color: .orange
                    ) {
                        // Navigate to reminders
                    }

                    QuickActionButton(
                        icon: "square.and.arrow.up",
                        title: "Export",
                        color: .purple
                    ) {
                        // Export data
                    }
                }
                .padding(.horizontal)
            }
        }
    }
}

struct QuickActionButton: View {
    let icon: String
    let title: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)

                Text(title)
                    .font(.caption)
                    .foregroundColor(.primary)
            }
            .frame(width: 80, height: 60)
            .background(Color(.systemGray6))
            .cornerRadius(8)
        }
    }
}

struct ProtocolCardView: View {
    let protocol: ProtocolModel
    let onStatsRequested: (ProtocolStats) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(protocol.name)
                        .font(.headline)
                        .fontWeight(.semibold)

                    Text("\(protocol.compounds.count) compounds • \(protocol.displayFrequency)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button(action: {
                    // Generate sample stats - in real app, fetch from API
                    let stats = ProtocolStats(
                        id: protocol.id,
                        name: protocol.name,
                        totalDays: 30,
                        adherence: 85.5,
                        streak: 7,
                        weeklyStats: [:],
                        monthlyStats: [:]
                    )
                    onStatsRequested(stats)
                }) {
                    Image(systemName: "chart.bar.xaxis")
                        .foregroundColor(.blue)
                }
            }

            // Compounds preview
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 2), spacing: 8) {
                ForEach(protocol.compounds.prefix(4), id: \.id) { compound in
                    HStack {
                        Text(compound.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Text("\(compound.dailyDosage)\(compound.unit)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color(.systemGray6))
                    .cornerRadius(4)
                }
            }

            if protocol.compounds.count > 4 {
                Text("and \(protocol.compounds.count - 4) more...")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack {
                NavigationLink(destination: ProtocolDetailView(protocol: protocol)) {
                    Text("Track Today")
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(Color.blue)
                        .cornerRadius(6)
                }

                NavigationLink(destination: ProtocolHistoryView(protocolId: protocol.id)) {
                    Text("History")
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(6)
                }
            }
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.1), radius: 2, x: 0, y: 1)
    }
}

struct EmptyStateView: View {
    @Binding var showingCreateProtocol: Bool

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "pills")
                .font(.system(size: 60))
                .foregroundColor(.secondary)

            Text("No Protocols Yet")
                .font(.title2)
                .fontWeight(.semibold)

            Text("Create your first supplement protocol to start tracking your daily intake")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button(action: {
                showingCreateProtocol = true
            }) {
                Text("Create Protocol")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(10)
            }
            .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, minHeight: 300)
    }
}

struct ProtocolStats: Identifiable {
    let id: String
    let name: String
    let totalDays: Int
    let adherence: Double
    let streak: Int
    let weeklyStats: [String: Any]
    let monthlyStats: [String: Any]
}

struct ProtocolStatsDetailView: View {
    let stats: ProtocolStats

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    Text("Protocol Statistics")
                        .font(.title2)
                        .fontWeight(.bold)

                    VStack(spacing: 16) {
                        StatRow(title: "Total Days", value: "\(stats.totalDays)")
                        StatRow(title: "Adherence", value: String(format: "%.1f%%", stats.adherence))
                        StatRow(title: "Current Streak", value: "\(stats.streak) days")
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                }
                .padding()
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        // Dismiss
                    }
                }
            }
        }
    }
}

struct StatRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .font(.subheadline)
            Spacer()
            Text(value)
                .font(.subheadline)
                .fontWeight(.semibold)
        }
    }
}

struct ProtocolHistoryView: View {
    let protocolId: String

    var body: some View {
        Text("Protocol History for \(protocolId)")
            .navigationTitle("History")
            .navigationBarTitleDisplayMode(.inline)
    }
}

struct SettingsView: View {
    var body: some View {
        Text("Settings")
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
    }
}

struct CreateProtocolView: View {
    let onProtocolCreated: (ProtocolModel) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            Text("Create Protocol")
                .navigationTitle("New Protocol")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button("Cancel") {
                            dismiss()
                        }
                    }
                }
        }
    }
}

#Preview {
    DashboardView()
}