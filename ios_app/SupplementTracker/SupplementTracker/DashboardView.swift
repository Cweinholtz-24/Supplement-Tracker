//
//  DashboardView.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var apiService: APIService
    @State private var protocols: [ProtocolModel] = []
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false
    @State private var showingCreateProtocol = false
    @State private var showingNotifications = false
    @State private var showingSettings = false
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            // Protocols Tab
            NavigationView {
                VStack {
                    if isLoading {
                        ProgressView("Loading protocols...")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else if protocols.isEmpty {
                        EmptyStateView {
                            showingCreateProtocol = true
                        }
                    } else {
                        ScrollView {
                            LazyVStack(spacing: 16) {
                                ForEach(protocols, id: \.id) { protocolItem in
                                    NavigationLink(destination: ProtocolDetailView(protocolItem: protocolItem)) {
                                        ProtocolRowView(protocolItem: protocolItem)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                            .padding()
                        }
                    }
                }
                .navigationTitle("Protocols")
                .navigationBarTitleDisplayMode(.large)
                .toolbar {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button(action: { showingNotifications = true }) {
                            Image(systemName: "bell")
                                .foregroundColor(.blue)
                        }
                    }
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button(action: { showingCreateProtocol = true }) {
                            Image(systemName: "plus")
                                .foregroundColor(.blue)
                        }
                    }
                }
            }
            .tabItem {
                Image(systemName: "pills")
                Text("Protocols")
            }
            .tag(0)

            // Analytics Tab
            AnalyticsTabView()
                .tabItem {
                    Image(systemName: "chart.bar")
                    Text("Analytics")
                }
                .tag(1)

            // Calendar Tab
            CalendarTabView()
                .tabItem {
                    Image(systemName: "calendar")
                    Text("Calendar")
                }
                .tag(2)

            // Settings Tab
            SettingsTabView()
                .tabItem {
                    Image(systemName: "gear")
                    Text("Settings")
                }
                .tag(3)
        }
        .onAppear {
            fetchProtocols()
            fetchNotifications()
        }
        .sheet(isPresented: $showingCreateProtocol) {
            CreateProtocolView { newProtocol in
                protocols.append(newProtocol)
            }
        }
        .sheet(isPresented: $showingNotifications) {
            NotificationsView()
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }

    private func fetchProtocols() {
        isLoading = true
        apiService.fetchProtocols { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let fetchedProtocols):
                    protocols = fetchedProtocols
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }

    private func fetchNotifications() {
        apiService.fetchNotifications { result in
            switch result {
            case .success:
                // Notifications are automatically updated in APIService
                break
            case .failure(let error):
                print("Failed to fetch notifications: \(error)")
            }
        }
    }
}

struct EmptyStateView: View {
    let onCreateProtocol: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "pills.circle")
                .font(.system(size: 80))
                .foregroundColor(.gray)

            VStack(spacing: 8) {
                Text("No Protocols Yet")
                    .font(.title2)
                    .fontWeight(.semibold)

                Text("Create your first supplement protocol to start tracking")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }

            Button(action: onCreateProtocol) {
                Text("Create Protocol")
                    .fontWeight(.semibold)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
            }
            .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct CreateProtocolView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var apiService: APIService
    @State private var protocolName = ""
    @State private var compounds = [""]
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingError = false

    let onProtocolCreated: (ProtocolModel) -> Void

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Protocol Details")) {
                    TextField("Protocol Name", text: $protocolName)
                }

                Section(header: Text("Compounds")) {
                    ForEach(compounds.indices, id: \.self) { compoundIndex in
                        HStack {
                            TextField("Compound name", text: $compounds[compoundIndex])
                            if compounds.count > 1 {
                                Button(action: { removeCompound(at: compoundIndex) }) {
                                    Image(systemName: "minus.circle.fill")
                                        .foregroundColor(.red)
                                }
                            }
                        }
                    }

                    Button(action: addCompound) {
                        HStack {
                            Image(systemName: "plus.circle.fill")
                                .foregroundColor(.blue)
                            Text("Add Compound")
                        }
                    }
                }
            }
            .navigationTitle("Create Protocol")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: createProtocol) {
                        if isLoading {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Text("Create")
                        }
                    }
                    .disabled(protocolName.isEmpty || compounds.allSatisfy { $0.isEmpty } || isLoading)
                }
            }
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }

    private func addCompound() {
        compounds.append("")
    }

    private func removeCompound(at index: Int) {
        compounds.remove(at: index)
    }

    private func createProtocol() {
        isLoading = true
        let filteredCompounds = compounds.filter { !$0.isEmpty }

        apiService.createProtocol(name: protocolName, compounds: filteredCompounds) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let newProtocol):
                    onProtocolCreated(newProtocol)
                    dismiss()
                case .failure(let error):
                    errorMessage = error.localizedDescription
                    showingError = true
                }
            }
        }
    }
}

struct AnalyticsTabView: View {
    @EnvironmentObject var apiService: APIService
    @State private var protocols: [ProtocolModel] = []
    @State private var selectedProtocolId: String?
    @State private var analytics: AnalyticsModel?
    @State private var isLoading = false

    var body: some View {
        NavigationView {
            VStack {
                if protocols.isEmpty {
                    Text("No protocols available for analytics")
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    VStack(spacing: 20) {
                        // Protocol Selector
                        Picker("Select Protocol", selection: $selectedProtocolId) {
                            ForEach(protocols) { protocol in
                                Text(protocol.name).tag(protocol.id as String?)
                            }
                        }
                        .pickerStyle(MenuPickerStyle())
                        .padding(.horizontal)

                        if isLoading {
                            ProgressView("Loading analytics...")
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        } else if let analytics = analytics {
                            ScrollView {
                                AnalyticsDetailView(analytics: analytics)
                            }
                        } else {
                            Text("Select a protocol to view analytics")
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    }
                }
            }
            .navigationTitle("Analytics")
            .onAppear {
                fetchProtocols()
            }
            .onChange(of: selectedProtocolId) { _, newValue in
                if let protocolId = newValue {
                    fetchAnalytics(for: protocolId)
                }
            }
        }
    }

    private func fetchProtocols() {
        apiService.fetchProtocols { result in
            DispatchQueue.main.async {
                switch result {
                case .success(let fetchedProtocols):
                    protocols = fetchedProtocols
                    if let firstProtocol = fetchedProtocols.first {
                        selectedProtocolId = firstProtocol.id
                    }
                case .failure:
                    break
                }
            }
        }
    }

    private func fetchAnalytics(for protocolId: String) {
        isLoading = true
        apiService.fetchProtocolAnalytics(protocolId: protocolId) { result in
            DispatchQueue.main.async {
                isLoading = false
                switch result {
                case .success(let fetchedAnalytics):
                    analytics = fetchedAnalytics
                case .failure:
                    analytics = nil
                }
            }
        }
    }
}

struct AnalyticsDetailView: View {
    let analytics: AnalyticsModel

    var body: some View {
        VStack(spacing: 20) {
            // Summary Cards
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 16) {
                AnalyticsCard(title: "Total Days", value: "\(analytics.totalDays)", color: .blue)
                AnalyticsCard(title: "Adherence", value: String(format: "%.1f%%", analytics.adherence), color: .green)
                AnalyticsCard(title: "Current Streak", value: "\(analytics.streak)", color: .orange)
                AnalyticsCard(title: "Missed Days", value: "\(analytics.missedDays)", color: .red)
            }
            .padding(.horizontal)

            // Compound Stats
            VStack(alignment: .leading, spacing: 12) {
                Text("Compound Statistics")
                    .font(.headline)
                    .padding(.horizontal)

                ForEach(Array(analytics.compoundStats.keys.sorted()), id: \.self) { compound in
                    CompoundStatsRow(compound: compound, stats: analytics.compoundStats[compound]!)
                }
            }
        }
    }
}

struct AnalyticsCard: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct CompoundStatsRow: View {
    let compound: String
    let stats: CompoundStats

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(compound)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
                Text(String(format: "%.1f%%", stats.percentage))
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(stats.percentage >= 80 ? .green : stats.percentage >= 60 ? .orange : .red)
            }

            ProgressView(value: stats.percentage / 100.0)
                .progressViewStyle(LinearProgressViewStyle(tint: stats.percentage >= 80 ? .green : stats.percentage >= 60 ? .orange : .red))

            HStack {
                Text("Taken: \(stats.taken)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text("Missed: \(stats.missed)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(8)
        .padding(.horizontal)
    }
}

struct CalendarTabView: View {
    var body: some View {
        NavigationView {
            Text("Calendar View")
                .navigationTitle("Calendar")
        }
    }
}

struct SettingsTabView: View {
    @EnvironmentObject var apiService: APIService
    @State private var showingLogoutAlert = false
    @State private var notificationsEnabled = true
    @State private var reminderTime = Date()

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Notifications")) {
                    Toggle("Enable Notifications", isOn: $notificationsEnabled)

                    if notificationsEnabled {
                        DatePicker("Daily Reminder", selection: $reminderTime, displayedComponents: .hourAndMinute)
                    }
                }

                Section(header: Text("Account")) {
                    Button("Logout") {
                        showingLogoutAlert = true
                    }
                    .foregroundColor(.red)
                }

                Section(header: Text("About")) {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundColor(.secondary)
                    }
                }
            }
            .navigationTitle("Settings")
        }
        .alert("Logout", isPresented: $showingLogoutAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Logout", role: .destructive) {
                apiService.logout()
            }
        } message: {
            Text("Are you sure you want to logout?")
        }
    }
}

struct NotificationsView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var apiService: APIService

    var body: some View {
        NavigationView {
            List {
                if apiService.notifications.isEmpty {
                    Text("No notifications")
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                } else {
                    ForEach(apiService.notifications) { notification in
                        NotificationRowView(notification: notification)
                    }
                }
            }
            .navigationTitle("Notifications")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct NotificationRowView: View {
    let notification: NotificationModel
    @EnvironmentObject var apiService: APIService

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(notification.title)
                    .font(.headline)
                    .fontWeight(notification.isRead ? .medium : .bold)

                Spacer()

                if !notification.isRead {
                    Circle()
                        .fill(Color.blue)
                        .frame(width: 8, height: 8)
                }
            }

            Text(notification.message)
                .font(.body)
                .foregroundColor(.secondary)

            Text(formatDate(notification.createdAt))
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
        .onTapGesture {
            if !notification.isRead {
                apiService.markNotificationAsRead(notificationId: notification.id) { _ in }
            }
        }
    }

    private func formatDate(_ dateString: String) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        if let date = formatter.date(from: dateString) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .medium
            displayFormatter.timeStyle = .short
            return displayFormatter.string(from: date)
        }
         // Return the original string if date conversion fails to avoid unexpected issues
        return dateString
    }
}



struct ProtocolRowView: View {
    let protocolItem: ProtocolModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(protocolItem.name)
                .font(.headline)
                .fontWeight(.semibold)

            Text("\(protocolItem.compounds.count) compounds • \(protocolItem.displayFrequency)")
                .font(.caption)
                .foregroundColor(.secondary)

            if let displayDescription = protocolItem.displayDescription, !displayDescription.isEmpty {
                Text(displayDescription)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.systemGray6))
        .cornerRadius(12)
        .padding(.horizontal)
    }
}

#Preview {
    DashboardView()
        .environmentObject(APIService.shared)
}