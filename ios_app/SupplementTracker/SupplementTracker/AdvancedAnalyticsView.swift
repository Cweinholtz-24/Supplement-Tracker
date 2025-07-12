
import SwiftUI
import Charts

struct AdvancedAnalyticsView: View {
    let protocolId: String
    @StateObject private var apiService = APIService.shared
    @State private var analytics: EnhancedAnalyticsModel?
    @State private var isLoading = true
    @State private var errorMessage: String?
    @State private var selectedTab = 0
    
    var body: some View {
        NavigationView {
            VStack {
                if isLoading {
                    ProgressView("Loading advanced analytics...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let analytics = analytics {
                    TabView(selection: $selectedTab) {
                        OverviewTab(analytics: analytics)
                            .tabItem {
                                Image(systemName: "chart.bar.fill")
                                Text("Overview")
                            }
                            .tag(0)
                        
                        AIInsightsTab(insights: analytics.aiInsights)
                            .tabItem {
                                Image(systemName: "brain.head.profile")
                                Text("AI Insights")
                            }
                            .tag(1)
                        
                        TrendsTab(weeklyTrends: analytics.weeklyTrends, monthlyTrends: analytics.monthlyTrends)
                            .tabItem {
                                Image(systemName: "chart.line.uptrend.xyaxis")
                                Text("Trends")
                            }
                            .tag(2)
                        
                        CorrelationsTab(correlations: analytics.correlations)
                            .tabItem {
                                Image(systemName: "arrow.triangle.branch")
                                Text("Correlations")
                            }
                            .tag(3)
                    }
                } else {
                    ErrorView(message: errorMessage ?? "Failed to load analytics") {
                        loadAnalytics()
                    }
                }
            }
            .navigationTitle("Advanced Analytics")
            .navigationBarTitleDisplayMode(.large)
            .onAppear {
                loadAnalytics()
            }
        }
    }
    
    private func loadAnalytics() {
        isLoading = true
        errorMessage = nil
        
        // First get basic analytics
        apiService.fetchProtocolAnalytics(protocolId: protocolId) { result in
            DispatchQueue.main.async {
                switch result {
                case .success(let analyticsData):
                    // Now get advanced analytics
                    self.apiService.fetchAdvancedAnalytics(protocolId: self.protocolId) { advancedResult in
                        DispatchQueue.main.async {
                            self.isLoading = false
                            switch advancedResult {
                            case .success(let advanced):
                                self.analytics = advanced
                            case .failure(_):
                                // Fallback to basic analytics
                                self.analytics = EnhancedAnalyticsModel(
                                    totalDays: analyticsData.totalDays,
                                    adherence: analyticsData.adherence,
                                    streak: analyticsData.streak,
                                    missedDays: analyticsData.missedDays,
                                    compoundStats: analyticsData.compoundStats,
                                    aiInsights: [],
                                    predictions: PredictionData(nextWeekAdherence: nil, trend: nil, daysToReachGoal: nil),
                                    correlations: [],
                                    weeklyTrends: [],
                                    monthlyTrends: [],
                                    bestPerformingDay: nil,
                                    adherencePattern: "good"
                                )
                            }
                        }
                    }
                case .failure(let error):
                    self.isLoading = false
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }
}

struct OverviewTab: View {
    let analytics: EnhancedAnalyticsModel
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 20) {
                // Key Metrics Cards
                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 2), spacing: 16) {
                    MetricCard(title: "Total Days", value: "\(analytics.totalDays)", icon: "calendar")
                    MetricCard(title: "Adherence", value: "\(analytics.adherence, specifier: "%.1f")%", icon: "chart.pie.fill")
                    MetricCard(title: "Current Streak", value: "\(analytics.streak)", icon: "flame.fill")
                    MetricCard(title: "Missed Days", value: "\(analytics.missedDays)", icon: "exclamationmark.triangle.fill")
                }
                
                // Adherence Pattern
                AdherencePatternCard(pattern: analytics.adherencePattern)
                
                // Best Performing Day
                if let bestDay = analytics.bestPerformingDay {
                    BestDayCard(bestDay: bestDay)
                }
                
                // Compound Stats
                CompoundStatsView(compoundStats: analytics.compoundStats)
            }
            .padding()
        }
    }
}

struct AIInsightsTab: View {
    let insights: [AIInsight]
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                if insights.isEmpty {
                    VStack {
                        Image(systemName: "brain.head.profile")
                            .font(.system(size: 50))
                            .foregroundColor(.secondary)
                        Text("No AI insights available yet")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text("Keep tracking to get personalized insights!")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                } else {
                    ForEach(insights.sorted(by: { $0.priorityLevel > $1.priorityLevel })) { insight in
                        AIInsightCard(insight: insight)
                    }
                }
            }
            .padding()
        }
    }
}

struct TrendsTab: View {
    let weeklyTrends: [WeeklyTrend]
    let monthlyTrends: [MonthlyTrend]
    @State private var selectedTimeframe = 0
    
    var body: some View {
        VStack {
            Picker("Timeframe", selection: $selectedTimeframe) {
                Text("Weekly").tag(0)
                Text("Monthly").tag(1)
            }
            .pickerStyle(SegmentedPickerStyle())
            .padding()
            
            ScrollView {
                if selectedTimeframe == 0 {
                    WeeklyTrendsChart(trends: weeklyTrends)
                } else {
                    MonthlyTrendsChart(trends: monthlyTrends)
                }
            }
        }
    }
}

struct CorrelationsTab: View {
    let correlations: [CorrelationData]
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                if correlations.isEmpty {
                    VStack {
                        Image(systemName: "arrow.triangle.branch")
                            .font(.system(size: 50))
                            .foregroundColor(.secondary)
                        Text("No correlations found")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text("More data needed to analyze patterns")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                } else {
                    ForEach(correlations.indices, id: \.self) { index in
                        CorrelationCard(correlation: correlations[index])
                    }
                }
            }
            .padding()
        }
    }
}

// MARK: - Supporting Views

struct MetricCard: View {
    let title: String
    let value: String
    let icon: String
    
    var body: some View {
        VStack {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(.blue)
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct AIInsightCard: View {
    let insight: AIInsight
    
    var body: some View {
        HStack {
            Image(systemName: insight.iconName)
                .font(.title2)
                .foregroundColor(colorForPriority(insight.priority))
            
            VStack(alignment: .leading, spacing: 4) {
                Text(insight.title)
                    .font(.headline)
                Text(insight.message)
                    .font(.body)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
    
    private func colorForPriority(_ priority: String) -> Color {
        switch priority {
        case "high": return .red
        case "medium": return .orange
        default: return .blue
        }
    }
}

struct AdherencePatternCard: View {
    let pattern: String
    
    var body: some View {
        VStack {
            Text("Adherence Pattern")
                .font(.headline)
            Text(patternDescription)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
    
    private var patternDescription: String {
        switch pattern {
        case "excellent": return "🌟 Excellent! Your consistency is outstanding."
        case "good": return "👍 Good progress! Keep up the steady improvement."
        case "needs_improvement": return "📈 Room for improvement. Consider setting reminders."
        case "poor": return "🎯 Let's work on building better habits."
        default: return "📊 Keep tracking to analyze your patterns."
        }
    }
}

struct BestDayCard: View {
    let bestDay: BestPerformingDay
    
    var body: some View {
        VStack {
            Text("Best Performance Day")
                .font(.headline)
            HStack {
                Text(bestDay.day)
                    .font(.title2)
                    .fontWeight(.bold)
                Spacer()
                Text("\(bestDay.adherence, specifier: "%.1f")%")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(.green)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct CompoundStatsView: View {
    let compoundStats: [String: CompoundStats]
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Compound Performance")
                .font(.headline)
            
            ForEach(Array(compoundStats.keys), id: \.self) { compound in
                if let stats = compoundStats[compound] {
                    CompoundStatRow(compound: compound, stats: stats)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct CompoundStatRow: View {
    let compound: String
    let stats: CompoundStats
    
    var body: some View {
        HStack {
            Text(compound)
                .font(.body)
            Spacer()
            Text("\(stats.percentage, specifier: "%.1f")%")
                .font(.body)
                .fontWeight(.semibold)
                .foregroundColor(stats.percentage >= 80 ? .green : stats.percentage >= 60 ? .orange : .red)
        }
        .padding(.vertical, 2)
    }
}

struct WeeklyTrendsChart: View {
    let trends: [WeeklyTrend]
    
    var body: some View {
        VStack {
            Text("Weekly Adherence Trends")
                .font(.headline)
                .padding()
            
            if !trends.isEmpty {
                Chart(trends) { trend in
                    LineMark(
                        x: .value("Week", trend.week),
                        y: .value("Adherence", trend.adherence)
                    )
                    .foregroundStyle(.blue)
                }
                .frame(height: 200)
                .padding()
            } else {
                Text("Not enough data for trends")
                    .foregroundColor(.secondary)
                    .padding()
            }
        }
    }
}

struct MonthlyTrendsChart: View {
    let trends: [MonthlyTrend]
    
    var body: some View {
        VStack {
            Text("Monthly Adherence Trends")
                .font(.headline)
                .padding()
            
            if !trends.isEmpty {
                Chart(trends) { trend in
                    LineMark(
                        x: .value("Month", trend.month),
                        y: .value("Adherence", trend.adherence)
                    )
                    .foregroundStyle(.green)
                }
                .frame(height: 200)
                .padding()
            } else {
                Text("Not enough data for trends")
                    .foregroundColor(.secondary)
                    .padding()
            }
        }
    }
}

struct CorrelationCard: View {
    let correlation: CorrelationData
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Date: \(correlation.date)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text("\(correlation.adherence, specifier: "%.1f")% adherence")
                    .font(.caption)
                    .fontWeight(.semibold)
            }
            
            HStack {
                VStack(alignment: .leading) {
                    Text("Mood: \(correlation.mood)")
                    Text("Energy: \(correlation.energy)")
                }
                .font(.body)
                Spacer()
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

struct ErrorView: View {
    let message: String
    let retry: () -> Void
    
    var body: some View {
        VStack {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 50))
                .foregroundColor(.red)
            Text(message)
                .font(.headline)
                .multilineTextAlignment(.center)
                .padding()
            Button("Retry", action: retry)
                .buttonStyle(.bordered)
        }
        .padding()
    }
}

#Preview {
    AdvancedAnalyticsView(protocolId: "test_protocol")
}
