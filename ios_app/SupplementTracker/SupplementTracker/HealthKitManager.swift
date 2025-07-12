
//
//  HealthKitManager.swift
//  SupplementTracker
//
//  Created by Developer on 2024-01-01.
//

import Foundation
import HealthKit

class HealthKitManager: ObservableObject {
    static let shared = HealthKitManager()
    
    private let healthStore = HKHealthStore()
    
    @Published var isAuthorized = false
    
    private init() {}
    
    func requestAuthorization() {
        guard HKHealthStore.isHealthDataAvailable() else {
            print("HealthKit is not available on this device")
            return
        }
        
        let typesToRead: Set<HKObjectType> = [
            HKObjectType.quantityType(forIdentifier: .bodyMass)!,
            HKObjectType.quantityType(forIdentifier: .height)!,
            HKObjectType.quantityType(forIdentifier: .heartRate)!,
            HKObjectType.quantityType(forIdentifier: .activeEnergyBurned)!
        ]
        
        let typesToWrite: Set<HKSampleType> = [
            HKObjectType.quantityType(forIdentifier: .dietarySupplements)!
        ]
        
        healthStore.requestAuthorization(toShare: typesToWrite, read: typesToRead) { [weak self] success, error in
            DispatchQueue.main.async {
                self?.isAuthorized = success
                if let error = error {
                    print("HealthKit authorization failed: \(error.localizedDescription)")
                }
            }
        }
    }
    
    func logSupplement(name: String, amount: Double, unit: String) {
        guard isAuthorized else { return }
        
        let supplementType = HKQuantityType.quantityType(forIdentifier: .dietarySupplements)!
        let quantity = HKQuantity(unit: HKUnit.count(), doubleValue: amount)
        
        let sample = HKQuantitySample(
            type: supplementType,
            quantity: quantity,
            start: Date(),
            end: Date(),
            metadata: [HKMetadataKeyFoodType: name]
        )
        
        healthStore.save(sample) { success, error in
            if let error = error {
                print("Failed to save supplement to HealthKit: \(error.localizedDescription)")
            } else {
                print("Successfully logged \(name) to HealthKit")
            }
        }
    }
    
    func readSupplementData(completion: @escaping ([HealthKitSupplement]) -> Void) {
        guard isAuthorized else {
            completion([])
            return
        }
        
        let supplementType = HKQuantityType.quantityType(forIdentifier: .dietarySupplements)!
        let calendar = Calendar.current
        let endDate = Date()
        let startDate = calendar.date(byAdding: .day, value: -30, to: endDate)!
        
        let predicate = HKQuery.predicateForSamples(withStart: startDate, end: endDate, options: .strictStartDate)
        
        let query = HKSampleQuery(
            sampleType: supplementType,
            predicate: predicate,
            limit: HKObjectQueryNoLimit,
            sortDescriptors: [NSSortDescriptor(key: HKSampleSortIdentifierStartDate, ascending: false)]
        ) { query, samples, error in
            
            guard let samples = samples as? [HKQuantitySample], error == nil else {
                print("Error reading supplement data: \(error?.localizedDescription ?? "Unknown error")")
                completion([])
                return
            }
            
            let supplements = samples.compactMap { sample -> HealthKitSupplement? in
                guard let supplementName = sample.metadata?[HKMetadataKeyFoodType] as? String else {
                    return nil
                }
                
                return HealthKitSupplement(
                    name: supplementName,
                    amount: sample.quantity.doubleValue(for: HKUnit.count()),
                    date: sample.startDate,
                    unit: "count"
                )
            }
            
            DispatchQueue.main.async {
                completion(supplements)
            }
        }
        
        healthStore.execute(query)
    }
    
    func syncHealthKitDataToServer() {
        readSupplementData { [weak self] supplements in
            Task {
                await self?.sendHealthKitDataToServer(supplements)
            }
        }
    }
    
    private func sendHealthKitDataToServer(_ supplements: [HealthKitSupplement]) async {
        do {
            let healthKitData = HealthKitSyncData(supplements: supplements)
            try await APIService.shared.syncHealthKitData(healthKitData)
            print("Successfully synced HealthKit data to server")
        } catch {
            print("Failed to sync HealthKit data to server: \(error.localizedDescription)")
        }
    }
}

// MARK: - Data Models
struct HealthKitSupplement: Codable {
    let name: String
    let amount: Double
    let date: Date
    let unit: String
}

struct HealthKitSyncData: Codable {
    let supplements: [HealthKitSupplement]
    let syncDate: Date = Date()
}
}
