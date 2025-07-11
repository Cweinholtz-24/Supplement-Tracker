
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
}
