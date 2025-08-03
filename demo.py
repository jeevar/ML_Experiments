"""
Malicious Package Detection Demo
===============================

This demo showcases the two-stage machine learning system for detecting
malicious software packages in supply chains using Perceptron and AdalineSGD.

Features:
- Stage 1: Perceptron for fast heuristic filtering
- Stage 2: AdalineSGD for nuanced behavioral analysis
- Integration with DataDog's malicious packages dataset
- Real-world feature extraction techniques

Usage:
    python demo.py
"""

import sys
import numpy as np
from pathlib import Path
from malicious_package_detector import (
    PackageInfo, 
    MaliciousPackageDetector, 
    create_sample_dataset, 
    main as run_basic_demo
)


def display_banner():
    """Display the demo banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  MALICIOUS PACKAGE DETECTOR  🛡️                         ║
║                                                                              ║
║           Two-Stage ML System for Supply Chain Security                     ║
║                                                                              ║
║  Stage 1: Perceptron    → Fast heuristic filtering                         ║
║  Stage 2: AdalineSGD    → Behavioral pattern analysis                      ║
║                                                                              ║
║  Dataset: DataDog's malicious software packages                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def display_menu():
    """Display the main menu"""
    menu = """
🚀 DEMO OPTIONS:

1. 📊 Basic Demo (Synthetic Dataset)
   - Quick demonstration with sample data
   - Shows the two-stage detection process
   - No external dependencies required

2. 🔬 DataDog Dataset Analysis  
   - Downloads real malicious packages dataset
   - Analyzes actual supply chain attacks
   - Requires git and internet connection

3. 📈 Feature Analysis Demo
   - Deep dive into feature extraction
   - Shows how heuristic and behavioral features work
   - Educational walkthrough

4. 🧪 Model Comparison
   - Compare Perceptron vs AdalineSGD performance
   - Show why two-stage approach is effective
   - Performance metrics and analysis

5. ❓ Help & Information
   - About the project
   - Technical details
   - Usage instructions

0. 🚪 Exit

"""
    print(menu)


def run_feature_analysis_demo():
    """Demonstrate feature extraction process"""
    print("\n🔍 FEATURE ANALYSIS DEMO")
    print("=" * 60)
    
    from malicious_package_detector import FeatureExtractor
    
    # Create sample packages for analysis
    packages = [
        PackageInfo(
            name="crypto-hack-123",
            version="1337.0.0", 
            description="crypto hack stealth mining backdoor",
            author="h4ck3r_user",
            ecosystem="pypi",
            file_size=150000,
            dependency_count=3,
            is_malicious=True
        ),
        PackageInfo(
            name="numpy",
            version="1.24.0",
            description="Fundamental package for array computing with Python",
            author="numpy-team",
            ecosystem="pypi", 
            file_size=15000000,
            dependency_count=5,
            is_malicious=False
        )
    ]
    
    extractor = FeatureExtractor()
    
    print("📦 Analyzing packages:")
    for i, pkg in enumerate(packages):
        status = "🚨 MALICIOUS" if pkg.is_malicious else "✅ BENIGN"
        print(f"\n{i+1}. {pkg.name} - {status}")
        print(f"   Version: {pkg.version}")
        print(f"   Description: {pkg.description}")
        print(f"   Author: {pkg.author}")
        print(f"   Size: {pkg.file_size:,} bytes")
        
        # Extract and display heuristic features
        heuristic_features = extractor.extract_heuristic_features(pkg)
        print(f"\n   🔧 Heuristic Features (Stage 1 - Perceptron):")
        feature_names = [
            "Suspicious keywords",
            "Typosquat score", 
            "Version anomaly",
            "High name entropy",
            "Short name with numbers"
        ]
        
        for j, (name, value) in enumerate(zip(feature_names, heuristic_features)):
            print(f"      {name}: {value:.2f}")
    
    # Extract behavioral features for both packages
    print(f"\n   🧠 Behavioral Features (Stage 2 - AdalineSGD):")
    behavioral_features = extractor.extract_behavioral_features(packages, fit_vectorizer=True)
    
    for i, (pkg, features) in enumerate(zip(packages, behavioral_features)):
        print(f"\n   {pkg.name}:")
        print(f"      File size (normalized): {features[0]:.2f}")
        print(f"      Dependency count: {features[1]:.0f}")
        print(f"      Author entropy: {features[2]:.2f}")
        print(f"      Description length: {features[3]:.0f}")
        print(f"      Name-description similarity: {features[4]:.2f}")
        print(f"      TF-IDF features: {len(features)-5} dimensions")


def run_model_comparison_demo():
    """Compare individual models vs combined approach"""
    print("\n⚔️  MODEL COMPARISON DEMO")
    print("=" * 60)
    
    from malicious_package_detector import Perceptron, AdalineSGD, FeatureExtractor
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import train_test_split
    
    # Create larger dataset for comparison
    packages = create_sample_dataset()
    
    # Create more samples by duplicating with variations
    extended_packages = []
    for pkg in packages:
        extended_packages.append(pkg)
        
        # Create variations
        for i in range(3):
            variation = PackageInfo(
                name=f"{pkg.name}_v{i}",
                version=pkg.version,
                description=pkg.description,
                author=pkg.author,
                ecosystem=pkg.ecosystem,
                file_size=pkg.file_size + (i * 10000),
                dependency_count=pkg.dependency_count + i,
                is_malicious=pkg.is_malicious
            )
            extended_packages.append(variation)
    
    print(f"📊 Dataset size: {len(extended_packages)} packages")
    malicious_count = sum(1 for pkg in extended_packages if pkg.is_malicious)
    print(f"   Malicious: {malicious_count}")
    print(f"   Benign: {len(extended_packages) - malicious_count}")
    
    # Split dataset
    train_packages, test_packages = train_test_split(
        extended_packages, test_size=0.3, random_state=42,
        stratify=[pkg.is_malicious for pkg in extended_packages]
    )
    
    # Extract features
    extractor = FeatureExtractor()
    
    # Heuristic features for Perceptron
    X_train_heur = np.array([
        extractor.extract_heuristic_features(pkg) for pkg in train_packages
    ])
    X_test_heur = np.array([
        extractor.extract_heuristic_features(pkg) for pkg in test_packages
    ])
    
    # Behavioral features for AdalineSGD
    X_train_behav = extractor.extract_behavioral_features(train_packages, fit_vectorizer=True)
    X_test_behav = extractor.extract_behavioral_features(test_packages, fit_vectorizer=False)
    
    # Scale behavioral features
    scaler = StandardScaler()
    X_train_behav_scaled = scaler.fit_transform(X_train_behav)
    X_test_behav_scaled = scaler.transform(X_test_behav)
    
    # Labels
    y_train = np.array([1 if pkg.is_malicious else 0 for pkg in train_packages])
    y_test = np.array([1 if pkg.is_malicious else 0 for pkg in test_packages])
    
    print("\n🔧 Training individual models...")
    
    # Train Perceptron only
    perceptron = Perceptron(eta=0.01, n_iter=50)
    perceptron.fit(X_train_heur, y_train)
    perc_pred = perceptron.predict(X_test_heur)
    perc_accuracy = accuracy_score(y_test, perc_pred)
    
    # Train AdalineSGD only
    adaline = AdalineSGD(eta=0.001, n_iter=100)
    adaline.fit(X_train_behav_scaled, y_train)
    ada_pred = adaline.predict(X_test_behav_scaled)
    ada_accuracy = accuracy_score(y_test, ada_pred)
    
    # Train combined system
    detector = MaliciousPackageDetector()
    detector.fit(train_packages)
    combined_pred, _ = detector.predict(test_packages)
    combined_accuracy = accuracy_score(y_test, combined_pred)
    
    print("\n📊 RESULTS COMPARISON:")
    print("-" * 40)
    print(f"Perceptron only:      {perc_accuracy:.2%}")
    print(f"AdalineSGD only:      {ada_accuracy:.2%}")
    print(f"Combined system:      {combined_accuracy:.2%}")
    
    # Show improvement
    best_individual = max(perc_accuracy, ada_accuracy)
    improvement = combined_accuracy - best_individual
    print(f"\nImprovement: +{improvement:.1%}")
    
    if improvement > 0:
        print("✅ Combined system outperforms individual models!")
    else:
        print("ℹ️  Individual models performed as well as combined system on this dataset.")


def show_help():
    """Display help information"""
    help_text = """
📚 HELP & INFORMATION
===================

🎯 PROJECT OVERVIEW:
This project implements a two-stage machine learning system for detecting
malicious software packages in supply chains (PyPI, NPM, etc.).

🏗️ ARCHITECTURE:

  Stage 1: Perceptron
  ├─ Fast heuristic checks
  ├─ Rule-based filtering  
  ├─ High precision for obvious threats
  └─ Acts as initial gate

  Stage 2: AdalineSGD
  ├─ Behavioral analysis
  ├─ Learns subtle patterns
  ├─ Handles edge cases
  └─ Refines Stage 1 decisions

🔧 TECHNICAL DETAILS:

  Features (Stage 1 - Heuristic):
  • Suspicious keywords in package names
  • Typosquat detection (similarity to popular packages)
  • Version number anomalies
  • Name entropy analysis
  • Short names with numbers

  Features (Stage 2 - Behavioral):
  • Package file size
  • Number of dependencies
  • Author metadata analysis
  • Description semantic analysis
  • Name-description coherence

📊 DATASET:
The system can work with DataDog's open-source dataset of malicious packages:
https://github.com/DataDog/malicious-software-packages-dataset

This dataset contains 9,000+ verified malicious packages from PyPI and NPM.

⚡ PERFORMANCE:
The two-stage approach provides:
• Fast initial filtering (Perceptron)
• High accuracy refinement (AdalineSGD)
• Better performance than individual models
• Reduced false positives

🚀 USAGE:
1. Install requirements: pip install -r requirements.txt
2. Run basic demo: python demo.py (option 1)
3. For DataDog integration: ensure git is installed
4. Explore features with option 3

💡 REAL-WORLD APPLICATION:
This system could be integrated into:
• Package managers (pip, npm)
• CI/CD pipelines
• Security scanning tools
• Supply chain monitoring systems

📞 SUPPORT:
This is a demonstration project showing ML techniques for cybersecurity.
"""
    print(help_text)


def main():
    """Main demo function"""
    display_banner()
    
    while True:
        display_menu()
        
        try:
            choice = input("🎯 Select an option (0-5): ").strip()
            
            if choice == "0":
                print("\n👋 Thanks for exploring the Malicious Package Detector!")
                print("Stay safe in the supply chain! 🛡️")
                break
                
            elif choice == "1":
                print("\n🚀 Running Basic Demo...")
                run_basic_demo()
                
            elif choice == "2":
                print("\n🔬 Running DataDog Dataset Analysis...")
                try:
                    from datadog_integration import run_datadog_analysis
                    run_datadog_analysis()
                except ImportError:
                    print("❌ DataDog integration not available")
                except Exception as e:
                    print(f"❌ Error: {e}")
                    
            elif choice == "3":
                run_feature_analysis_demo()
                
            elif choice == "4":
                run_model_comparison_demo()
                
            elif choice == "5":
                show_help()
                
            else:
                print("❌ Invalid choice. Please select 0-5.")
            
            input("\n⏸️  Press Enter to continue...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Exiting demo. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            input("⏸️  Press Enter to continue...")


if __name__ == "__main__":
    main()