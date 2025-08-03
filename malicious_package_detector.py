"""
Malicious Software Package Detection System
==========================================

A two-stage ML pipeline for detecting malicious packages in software supply chains:
1. Perceptron: Fast heuristic-based filtering
2. AdalineSGD: Nuanced behavioral analysis

Based on DataDog's malicious software packages dataset:
https://github.com/DataDog/malicious-software-packages-dataset
"""

import numpy as np
import pandas as pd
import re
import json
import zipfile
import os
from pathlib import Path
from typing import List, Tuple, Dict, Any
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


@dataclass
class PackageInfo:
    """Data class for package information"""
    name: str
    version: str = "unknown"
    description: str = ""
    author: str = ""
    ecosystem: str = "unknown"  # pypi, npm, etc.
    file_size: int = 0
    dependency_count: int = 0
    is_malicious: bool = False


class FeatureExtractor:
    """Extract features from package metadata for ML models"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'auth', 'token', 'password', 'crypto', 'hack', 'root',
            'admin', 'stealth', 'backdoor', 'exploit', 'payload', 'shell',
            'keylog', 'bitcoin', 'wallet', 'mining', 'trojan', 'rat'
        ]
        
        self.popular_packages = {
            'pypi': ['numpy', 'pandas', 'requests', 'urllib3', 'setuptools', 
                    'wheel', 'pip', 'tensorflow', 'django', 'flask'],
            'npm': ['react', 'express', 'lodash', 'axios', 'webpack', 
                   'babel', 'eslint', 'typescript', 'jquery', 'vue']
        }
        
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=100, 
            stop_words='english',
            ngram_range=(1, 2)
        )
    
    def extract_heuristic_features(self, package: PackageInfo) -> np.ndarray:
        """Extract rule-based features for Perceptron (Stage 1)"""
        features = []
        
        # 1. Suspicious name check
        name_lower = package.name.lower()
        has_suspicious_keyword = any(keyword in name_lower for keyword in self.suspicious_keywords)
        features.append(1 if has_suspicious_keyword else 0)
        
        # 2. Typosquat detection
        typosquat_score = self._calculate_typosquat_score(package.name, package.ecosystem)
        features.append(typosquat_score)
        
        # 3. Version anomaly detection
        version_anomaly = self._detect_version_anomaly(package.version)
        features.append(version_anomaly)
        
        # 4. Name entropy (randomness)
        name_entropy = self._calculate_entropy(package.name)
        features.append(1 if name_entropy > 3.5 else 0)
        
        # 5. Short name with numbers (common in malicious packages)
        short_with_numbers = 1 if (len(package.name) < 6 and re.search(r'\d', package.name)) else 0
        features.append(short_with_numbers)
        
        return np.array(features)
    
    def extract_behavioral_features(self, packages: List[PackageInfo], fit_vectorizer: bool = False) -> np.ndarray:
        """Extract complex features for AdalineSGD (Stage 2)"""
        
        behavioral_features = []
        descriptions = [pkg.description for pkg in packages]
        
        # Handle TF-IDF fitting
        if fit_vectorizer:
            tfidf_features = self.tfidf_vectorizer.fit_transform(descriptions).toarray()
        else:
            tfidf_features = self.tfidf_vectorizer.transform(descriptions).toarray()
        
        for i, package in enumerate(packages):
            features = []
            
            # 1. File size (normalized)
            features.append(min(package.file_size / 1000000, 10))  # MB, capped at 10
            
            # 2. Dependency count
            features.append(min(package.dependency_count, 50))  # Capped at 50
            
            # 3. Author name entropy
            author_entropy = self._calculate_entropy(package.author)
            features.append(author_entropy)
            
            # 4. Description length
            features.append(len(package.description))
            
            # 5. Name-description similarity (semantic coherence)
            name_desc_similarity = self._calculate_name_description_similarity(
                package.name, package.description
            )
            features.append(name_desc_similarity)
            
            # 6. Add TF-IDF features
            features.extend(tfidf_features[i])
            
            behavioral_features.append(features)
        
        return np.array(behavioral_features)
    
    def _calculate_typosquat_score(self, package_name: str, ecosystem: str) -> float:
        """Calculate similarity to popular packages (typosquat detection)"""
        if ecosystem not in self.popular_packages:
            return 0.0
        
        min_distance = float('inf')
        for popular_pkg in self.popular_packages[ecosystem]:
            distance = self._levenshtein_distance(package_name.lower(), popular_pkg)
            # Normalize by length
            normalized_distance = distance / max(len(package_name), len(popular_pkg))
            min_distance = min(min_distance, normalized_distance)
        
        # Return suspicion score (lower distance = higher suspicion)
        return max(0, 1 - min_distance * 2)  # Convert to 0-1 scale
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _detect_version_anomaly(self, version: str) -> int:
        """Detect suspicious version patterns"""
        if not version or version == "unknown":
            return 0
        
        # Suspicious patterns
        suspicious_patterns = [
            r'^\d+\.\d+\.\d+\.\d+',  # Too many version parts
            r'1337|666|420|69',      # Suspicious numbers
            r'^0\.0\.0$',            # Null version
            r'[a-zA-Z]{5,}',         # Long alphabetic strings
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, version):
                return 1
        
        return 0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text.lower():
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_name_description_similarity(self, name: str, description: str) -> float:
        """Calculate semantic similarity between package name and description"""
        if not description:
            return 0
        
        name_words = set(re.findall(r'\w+', name.lower()))
        desc_words = set(re.findall(r'\w+', description.lower()))
        
        if not name_words or not desc_words:
            return 0
        
        # Jaccard similarity
        intersection = len(name_words.intersection(desc_words))
        union = len(name_words.union(desc_words))
        
        return intersection / union if union > 0 else 0


class Perceptron:
    """
    Perceptron classifier for binary classification
    Used as Stage 1 filter for obvious malicious packages
    """
    
    def __init__(self, eta: float = 0.01, n_iter: int = 50, random_state: int = 1):
        self.eta = eta  # Learning rate
        self.n_iter = n_iter  # Number of iterations
        self.random_state = random_state
        self.w_ = None  # Weights
        self.b_ = None  # Bias
        self.errors_ = []  # Track errors per epoch
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Train the perceptron"""
        rgen = np.random.RandomState(self.random_state)
        self.w_ = rgen.normal(loc=0.0, scale=0.01, size=X.shape[1])
        self.b_ = 0.0
        self.errors_ = []
        
        for _ in range(self.n_iter):
            errors = 0
            for xi, target in zip(X, y):
                prediction = self.predict(xi.reshape(1, -1))[0]
                update = self.eta * (target - prediction)
                self.w_ += update * xi
                self.b_ += update
                errors += int(update != 0.0)
            self.errors_.append(errors)
        
        return self
    
    def net_input(self, X: np.ndarray) -> np.ndarray:
        """Calculate net input"""
        return np.dot(X, self.w_) + self.b_
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        return np.where(self.net_input(X) >= 0.0, 1, 0)


class AdalineSGD:
    """
    Adaptive Linear Neuron with Stochastic Gradient Descent
    Used as Stage 2 for nuanced behavioral analysis
    """
    
    def __init__(self, eta: float = 0.01, n_iter: int = 100, random_state: int = 1):
        self.eta = eta
        self.n_iter = n_iter
        self.random_state = random_state
        self.w_ = None
        self.b_ = None
        self.cost_ = []
    
    def fit(self, X: np.ndarray, y: np.ndarray):
        """Train using stochastic gradient descent"""
        rgen = np.random.RandomState(self.random_state)
        self.w_ = rgen.normal(loc=0.0, scale=0.01, size=X.shape[1])
        self.b_ = 0.0
        self.cost_ = []
        
        for i in range(self.n_iter):
            # Shuffle data for each epoch
            indices = np.random.permutation(len(X))
            X_shuffled = X[indices]
            y_shuffled = y[indices]
            
            cost = 0
            for xi, target in zip(X_shuffled, y_shuffled):
                output = self.net_input(xi.reshape(1, -1))[0]
                error = target - output
                
                # Update weights and bias
                self.w_ += self.eta * xi * error
                self.b_ += self.eta * error
                
                cost += 0.5 * error**2
            
            avg_cost = cost / len(X)
            self.cost_.append(avg_cost)
        
        return self
    
    def net_input(self, X: np.ndarray) -> np.ndarray:
        """Calculate net input"""
        return np.dot(X, self.w_) + self.b_
    
    def activation(self, X: np.ndarray) -> np.ndarray:
        """Linear activation function"""
        return self.net_input(X)
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions using threshold of 0.5"""
        return np.where(self.activation(X) >= 0.5, 1, 0)


class MaliciousPackageDetector:
    """
    Two-stage malicious package detection system
    Stage 1: Perceptron for fast heuristic filtering
    Stage 2: AdalineSGD for behavioral analysis
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.perceptron = Perceptron(eta=0.01, n_iter=50)
        self.adaline = AdalineSGD(eta=0.001, n_iter=100)
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, packages: List[PackageInfo]):
        """Train the two-stage detection system"""
        print("🔧 Training malicious package detector...")
        
        # Extract labels
        y = np.array([1 if pkg.is_malicious else 0 for pkg in packages])
        
        # Stage 1: Extract heuristic features for Perceptron
        print("📊 Extracting heuristic features...")
        X_heuristic = np.array([
            self.feature_extractor.extract_heuristic_features(pkg) 
            for pkg in packages
        ])
        
        # Train Perceptron
        print("🧠 Training Perceptron (Stage 1)...")
        self.perceptron.fit(X_heuristic, y)
        
        # Stage 2: Extract behavioral features for AdalineSGD
        print("📈 Extracting behavioral features...")
        X_behavioral = self.feature_extractor.extract_behavioral_features(packages, fit_vectorizer=True)
        
        # Scale features for AdalineSGD
        X_behavioral_scaled = self.scaler.fit_transform(X_behavioral)
        
        # Train AdalineSGD
        print("🧠 Training AdalineSGD (Stage 2)...")
        self.adaline.fit(X_behavioral_scaled, y)
        
        self.is_fitted = True
        print("✅ Training completed!")
        
        return self
    
    def predict(self, packages: List[PackageInfo]) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Predict maliciousness using two-stage approach
        Returns: (predictions, metadata)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before making predictions")
        
        # Stage 1: Perceptron filtering
        X_heuristic = np.array([
            self.feature_extractor.extract_heuristic_features(pkg) 
            for pkg in packages
        ])
        
        stage1_predictions = self.perceptron.predict(X_heuristic)
        
        # Stage 2: Behavioral analysis for packages not flagged by Stage 1
        X_behavioral = self.feature_extractor.extract_behavioral_features(packages, fit_vectorizer=False)
        X_behavioral_scaled = self.scaler.transform(X_behavioral)
        
        stage2_predictions = self.adaline.predict(X_behavioral_scaled)
        
        # Combine predictions: Stage 1 acts as a gate
        # If Stage 1 flags as malicious (1), keep that prediction
        # If Stage 1 says benign (0), use Stage 2 prediction
        final_predictions = np.where(stage1_predictions == 1, 1, stage2_predictions)
        
        metadata = {
            'stage1_flagged': np.sum(stage1_predictions),
            'stage2_flagged': np.sum(stage2_predictions),
            'total_flagged': np.sum(final_predictions),
            'stage1_predictions': stage1_predictions,
            'stage2_predictions': stage2_predictions
        }
        
        return final_predictions, metadata
    
    def evaluate(self, packages: List[PackageInfo]) -> Dict[str, Any]:
        """Evaluate the model performance"""
        y_true = np.array([1 if pkg.is_malicious else 0 for pkg in packages])
        y_pred, metadata = self.predict(packages)
        
        accuracy = accuracy_score(y_true, y_pred)
        
        return {
            'accuracy': accuracy,
            'classification_report': classification_report(y_true, y_pred),
            'confusion_matrix': confusion_matrix(y_true, y_pred),
            'metadata': metadata
        }


def create_sample_dataset() -> List[PackageInfo]:
    """
    Create a sample dataset for demonstration
    In practice, this would load from the DataDog dataset
    """
    
    # Malicious packages (based on real examples from DataDog dataset)
    malicious_packages = [
        PackageInfo(
            name="login4u", 
            version="1.0.0",
            description="login token root access authentication",
            author="suspicioususer123",
            ecosystem="pypi",
            file_size=50000,
            dependency_count=15,
            is_malicious=True
        ),
        PackageInfo(
            name="crypto-stealth", 
            version="1337.42.0",
            description="stealth crypto mining backdoor system",
            author="h4ck3r",
            ecosystem="pypi",
            file_size=200000,
            dependency_count=3,
            is_malicious=True
        ),
        PackageInfo(
            name="reqeusts",  # Typosquat of 'requests'
            version="2.28.1",
            description="HTTP library for Python",
            author="normaluser",
            ecosystem="pypi",
            file_size=100000,
            dependency_count=8,
            is_malicious=True
        ),
        PackageInfo(
            name="auth-bypass",
            version="0.0.0",
            description="auth token bypass root admin",
            author="evil@hacker.com",
            ecosystem="pypi",
            file_size=75000,
            dependency_count=20,
            is_malicious=True
        ),
        PackageInfo(
            name="npmtest123",
            version="1.0.0",
            description="trojan payload shell backdoor",
            author="badactor",
            ecosystem="npm",
            file_size=300000,
            dependency_count=2,
            is_malicious=True
        )
    ]
    
    # Benign packages
    benign_packages = [
        PackageInfo(
            name="numpy",
            version="1.24.0",
            description="Fundamental package for array computing with Python",
            author="numpy-team",
            ecosystem="pypi",
            file_size=15000000,
            dependency_count=5,
            is_malicious=False
        ),
        PackageInfo(
            name="requests",
            version="2.28.1",
            description="Python HTTP for Humans",
            author="psf",
            ecosystem="pypi",
            file_size=500000,
            dependency_count=12,
            is_malicious=False
        ),
        PackageInfo(
            name="express",
            version="4.18.2",
            description="Fast, unopinionated, minimalist web framework",
            author="express-team",
            ecosystem="npm",
            file_size=800000,
            dependency_count=30,
            is_malicious=False
        ),
        PackageInfo(
            name="pandas",
            version="1.5.2",
            description="Powerful data structures for data analysis",
            author="pandas-dev",
            ecosystem="pypi",
            file_size=25000000,
            dependency_count=8,
            is_malicious=False
        ),
        PackageInfo(
            name="lodash",
            version="4.17.21",
            description="A modern JavaScript utility library",
            author="lodash-team",
            ecosystem="npm",
            file_size=1200000,
            dependency_count=0,
            is_malicious=False
        )
    ]
    
    return malicious_packages + benign_packages


def main():
    """Main demonstration function"""
    print("🚀 Malicious Package Detection System")
    print("=" * 50)
    
    # Create sample dataset
    print("📦 Loading package dataset...")
    packages = create_sample_dataset()
    
    print(f"Total packages: {len(packages)}")
    print(f"Malicious: {sum(1 for pkg in packages if pkg.is_malicious)}")
    print(f"Benign: {sum(1 for pkg in packages if not pkg.is_malicious)}")
    
    # Split into train/test
    train_packages, test_packages = train_test_split(
        packages, test_size=0.3, random_state=42,
        stratify=[pkg.is_malicious for pkg in packages]
    )
    
    # Train the model
    detector = MaliciousPackageDetector()
    detector.fit(train_packages)
    
    # Evaluate on test set
    print("\n📊 Evaluation Results:")
    print("-" * 30)
    
    results = detector.evaluate(test_packages)
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"Packages flagged by Stage 1: {results['metadata']['stage1_flagged']}")
    print(f"Packages flagged by Stage 2: {results['metadata']['stage2_flagged']}")
    print(f"Total flagged: {results['metadata']['total_flagged']}")
    
    print("\nClassification Report:")
    print(results['classification_report'])
    
    print("\nConfusion Matrix:")
    print(results['confusion_matrix'])
    
    # Demonstrate on new packages
    print("\n🔍 Testing on new packages:")
    print("-" * 30)
    
    new_packages = [
        PackageInfo(
            name="crypto-hack-tool",
            version="666.0.0", 
            description="hack crypto bitcoin mining stealth",
            author="anonymous",
            ecosystem="pypi",
            file_size=100000,
            dependency_count=5,
            is_malicious=True  # We know this is malicious for testing
        ),
        PackageInfo(
            name="matplotlib",
            version="3.6.0",
            description="Python plotting library",
            author="matplotlib-team", 
            ecosystem="pypi",
            file_size=20000000,
            dependency_count=15,
            is_malicious=False  # We know this is benign for testing
        )
    ]
    
    predictions, metadata = detector.predict(new_packages)
    
    for i, (pkg, pred) in enumerate(zip(new_packages, predictions)):
        status = "🚨 MALICIOUS" if pred == 1 else "✅ SAFE"
        print(f"{pkg.name}: {status}")
        print(f"  Stage 1: {'FLAGGED' if metadata['stage1_predictions'][i] == 1 else 'PASSED'}")
        print(f"  Stage 2: {'FLAGGED' if metadata['stage2_predictions'][i] == 1 else 'PASSED'}")
        print()


if __name__ == "__main__":
    main()