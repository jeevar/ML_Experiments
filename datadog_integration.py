"""
DataDog Dataset Integration
==========================

This module integrates with the DataDog malicious software packages dataset:
https://github.com/DataDog/malicious-software-packages-dataset

It downloads, processes, and extracts features from real malicious packages
for use with the two-stage detection system.
"""

import os
import json
import zipfile
import requests
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import pandas as pd
from malicious_package_detector import PackageInfo, MaliciousPackageDetector


class DataDogDatasetLoader:
    """Loader for the DataDog malicious packages dataset"""
    
    def __init__(self, data_dir: str = "datadog_dataset"):
        self.data_dir = Path(data_dir)
        self.repo_url = "https://github.com/DataDog/malicious-software-packages-dataset.git"
        self.password = "infected"  # Password for encrypted ZIP files
        self.extracted_dir = self.data_dir / "extracted"  # Directory for extracted contents
    
    def download_dataset(self):
        """Download the DataDog dataset using git clone"""
        if self.data_dir.exists():
            print(f"📁 Dataset directory already exists: {self.data_dir}")
            return
        
        print("📥 Downloading DataDog malicious packages dataset...")
        try:
            subprocess.run([
                "git", "clone", self.repo_url, str(self.data_dir)
            ], check=True, capture_output=True, text=True)
            print("✅ Dataset downloaded successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to download dataset: {e}")
            print("Please ensure git is installed and try again.")
            raise
    
    def unzip_all_samples(self, ecosystem: str = "pypi", force_extract: bool = False):
        """
        Automatically extract all ZIP files from the DataDog dataset
        
        Args:
            ecosystem: The package ecosystem (pypi, npm)
            force_extract: If True, re-extract even if files already exist
        """
        samples_dir = self.data_dir / "samples" / ecosystem
        ecosystem_extract_dir = self.extracted_dir / ecosystem
        
        if not samples_dir.exists():
            print(f"❌ Samples directory not found: {samples_dir}")
            print("Please run download_dataset() first.")
            return
        
        # Create extraction directory
        ecosystem_extract_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🗜️ Extracting all ZIP files for {ecosystem} ecosystem...")
        print(f"   Source: {samples_dir}")
        print(f"   Target: {ecosystem_extract_dir}")
        
        extracted_count = 0
        skipped_count = 0
        error_count = 0
        
        # Walk through all package directories
        for package_dir in samples_dir.iterdir():
            if not package_dir.is_dir():
                continue
                
            package_name = package_dir.name
            
            # Walk through version directories
            for version_dir in package_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                    
                version_name = version_dir.name
                
                # Look for ZIP files in this version directory
                for zip_file in version_dir.glob("*.zip"):
                    # Create extraction path: extracted/pypi/package_name/version/
                    extract_path = ecosystem_extract_dir / package_name / version_name
                    
                    # Skip if already extracted (unless force_extract is True)
                    if extract_path.exists() and not force_extract:
                        skipped_count += 1
                        continue
                    
                    # Create extraction directory
                    extract_path.mkdir(parents=True, exist_ok=True)
                    
                    try:
                        # Extract with password
                        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                            zip_ref.extractall(extract_path, pwd=self.password.encode())
                        
                        print(f"✅ Extracted: {package_name}/{version_name}")
                        extracted_count += 1
                        
                    except zipfile.BadZipFile:
                        print(f"❌ Bad ZIP file: {package_name}/{version_name}")
                        error_count += 1
                    except RuntimeError as e:
                        if "Bad password" in str(e):
                            print(f"❌ Password error: {package_name}/{version_name}")
                        else:
                            print(f"❌ Runtime error: {package_name}/{version_name} - {e}")
                        error_count += 1
                    except Exception as e:
                        print(f"❌ Unexpected error: {package_name}/{version_name} - {e}")
                        error_count += 1
        
        print(f"\n📊 Extraction Summary:")
        print(f"   ✅ Extracted: {extracted_count} packages")
        print(f"   ⏭️ Skipped: {skipped_count} packages (already exist)")
        print(f"   ❌ Errors: {error_count} packages")
        print(f"   📁 Total files in: {ecosystem_extract_dir}")
        
        return extracted_count, skipped_count, error_count
    
    def load_manifest(self, ecosystem: str = "pypi") -> Dict:
        """Load the manifest.json file for an ecosystem"""
        manifest_path = self.data_dir / "samples" / ecosystem / "manifest.json"
        
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")
        
        with open(manifest_path, 'r') as f:
            return json.load(f)
    
    def extract_package_info(self, ecosystem: str = "pypi", limit: Optional[int] = None, auto_extract: bool = True) -> List[PackageInfo]:
        """
        Extract package information from the DataDog dataset
        
        Args:
            ecosystem: The package ecosystem (pypi, npm)
            limit: Maximum number of packages to process (None for all)
            auto_extract: If True, automatically extract ZIP files before processing
        
        Returns:
            List of PackageInfo objects for malicious packages
        """
        if not self.data_dir.exists():
            self.download_dataset()
        
        # Auto-extract ZIP files if requested
        if auto_extract:
            print("🗜️ Auto-extracting ZIP files...")
            self.unzip_all_samples(ecosystem)
        
        print(f"📦 Processing {ecosystem} packages from DataDog dataset...")
        
        # Load manifest
        manifest = self.load_manifest(ecosystem)
        packages = []
        
        count = 0
        for package_name, package_data in manifest.items():
            if limit and count >= limit:
                break
            
            # Get versions (some packages have empty version lists)
            versions = package_data.get('versions', ['unknown'])
            if not versions:
                versions = ['unknown']
            
            # Create PackageInfo for each version
            for version in versions[:1]:  # Take first version to avoid duplicates
                try:
                    package_info = self._create_package_info(
                        package_name, version, ecosystem, package_data
                    )
                    packages.append(package_info)
                    count += 1
                except Exception as e:
                    print(f"⚠️ Failed to process {package_name}: {e}")
                    continue
        
        print(f"✅ Processed {len(packages)} malicious packages")
        return packages
    
    def _create_package_info(self, name: str, version: str, ecosystem: str, data: Dict) -> PackageInfo:
        """Create a PackageInfo object from manifest data and extracted files"""
        
        # Try to extract additional metadata from the extracted package files
        description = self._extract_description(name, version, ecosystem)
        author = self._extract_author(name, version, ecosystem)
        file_size = self._extract_file_size(name, version, ecosystem)
        dependency_count = self._extract_dependency_count(name, version, ecosystem)
        
        return PackageInfo(
            name=name,
            version=version,
            description=description,
            author=author,
            ecosystem=ecosystem,
            file_size=file_size,
            dependency_count=dependency_count,
            is_malicious=True    # All packages in DataDog dataset are malicious
        )
    
    def _extract_description(self, name: str, version: str, ecosystem: str) -> str:
        """Extract package description from extracted files"""
        extract_path = self.extracted_dir / ecosystem / name / version
        
        if not extract_path.exists():
            return f"Malicious {ecosystem} package: {name}"
        
        # Try to find description in metadata files
        try:
            if ecosystem == "pypi":
                # Look for setup.py, PKG-INFO, or METADATA files
                for metadata_file in ["setup.py", "PKG-INFO", "METADATA", "setup.cfg"]:
                    metadata_path = self._find_file_recursive(extract_path, metadata_file)
                    if metadata_path:
                        desc = self._parse_python_description(metadata_path)
                        if desc:
                            return desc
                            
            elif ecosystem == "npm":
                # Look for package.json
                package_json = self._find_file_recursive(extract_path, "package.json")
                if package_json:
                    desc = self._parse_npm_description(package_json)
                    if desc:
                        return desc
        except Exception:
            pass  # Ignore parsing errors
        
        # Fallback description
        return f"Malicious {ecosystem} package: {name}"
    
    def _extract_author(self, name: str, version: str, ecosystem: str) -> str:
        """Extract package author from extracted files"""
        extract_path = self.extracted_dir / ecosystem / name / version
        
        if not extract_path.exists():
            return "unknown"
        
        try:
            if ecosystem == "pypi":
                # Look for setup.py or PKG-INFO
                for metadata_file in ["setup.py", "PKG-INFO", "METADATA"]:
                    metadata_path = self._find_file_recursive(extract_path, metadata_file)
                    if metadata_path:
                        author = self._parse_python_author(metadata_path)
                        if author:
                            return author
                            
            elif ecosystem == "npm":
                # Look for package.json
                package_json = self._find_file_recursive(extract_path, "package.json")
                if package_json:
                    author = self._parse_npm_author(package_json)
                    if author:
                        return author
        except Exception:
            pass
        
        return "unknown"
    
    def _extract_file_size(self, name: str, version: str, ecosystem: str) -> int:
        """Extract package file size from original ZIP or extracted contents"""
        # First try the original ZIP file
        zip_path = self.data_dir / "samples" / ecosystem / name / version
        if zip_path.exists():
            for zip_file in zip_path.glob("*.zip"):
                return zip_file.stat().st_size
        
        # Fallback: calculate size of extracted contents
        extract_path = self.extracted_dir / ecosystem / name / version
        if extract_path.exists():
            total_size = 0
            for file_path in extract_path.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            return total_size
        
        return 0
    
    def _extract_dependency_count(self, name: str, version: str, ecosystem: str) -> int:
        """Extract dependency count from extracted files"""
        extract_path = self.extracted_dir / ecosystem / name / version
        
        if not extract_path.exists():
            return 0
        
        try:
            if ecosystem == "pypi":
                # Look for requirements.txt, setup.py, or pyproject.toml
                requirements_file = self._find_file_recursive(extract_path, "requirements.txt")
                if requirements_file:
                    return self._count_python_dependencies(requirements_file)
                
                # Try setup.py
                setup_file = self._find_file_recursive(extract_path, "setup.py")
                if setup_file:
                    return self._count_setup_py_dependencies(setup_file)
                    
            elif ecosystem == "npm":
                # Look for package.json
                package_json = self._find_file_recursive(extract_path, "package.json")
                if package_json:
                    return self._count_npm_dependencies(package_json)
        except Exception:
            pass
        
        return 0
    
    def create_balanced_dataset(self, malicious_limit: int = 100) -> List[PackageInfo]:
        """
        Create a balanced dataset with malicious and benign packages
        
        Args:
            malicious_limit: Number of malicious packages to include
        
        Returns:
            Balanced list of PackageInfo objects
        """
        # Get malicious packages from DataDog
        malicious_packages = self.extract_package_info("pypi", limit=malicious_limit)
        
        # Create synthetic benign packages (in practice, you'd have a real benign dataset)
        benign_packages = self._create_benign_packages(len(malicious_packages))
        
        return malicious_packages + benign_packages
    
    def _create_benign_packages(self, count: int) -> List[PackageInfo]:
        """Create synthetic benign packages for balanced training"""
        
        popular_packages = [
            ("numpy", "1.24.0", "Fundamental package for array computing with Python", "numpy-team"),
            ("pandas", "1.5.2", "Powerful data structures for data analysis", "pandas-dev"),
            ("requests", "2.28.1", "Python HTTP for Humans", "psf"),
            ("django", "4.1.4", "High-level Python Web framework", "django-team"),
            ("flask", "2.2.2", "A simple framework for building complex web applications", "flask-team"),
            ("tensorflow", "2.11.0", "TensorFlow is an open source machine learning framework", "tensorflow-team"),
            ("scikit-learn", "1.2.0", "A set of python modules for machine learning", "scikit-learn-team"),
            ("matplotlib", "3.6.2", "Python plotting package", "matplotlib-team"),
            ("pillow", "9.3.0", "Python Imaging Library", "pillow-team"),
            ("beautifulsoup4", "4.11.1", "Screen-scraping library", "bs4-team"),
            ("selenium", "4.7.2", "Python bindings for Selenium WebDriver", "selenium-team"),
            ("pytest", "7.2.0", "pytest: simple powerful testing with Python", "pytest-dev"),
            ("click", "8.1.3", "Composable command line interface toolkit", "click-team"),
            ("jinja2", "3.1.2", "A small but fast and easy to use stand-alone template engine", "jinja-team"),
            ("sqlalchemy", "1.4.45", "Database Abstraction Library", "sqlalchemy-team"),
        ]
        
        benign = []
        for i in range(count):
            pkg_data = popular_packages[i % len(popular_packages)]
            
            package = PackageInfo(
                name=pkg_data[0],
                version=pkg_data[1],
                description=pkg_data[2],
                author=pkg_data[3],
                ecosystem="pypi",
                file_size=1000000 + (i * 50000),  # Vary file sizes
                dependency_count=5 + (i % 10),     # Vary dependency counts
                is_malicious=False
            )
            benign.append(package)
        
        return benign
    
    # Helper methods for parsing extracted files
    def _find_file_recursive(self, base_path: Path, filename: str) -> Optional[Path]:
        """Find a file recursively in the given base path"""
        for file_path in base_path.rglob(filename):
            if file_path.is_file():
                return file_path
        return None
    
    def _parse_python_description(self, file_path: Path) -> Optional[str]:
        """Parse description from Python metadata files"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Try different patterns for description
            patterns = [
                r'description\s*=\s*["\']([^"\']+)["\']',
                r'Description:\s*(.+)',
                r'Summary:\s*(.+)',
            ]
            
            for pattern in patterns:
                import re
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None
    
    def _parse_python_author(self, file_path: Path) -> Optional[str]:
        """Parse author from Python metadata files"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            patterns = [
                r'author\s*=\s*["\']([^"\']+)["\']',
                r'Author:\s*(.+)',
                r'Maintainer:\s*(.+)',
            ]
            
            for pattern in patterns:
                import re
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None
    
    def _parse_npm_description(self, file_path: Path) -> Optional[str]:
        """Parse description from package.json"""
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('description', '').strip()
        except Exception:
            pass
        return None
    
    def _parse_npm_author(self, file_path: Path) -> Optional[str]:
        """Parse author from package.json"""
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                author = data.get('author', '')
                if isinstance(author, dict):
                    return author.get('name', '').strip()
                elif isinstance(author, str):
                    return author.strip()
        except Exception:
            pass
        return None
    
    def _count_python_dependencies(self, file_path: Path) -> int:
        """Count dependencies from requirements.txt"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = [line.strip() for line in content.split('\n')]
            deps = [line for line in lines if line and not line.startswith('#')]
            return len(deps)
        except Exception:
            pass
        return 0
    
    def _count_setup_py_dependencies(self, file_path: Path) -> int:
        """Count dependencies from setup.py"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            import re
            
            # Look for install_requires or requires patterns
            patterns = [
                r'install_requires\s*=\s*\[(.*?)\]',
                r'requires\s*=\s*\[(.*?)\]',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content, re.DOTALL)
                if match:
                    deps_str = match.group(1)
                    # Count quoted strings (approximate dependency count)
                    deps = re.findall(r'["\']([^"\']+)["\']', deps_str)
                    return len(deps)
        except Exception:
            pass
        return 0
    
    def _count_npm_dependencies(self, file_path: Path) -> int:
        """Count dependencies from package.json"""
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            dep_count = 0
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    dep_count += len(data[dep_type])
            
            return dep_count
        except Exception:
            pass
        return 0


def run_datadog_analysis():
    """Run analysis using the DataDog dataset with automatic ZIP extraction"""
    
    print("🔬 DataDog Malicious Package Analysis with Auto-Extraction")
    print("=" * 60)
    
    # Initialize dataset loader
    loader = DataDogDatasetLoader()
    
    try:
        # Step 1: Download dataset (if not already downloaded)
        if not loader.data_dir.exists():
            print("📥 Downloading DataDog dataset...")
            loader.download_dataset()
        
        # Step 2: Auto-extract all ZIP files
        print("🗜️ Auto-extracting ZIP files...")
        extracted, skipped, errors = loader.unzip_all_samples("pypi", force_extract=False)
        
        # Step 3: Create balanced dataset using extracted files
        print("📊 Creating balanced dataset from extracted files...")
        packages = loader.create_balanced_dataset(malicious_limit=50)
        
        print(f"Total packages: {len(packages)}")
        malicious_count = sum(1 for pkg in packages if pkg.is_malicious)
        benign_count = len(packages) - malicious_count
        print(f"Malicious: {malicious_count}")
        print(f"Benign: {benign_count}")
        
        # Train and evaluate the detector
        from sklearn.model_selection import train_test_split
        
        train_packages, test_packages = train_test_split(
            packages, test_size=0.3, random_state=42,
            stratify=[pkg.is_malicious for pkg in packages]
        )
        
        # Initialize and train detector
        detector = MaliciousPackageDetector()
        detector.fit(train_packages)
        
        # Evaluate
        print("\n📊 Evaluation Results:")
        print("-" * 30)
        
        results = detector.evaluate(test_packages)
        print(f"Accuracy: {results['accuracy']:.2%}")
        print(f"Packages flagged by Stage 1: {results['metadata']['stage1_flagged']}")
        print(f"Packages flagged by Stage 2: {results['metadata']['stage2_flagged']}")
        print(f"Total flagged: {results['metadata']['total_flagged']}")
        
        print("\nClassification Report:")
        print(results['classification_report'])
        
        # Show some examples of detected packages
        print("\n🔍 Sample Detections:")
        print("-" * 30)
        
        predictions, metadata = detector.predict(test_packages[:5])
        
        for i, (pkg, pred) in enumerate(zip(test_packages[:5], predictions)):
            status = "🚨 MALICIOUS" if pred == 1 else "✅ SAFE"
            actual = "MALICIOUS" if pkg.is_malicious else "BENIGN"
            correct = "✓" if (pred == 1) == pkg.is_malicious else "✗"
            
            print(f"{pkg.name} ({pkg.ecosystem}): {status} [Actually: {actual}] {correct}")
            print(f"  Stage 1: {'FLAGGED' if metadata['stage1_predictions'][i] == 1 else 'PASSED'}")
            print(f"  Stage 2: {'FLAGGED' if metadata['stage2_predictions'][i] == 1 else 'PASSED'}")
            print()
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        print("Make sure git is installed and you have internet access.")


def analyze_datadog_statistics():
    """Analyze statistics from the DataDog dataset"""
    
    print("📈 DataDog Dataset Statistics")
    print("=" * 50)
    
    loader = DataDogDatasetLoader()
    
    try:
        if not loader.data_dir.exists():
            loader.download_dataset()
        
        # Analyze PyPI packages
        print("📦 PyPI Package Analysis:")
        pypi_manifest = loader.load_manifest("pypi")
        
        total_packages = len(pypi_manifest)
        packages_with_versions = sum(1 for pkg_data in pypi_manifest.values() 
                                   if pkg_data.get('versions'))
        
        print(f"Total malicious PyPI packages: {total_packages}")
        print(f"Packages with version info: {packages_with_versions}")
        print(f"Packages without version info: {total_packages - packages_with_versions}")
        
        # Sample some package names for analysis
        print(f"\nSample malicious package names:")
        for i, name in enumerate(list(pypi_manifest.keys())[:10]):
            print(f"  {i+1}. {name}")
        
        # Analyze NPM packages if available
        try:
            npm_manifest = loader.load_manifest("npm")
            print(f"\nTotal malicious NPM packages: {len(npm_manifest)}")
        except FileNotFoundError:
            print("\nNPM manifest not found or not available")
        
    except Exception as e:
        print(f"❌ Error analyzing dataset: {e}")


def demo_zip_extraction():
    """Demonstrate the automatic ZIP extraction feature"""
    
    print("🗜️ DATADOG AUTO-EXTRACTION DEMO")
    print("=" * 50)
    
    # Initialize loader
    loader = DataDogDatasetLoader()
    
    # Check if dataset exists
    if not loader.data_dir.exists():
        print("📥 DataDog dataset not found. Downloading...")
        try:
            loader.download_dataset()
        except Exception as e:
            print(f"❌ Could not download dataset: {e}")
            print("💡 Make sure git is installed and try again.")
            return
    
    # Show extraction process
    print(f"📁 Dataset location: {loader.data_dir}")
    print(f"🎯 Extraction target: {loader.extracted_dir}")
    
    # Run extraction
    print("\n🗜️ Starting automatic extraction...")
    try:
        extracted, skipped, errors = loader.unzip_all_samples("pypi", force_extract=False)
        
        print(f"\n✅ EXTRACTION COMPLETE!")
        print(f"   📦 New extractions: {extracted}")
        print(f"   ⏭️ Already existed: {skipped}")
        print(f"   ❌ Errors: {errors}")
        
        # Show some sample extracted files
        sample_dir = loader.extracted_dir / "pypi"
        if sample_dir.exists():
            packages = list(sample_dir.iterdir())[:5]
            print(f"\n📂 Sample extracted packages:")
            for pkg in packages:
                print(f"   📁 {pkg.name}")
        
    except Exception as e:
        print(f"❌ Extraction failed: {e}")


if __name__ == "__main__":
    print("🛡️ DATADOG DATASET INTEGRATION")
    print("=" * 40)
    print("Choose an option:")
    print("1. 📊 Analyze DataDog dataset statistics")
    print("2. 🔬 Run full detection analysis with DataDog data")
    print("3. 🗜️ Demo automatic ZIP extraction")
    
    choice = input("\nEnter choice (1, 2, or 3): ").strip()
    
    if choice == "1":
        analyze_datadog_statistics()
    elif choice == "2":
        run_datadog_analysis()
    elif choice == "3":
        demo_zip_extraction()
    else:
        print("Invalid choice. Running ZIP extraction demo...")
        demo_zip_extraction()