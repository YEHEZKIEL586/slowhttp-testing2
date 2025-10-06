#!/usr/bin/env python3
"""
Project Reorganization Script
Automatically reorganizes project files into proper folder structure
"""

import os
import shutil
import sys
from pathlib import Path
from datetime import datetime

class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[✗]{Colors.NC} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")

def print_info(msg):
    print(f"{Colors.BLUE}[i]{Colors.NC} {msg}")

# File mapping: source -> destination
FILE_MAPPING = {
    # Agents
    'agent_upgraded.py': 'agents/agent_upgraded.py',
    'improved_attackers.py': 'agents/improved_attackers.py',
    
    # Managers
    'ssh_manager_upgraded.py': 'managers/ssh_manager_upgraded.py',
    'database_manager_upgraded.py': 'managers/database_manager_upgraded.py',
    'security_manager_upgraded.py': 'managers/security_manager_upgraded.py',
    
    # Config
    'default_config.py': 'config/default_config.py',
    
    # Utils
    'enhancements.py': 'utils/enhancements.py',
    
    # Core
    'slowhttpv2.py': 'core/slowhttpv2.py',
    
    # Scripts
    'fix_deployment.sh': 'scripts/fix_deployment.sh',
    'deploy_agent.sh': 'scripts/deploy_agent.sh',
    'validate_files.py': 'scripts/validate_files.py',
    
    # Docs
    'README.md': 'docs/README.md',
    'DEPLOYMENT_GUIDE.md': 'docs/DEPLOYMENT_GUIDE.md',
    'SYSTEM_DOCUMENTATION.md': 'docs/SYSTEM_DOCUMENTATION.md',
    'FINAL_REPORT.md': 'docs/FINAL_REPORT.md',
    'COMPREHENSIVE_ANALYSIS.md': 'docs/COMPREHENSIVE_ANALYSIS.md',
    'ATTACK_METHODS_ANALYSIS.md': 'docs/ATTACK_METHODS_ANALYSIS.md',
    'VPS_AGENT_ANALYSIS.md': 'docs/VPS_AGENT_ANALYSIS.md',
    'FOLDER_STRUCTURE_RECOMMENDATION.md': 'docs/FOLDER_STRUCTURE_RECOMMENDATION.md',
    'DELIVERABLES_SUMMARY.md': 'docs/DELIVERABLES_SUMMARY.md',
    'INDEX.md': 'docs/INDEX.md',
    'QUICK_SUMMARY.txt': 'docs/QUICK_SUMMARY.txt',
    'FILE_LIST.txt': 'docs/FILE_LIST.txt',
    'analysis_report.md': 'docs/analysis_report.md',
}

# Import updates needed in files
IMPORT_UPDATES = {
    'core/slowhttpv2.py': {
        'from ssh_manager_upgraded import': 'from managers.ssh_manager_upgraded import',
        'from database_manager_upgraded import': 'from managers.database_manager_upgraded import',
        'from security_manager_upgraded import': 'from managers.security_manager_upgraded import',
        'from default_config import': 'from config.default_config import',
    },
    'managers/ssh_manager_upgraded.py': {
        'from database_manager_upgraded import': 'from .database_manager_upgraded import',
    },
    'scripts/fix_deployment.sh': {
        'agent_upgraded.py': 'agents/agent_upgraded.py',
    },
    'scripts/deploy_agent.sh': {
        'agent_upgraded.py': 'agents/agent_upgraded.py',
    },
}

def create_backup():
    """Create backup of current state"""
    print_info("Creating backup...")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = f'backup_before_reorganization_{timestamp}'
    
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup all Python files, scripts, and docs
        files_to_backup = []
        for pattern in ['*.py', '*.sh', '*.md', '*.txt']:
            files_to_backup.extend(Path('.').glob(pattern))
        
        for file in files_to_backup:
            if file.is_file():
                shutil.copy2(file, backup_dir)
        
        print_success(f"Backup created: {backup_dir}")
        return True, backup_dir
    
    except Exception as e:
        print_error(f"Backup failed: {e}")
        return False, None

def create_folder_structure():
    """Create new folder structure"""
    print_info("Creating folder structure...")
    
    folders = [
        'agents',
        'managers',
        'config',
        'utils',
        'core',
        'scripts',
        'docs',
        'tests',
        'logs',
        'data'
    ]
    
    try:
        for folder in folders:
            os.makedirs(folder, exist_ok=True)
            print_success(f"Created: {folder}/")
        
        # Create __init__.py files
        python_packages = ['agents', 'managers', 'config', 'utils', 'core', 'tests']
        for package in python_packages:
            init_file = os.path.join(package, '__init__.py')
            if not os.path.exists(init_file):
                with open(init_file, 'w') as f:
                    f.write(f'"""\n{package.capitalize()} package\n"""\n')
                print_success(f"Created: {init_file}")
        
        # Create .gitkeep for empty folders
        for folder in ['logs', 'data']:
            gitkeep = os.path.join(folder, '.gitkeep')
            Path(gitkeep).touch()
        
        return True
    
    except Exception as e:
        print_error(f"Failed to create folder structure: {e}")
        return False

def move_files():
    """Move files to new locations"""
    print_info("Moving files...")
    
    moved_count = 0
    skipped_count = 0
    
    for source, destination in FILE_MAPPING.items():
        if os.path.exists(source):
            try:
                # Create destination directory if needed
                dest_dir = os.path.dirname(destination)
                os.makedirs(dest_dir, exist_ok=True)
                
                # Move file
                shutil.move(source, destination)
                print_success(f"Moved: {source} -> {destination}")
                moved_count += 1
            
            except Exception as e:
                print_error(f"Failed to move {source}: {e}")
        else:
            print_warning(f"Skipped: {source} (not found)")
            skipped_count += 1
    
    print_info(f"Moved: {moved_count} files, Skipped: {skipped_count} files")
    return True

def update_imports():
    """Update import statements in files"""
    print_info("Updating import statements...")
    
    updated_count = 0
    
    for file_path, replacements in IMPORT_UPDATES.items():
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                original_content = content
                
                for old_import, new_import in replacements.items():
                    content = content.replace(old_import, new_import)
                
                if content != original_content:
                    with open(file_path, 'w') as f:
                        f.write(content)
                    print_success(f"Updated imports: {file_path}")
                    updated_count += 1
            
            except Exception as e:
                print_error(f"Failed to update {file_path}: {e}")
    
    print_info(f"Updated imports in {updated_count} files")
    return True

def create_requirements_txt():
    """Create requirements.txt file"""
    print_info("Creating requirements.txt...")
    
    requirements = """# SlowHTTP Project Dependencies

# SSH and Remote Execution
paramiko>=2.7.0

# System Monitoring
psutil>=5.8.0

# HTTP Requests
requests>=2.25.0

# DNS Operations
dnspython>=2.1.0

# Optional: For enhanced features
# cryptography>=3.4.0
# pyyaml>=5.4.0
"""
    
    try:
        with open('requirements.txt', 'w') as f:
            f.write(requirements)
        print_success("Created: requirements.txt")
        return True
    
    except Exception as e:
        print_error(f"Failed to create requirements.txt: {e}")
        return False

def create_main_readme():
    """Create main README.md"""
    print_info("Creating main README.md...")
    
    readme_content = """# SlowHTTP Attack System

## 📁 Project Structure

```
slowhttp_project/
├── agents/          # Agent files for attacks
├── managers/        # Resource managers (SSH, DB, Security)
├── config/          # Configuration files
├── utils/           # Utility modules
├── core/            # Main application logic
├── scripts/         # Deployment and utility scripts
├── docs/            # Documentation
├── tests/           # Test files
├── logs/            # Log files
└── data/            # Database and data files
```

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Run main controller
python3 -m core.slowhttpv2

# Deploy agent to VPS
cd scripts
./fix_deployment.sh <VPS_IP> <USER> <PORT>

# Validate files
python3 scripts/validate_files.py
```

## 📚 Documentation

See `docs/` folder for complete documentation:
- `DEPLOYMENT_GUIDE.md` - Deployment instructions
- `SYSTEM_DOCUMENTATION.md` - System architecture
- `ATTACK_METHODS_ANALYSIS.md` - Available attack methods
- `VPS_AGENT_ANALYSIS.md` - VPS deployment analysis

## ⚠️ Warning

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!**

Unauthorized use is illegal and may result in criminal prosecution.

## 📝 License

For educational purposes only.
"""
    
    try:
        with open('README.md', 'w') as f:
            f.write(readme_content)
        print_success("Created: README.md")
        return True
    
    except Exception as e:
        print_error(f"Failed to create README.md: {e}")
        return False

def verify_reorganization():
    """Verify that reorganization was successful"""
    print_info("Verifying reorganization...")
    
    # Check if key files exist in new locations
    key_files = [
        'agents/agent_upgraded.py',
        'core/slowhttpv2.py',
        'managers/ssh_manager_upgraded.py',
        'scripts/fix_deployment.sh',
        'docs/DEPLOYMENT_GUIDE.md'
    ]
    
    all_good = True
    for file in key_files:
        if os.path.exists(file):
            print_success(f"Verified: {file}")
        else:
            print_error(f"Missing: {file}")
            all_good = False
    
    return all_good

def main():
    """Main reorganization process"""
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}SlowHTTP Project Reorganization Script{Colors.NC}")
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")
    
    # Confirm with user
    print_warning("This script will reorganize your project structure.")
    print_warning("A backup will be created before any changes.")
    response = input(f"\n{Colors.YELLOW}Continue? (yes/no): {Colors.NC}")
    
    if response.lower() not in ['yes', 'y']:
        print_info("Reorganization cancelled.")
        return
    
    print()
    
    # Step 1: Create backup
    success, backup_dir = create_backup()
    if not success:
        print_error("Backup failed. Aborting reorganization.")
        return
    
    print()
    
    # Step 2: Create folder structure
    if not create_folder_structure():
        print_error("Failed to create folder structure. Aborting.")
        return
    
    print()
    
    # Step 3: Move files
    if not move_files():
        print_error("Failed to move files. Check backup.")
        return
    
    print()
    
    # Step 4: Update imports
    if not update_imports():
        print_warning("Some imports may need manual update.")
    
    print()
    
    # Step 5: Create additional files
    create_requirements_txt()
    create_main_readme()
    
    print()
    
    # Step 6: Verify
    if verify_reorganization():
        print()
        print(f"{Colors.GREEN}{'='*60}{Colors.NC}")
        print(f"{Colors.GREEN}✓ Reorganization completed successfully!{Colors.NC}")
        print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")
        
        print_info(f"Backup location: {backup_dir}")
        print_info("Next steps:")
        print("  1. Test imports: python3 -c 'from core.slowhttpv2 import *'")
        print("  2. Test scripts: cd scripts && ./fix_deployment.sh --help")
        print("  3. Review docs: ls docs/")
        print()
    else:
        print_error("Verification failed. Please check manually.")
        print_info(f"Backup available at: {backup_dir}")

if __name__ == '__main__':
    main()