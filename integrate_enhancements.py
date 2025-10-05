#!/usr/bin/env python3
"""
Integration script to add all enhancements to slowhttpv2.py
This script safely integrates new features without breaking existing code
"""

import sys
import os
import shutil
from datetime import datetime

def backup_file(filename):
    """Create a backup of the original file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"{filename}.backup_{timestamp}"
    shutil.copy2(filename, backup_name)
    print(f"[+] Backup created: {backup_name}")
    return backup_name

def read_file(filename):
    """Read file content"""
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(filename, content):
    """Write content to file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[+] File written: {filename}")

def integrate_enhancements():
    """Main integration function"""
    print("="*60)
    print("SlowHTTP v2 Enhancement Integration Script")
    print("="*60)
    print()
    
    # Check if main file exists
    if not os.path.exists('slowhttpv2.py'):
        print("[!] Error: slowhttpv2.py not found!")
        sys.exit(1)
    
    # Create backup
    print("[*] Creating backup...")
    backup_file('slowhttpv2.py')
    
    # Read main file
    print("[*] Reading main file...")
    content = read_file('slowhttpv2.py')
    
    # Read enhancement code
    print("[*] Reading enhancement code...")
    enhancement_code = read_file('slowhttpv2_enhanced.py')
    
    # Extract the enhanced classes
    start_marker = "ENHANCED_CLASSES = '''"
    end_marker = "'''"
    
    start_idx = enhancement_code.find(start_marker) + len(start_marker)
    end_idx = enhancement_code.find(end_marker, start_idx)
    
    if start_idx == -1 or end_idx == -1:
        print("[!] Error: Could not extract enhancement code!")
        sys.exit(1)
    
    enhanced_classes = enhancement_code[start_idx:end_idx]
    
    # Find insertion point (before def main():)
    insertion_point = content.rfind('\ndef main():')
    
    if insertion_point == -1:
        print("[!] Error: Could not find insertion point!")
        sys.exit(1)
    
    # Insert enhanced classes
    print("[*] Integrating enhanced features...")
    new_content = content[:insertion_point] + enhanced_classes + content[insertion_point:]
    
    # Add import for warnings at the top
    import_insertion = content.find('import traceback')
    if import_insertion != -1:
        import_line = content.find('\n', import_insertion) + 1
        warning_import = "import warnings\nwarnings.filterwarnings('ignore', message='Unverified HTTPS request')\n"
        new_content = new_content[:import_line] + warning_import + new_content[import_line:]
    
    # Write integrated file
    print("[*] Writing integrated file...")
    write_file('slowhttpv2.py', new_content)
    
    # Verify syntax
    print("[*] Verifying Python syntax...")
    import py_compile
    try:
        py_compile.compile('slowhttpv2.py', doraise=True)
        print("[+] Syntax check passed!")
    except py_compile.PyCompileError as e:
        print(f"[!] Syntax error: {e}")
        print("[!] Restoring from backup...")
        # Restore from backup
        backups = [f for f in os.listdir('.') if f.startswith('slowhttpv2.py.backup_')]
        if backups:
            latest_backup = sorted(backups)[-1]
            shutil.copy2(latest_backup, 'slowhttpv2.py')
            print(f"[+] Restored from {latest_backup}")
        sys.exit(1)
    
    # Count lines
    lines = len(new_content.split('\n'))
    print(f"\n[+] Integration complete!")
    print(f"[+] Total lines: {lines}")
    print(f"[+] Original file backed up")
    print(f"[+] Enhanced features added:")
    print("    - DNSHistoryTool")
    print("    - CloudflareBypassAttack")
    print("    - TargetHealthMonitor")
    print()
    print("="*60)
    print("Next steps:")
    print("1. Test the application: python3 slowhttpv2.py")
    print("2. Add menu options for new features in SlowHTTPTUI class")
    print("3. Run full test suite")
    print("="*60)

if __name__ == '__main__':
    try:
        integrate_enhancements()
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
