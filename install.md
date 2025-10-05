📦 Installation Tutorial - SlowHTTP v2 from GitHub

Complete step-by-step guide to install SlowHTTP v2 from GitHub repository.


⸻


📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [Quick Installation](#quick-installation)
3. [Detailed Installation](#detailed-installation)
4. [Verification](#verification)
5. [First Run](#first-run)
6. [Troubleshooting](#troubleshooting)


⸻


🔧 Prerequisites

System Requirements
• **Operating System**: Linux (Ubuntu 20.04+, Debian 10+, CentOS 8+, Arch Linux)
• **Python**: Version 3.8 or higher
• **RAM**: Minimum 2GB (4GB recommended)
• **Disk Space**: At least 1GB free
• **Internet**: Stable connection for downloading
• **Privileges**: Root/sudo access


Check Your System

# Check OS version
cat /etc/os-release

# Check Python version (must be 3.8+)
python3 --version

# Check available RAM
free -h

# Check disk space
df -h

# Check if you have sudo access
sudo -v


⸻


🚀 Quick Installation (3 Steps)

Step 1: Clone Repository

git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git
cd slowhttp-testing2


Step 2: Run Automated Installer

chmod +x install.sh
sudo ./install.sh


Step 3: Start Application

slowhttp


**That's it! Installation complete in 5-10 minutes.**


⸻


📖 Detailed Installation

Method 1: Automated Installation (Recommended)

Step 1: Install Git (if not installed)

**Ubuntu/Debian:**

sudo apt-get update
sudo apt-get install -y git


**CentOS/RHEL:**

sudo yum install -y git


**Arch Linux:**

sudo pacman -Sy git


Step 2: Clone the Repository

# Clone from GitHub
git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git

# Navigate to directory
cd slowhttp-testing2

# Verify files
ls -la


You should see:

slowhttpv2.py
install.sh
requirements.txt
README.md
... and other files


Step 3: Make Installer Executable

chmod +x install.sh


Step 4: Run Automated Installer

sudo ./install.sh


The installer will:
1. ✅ Check system requirements
2. ✅ Install system dependencies
3. ✅ Create virtual environment
4. ✅ Install Python packages
5. ✅ Configure firewall
6. ✅ Set up systemd service
7. ✅ Apply security hardening
8. ✅ Create command aliases


**Installation Progress:**

============================================================
SlowHTTP v2 - Installation Script
============================================================

[+] Checking system requirements...
[+] Detected OS: Ubuntu 22.04
[+] Python 3.10.12 found (OK)
[+] Installing system dependencies...
[+] Creating virtual environment...
[+] Installing Python dependencies...
[+] Configuring firewall...
[+] Creating systemd service...
[+] Installation completed successfully!


Step 5: Verify Installation

# Check if command is available
which slowhttp

# Test Python dependencies
python3 -c "import paramiko, cryptography, psutil, colorama, requests, dns.resolver; print('All dependencies OK')"


⸻


Method 2: Manual Installation

Step 1: Clone Repository

git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git
cd slowhttp-testing2


Step 2: Install System Dependencies

**For Ubuntu/Debian:**

sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    git \
    curl \
    wget \
    net-tools \
    dnsutils \
    nmap \
    tcpdump \
    iptables


**For CentOS/RHEL:**

sudo yum install -y epel-release
sudo yum install -y \
    python3 \
    python3-pip \
    python3-devel \
    gcc \
    gcc-c++ \
    make \
    openssl-devel \
    libffi-devel \
    git \
    curl \
    wget \
    net-tools \
    bind-utils \
    nmap \
    tcpdump \
    iptables


**For Arch Linux:**

sudo pacman -Sy --noconfirm \
    python \
    python-pip \
    base-devel \
    openssl \
    libffi \
    git \
    curl \
    wget \
    net-tools \
    bind-tools \
    nmap \
    tcpdump \
    iptables


Step 3: Create Virtual Environment

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Your prompt should now show (venv)


Step 4: Upgrade pip

pip install --upgrade pip setuptools wheel


Step 5: Install Python Dependencies

pip install -r requirements.txt


**Installation output:**

Collecting paramiko>=3.4.0
  Downloading paramiko-3.4.0-py3-none-any.whl
Collecting cryptography>=41.0.7
  Downloading cryptography-41.0.7-cp310-cp310-linux_x86_64.whl
...
Successfully installed paramiko-3.4.0 cryptography-41.0.7 ...


Step 6: Verify Installation

# Test imports
python3 -c "import paramiko, cryptography, psutil, colorama, requests, dns.resolver; print('✓ All dependencies installed successfully')"


Step 7: Create Command Alias (Optional)

# Add to .bashrc
echo "alias slowhttp='cd $(pwd) && source venv/bin/activate && python3 slowhttpv2.py'" >> ~/.bashrc

# Reload .bashrc
source ~/.bashrc

# Now you can use 'slowhttp' command from anywhere


⸻


✅ Verification

Test Installation

# Method 1: Using alias (if automated install)
slowhttp --version

# Method 2: Direct execution
cd slowhttp-testing2
source venv/bin/activate
python3 slowhttpv2.py --version


Expected output:

SlowHTTP v2 - Version 5.0
Build Date: 2025-01-04
Status: Production Ready


Check Dependencies

# List installed packages
pip list | grep -E "paramiko|cryptography|psutil|colorama|requests|dnspython"


Expected output:

colorama           0.4.6
cryptography       41.0.7
dnspython          2.4.2
paramiko           3.4.0
psutil             5.9.6
requests           2.31.0


Test Basic Functionality

# Start application
slowhttp

# You should see the main menu


⸻


🎮 First Run

Starting the Application

# If you used automated installation:
slowhttp

# If you used manual installation:
cd slowhttp-testing2
source venv/bin/activate
python3 slowhttpv2.py


Main Menu

You should see:

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           SlowHTTP v2 - Distributed C2 Framework          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

[1] VPS Management
[2] Attack Management
[3] Target Intelligence
[4] Tools
[5] System Status
[6] Settings
[0] Exit

Select option:


First Steps
1. **Explore the Menu**
- Navigate through options
- Check system status (option 5)
- Review settings (option 6)

2. **Add a VPS Node** (if you have one)
- Select option 1 (VPS Management)
- Select option 1 (Add VPS)
- Enter VPS details

3. **Read Documentation**
- Exit the application (option 0)
- Read README.md
- Review INSTALLATION_GUIDE.md


⸻


🔍 Troubleshooting

Common Issues and Solutions

Issue 1: Git Not Found

**Error:**

bash: git: command not found


**Solution:**

# Ubuntu/Debian
sudo apt-get install git

# CentOS/RHEL
sudo yum install git

# Arch
sudo pacman -S git


Issue 2: Python Version Too Old

**Error:**

Python 3.6.9 found
Python 3.8+ required


**Solution:**

# Ubuntu/Debian - Install Python 3.10
sudo apt-get update
sudo apt-get install python3.10 python3.10-venv python3.10-dev

# Use python3.10 instead of python3
python3.10 -m venv venv


Issue 3: Permission Denied

**Error:**

Permission denied: './install.sh'


**Solution:**

chmod +x install.sh
sudo ./install.sh


Issue 4: pip Install Fails

**Error:**

ERROR: Could not build wheels for cryptography


**Solution:**

# Install build dependencies
sudo apt-get install python3-dev build-essential libssl-dev libffi-dev

# Try again
pip install -r requirements.txt


Issue 5: Module Not Found

**Error:**

ModuleNotFoundError: No module named 'paramiko'


**Solution:**

# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt


Issue 6: Port Already in Use

**Error:**

Address already in use: port 8080


**Solution:**

# Find process using port
sudo lsof -i :8080

# Kill process
sudo kill -9 <PID>

# Or change port in config
nano configs/config.json


Issue 7: Database Locked

**Error:**

database is locked


**Solution:**

# Check for running instances
ps aux | grep slowhttp

# Kill all instances
killall -9 python3

# Remove lock file
rm -f data/c2_database.db-journal

# Restart application


Getting Help

If you encounter issues not listed here:

1. **Check Logs**
```bash
tail -f logs/slowhttp_c2_*.log
```

2. **Enable Debug Mode**
```bash
export SLOWHTTP_LOG_LEVEL="DEBUG"
python3 slowhttpv2.py
```

3. **Report Issue on GitHub**
- Go to: https://github.com/YEHEZKIEL586/slowhttp-testing2/issues
- Click "New Issue"
- Provide:
  - OS version
  - Python version
  - Error message
  - Steps to reproduce


⸻


📚 Next Steps

After successful installation:

1. **Read Documentation**
- README.md - Overview and features
- INSTALLATION_GUIDE.md - Detailed setup
- UPGRADE_SUMMARY.md - What's new

2. **Configure Settings**
- Edit configs/config.json
- Set up VPS nodes
- Configure attack parameters

3. **Test in Safe Environment**
- Use only on authorized systems
- Start with small attacks
- Monitor system resources

4. **Learn Features**
- Try DNS History tool
- Test Cloudflare Bypass
- Explore attack types


⸻


🔄 Updating

Update from GitHub

# Navigate to directory
cd slowhttp-testing2

# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart application
slowhttp


⸻


🗑️ Uninstallation

Complete Removal

# Using uninstall script
cd slowhttp-testing2
sudo ./uninstall.sh

# Manual removal
sudo systemctl stop slowhttp
sudo systemctl disable slowhttp
sudo rm /etc/systemd/system/slowhttp.service
sudo rm /usr/local/bin/slowhttp
cd ..
rm -rf slowhttp-testing2


⸻


⚠️ Important Reminders

Legal Compliance
• ⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**
• ⚠️ Use only on systems you own or have written authorization
• ⚠️ Unauthorized use is illegal and punishable by law
• ⚠️ Follow local cybersecurity laws and regulations


Security
• ✅ Keep software updated
• ✅ Use strong passwords
• ✅ Enable encryption
• ✅ Monitor logs regularly
• ✅ Use VPN for C2 communications


Best Practices
• ✅ Test in isolated environment first
• ✅ Document all activities
• ✅ Obtain written permission
• ✅ Follow responsible disclosure
• ✅ Maintain audit logs


⸻


🎯 Quick Reference

Installation Commands

# Clone
git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git
cd slowhttp-testing2

# Install
chmod +x install.sh
sudo ./install.sh

# Run
slowhttp


Update Commands

cd slowhttp-testing2
git pull
pip install -r requirements.txt --upgrade


Uninstall Commands

cd slowhttp-testing2
sudo ./uninstall.sh


⸻


📞 Support

Resources
• **GitHub Repository**: https://github.com/YEHEZKIEL586/slowhttp-testing2
• **Issues**: https://github.com/YEHEZKIEL586/slowhttp-testing2/issues
• **Documentation**: See README.md and other .md files


Community
• Report bugs on GitHub Issues
• Request features on GitHub Issues
• Contribute via Pull Requests


⸻


**Installation Complete! Happy Testing!**


Remember: Use responsibly and ethically! 🛡️


⸻


*Last Updated: January 4, 2025*
*Version: 5.0 Enhanced*
