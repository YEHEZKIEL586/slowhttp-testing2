# 🚀 Distributed Slow HTTP C2 System

<div align="center">

![Version](https://img.shields.io/badge/version-5.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**Command & Control System untuk Distributed Slow HTTP Attack Testing**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation)

</div>

---

## ⚠️ DISCLAIMER - BACA DENGAN SEKSAMA

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  LEGAL WARNING ⚠️                            ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  Tool ini HANYA untuk:                                                    ║
║  ✓ Penetration Testing yang AUTHORIZED                                   ║
║  ✓ Security Research dengan izin tertulis                                ║
║  ✓ Educational purposes di environment terkontrol                        ║
║                                                                           ║
║  DILARANG untuk:                                                          ║
║  ✗ Menyerang sistem tanpa izin                                           ║
║  ✗ Aktivitas ilegal atau malicious                                       ║
║  ✗ Mengganggu layanan publik                                             ║
║                                                                           ║
║  Penggunaan ilegal dapat mengakibatkan:                                   ║
║  • Tuntutan pidana                                                        ║
║  • Denda besar                                                            ║
║  • Hukuman penjara                                                        ║
║                                                                           ║
║  Pengguna bertanggung jawab penuh atas penggunaan tool ini.              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
  - [Windows Installation](#-windows-installation)
  - [Linux Installation](#-linux-installation)
  - [macOS Installation](#-macos-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**Distributed Slow HTTP C2** adalah sistem Command & Control yang dirancang untuk melakukan distributed slow HTTP attack testing. Sistem ini memungkinkan pengelolaan multiple VPS nodes untuk melakukan coordinated attack testing terhadap web servers.

### Apa itu Slow HTTP Attack?

Slow HTTP attack adalah teknik Denial of Service (DoS) yang memanfaatkan cara kerja protokol HTTP dengan:
- **Slowloris**: Mengirim HTTP headers secara perlahan
- **Slow POST**: Mengirim HTTP POST body secara perlahan
- **Slow Read**: Membaca response server secara perlahan

### Mengapa Tool Ini?

- ✅ **Centralized Management**: Kelola multiple VPS dari satu interface
- ✅ **Distributed Attack**: Koordinasi attack dari berbagai lokasi
- ✅ **Real-time Monitoring**: Monitor attack progress secara real-time
- ✅ **Automated Deployment**: Deploy agent ke VPS secara otomatis
- ✅ **Comprehensive Logging**: Log lengkap untuk analisis
- ✅ **Security Features**: Encryption, authentication, input validation

---

## ✨ Features

### 🎮 Core Features

#### 1. **VPS Management**
- ✅ Add/Remove VPS nodes
- ✅ SSH connection management
- ✅ Automatic reconnection
- ✅ System information monitoring
- ✅ Health check & status monitoring
- ✅ Bulk operations

#### 2. **Attack Management**
- ✅ Multiple attack types (Slowloris, Slow POST, Slow Read)
- ✅ Distributed attack coordination
- ✅ Real-time attack monitoring
- ✅ Attack session management
- ✅ Customizable attack parameters
- ✅ Attack scheduling

#### 3. **Agent System**
- ✅ Automatic agent deployment
- ✅ Remote command execution
- ✅ Resource monitoring (CPU, Memory, Network)
- ✅ Error handling & recovery
- ✅ Upgrade mechanism

#### 4. **Security Features**
- ✅ Password encryption (Fernet, AES-GCM, PBKDF2)
- ✅ Input sanitization
- ✅ SQL injection protection
- ✅ Command injection prevention
- ✅ Secure SSH connections
- ✅ Audit logging

#### 5. **Database Management**
- ✅ SQLite database
- ✅ Automatic migrations
- ✅ Backup & restore
- ✅ Transaction management
- ✅ Data integrity checks

#### 6. **Monitoring & Reporting**
- ✅ Real-time statistics
- ✅ Attack results tracking
- ✅ Performance metrics
- ✅ Export to JSON/CSV
- ✅ Visualization support

#### 7. **Web Interface** (Optional)
- ✅ Dashboard overview
- ✅ VPS management UI
- ✅ Attack control panel
- ✅ Real-time charts
- ✅ Log viewer

---

## 💻 System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11, Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+), macOS 10.14+ |
| **Python** | 3.8 or higher |
| **RAM** | 2 GB minimum, 4 GB recommended |
| **Storage** | 500 MB free space |
| **Network** | Internet connection for VPS management |
| **Privileges** | Admin/sudo for service installation (optional) |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Ubuntu 22.04 LTS / Windows 11 |
| **Python** | 3.11+ |
| **RAM** | 8 GB |
| **Storage** | 2 GB SSD |
| **Network** | High-speed internet (100+ Mbps) |
| **CPU** | 4+ cores |

### VPS Requirements (Target Nodes)

| Component | Requirement |
|-----------|-------------|
| **OS** | Linux (Ubuntu/Debian/CentOS) |
| **Python** | 3.8+ |
| **RAM** | 512 MB minimum |
| **Network** | Stable internet connection |
| **SSH** | SSH server enabled |

---

## 📦 Installation

### 🪟 Windows Installation

#### Method 1: Automated Installation (Recommended)

```powershell
# 1. Download dan extract files
# Extract ke folder, misalnya: C:\slowhttp-c2

# 2. Buka PowerShell sebagai Administrator
cd C:\slowhttp-c2

# 3. Install Python (jika belum ada)
# Download dari: https://www.python.org/downloads/
# Pastikan centang "Add Python to PATH"

# 4. Verify Python installation
python --version
# Output: Python 3.11.x

# 5. Create virtual environment
python -m venv venv

# 6. Activate virtual environment
.\venv\Scripts\activate

# 7. Upgrade pip
python -m pip install --upgrade pip

# 8. Install dependencies
pip install -r requirements_upgraded.txt

# 9. Verify installation
python -c "import paramiko, cryptography, psutil; print('Installation OK')"

# 10. Run the C2 server
python slowhttp_fixed.py
```

#### Method 2: Manual Installation

```powershell
# 1. Install Python 3.11+
# Download: https://www.python.org/downloads/windows/

# 2. Install Git (optional)
# Download: https://git-scm.com/download/win

# 3. Create project directory
mkdir C:\slowhttp-c2
cd C:\slowhttp-c2

# 4. Copy all files ke directory ini

# 5. Create virtual environment
python -m venv venv

# 6. Activate virtual environment
.\venv\Scripts\activate

# 7. Install core dependencies
pip install paramiko>=3.4.0
pip install cryptography>=41.0.7
pip install psutil>=5.9.6
pip install colorama>=0.4.6
pip install requests>=2.31.0
pip install dnspython>=2.4.2

# 8. Install optional dependencies
pip install aiohttp>=3.9.1
pip install rich>=13.7.0
pip install pydantic>=2.5.3

# 9. Test installation
python slowhttp_fixed.py --help
```

#### Method 3: Using Chocolatey

```powershell
# 1. Install Chocolatey (jika belum ada)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install Python
choco install python311 -y

# 3. Refresh environment
refreshenv

# 4. Continue with Method 1 steps 2-10
```

#### Windows Service Installation (Optional)

```powershell
# 1. Install NSSM (Non-Sucking Service Manager)
choco install nssm -y

# 2. Create service
nssm install SlowHTTP-C2 "C:\slowhttp-c2\venv\Scripts\python.exe" "C:\slowhttp-c2\slowhttp_fixed.py"

# 3. Configure service
nssm set SlowHTTP-C2 AppDirectory "C:\slowhttp-c2"
nssm set SlowHTTP-C2 DisplayName "Slow HTTP C2 Server"
nssm set SlowHTTP-C2 Description "Distributed Slow HTTP C2 System"
nssm set SlowHTTP-C2 Start SERVICE_AUTO_START

# 4. Start service
nssm start SlowHTTP-C2

# 5. Check status
nssm status SlowHTTP-C2

# 6. View logs
nssm set SlowHTTP-C2 AppStdout "C:\slowhttp-c2\logs\service.log"
nssm set SlowHTTP-C2 AppStderr "C:\slowhttp-c2\logs\error.log"
```

---

### 🐧 Linux Installation

#### Method 1: Automated Installation (Recommended)

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# sudo yum update -y  # CentOS/RHEL

# 2. Install Python 3.11+ dan dependencies
sudo apt install python3.11 python3.11-venv python3-pip git -y  # Ubuntu/Debian
# sudo yum install python311 python311-pip git -y  # CentOS/RHEL

# 3. Create installation directory
sudo mkdir -p /opt/slowhttp-c2
cd /opt/slowhttp-c2

# 4. Copy atau clone files
# Jika dari zip:
unzip slowhttp-c2.zip -d /opt/slowhttp-c2
# Jika dari git:
# git clone https://github.com/yourusername/slowhttp-c2.git .

# 5. Set ownership
sudo chown -R $USER:$USER /opt/slowhttp-c2

# 6. Create virtual environment
python3.11 -m venv venv

# 7. Activate virtual environment
source venv/bin/activate

# 8. Upgrade pip
pip install --upgrade pip

# 9. Install dependencies
pip install -r requirements_upgraded.txt

# 10. Set permissions
chmod 755 *.sh
chmod 644 *.py

# 11. Verify installation
python -c "import paramiko, cryptography, psutil; print('Installation OK')"

# 12. Run the C2 server
python slowhttp_fixed.py
```

#### Method 2: Quick Install Script

```bash
# 1. Download and run install script
curl -sSL https://raw.githubusercontent.com/yourusername/slowhttp-c2/main/install.sh | bash

# Or if you have the files locally:
chmod +x install.sh
sudo ./install.sh
```

#### Method 3: Docker Installation (Recommended for Production)

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# 2. Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements_upgraded.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements_upgraded.txt

# Copy application files
COPY . .

# Create non-root user
RUN useradd -m -s /bin/bash slowhttp && \
    chown -R slowhttp:slowhttp /app && \
    chmod 600 key.key 2>/dev/null || true

# Switch to non-root user
USER slowhttp

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',5000)); s.close()" || exit 1

# Run application
CMD ["python", "slowhttp_fixed.py", "--host", "0.0.0.0"]
EOF

# 3. Build Docker image
docker build -t slowhttp-c2:latest .

# 4. Run container
docker run -d \
    --name slowhttp-c2 \
    --restart unless-stopped \
    -p 5000:5000 \
    -v $(pwd)/data:/app/data \
    -v $(pwd)/logs:/app/logs \
    slowhttp-c2:latest

# 5. Check logs
docker logs -f slowhttp-c2

# 6. Stop container
docker stop slowhttp-c2

# 7. Start container
docker start slowhttp-c2
```

#### Method 4: Systemd Service Installation

```bash
# 1. Install application first (Method 1)

# 2. Run setup service script
sudo ./setup_service.sh

# 3. Service will be installed and started automatically

# 4. Manage service
sudo systemctl start slowhttp-c2
sudo systemctl stop slowhttp-c2
sudo systemctl restart slowhttp-c2
sudo systemctl status slowhttp-c2

# 5. View logs
sudo journalctl -u slowhttp-c2 -f

# 6. Enable auto-start on boot
sudo systemctl enable slowhttp-c2

# 7. Disable auto-start
sudo systemctl disable slowhttp-c2
```

---

### 🍎 macOS Installation

#### Method 1: Using Homebrew (Recommended)

```bash
# 1. Install Homebrew (jika belum ada)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python 3.11+
brew install python@3.11

# 3. Install Git
brew install git

# 4. Create installation directory
mkdir -p ~/slowhttp-c2
cd ~/slowhttp-c2

# 5. Copy atau clone files
# Jika dari zip:
unzip ~/Downloads/slowhttp-c2.zip -d ~/slowhttp-c2
# Jika dari git:
# git clone https://github.com/yourusername/slowhttp-c2.git .

# 6. Create virtual environment
python3.11 -m venv venv

# 7. Activate virtual environment
source venv/bin/activate

# 8. Upgrade pip
pip install --upgrade pip

# 9. Install dependencies
pip install -r requirements_upgraded.txt

# 10. Set permissions
chmod 755 *.sh
chmod 644 *.py

# 11. Verify installation
python -c "import paramiko, cryptography, psutil; print('Installation OK')"

# 12. Run the C2 server
python slowhttp_fixed.py
```

#### Method 2: Using pyenv

```bash
# 1. Install pyenv
brew install pyenv

# 2. Install Python 3.11
pyenv install 3.11.7
pyenv global 3.11.7

# 3. Add to shell profile
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc

# 4. Reload shell
source ~/.zshrc

# 5. Continue with Method 1 steps 4-12
```

#### macOS Service Installation (LaunchAgent)

```bash
# 1. Create LaunchAgent plist
cat > ~/Library/LaunchAgents/com.slowhttp.c2.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.slowhttp.c2</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/YOUR_USERNAME/slowhttp-c2/venv/bin/python</string>
        <string>/Users/YOUR_USERNAME/slowhttp-c2/slowhttp_fixed.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/YOUR_USERNAME/slowhttp-c2</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Users/YOUR_USERNAME/slowhttp-c2/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/YOUR_USERNAME/slowhttp-c2/logs/stderr.log</string>
</dict>
</plist>
EOF

# 2. Replace YOUR_USERNAME dengan username Anda
sed -i '' "s/YOUR_USERNAME/$USER/g" ~/Library/LaunchAgents/com.slowhttp.c2.plist

# 3. Load service
launchctl load ~/Library/LaunchAgents/com.slowhttp.c2.plist

# 4. Start service
launchctl start com.slowhttp.c2

# 5. Check status
launchctl list | grep slowhttp

# 6. Stop service
launchctl stop com.slowhttp.c2

# 7. Unload service
launchctl unload ~/Library/LaunchAgents/com.slowhttp.c2.plist
```

---

## ⚙️ Configuration

### 1. Basic Configuration

Edit file `default_config.py`:

```python
# Database
DATABASE_FILE = "c2_database.db"

# Security
ENCRYPTION_KEY_FILE = "key.key"
ENCRYPTION_ALGORITHM = "Fernet"

# SSH Settings
SSH_DEFAULT_PORT = 22
SSH_TIMEOUT = 30
SSH_MAX_RETRIES = 3

# Attack Settings
DEFAULT_CONNECTIONS = 1000
DEFAULT_DELAY = 10
DEFAULT_DURATION = 3600

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/c2.log"
LOG_MAX_SIZE = 10485760  # 10 MB
LOG_BACKUP_COUNT = 5

# Web Interface (Optional)
WEB_ENABLED = False
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
WEB_DEBUG = False
```

### 2. Environment Variables

Create `.env` file:

```bash
# Database
DATABASE_FILE=c2_database.db

# Security
ENCRYPTION_KEY_FILE=key.key

# SSH
SSH_DEFAULT_PORT=22
SSH_TIMEOUT=30

# Logging
LOG_LEVEL=INFO

# Web Interface
WEB_ENABLED=false
WEB_HOST=127.0.0.1
WEB_PORT=5000
```

### 3. Advanced Configuration

```python
# Advanced SSH Settings
SSH_KEY_EXCHANGE_ALGORITHMS = [
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group14-sha256'
]

SSH_ENCRYPTION_ALGORITHMS = [
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr'
]

# Advanced Attack Settings
ATTACK_RANDOMIZATION = True
ATTACK_STEALTH_MODE = False
ATTACK_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
]

# Resource Limits
MAX_VPS_NODES = 100
MAX_CONCURRENT_ATTACKS = 10
MAX_CONNECTIONS_PER_VPS = 5000
```

---

## 🚀 Usage

### Starting the C2 Server

#### Windows
```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Run server
python slowhttp_fixed.py

# Run with custom config
python slowhttp_fixed.py --config custom_config.py

# Run in background (using pythonw)
start /B pythonw slowhttp_fixed.py
```

#### Linux/macOS
```bash
# Activate virtual environment
source venv/bin/activate

# Run server
python slowhttp_fixed.py

# Run with custom config
python slowhttp_fixed.py --config custom_config.py

# Run in background
nohup python slowhttp_fixed.py > logs/c2.log 2>&1 &

# Or using screen
screen -dmS slowhttp python slowhttp_fixed.py

# Or using tmux
tmux new-session -d -s slowhttp 'python slowhttp_fixed.py'
```

### Main Menu Navigation

```
╔═══════════════════════════════════════════════════════════════╗
║           DISTRIBUTED SLOW HTTP C2 - MAIN MENU               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  1. VPS Management                                            ║
║  2. Attack Management                                         ║
║  3. View Statistics                                           ║
║  4. System Settings                                           ║
║  5. Help & Documentation                                      ║
║  6. Exit                                                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

### 1. VPS Management

#### Add VPS Node
```
Menu: 1 → 1 (Add VPS)

Input:
- IP Address: 192.168.1.100
- Username: root
- Password: ********
- SSH Port: 22 (default)
- Location: US-East (optional)
- Tags: production,web (optional)

Output:
✓ VPS added successfully
✓ Connection test: OK
✓ Agent deployed: OK
```

#### List VPS Nodes
```
Menu: 1 → 2 (List VPS)

Output:
┌────┬─────────────────┬──────────┬──────────┬────────────┬──────────┐
│ ID │ IP Address      │ Username │ Status   │ Location   │ Tags     │
├────┼─────────────────┼──────────┼──────────┼────────────┼──────────┤
│ 1  │ 192.168.1.100   │ root     │ Online   │ US-East    │ prod,web │
│ 2  │ 192.168.1.101   │ admin    │ Online   │ US-West    │ test     │
│ 3  │ 192.168.1.102   │ root     │ Offline  │ EU-Central │ backup   │
└────┴─────────────────┴──────────┴──────────┴────────────┴──────────┘
```

#### Check VPS Status
```
Menu: 1 → 3 (Check Status)

Output:
VPS: 192.168.1.100
├─ Status: Online
├─ Uptime: 15 days, 3 hours
├─ CPU Usage: 25%
├─ Memory: 2.1 GB / 4.0 GB (52%)
├─ Disk: 15 GB / 50 GB (30%)
├─ Network: ↓ 1.2 MB/s ↑ 0.8 MB/s
└─ Agent Version: 5.0
```

#### Remove VPS Node
```
Menu: 1 → 4 (Remove VPS)

Input:
- IP Address: 192.168.1.102

Confirmation:
⚠ Are you sure you want to remove VPS 192.168.1.102? (yes/no): yes

Output:
✓ VPS removed successfully
✓ Agent uninstalled
✓ Database cleaned
```

### 2. Attack Management

#### Create Attack Session
```
Menu: 2 → 1 (Create Attack)

Input:
- Session Name: test-attack-001
- Target URL: http://target.example.com
- Attack Type: 
  1. Slowloris
  2. Slow POST
  3. Slow Read
  Choice: 1

- Select VPS Nodes:
  [x] 192.168.1.100
  [x] 192.168.1.101
  [ ] 192.168.1.102
  
- Attack Parameters:
  - Connections per VPS: 1000
  - Delay (seconds): 10
  - Duration (seconds): 3600
  - User Agent: Random

Confirmation:
⚠ Start attack with 2 VPS nodes? (yes/no): yes

Output:
✓ Attack session created: #12345
✓ Deploying to VPS nodes...
  ✓ 192.168.1.100: Ready
  ✓ 192.168.1.101: Ready
✓ Attack started successfully
```

#### Monitor Active Attacks
```
Menu: 2 → 2 (Monitor Attacks)

Output:
╔═══════════════════════════════════════════════════════════════╗
║                    ACTIVE ATTACK SESSIONS                     ║
╠═══════════════════════════════════════════════════════════════╣

Session: #12345 - test-attack-001
Target: http://target.example.com
Type: Slowloris
Status: Running
Duration: 00:15:32 / 01:00:00

VPS Nodes: 2 active
├─ 192.168.1.100
│  ├─ Connections: 1000/1000
│  ├─ Packets Sent: 45,230
│  ├─ Bytes Sent: 2.3 MB
│  ├─ CPU: 45%
│  └─ Memory: 512 MB
│
└─ 192.168.1.101
   ├─ Connections: 1000/1000
   ├─ Packets Sent: 44,890
   ├─ Bytes Sent: 2.2 MB
   ├─ CPU: 42%
   └─ Memory: 498 MB

Total Statistics:
├─ Total Connections: 2000
├─ Total Packets: 90,120
├─ Total Bytes: 4.5 MB
├─ Average Response Time: 15.2s
└─ Error Rate: 0.02%

[R] Refresh | [S] Stop Attack | [Q] Back to Menu
```

#### Stop Attack
```
Menu: 2 → 3 (Stop Attack)

Input:
- Session ID: 12345

Confirmation:
⚠ Stop attack session #12345? (yes/no): yes

Output:
✓ Stopping attack on all VPS nodes...
  ✓ 192.168.1.100: Stopped
  ✓ 192.168.1.101: Stopped
✓ Attack session #12345 stopped
✓ Final report saved to: reports/attack-12345.json
```

#### View Attack History
```
Menu: 2 → 4 (Attack History)

Output:
┌────────┬──────────────────┬─────────────────────────┬──────────┬──────────┐
│ ID     │ Name             │ Target                  │ Type     │ Status   │
├────────┼──────────────────┼─────────────────────────┼──────────┼──────────┤
│ 12345  │ test-attack-001  │ http://target.com       │ Slowloris│ Stopped  │
│ 12344  │ prod-test-002    │ http://example.com      │ SlowPOST │ Complete │
│ 12343  │ stress-test-001  │ http://testsite.com     │ SlowRead │ Complete │
└────────┴──────────────────┴─────────────────────────┴──────────┴──────────┘

[V] View Details | [E] Export Report | [D] Delete | [Q] Back
```

### 3. View Statistics

```
Menu: 3 (Statistics)

╔═══════════════════════════════════════════════════════════════╗
║                      SYSTEM STATISTICS                        ║
╠═══════════════════════════════════════════════════════════════╣

VPS Nodes:
├─ Total: 10
├─ Online: 8
├─ Offline: 2
└─ Average Uptime: 98.5%

Attack Sessions:
├─ Total: 156
├─ Active: 2
├─ Completed: 150
├─ Failed: 4
└─ Success Rate: 96.2%

Performance:
├─ Total Connections: 1,250,000
├─ Total Packets: 45,678,900
├─ Total Bytes: 2.3 TB
├─ Average Duration: 45 minutes
└─ Peak Concurrent: 15,000 connections

System Health:
├─ Database Size: 125 MB
├─ Log Files: 450 MB
├─ Uptime: 30 days, 5 hours
└─ Memory Usage: 1.2 GB / 4.0 GB
```

### 4. System Settings

```
Menu: 4 (Settings)

╔═══════════════════════════════════════════════════════════════╗
║                      SYSTEM SETTINGS                          ║
╠═══════════════════════════════════════════════════════════════╣

1. General Settings
2. Security Settings
3. Network Settings
4. Attack Defaults
5. Logging Settings
6. Backup & Restore
7. Update System
8. Back to Main Menu
```

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     C2 SERVER (Master)                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Web UI     │  │   CLI Menu   │  │   REST API   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                            │                                 │
│  ┌─────────────────────────┴─────────────────────────┐     │
│  │              Core Controller                       │     │
│  ├────────────────────────────────────────────────────┤     │
│  │  • VPS Manager                                     │     │
│  │  • Attack Coordinator                              │     │
│  │  • Session Manager                                 │     │
│  │  • Statistics Collector                            │     │
│  └────────────────────────────────────────────────────┘     │
│                            │                                 │
│  ┌─────────────────────────┴─────────────────────────┐     │
│  │           Support Modules                          │     │
│  ├────────────────────────────────────────────────────┤     │
│  │  • SSH Manager                                     │     │
│  │  • Database Manager                                │     │
│  │  • Security Manager                                │     │
│  │  • Logger                                          │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
└──────────────────────────┬───────────────────────────────────┘
                           │
                           │ SSH Connections
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   VPS Node 1  │  │   VPS Node 2  │  │   VPS Node N  │
├───────────────┤  ├───────────────┤  ├───────────────┤
│               │  │               │  │               │
│  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │
│  │  Agent  │  │  │  │  Agent  │  │  │  │  Agent  │  │
│  └────┬────┘  │  │  └────┬────┘  │  │  └────┬────┘  │
│       │       │  │       │       │  │       │       │
│       ▼       │  │       ▼       │  │       ▼       │
│  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │
│  │ Attack  │  │  │  │ Attack  │  │  │  │ Attack  │  │
│  │ Module  │  │  │  │ Module  │  │  │  │ Module  │  │
│  └────┬────┘  │  │  └────┬────┘  │  │  └────┬────┘  │
│       │       │  │       │       │  │       │       │
└───────┼───────┘  └───────┼───────┘  └───────┼───────┘
        │                  │                  │
        └──────────────────┴──────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Target Server  │
                  └─────────────────┘
```

### Data Flow

```
1. User Input → CLI/Web UI
2. Command Processing → Core Controller
3. VPS Selection → VPS Manager
4. Agent Deployment → SSH Manager
5. Attack Coordination → Attack Coordinator
6. Real-time Monitoring → Statistics Collector
7. Results Storage → Database Manager
8. Logging → Logger
9. Display Results → UI
```

### File Structure

```
slowhttp-c2/
├── slowhttp.py                    # Original C2 server
├── slowhttp_fixed.py              # Fixed version (recommended)
├── agent_upgraded.py              # Attack agent for VPS nodes
├── database_manager_upgraded.py   # Database operations
├── security_manager_upgraded.py   # Security & encryption
├── ssh_manager_upgraded.py        # SSH connection management
├── default_config.py              # Configuration file
├── requirements_upgraded.txt      # Python dependencies
├── setup_service.sh               # Linux service installer
├── uninstall.sh                   # Uninstaller script
├── update.sh                      # Update script
├── README.md                      # This file
├── security_audit_report.md       # Security audit report
├── key.key                        # Encryption key (auto-generated)
├── c2_database.db                 # SQLite database (auto-generated)
├── logs/                          # Log files
│   ├── c2.log
│   ├── ssh.log
│   └── attack.log
├── data/                          # Data directory
│   ├── backups/
│   └── exports/
└── venv/                          # Virtual environment
```

---

## 🔒 Security

### Security Features

1. **Encryption**
   - Password encryption (Fernet/AES-GCM/PBKDF2)
   - SSH key support
   - Secure key storage (0600 permissions)

2. **Input Validation**
   - SQL injection prevention
   - Command injection prevention
   - Path traversal prevention
   - XSS prevention (web UI)

3. **Authentication**
   - SSH authentication
   - Session management
   - Access control

4. **Audit Logging**
   - All operations logged
   - Timestamp tracking
   - User action tracking

### Security Best Practices

```bash
# 1. Set proper file permissions
chmod 600 key.key
chmod 600 c2_database.db
chmod 600 .env
chmod 700 logs/

# 2. Use SSH keys instead of passwords
ssh-keygen -t rsa -b 4096 -f ~/.ssh/slowhttp_key
# Add public key to VPS: ~/.ssh/authorized_keys

# 3. Configure firewall
# Linux (UFW)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5000/tcp  # Web UI (if needed)
sudo ufw enable

# Windows (PowerShell as Admin)
New-NetFirewallRule -DisplayName "SlowHTTP C2" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow

# 4. Enable SSL/TLS for web interface
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# 5. Regular updates
pip install --upgrade -r requirements_upgraded.txt

# 6. Backup encryption key
cp key.key key.key.backup
chmod 600 key.key.backup

# 7. Monitor logs
tail -f logs/c2.log

# 8. Use strong passwords
# Minimum 12 characters, mix of upper/lower/numbers/symbols
```

### Security Checklist

- [ ] Change default passwords
- [ ] Use SSH keys
- [ ] Enable firewall
- [ ] Set file permissions (600 for sensitive files)
- [ ] Enable SSL/TLS
- [ ] Regular backups
- [ ] Monitor logs
- [ ] Update dependencies
- [ ] Audit access logs
- [ ] Use strong encryption
- [ ] Limit network access
- [ ] Disable unnecessary services

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Installation Issues

**Problem:** `pip install` fails
```bash
# Solution 1: Upgrade pip
python -m pip install --upgrade pip

# Solution 2: Use --user flag
pip install --user -r requirements_upgraded.txt

# Solution 3: Install individually
pip install paramiko cryptography psutil colorama requests
```

**Problem:** Python version too old
```bash
# Check version
python --version

# Install Python 3.11+
# Windows: Download from python.org
# Linux: sudo apt install python3.11
# macOS: brew install python@3.11
```

#### 2. Connection Issues

**Problem:** Cannot connect to VPS
```bash
# Check SSH connectivity
ssh username@vps_ip

# Check firewall
# Linux
sudo ufw status
# Windows
netsh advfirewall show allprofiles

# Check SSH service
# Linux
sudo systemctl status sshd
```

**Problem:** SSH timeout
```python
# Increase timeout in default_config.py
SSH_TIMEOUT = 60  # Increase from 30 to 60 seconds
```

#### 3. Database Issues

**Problem:** Database locked
```bash
# Solution 1: Close other connections
# Check for other processes
ps aux | grep slowhttp

# Solution 2: Remove lock file
rm c2_database.db-journal

# Solution 3: Backup and recreate
cp c2_database.db c2_database.db.backup
rm c2_database.db
# Restart application to recreate
```

**Problem:** Database corruption
```bash
# Restore from backup
cp data/backups/c2_database_YYYYMMDD.db c2_database.db

# Or recreate database
rm c2_database.db
python slowhttp_fixed.py --init-db
```

#### 4. Agent Deployment Issues

**Problem:** Agent deployment fails
```bash
# Check Python on VPS
ssh username@vps_ip "python3 --version"

# Manually deploy agent
scp agent_upgraded.py username@vps_ip:/tmp/
ssh username@vps_ip "python3 /tmp/agent_upgraded.py --test"

# Check permissions
ssh username@vps_ip "ls -la /tmp/agent_upgraded.py"
```

#### 5. Attack Issues

**Problem:** Attack not starting
```bash
# Check VPS status
# Menu: 1 → 3 (Check Status)

# Check agent logs on VPS
ssh username@vps_ip "tail -f /tmp/agent.log"

# Restart agent
# Menu: 1 → 5 (Restart Agent)
```

**Problem:** Low connection count
```python
# Increase system limits on VPS
ssh username@vps_ip
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
ulimit -n 65535
```

#### 6. Performance Issues

**Problem:** High memory usage
```python
# Reduce concurrent connections in default_config.py
MAX_CONNECTIONS_PER_VPS = 1000  # Reduce from 5000

# Enable memory monitoring
MEMORY_MONITORING = True
MAX_MEMORY_MB = 512
```

**Problem:** Slow response
```bash
# Check system resources
# Linux
top
htop
# Windows
taskmgr

# Optimize database
python -c "from database_manager_upgraded import DatabaseManager; db = DatabaseManager(); db.optimize()"
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python slowhttp_fixed.py

# Or in config
LOG_LEVEL = "DEBUG"
```

### Getting Help

```bash
# View help
python slowhttp_fixed.py --help

# Check version
python slowhttp_fixed.py --version

# Run diagnostics
python slowhttp_fixed.py --diagnose

# View logs
tail -f logs/c2.log

# Export debug info
python slowhttp_fixed.py --export-debug debug_info.zip
```

---

## ❓ FAQ

### General Questions

**Q: Apakah tool ini legal?**
A: Tool ini legal untuk penetration testing yang AUTHORIZED. Penggunaan tanpa izin adalah ILEGAL.

**Q: Apakah saya perlu VPS?**
A: Ya, untuk distributed attack testing Anda memerlukan multiple VPS nodes.

**Q: Berapa banyak VPS yang dibutuhkan?**
A: Minimum 1 VPS, recommended 3-10 VPS untuk distributed testing.

**Q: Apakah bisa digunakan di localhost?**
A: Ya, untuk testing Anda bisa menggunakan localhost sebagai target.

**Q: Apakah ada web interface?**
A: Ya, web interface tersedia (optional). Enable di config: `WEB_ENABLED = True`

### Technical Questions

**Q: Apa perbedaan slowhttp.py dan slowhttp_fixed.py?**
A: slowhttp_fixed.py adalah versi yang sudah diperbaiki dengan bug fixes dan improvements.

**Q: Bagaimana cara backup database?**
A: Automatic backup saat migration, atau manual: `cp c2_database.db backup.db`

**Q: Apakah support IPv6?**
A: Ya, support IPv4 dan IPv6.

**Q: Bagaimana cara update?**
A: Jalankan `./update.sh` (Linux) atau download versi terbaru.

**Q: Apakah bisa run multiple instances?**
A: Ya, gunakan database dan port yang berbeda untuk setiap instance.

### Attack Questions

**Q: Apa perbedaan Slowloris, Slow POST, dan Slow Read?**
A: 
- **Slowloris**: Mengirim HTTP headers perlahan
- **Slow POST**: Mengirim POST body perlahan
- **Slow Read**: Membaca response perlahan

**Q: Berapa lama durasi attack yang recommended?**
A: Untuk testing: 5-10 menit. Untuk stress test: 30-60 menit.

**Q: Berapa banyak connections yang optimal?**
A: Tergantung target dan VPS. Start dengan 500-1000 per VPS.

**Q: Apakah attack bisa di-pause?**
A: Tidak, tapi bisa di-stop dan di-restart dengan session yang sama.

**Q: Bagaimana cara melihat hasil attack?**
A: Menu: 2 → 4 (Attack History) → View Details

### Security Questions

**Q: Apakah password tersimpan dengan aman?**
A: Ya, password di-encrypt menggunakan Fernet/AES-GCM.

**Q: Apakah ada logging?**
A: Ya, semua operasi di-log dengan timestamp.

**Q: Bagaimana cara menghapus logs?**
A: Manual: `rm logs/*.log` atau gunakan log rotation.

**Q: Apakah support 2FA?**
A: Saat ini belum, tapi bisa menggunakan SSH key authentication.

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable names
- Add comments for complex logic
- Write docstrings for functions
- Include type hints

### Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/

# Run specific test
python -m pytest tests/test_database.py
```

### Reporting Bugs

Please include:
- OS and version
- Python version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages
- Screenshots (if applicable)

### Feature Requests

Please include:
- Clear description
- Use case
- Expected behavior
- Mockups (if applicable)

---

## 📄 License

This project is licensed for **EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**.

### Terms of Use

1. **Authorized Use Only**
   - Only use on systems you own or have written permission to test
   - Obtain proper authorization before any testing
   - Document all testing activities

2. **Prohibited Uses**
   - Unauthorized access to systems
   - Malicious activities
   - Disrupting public services
   - Any illegal activities

3. **Liability**
   - Users are solely responsible for their actions
   - Developers are not liable for misuse
   - No warranty provided

4. **Compliance**
   - Follow local laws and regulations
   - Respect terms of service
   - Practice responsible disclosure

---

## 📞 Support

### Documentation

- **Full Documentation**: [docs/](docs/)
- **API Reference**: [docs/api.md](docs/api.md)
- **Security Guide**: [security_audit_report.md](security_audit_report.md)

### Community

- **Issues**: [GitHub Issues](https://github.com/yourusername/slowhttp-c2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/slowhttp-c2/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/yourusername/slowhttp-c2/wiki)

### Contact

- **Email**: security@example.com
- **Twitter**: @slowhttpc2
- **Discord**: [Join Server](https://discord.gg/slowhttpc2)

---

## 🙏 Acknowledgments

- **Paramiko** - SSH implementation
- **Cryptography** - Encryption library
- **SQLite** - Database engine
- **Python Community** - Amazing ecosystem

---

## 📊 Project Status

- **Version**: 5.0
- **Status**: Active Development
- **Last Updated**: 2025-10-03
- **Python**: 3.8+
- **Platforms**: Windows, Linux, macOS

---

## 🗺️ Roadmap

### Version 5.1 (Q1 2025)
- [ ] Web UI improvements
- [ ] REST API
- [ ] Docker support
- [ ] Kubernetes deployment
- [ ] Advanced analytics

### Version 5.2 (Q2 2025)
- [ ] Multi-user support
- [ ] Role-based access control
- [ ] 2FA authentication
- [ ] Cloud integration (AWS, GCP, Azure)
- [ ] Automated reporting

### Version 6.0 (Q3 2025)
- [ ] Machine learning integration
- [ ] Predictive analytics
- [ ] Auto-scaling
- [ ] Advanced visualization
- [ ] Mobile app

---

## 📝 Changelog

### Version 5.0 (2025-10-03)
- ✨ Complete rewrite with upgraded architecture
- ✨ Enhanced security features
- ✨ Improved performance
- ✨ Better error handling
- ✨ Comprehensive logging
- 🐛 Fixed multiple bugs
- 📚 Updated documentation

### Version 4.0 (2024-09-15)
- ✨ Added web interface
- ✨ Database migration system
- ✨ Improved SSH management
- 🐛 Fixed connection issues

### Version 3.0 (2024-06-01)
- ✨ Multi-VPS support
- ✨ Attack coordination
- ✨ Statistics tracking

---

## ⚖️ Legal Notice

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                           LEGAL NOTICE                                    ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  This tool is provided for EDUCATIONAL and AUTHORIZED TESTING purposes   ║
║  only. The developers and contributors are NOT responsible for any       ║
║  misuse or damage caused by this tool.                                   ║
║                                                                           ║
║  By using this tool, you agree to:                                       ║
║  • Only use it on systems you own or have written permission to test    ║
║  • Comply with all applicable laws and regulations                       ║
║  • Take full responsibility for your actions                             ║
║  • Not hold the developers liable for any consequences                   ║
║                                                                           ║
║  Unauthorized access to computer systems is ILLEGAL and punishable by    ║
║  law in most jurisdictions.                                              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

<div align="center">

**Made with ❤️ for Security Professionals**

[⬆ Back to Top](#-distributed-slow-http-c2-system)

</div>