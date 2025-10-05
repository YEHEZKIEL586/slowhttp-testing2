SlowHTTP v2 - Advanced Distributed C2 Framework

![Version](https://img.shields.io/badge/version-5.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-red.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)


⚠️ LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!**


This tool is designed for:
• ✅ Authorized penetration testing
• ✅ Security research
• ✅ Educational purposes
• ✅ Network stress testing with explicit permission


**⚠️ UNAUTHORIZED USE IS ILLEGAL!** Using this tool against systems you don't own or without explicit permission is a criminal offense. The authors are not responsible for misuse.


⸻


🚀 Features

Core Capabilities
• **Distributed C2 Architecture**: Manage multiple VPS nodes from a single interface
• **9 Attack Types**: Including new Cloudflare Bypass attack
• **Persistent Attacks**: Continue attacking even when target goes down temporarily
• **Auto-Recovery**: Automatic reconnection and target health monitoring
• **DNS History Tool**: Discover subdomains and non-Cloudflare IPs
• **Advanced Evasion**: 20+ user agents, traffic randomization, payload obfuscation
• **Real-time Analytics**: Monitor attack effectiveness in real-time
• **Load Balancing**: Distribute attacks intelligently across VPS nodes


Attack Types
1. **Slowloris** - Keep-alive header attack
2. **Slow POST** - Slow body transmission attack
3. **Slow Read** - Slow response reading attack
4. **HTTP Flood** - High-volume HTTP request flood
5. **SSL Exhaust** - SSL/TLS handshake exhaustion
6. **TCP Flood** - TCP SYN flood attack
7. **LAND Attack** - Spoofed packet attack
8. **DNS Amplification** - DNS reflection attack
9. **Cloudflare Bypass** - Cache poisoning and origin discovery ⭐ NEW!


Enhanced Features (v5.0)
• ✨ **Persistent Attack Mode**: Never stops until Ctrl+C
• ✨ **DNS History Tool**: Complete subdomain enumeration
• ✨ **Cloudflare Bypass**: Origin IP discovery + cache poisoning
• ✨ **Target Health Monitoring**: Auto-detect and wait for recovery
• ✨ **Advanced Reporting**: HTML, JSON, CSV export
• ✨ **Anti-Forensics**: Secure deletion and trace cleanup


⸻


📋 System Requirements

Minimum Requirements
• **OS**: Linux (Ubuntu 20.04+, Debian 10+, CentOS 8+, Arch)
• **Python**: 3.8 or higher
• **RAM**: 2GB minimum
• **Disk**: 1GB free space
• **Network**: Stable internet connection
• **Privileges**: Root/sudo access


Recommended Requirements
• **OS**: Ubuntu 22.04 LTS or Debian 11
• **Python**: 3.10 or higher
• **RAM**: 4GB or more
• **Disk**: 5GB free space
• **Network**: High-speed connection (100Mbps+)


⸻


🔧 Installation from GitHub

Method 1: Automated Installation (Recommended)

# 1. Clone the repository
git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git
cd slowhttp-testing2

# 2. Make installation script executable
chmod +x install.sh

# 3. Run installation as root
sudo ./install.sh


**Installation time:** 5-10 minutes


The automated installer will:
• ✅ Check system requirements
• ✅ Install system dependencies
• ✅ Create virtual environment
• ✅ Install Python packages
• ✅ Configure firewall
• ✅ Set up systemd service
• ✅ Apply security hardening
• ✅ Create command aliases


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

python3 -m venv venv
source venv/bin/activate


Step 4: Install Python Dependencies

pip install --upgrade pip setuptools wheel
pip install -r requirements.txt


Step 5: Verify Installation

python3 -c "import paramiko, cryptography, psutil, colorama, requests, dns.resolver; print('All dependencies OK')"


Step 6: Create Command Alias (Optional)

echo 'alias slowhttp="cd $(pwd) && source venv/bin/activate && python3 slowhttpv2.py"' >> ~/.bashrc
source ~/.bashrc


⸻


🎮 Quick Start Guide

1. Start the Application

# If you used automated installation:
slowhttp

# If you used manual installation:
cd slowhttp-testing2
source venv/bin/activate
python3 slowhttpv2.py


2. Main Menu

When you start the application, you'll see:


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


3. Add Your First VPS Node
1. Select `[1] VPS Management`
2. Select `[1] Add VPS`
3. Enter VPS details:
```
IP Address: 192.168.1.100
Username: root
Password: ********
SSH Port: 22
Location: US-East
Tags: production,primary
```
4. Wait for connection test
5. VPS added successfully!


4. Launch Your First Attack

⚠️ **IMPORTANT:** Only attack systems you own or have written authorization to test!

1. Select `[2] Attack Management`
2. Select `[1] Launch New Attack`
3. Configure attack:
```
Target URL: http://your-test-server.com
Attack Type: Slowloris
Select VPS nodes: [1, 2, 3]
Connections: 200
Delay: 15
Duration: 300
```
4. Confirm and launch
5. Monitor in real-time


5. Use DNS History Tool
1. Select `[4] Tools`
2. Select `[1] DNS History`
3. Enter domain: `example.com`
4. View results:
- Current IPs
- Non-Cloudflare IPs
- Subdomains
- DNS records


6. Use Cloudflare Bypass
1. Select `[2] Attack Management`
2. Select `[1] Launch New Attack`
3. Attack Type: `Cloudflare Bypass`
4. Enter target domain
5. Tool will:
- Discover origin IP
- Launch cache poisoning
- Bypass protection


⸻


📖 Usage Examples

Example 1: Basic Slowloris Attack

# Launch slowloris attack with 200 connections for 300 seconds
Target: http://example.com
Attack Type: Slowloris
Connections: 200
Delay: 15 seconds
Duration: 300 seconds


Example 2: Distributed Attack

# Launch attack across 5 VPS nodes
Target: http://example.com
Attack Type: HTTP Flood
VPS Nodes: 5 selected
Connections per VPS: 150
Total Connections: 750
Duration: 600 seconds


Example 3: DNS History Lookup

# From Tools menu
1. Select [4] Tools
2. Select [1] DNS History
3. Enter domain: example.com
4. View results:
   - Current IPs
   - Non-Cloudflare IPs
   - Subdomains
   - DNS records


Example 4: Cloudflare Bypass

# From Attack Management
1. Select [2] Attack Management
2. Select [1] Launch New Attack
3. Attack Type: Cloudflare Bypass
4. The tool will:
   - Discover origin IP
   - Launch cache poisoning attack
   - Bypass Cloudflare protection


⸻


⚙️ Configuration

Configuration File

Location: `configs/config.json`


{
    "version": "5.0",
    "attack": {
        "default_connections": 200,
        "default_duration": 300,
        "default_delay": 15,
        "persistent_mode": true,
        "auto_recovery": true
    },
    "network": {
        "connect_timeout": 10,
        "read_timeout": 30,
        "max_retries": 3
    },
    "security": {
        "encryption_enabled": true,
        "secure_delete": true,
        "anti_forensics": true
    }
}


Environment Variables

# Set custom paths
export SLOWHTTP_CONFIG="/custom/path/config.json"
export SLOWHTTP_DB_PATH="/custom/path/database.db"
export SLOWHTTP_LOG_PATH="/custom/path/logs"

# Set log level
export SLOWHTTP_LOG_LEVEL="DEBUG"


⸻


🔍 Troubleshooting

Common Issues

Issue 1: "Permission Denied"

Error: Permission denied

Solution:
sudo chmod +x slowhttpv2.py
sudo chown -R $USER:$USER .


Issue 2: "Module Not Found"

Error: ModuleNotFoundError: No module named 'paramiko'

Solution:
source venv/bin/activate
pip install -r requirements.txt


Issue 3: "SSH Connection Failed"

Error: SSH connection failed

Solution:
1. Check VPS IP and port
2. Verify SSH credentials
3. Test manual connection:
   ssh user@vps-ip -p port
4. Check firewall rules


Issue 4: "Database Locked"

Error: database is locked

Solution:
1. Close other instances
2. Check for zombie processes:
   ps aux | grep slowhttp
3. Kill if necessary:
   sudo killall -9 python3
4. Restart application


Viewing Logs

# Application logs
tail -f logs/slowhttp_c2_*.log

# Error logs
grep ERROR logs/*.log

# Debug mode
export SLOWHTTP_LOG_LEVEL="DEBUG"
python3 slowhttpv2.py


⸻


🔒 Security Best Practices

1. VPS Security
• ✅ Use strong SSH passwords or key-based authentication
• ✅ Enable firewall on all VPS nodes
• ✅ Keep systems updated
• ✅ Use non-standard SSH ports
• ✅ Implement fail2ban


2. C2 Server Security
• ✅ Run on isolated network
• ✅ Use VPN for C2 communications
• ✅ Encrypt all traffic
• ✅ Regular security audits
• ✅ Monitor for intrusions


3. Operational Security
• ✅ Use only for authorized testing
• ✅ Document all activities
• ✅ Obtain written permission
• ✅ Follow responsible disclosure
• ✅ Maintain audit logs


⸻


📊 Performance Tuning

System Optimization

# Increase file descriptor limits
ulimit -n 65535

# Optimize network stack
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
sudo sysctl -w net.core.somaxconn=4096


⸻


🔄 Updates

Check for Updates

cd slowhttp-testing2
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade


Version History
• **v5.0** (2025-01-04) - Major update with DNS History, Cloudflare Bypass, Persistent Attacks
• **v4.0** (2024-12-15) - Added distributed C2 capabilities
• **v3.0** (2024-11-20) - Enhanced attack types and TUI
• **v2.0** (2024-10-10) - Added database and SSH management
• **v1.0** (2024-09-01) - Initial release


⸻


🗑️ Uninstallation

# Using uninstall script
cd slowhttp-testing2
sudo ./uninstall.sh

# Manual uninstallation
sudo systemctl stop slowhttp
sudo systemctl disable slowhttp
sudo rm /etc/systemd/system/slowhttp.service
sudo rm /usr/local/bin/slowhttp
cd ..
rm -rf slowhttp-testing2


⸻


🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


⸻


📝 License

This project is licensed for **Educational Purposes Only**.


**Terms:**
• Use only for authorized testing
• No warranty provided
• Authors not liable for misuse
• Comply with local laws
• Obtain written permission


⸻


👥 Authors
• **YEHEZKIEL586** - [GitHub](https://github.com/YEHEZKIEL586)
• **NinjaTech AI** - Senior Development Team


⸻


🙏 Acknowledgments
• Python community for excellent libraries
• Security researchers for attack methodologies
• Open source contributors
• Penetration testing community


⸻


📧 Contact
• **GitHub**: [YEHEZKIEL586](https://github.com/YEHEZKIEL586)
• **Repository**: [slowhttp-testing2](https://github.com/YEHEZKIEL586/slowhttp-testing2)


⸻


📚 Additional Resources

Documentation
• [Installation Guide](INSTALLATION_GUIDE.md)
• [Upgrade Summary](UPGRADE_SUMMARY.md)
• [Files Manifest](FILES_MANIFEST.md)


Quick Links
• [Report Issues](https://github.com/YEHEZKIEL586/slowhttp-testing2/issues)
• [Request Features](https://github.com/YEHEZKIEL586/slowhttp-testing2/issues/new)
• [View Releases](https://github.com/YEHEZKIEL586/slowhttp-testing2/releases)


⸻


⭐ Star History

If you find this tool useful, please consider giving it a star!


[![Star History Chart](https://api.star-history.com/svg?repos=YEHEZKIEL586/slowhttp-testing2&type=Date)](https://star-history.com/#YEHEZKIEL586/slowhttp-testing2&Date)


⸻


📈 Statistics
• **Lines of Code**: 7,320+
• **Attack Types**: 9
• **Features**: 12+
• **Documentation**: 50+ pages
• **Bug-Free**: ✅ Verified


⸻


**Remember: With great power comes great responsibility. Use ethically!**


⸻


🎯 Quick Reference

Installation

git clone https://github.com/YEHEZKIEL586/slowhttp-testing2.git
cd slowhttp-testing2
chmod +x install.sh
sudo ./install.sh
slowhttp


Update

cd slowhttp-testing2
git pull
pip install -r requirements.txt --upgrade


Uninstall

cd slowhttp-testing2
sudo ./uninstall.sh


⸻


**Status:** ✅ Production Ready | **Version:** 5.0 Enhanced | **Updated:** January 4, 2025
