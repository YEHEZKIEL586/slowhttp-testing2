#!/bin/bash

#############################################################################
# SlowHTTP v2 - Advanced Installation Script
# Automated installation with dependency checking and system configuration
#############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/slowhttp"
VENV_DIR="$INSTALL_DIR/venv"
LOG_FILE="/var/log/slowhttp_install.log"
PYTHON_MIN_VERSION="3.8"

#############################################################################
# Helper Functions
#############################################################################

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║           SlowHTTP v2 - Installation Script               ║"
    echo "║                                                            ║"
    echo "║              Advanced Distributed C2 Framework             ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[*]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        log "Detected OS: $OS $VER"
    else
        error "Cannot detect operating system"
        exit 1
    fi
}

check_python() {
    log "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [[ $PYTHON_MAJOR -ge 3 ]] && [[ $PYTHON_MINOR -ge 8 ]]; then
            log "Python $PYTHON_VERSION found (OK)"
            return 0
        else
            error "Python 3.8+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        error "Python 3 not found"
        return 1
    fi
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
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
                iptables \
                ufw
            ;;
        centos|rhel|fedora)
            yum install -y epel-release
            yum install -y \
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
            ;;
        arch)
            pacman -Sy --noconfirm \
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
            ;;
        *)
            warning "Unsupported OS: $OS"
            warning "Please install dependencies manually"
            ;;
    esac
    
    log "System dependencies installed"
}

create_directories() {
    log "Creating installation directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/configs"
    
    log "Directories created"
}

setup_virtual_environment() {
    log "Setting up Python virtual environment..."
    
    cd "$INSTALL_DIR"
    python3 -m venv "$VENV_DIR"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    log "Virtual environment created"
}

install_python_dependencies() {
    log "Installing Python dependencies..."
    
    source "$VENV_DIR/bin/activate"
    
    # Install from requirements file
    if [[ -f "requirements_upgraded.txt" ]]; then
        pip install -r requirements_upgraded.txt
    else
        # Install core dependencies manually
        pip install \
            paramiko>=3.4.0 \
            cryptography>=41.0.7 \
            psutil>=5.9.6 \
            colorama>=0.4.6 \
            requests>=2.31.0 \
            dnspython>=2.4.2 \
            aiohttp>=3.9.1 \
            rich>=13.7.0 \
            pydantic>=2.5.3
    fi
    
    log "Python dependencies installed"
}

copy_files() {
    log "Copying application files..."
    
    # Copy main files
    cp slowhttpv2.py "$INSTALL_DIR/"
    cp agent_upgraded.py "$INSTALL_DIR/"
    cp ssh_manager_upgraded.py "$INSTALL_DIR/"
    cp database_manager_upgraded.py "$INSTALL_DIR/"
    cp security_manager_upgraded.py "$INSTALL_DIR/"
    cp default_config.py "$INSTALL_DIR/"
    cp enhancements.py "$INSTALL_DIR/"
    cp improved_attackers.py "$INSTALL_DIR/"
    
    # Copy scripts
    cp update.sh "$INSTALL_DIR/"
    cp uninstall.sh "$INSTALL_DIR/"
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR"/*.sh
    chmod +x "$INSTALL_DIR"/*.py
    
    log "Files copied"
}

create_systemd_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/slowhttp.service << EOF
[Unit]
Description=SlowHTTP v2 C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/slowhttpv2.py
Restart=on-failure
RestartSec=10
StandardOutput=append:$INSTALL_DIR/logs/slowhttp.log
StandardError=append:$INSTALL_DIR/logs/slowhttp_error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    log "Systemd service created"
}

create_command_alias() {
    log "Creating command alias..."
    
    cat > /usr/local/bin/slowhttp << EOF
#!/bin/bash
source $VENV_DIR/bin/activate
cd $INSTALL_DIR
python3 slowhttpv2.py "\$@"
EOF
    
    chmod +x /usr/local/bin/slowhttp
    
    log "Command alias created: 'slowhttp'"
}

configure_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # UFW (Ubuntu/Debian)
        ufw --force enable
        ufw allow 22/tcp  # SSH
        ufw allow 8080/tcp  # C2 Server (if needed)
        log "UFW configured"
    elif command -v firewall-cmd &> /dev/null; then
        # FirewallD (CentOS/RHEL)
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --reload
        log "FirewallD configured"
    else
        warning "No firewall detected, skipping firewall configuration"
    fi
}

setup_logging() {
    log "Setting up logging..."
    
    # Create log rotation configuration
    cat > /etc/logrotate.d/slowhttp << EOF
$INSTALL_DIR/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    
    log "Logging configured"
}

security_hardening() {
    log "Applying security hardening..."
    
    # Set proper permissions
    chmod 700 "$INSTALL_DIR"
    chmod 600 "$INSTALL_DIR"/*.py
    chmod 700 "$INSTALL_DIR"/*.sh
    
    # Secure database
    if [[ -f "$INSTALL_DIR/c2_database.db" ]]; then
        chmod 600 "$INSTALL_DIR/c2_database.db"
    fi
    
    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf
    
    log "Security hardening applied"
}

create_config() {
    log "Creating default configuration..."
    
    cat > "$INSTALL_DIR/configs/config.json" << EOF
{
    "version": "5.0",
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "ssl_enabled": false
    },
    "database": {
        "path": "$INSTALL_DIR/data/c2_database.db"
    },
    "logging": {
        "level": "INFO",
        "path": "$INSTALL_DIR/logs"
    },
    "security": {
        "encryption_enabled": true,
        "max_login_attempts": 3,
        "session_timeout": 3600
    }
}
EOF
    
    log "Configuration created"
}

run_tests() {
    log "Running installation tests..."
    
    source "$VENV_DIR/bin/activate"
    
    # Test Python imports
    python3 -c "import paramiko, cryptography, psutil, colorama, requests, dns.resolver" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        log "Python dependencies test: PASSED"
    else
        error "Python dependencies test: FAILED"
        return 1
    fi
    
    # Test main script syntax
    python3 -m py_compile "$INSTALL_DIR/slowhttpv2.py" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        log "Main script syntax test: PASSED"
    else
        error "Main script syntax test: FAILED"
        return 1
    fi
    
    log "All tests passed"
    return 0
}

print_completion_message() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║          Installation Completed Successfully!             ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Details:${NC}"
    echo -e "  Installation Directory: ${GREEN}$INSTALL_DIR${NC}"
    echo -e "  Virtual Environment: ${GREEN}$VENV_DIR${NC}"
    echo -e "  Log File: ${GREEN}$LOG_FILE${NC}"
    echo ""
    echo -e "${BLUE}Usage:${NC}"
    echo -e "  Start application: ${GREEN}slowhttp${NC}"
    echo -e "  Or manually: ${GREEN}cd $INSTALL_DIR && source venv/bin/activate && python3 slowhttpv2.py${NC}"
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo -e "  Start service: ${GREEN}systemctl start slowhttp${NC}"
    echo -e "  Stop service: ${GREEN}systemctl stop slowhttp${NC}"
    echo -e "  Enable on boot: ${GREEN}systemctl enable slowhttp${NC}"
    echo -e "  View logs: ${GREEN}journalctl -u slowhttp -f${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT SECURITY NOTES:${NC}"
    echo -e "  1. Change default passwords immediately"
    echo -e "  2. Configure firewall rules for your network"
    echo -e "  3. Use only for authorized testing"
    echo -e "  4. Review security settings in $INSTALL_DIR/configs/config.json"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  1. Review configuration: ${GREEN}nano $INSTALL_DIR/configs/config.json${NC}"
    echo -e "  2. Add VPS nodes to the database"
    echo -e "  3. Start the application: ${GREEN}slowhttp${NC}"
    echo ""
}

#############################################################################
# Main Installation Process
#############################################################################

main() {
    print_banner
    
    log "Starting SlowHTTP v2 installation..."
    
    # Pre-installation checks
    check_root
    check_os
    
    if ! check_python; then
        error "Python 3.8+ is required but not found"
        info "Please install Python 3.8 or higher and run this script again"
        exit 1
    fi
    
    # Installation steps
    install_system_dependencies
    create_directories
    setup_virtual_environment
    install_python_dependencies
    copy_files
    create_systemd_service
    create_command_alias
    configure_firewall
    setup_logging
    security_hardening
    create_config
    
    # Post-installation
    if run_tests; then
        print_completion_message
        log "Installation completed successfully"
        exit 0
    else
        error "Installation completed with errors"
        error "Please check the log file: $LOG_FILE"
        exit 1
    fi
}

# Run main installation
main "$@"
