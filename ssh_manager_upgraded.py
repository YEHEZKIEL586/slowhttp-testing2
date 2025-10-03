#!/usr/bin/env python3
"""
Enhanced SSH Manager for Distributed Slow HTTP C2
Provides secure SSH operations with connection pooling, key authentication, and proper resource management
"""

import os
import time
import threading
import logging
import shlex
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path
from contextlib import contextmanager
from collections import OrderedDict

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Base exception for SSH-related errors"""
    pass


class SSHConnectionError(SSHError):
    """Raised when SSH connection fails"""
    pass


class SSHAuthenticationError(SSHError):
    """Raised when SSH authentication fails"""
    pass


class SSHCommandError(SSHError):
    """Raised when SSH command execution fails"""
    pass


class SSHConnection:
    """
    Wrapper for SSH connection with automatic cleanup and health checking.
    """
    
    def __init__(
        self,
        ip: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: int = 30
    ):
        """
        Initialize SSH connection wrapper.
        
        Args:
            ip: Remote host IP
            username: SSH username
            password: SSH password (optional if using key)
            key_path: Path to SSH private key (optional)
            port: SSH port
            timeout: Connection timeout
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        
        self.client: Optional[paramiko.SSHClient] = None
        self.connected = False
        self.last_used = time.time()
        self.lock = threading.Lock()
        
        # Connect
        self._connect()
    
    def _connect(self) -> None:
        """Establish SSH connection"""
        if not SSH_AVAILABLE:
            raise SSHError("paramiko module not available")
        
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Prepare connection parameters
            connect_kwargs = {
                'hostname': self.ip,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'banner_timeout': 15,
                'auth_timeout': 10,
                'look_for_keys': False,
                'allow_agent': False
            }
            
            # Use SSH key if provided
            if self.key_path:
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(self.key_path)
                    connect_kwargs['pkey'] = private_key
                    logger.info(f"Using SSH key authentication for {self.ip}")
                except Exception as e:
                    logger.warning(f"Failed to load SSH key, trying password: {e}")
                    if self.password:
                        connect_kwargs['password'] = self.password
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                raise SSHAuthenticationError("No authentication method provided")
            
            # Connect
            self.client.connect(**connect_kwargs)
            self.connected = True
            self.last_used = time.time()
            
            logger.info(f"SSH connection established to {self.ip}:{self.port}")
            
        except paramiko.AuthenticationException as e:
            raise SSHAuthenticationError(f"Authentication failed for {self.ip}: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH connection failed for {self.ip}: {e}")
        except Exception as e:
            raise SSHConnectionError(f"Failed to connect to {self.ip}: {e}")
    
    def execute_command(
        self,
        command: str,
        timeout: int = 30,
        get_pty: bool = False
    ) -> Tuple[bool, str]:
        """
        Execute command on remote host.
        
        Args:
            command: Command to execute
            timeout: Command timeout
            get_pty: Request pseudo-terminal
            
        Returns:
            Tuple of (success, output/error)
        """
        with self.lock:
            if not self.is_alive():
                raise SSHConnectionError("Connection is not alive")
            
            try:
                # Execute command
                stdin, stdout, stderr = self.client.exec_command(
                    command,
                    timeout=timeout,
                    get_pty=get_pty
                )
                
                # Read output
                output = stdout.read().decode('utf-8', errors='ignore')
                error = stderr.read().decode('utf-8', errors='ignore')
                
                # Get exit status
                exit_status = stdout.channel.recv_exit_status()
                
                # Update last used time
                self.last_used = time.time()
                
                if exit_status == 0:
                    return True, output
                else:
                    return False, error if error else output
                
            except paramiko.SSHException as e:
                logger.error(f"SSH command execution failed: {e}")
                return False, str(e)
            except Exception as e:
                logger.error(f"Command execution error: {e}")
                return False, str(e)
    
    def is_alive(self) -> bool:
        """
        Check if connection is alive.
        
        Returns:
            True if connection is alive
        """
        if not self.connected or not self.client:
            return False
        
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_active():
                return False
            
            # Send keepalive
            transport.send_ignore()
            return True
        except Exception:
            return False
    
    def close(self) -> None:
        """Close SSH connection"""
        with self.lock:
            if self.client:
                try:
                    self.client.close()
                    logger.info(f"SSH connection closed to {self.ip}")
                except Exception as e:
                    logger.warning(f"Error closing SSH connection: {e}")
                finally:
                    self.client = None
                    self.connected = False
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False


class SSHConnectionPool:
    """
    Connection pool for SSH connections with automatic cleanup and reuse.
    """
    
    def __init__(
        self,
        max_connections: int = 50,
        max_idle_time: int = 300,
        cleanup_interval: int = 60
    ):
        """
        Initialize SSH connection pool.
        
        Args:
            max_connections: Maximum number of pooled connections
            max_idle_time: Maximum idle time before connection is closed (seconds)
            cleanup_interval: Interval for cleanup thread (seconds)
        """
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.cleanup_interval = cleanup_interval
        
        self.pool: OrderedDict[str, SSHConnection] = OrderedDict()
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info(f"SSH connection pool initialized (max: {max_connections})")
    
    def _get_key(
        self,
        ip: str,
        username: str,
        port: int
    ) -> str:
        """Generate pool key for connection"""
        return f"{ip}:{port}:{username}"
    
    def get_connection(
        self,
        ip: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: int = 30
    ) -> SSHConnection:
        """
        Get SSH connection from pool or create new one.
        
        Args:
            ip: Remote host IP
            username: SSH username
            password: SSH password
            key_path: Path to SSH private key
            port: SSH port
            timeout: Connection timeout
            
        Returns:
            SSHConnection instance
        """
        key = self._get_key(ip, username, port)
        
        with self.lock:
            # Check if connection exists in pool
            if key in self.pool:
                conn = self.pool[key]
                
                # Check if connection is still alive
                if conn.is_alive():
                    # Move to end (most recently used)
                    self.pool.move_to_end(key)
                    conn.last_used = time.time()
                    logger.debug(f"Reusing pooled connection to {ip}")
                    return conn
                else:
                    # Connection dead, remove from pool
                    logger.info(f"Removing dead connection from pool: {ip}")
                    conn.close()
                    del self.pool[key]
            
            # Create new connection
            if len(self.pool) >= self.max_connections:
                # Remove oldest connection
                oldest_key = next(iter(self.pool))
                oldest_conn = self.pool[oldest_key]
                logger.info(f"Pool full, removing oldest connection: {oldest_key}")
                oldest_conn.close()
                del self.pool[oldest_key]
            
            # Create and add new connection
            try:
                conn = SSHConnection(ip, username, password, key_path, port, timeout)
                self.pool[key] = conn
                logger.info(f"Created new pooled connection to {ip}")
                return conn
            except Exception as e:
                logger.error(f"Failed to create connection to {ip}: {e}")
                raise
    
    def release_connection(self, conn: SSHConnection) -> None:
        """
        Release connection back to pool (no-op, connections stay in pool).
        
        Args:
            conn: SSH connection to release
        """
        # Connection stays in pool for reuse
        pass
    
    def remove_connection(self, ip: str, username: str, port: int = 22) -> None:
        """
        Remove connection from pool.
        
        Args:
            ip: Remote host IP
            username: SSH username
            port: SSH port
        """
        key = self._get_key(ip, username, port)
        
        with self.lock:
            if key in self.pool:
                conn = self.pool[key]
                conn.close()
                del self.pool[key]
                logger.info(f"Removed connection from pool: {key}")
    
    def _cleanup_loop(self) -> None:
        """Background thread to cleanup idle connections"""
        while True:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_idle_connections()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    def _cleanup_idle_connections(self) -> None:
        """Remove idle connections from pool"""
        with self.lock:
            current_time = time.time()
            keys_to_remove = []
            
            for key, conn in self.pool.items():
                # Check if connection is idle
                idle_time = current_time - conn.last_used
                
                if idle_time > self.max_idle_time:
                    keys_to_remove.append(key)
                elif not conn.is_alive():
                    keys_to_remove.append(key)
            
            # Remove idle/dead connections
            for key in keys_to_remove:
                conn = self.pool[key]
                conn.close()
                del self.pool[key]
                logger.info(f"Cleaned up idle connection: {key}")
    
    def close_all(self) -> None:
        """Close all connections in pool"""
        with self.lock:
            for conn in self.pool.values():
                conn.close()
            self.pool.clear()
            logger.info("Closed all pooled connections")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get pool statistics.
        
        Returns:
            Statistics dictionary
        """
        with self.lock:
            alive_count = sum(1 for conn in self.pool.values() if conn.is_alive())
            
            return {
                'total_connections': len(self.pool),
                'alive_connections': alive_count,
                'dead_connections': len(self.pool) - alive_count,
                'max_connections': self.max_connections
            }


class SSHManager:
    """
    Enhanced SSH Manager with connection pooling, command validation, and security features.
    """
    
    def __init__(
        self,
        security_manager,
        max_connections: int = 50,
        command_timeout: int = 30
    ):
        """
        Initialize SSH manager.
        
        Args:
            security_manager: SecurityManager instance for password handling
            max_connections: Maximum pooled connections
            command_timeout: Default command timeout
        """
        self.security_manager = security_manager
        self.command_timeout = command_timeout
        
        # Initialize connection pool
        self.pool = SSHConnectionPool(max_connections=max_connections)
        
        # Command whitelist for security
        self.allowed_commands = {
            'ls', 'cd', 'pwd', 'cat', 'echo', 'mkdir', 'rm', 'cp', 'mv',
            'chmod', 'chown', 'grep', 'find', 'ps', 'kill', 'pkill',
            'python3', 'python', 'pip', 'pip3', 'apt-get', 'yum',
            'systemctl', 'service', 'wget', 'curl', 'git',
            'tar', 'gzip', 'unzip', 'df', 'du', 'free', 'top', 'htop',
            'uname', 'hostname', 'uptime', 'whoami', 'id'
        }
        
        logger.info("SSHManager initialized")
    
    def connect_vps(
        self,
        ip: str,
        username: str,
        encrypted_password: str,
        port: int = 22,
        key_path: Optional[str] = None,
        timeout: int = 30
    ) -> Tuple[bool, str]:
        """
        Connect to VPS and add to pool.
        
        Args:
            ip: VPS IP address
            username: SSH username
            encrypted_password: Encrypted password
            port: SSH port
            key_path: Path to SSH private key
            timeout: Connection timeout
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Decrypt password if not using key
            password = None
            if not key_path and encrypted_password:
                try:
                    password = self.security_manager.decrypt_password(encrypted_password)
                except Exception as e:
                    logger.error(f"Failed to decrypt password: {e}")
                    return False, f"Password decryption failed: {e}"
            
            # Get connection from pool
            conn = self.pool.get_connection(
                ip, username, password, key_path, port, timeout
            )
            
            # Test connection
            success, output = conn.execute_command('echo "test"', timeout=5)
            
            if success:
                return True, f"Connected to {ip}"
            else:
                return False, f"Connection test failed: {output}"
            
        except SSHAuthenticationError as e:
            logger.error(f"Authentication failed for {ip}: {e}")
            return False, f"Authentication failed: {e}"
        except SSHConnectionError as e:
            logger.error(f"Connection failed for {ip}: {e}")
            return False, f"Connection failed: {e}"
        except Exception as e:
            logger.error(f"Unexpected error connecting to {ip}: {e}")
            return False, f"Connection error: {e}"
    
    def disconnect_vps(self, ip: str, username: str, port: int = 22) -> bool:
        """
        Disconnect from VPS and remove from pool.
        
        Args:
            ip: VPS IP address
            username: SSH username
            port: SSH port
            
        Returns:
            True if successful
        """
        try:
            self.pool.remove_connection(ip, username, port)
            return True
        except Exception as e:
            logger.error(f"Error disconnecting from {ip}: {e}")
            return False
    
    def validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Validate command for security.
        
        Args:
            command: Command to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Sanitize command
            sanitized = self.security_manager.sanitize_command(command)
            
            # Parse command
            parts = shlex.split(sanitized)
            if not parts:
                return False, "Empty command"
            
            base_command = parts[0]
            
            # Check if command is in whitelist
            if base_command not in self.allowed_commands:
                return False, f"Command '{base_command}' not allowed"
            
            # Additional security checks
            dangerous_patterns = [
                r'rm\s+-rf\s+/',  # Dangerous rm
                r'dd\s+if=',      # dd command
                r'>\s*/dev/',     # Writing to devices
                r'mkfs',          # Format filesystem
                r'fdisk',         # Disk partitioning
            ]
            
            import re
            for pattern in dangerous_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return False, f"Command contains dangerous pattern: {pattern}"
            
            return True, "Command is valid"
            
        except Exception as e:
            return False, f"Command validation error: {e}"
    
    def execute_command(
        self,
        ip: str,
        command: str,
        username: str = 'root',
        port: int = 22,
        timeout: Optional[int] = None,
        validate: bool = True,
        auto_reconnect: bool = True
    ) -> Tuple[bool, str]:
        """
        Execute command on VPS.
        
        Args:
            ip: VPS IP address
            command: Command to execute
            username: SSH username
            port: SSH port
            timeout: Command timeout
            validate: Validate command before execution
            auto_reconnect: Automatically reconnect if connection lost
            
        Returns:
            Tuple of (success, output/error)
        """
        # Validate command if requested
        if validate:
            valid, msg = self.validate_command(command)
            if not valid:
                logger.warning(f"Command validation failed: {msg}")
                return False, f"Command validation failed: {msg}"
        
        # Use default timeout if not specified
        if timeout is None:
            timeout = self.command_timeout
        
        try:
            # Get connection from pool
            key = self.pool._get_key(ip, username, port)
            
            if key not in self.pool.pool:
                return False, f"No connection to {ip}. Please connect first."
            
            conn = self.pool.pool[key]
            
            # Execute command
            success, output = conn.execute_command(command, timeout)
            
            return success, output
            
        except SSHConnectionError as e:
            logger.error(f"Connection error executing command on {ip}: {e}")
            
            if auto_reconnect:
                logger.info(f"Attempting to reconnect to {ip}")
                # Connection will be recreated on next get_connection call
                self.pool.remove_connection(ip, username, port)
                return False, f"Connection lost, please retry"
            
            return False, f"Connection error: {e}"
        except Exception as e:
            logger.error(f"Error executing command on {ip}: {e}")
            return False, f"Execution error: {e}"
    
    def execute_on_multiple_vps(
        self,
        vps_list: List[Dict[str, Any]],
        command: str,
        timeout: Optional[int] = None,
        max_workers: int = 10
    ) -> Dict[str, Tuple[bool, str]]:
        """
        Execute command on multiple VPS concurrently.
        
        Args:
            vps_list: List of VPS dictionaries
            command: Command to execute
            timeout: Command timeout
            max_workers: Maximum concurrent executions
            
        Returns:
            Dictionary mapping IP to (success, output)
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = {}
        
        def execute_on_vps(vps):
            ip = vps['ip_address']
            username = vps.get('username', 'root')
            port = vps.get('ssh_port', 22)
            
            success, output = self.execute_command(
                ip, command, username, port, timeout
            )
            return ip, (success, output)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(execute_on_vps, vps): vps
                for vps in vps_list
            }
            
            for future in as_completed(futures):
                try:
                    ip, result = future.result()
                    results[ip] = result
                except Exception as e:
                    vps = futures[future]
                    ip = vps['ip_address']
                    results[ip] = (False, f"Execution failed: {e}")
        
        return results
    
    def get_system_info(self, ip: str, username: str = 'root', port: int = 22) -> Optional[Dict[str, Any]]:
        """
        Get system information from VPS.
        
        Args:
            ip: VPS IP address
            username: SSH username
            port: SSH port
            
        Returns:
            System information dictionary or None
        """
        try:
            # Create command to gather system information
            cmd = """
            echo "{"
            echo "  \&quot;hostname\&quot;: \&quot;$(hostname)\&quot;,"
            echo "  \&quot;os\&quot;: \&quot;$(cat /etc/os-release | grep PRETTY_NAME | cut -d = -f 2 | tr -d '\&quot;')\&quot;,"
            echo "  \&quot;kernel\&quot;: \&quot;$(uname -r)\&quot;,"
            echo "  \&quot;cpu\&quot;: \&quot;$(grep 'model name' /proc/cpuinfo | head -1 | cut -d : -f 2 | xargs)\&quot;,"
            echo "  \&quot;cpu_cores\&quot;: $(grep -c processor /proc/cpuinfo),"
            echo "  \&quot;memory_total\&quot;: \&quot;$(free -h | grep Mem | awk '{print $2}')\&quot;,"
            echo "  \&quot;memory_used\&quot;: \&quot;$(free -h | grep Mem | awk '{print $3}')\&quot;,"
            echo "  \&quot;disk_total\&quot;: \&quot;$(df -h / | tail -1 | awk '{print $2}')\&quot;,"
            echo "  \&quot;disk_used\&quot;: \&quot;$(df -h / | tail -1 | awk '{print $3}')\&quot;,"
            echo "  \&quot;python_version\&quot;: \&quot;$(python3 --version 2>&1)\&quot;,"
            echo "  \&quot;uptime\&quot;: \&quot;$(uptime -p)\&quot;"
            echo "}"
            """
            
            success, output = self.execute_command(
                ip, cmd, username, port, timeout=10, validate=False
            )
            
            if not success:
                logger.error(f"Failed to get system info from {ip}: {output}")
                return None
            
            # Parse JSON output
            import json
            try:
                system_info = json.loads(output)
                return system_info
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse system info from {ip}: {e}")
                return None
            
        except Exception as e:
            logger.error(f"Error getting system info from {ip}: {e}")
            return None
    
    def deploy_file(
        self,
        ip: str,
        local_path: str,
        remote_path: str,
        username: str = 'root',
        port: int = 22
    ) -> Tuple[bool, str]:
        """
        Deploy file to VPS using SFTP.
        
        Args:
            ip: VPS IP address
            local_path: Local file path
            remote_path: Remote file path
            username: SSH username
            port: SSH port
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get connection
            key = self.pool._get_key(ip, username, port)
            
            if key not in self.pool.pool:
                return False, f"No connection to {ip}"
            
            conn = self.pool.pool[key]
            
            if not conn.is_alive():
                return False, f"Connection to {ip} is not alive"
            
            # Open SFTP session
            sftp = conn.client.open_sftp()
            
            try:
                # Upload file
                sftp.put(local_path, remote_path)
                logger.info(f"Deployed {local_path} to {ip}:{remote_path}")
                return True, f"File deployed successfully"
            finally:
                sftp.close()
            
        except Exception as e:
            logger.error(f"Error deploying file to {ip}: {e}")
            return False, f"Deployment failed: {e}"
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """
        Get connection pool statistics.
        
        Returns:
            Statistics dictionary
        """
        return self.pool.get_stats()
    
    def close_all_connections(self) -> None:
        """Close all SSH connections"""
        self.pool.close_all()
        logger.info("All SSH connections closed")


if __name__ == "__main__":
    # Test SSH manager
    import sys
    from security_manager_upgraded import SecurityManager
    
    logging.basicConfig(level=logging.INFO)
    
    print("Testing SSHManager...")
    print("Note: This test requires a real SSH server to connect to")
    print()
    
    # Initialize managers
    sec_mgr = SecurityManager('test_key.key')
    ssh_mgr = SSHManager(sec_mgr)
    
    # Test command validation
    print("1. Testing command validation...")
    test_commands = [
        "ls -la",
        "rm -rf /",
        "cat /etc/passwd",
        "python3 --version",
        "malicious_command"
    ]
    
    for cmd in test_commands:
        valid, msg = ssh_mgr.validate_command(cmd)
        print(f"  '{cmd}': {'✓' if valid else '✗'} {msg}")
    
    # Test connection pool stats
    print("\n2. Testing connection pool...")
    stats = ssh_mgr.get_pool_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✓ Basic tests passed!")
    print("Note: Full testing requires SSH server access")
    
    # Cleanup
    ssh_mgr.close_all_connections()
    if Path('test_key.key').exists():
        Path('test_key.key').unlink()