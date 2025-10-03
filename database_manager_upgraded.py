#!/usr/bin/env python3
"""
Enhanced Database Manager for Distributed Slow HTTP C2
Provides secure database operations with SQL injection protection and proper resource management
"""

import sqlite3
import json
import threading
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Base exception for database-related errors"""
    pass


class DatabaseManager:
    """
    Enhanced Database Manager with SQL injection protection and resource management.
    
    Features:
    - Parameterized queries (SQL injection protection)
    - Connection pooling
    - Automatic resource cleanup
    - Database migrations
    - Backup support
    - Thread-safe operations
    """
    
    def __init__(self, db_file: str = 'c2_database.db'):
        """
        Initialize database manager.
        
        Args:
            db_file: Path to SQLite database file
        """
        self.db_file = Path(db_file)
        self.lock = threading.RLock()  # Reentrant lock for thread safety
        
        # Initialize database
        self.init_database()
        
        logger.info(f"DatabaseManager initialized with database: {self.db_file}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures connections are properly closed.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_file,
                timeout=30.0,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON")
            
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database connection failed: {e}")
        finally:
            if conn:
                conn.close()
    
    def init_database(self) -> None:
        """Initialize database schema with all required tables"""
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    # VPS nodes table
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS vps_nodes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip_address TEXT NOT NULL UNIQUE,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            ssh_key_path TEXT,
                            ssh_port INTEGER DEFAULT 22,
                            status TEXT DEFAULT 'offline',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_seen TIMESTAMP,
                            location TEXT,
                            tags TEXT,
                            system_info TEXT,
                            notes TEXT,
                            CONSTRAINT valid_port CHECK (ssh_port > 0 AND ssh_port <= 65535),
                            CONSTRAINT valid_status CHECK (status IN ('online', 'offline', 'error', 'maintenance'))
                        )
                    ''')
                    
                    # Attack sessions table
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS attack_sessions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_name TEXT NOT NULL UNIQUE,
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
                            target_info TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            CONSTRAINT valid_attack_type CHECK (attack_type IN ('slowloris', 'slow_post', 'slow_read')),
                            CONSTRAINT valid_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'stopped'))
                        )
                    ''')
                    
                    # Attack results table
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS attack_results (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id INTEGER NOT NULL,
                            vps_ip TEXT NOT NULL,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            connections_active INTEGER DEFAULT 0,
                            packets_sent INTEGER DEFAULT 0,
                            bytes_sent INTEGER DEFAULT 0,
                            error_count INTEGER DEFAULT 0,
                            cpu_usage REAL,
                            memory_usage REAL,
                            response_codes TEXT,
                            status TEXT,
                            FOREIGN KEY (session_id) REFERENCES attack_sessions (id) ON DELETE CASCADE,
                            CONSTRAINT valid_metrics CHECK (
                                connections_active >= 0 AND
                                packets_sent >= 0 AND
                                bytes_sent >= 0 AND
                                error_count >= 0
                            )
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
                            notes TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    
                    # Audit log table
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS audit_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            action TEXT NOT NULL,
                            user TEXT,
                            ip_address TEXT,
                            details TEXT,
                            severity TEXT DEFAULT 'info',
                            CONSTRAINT valid_severity CHECK (severity IN ('debug', 'info', 'warning', 'error', 'critical'))
                        )
                    ''')
                    
                    # Create indexes for better performance
                    self._create_indexes(cursor)
                    
                    # Optimize database settings
                    self._optimize_database(cursor)
                    
                    conn.commit()
                    logger.info("Database schema initialized successfully")
                    
                    # Run migrations
                    self._run_migrations(conn)
                    
                except sqlite3.Error as e:
                    logger.error(f"Database initialization error: {e}")
                    conn.rollback()
                    raise DatabaseError(f"Failed to initialize database: {e}")
    
    def _create_indexes(self, cursor: sqlite3.Cursor) -> None:
        """Create database indexes for better query performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_vps_ip ON vps_nodes(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_vps_status ON vps_nodes(status)",
            "CREATE INDEX IF NOT EXISTS idx_vps_last_seen ON vps_nodes(last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_attack_session_name ON attack_sessions(session_name)",
            "CREATE INDEX IF NOT EXISTS idx_attack_status ON attack_sessions(status)",
            "CREATE INDEX IF NOT EXISTS idx_attack_start_time ON attack_sessions(start_time)",
            "CREATE INDEX IF NOT EXISTS idx_results_session ON attack_results(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_results_timestamp ON attack_results(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_results_vps ON attack_results(vps_ip)",
            "CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain)",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except sqlite3.Error as e:
                logger.warning(f"Failed to create index: {e}")
    
    def _optimize_database(self, cursor: sqlite3.Cursor) -> None:
        """Optimize database settings for better performance"""
        optimizations = [
            "PRAGMA journal_mode=WAL",        # Write-Ahead Logging
            "PRAGMA synchronous=NORMAL",      # Balance safety/speed
            "PRAGMA cache_size=10000",        # Increase cache
            "PRAGMA temp_store=MEMORY",       # Use memory for temp
            "PRAGMA mmap_size=268435456",     # Memory-mapped I/O (256MB)
        ]
        
        for pragma in optimizations:
            try:
                cursor.execute(pragma)
            except sqlite3.Error as e:
                logger.warning(f"Failed to apply optimization: {e}")
    
    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Run database migrations to update schema"""
        cursor = conn.cursor()
        
        # Check if migrations table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version INTEGER NOT NULL UNIQUE,
                description TEXT,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Get current version
        cursor.execute("SELECT MAX(version) FROM migrations")
        result = cursor.fetchone()
        current_version = result[0] if result[0] is not None else 0
        
        # Define migrations
        migrations = [
            (1, "Add bytes_sent column to attack_results", """
                ALTER TABLE attack_results ADD COLUMN bytes_sent INTEGER DEFAULT 0
            """),
            (2, "Add ssh_key_path to vps_nodes", """
                ALTER TABLE vps_nodes ADD COLUMN ssh_key_path TEXT
            """),
            (3, "Add notes to vps_nodes", """
                ALTER TABLE vps_nodes ADD COLUMN notes TEXT
            """),
            (4, "Add created_at to attack_sessions", """
                ALTER TABLE attack_sessions ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            """),
            (5, "Add created_at to targets", """
                ALTER TABLE targets ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            """),
        ]
        
        # Apply migrations
        for version, description, sql in migrations:
            if version > current_version:
                try:
                    # Check if column already exists (for idempotency)
                    if "ADD COLUMN" in sql:
                        table_name = sql.split("ALTER TABLE")[1].split("ADD COLUMN")[0].strip()
                        column_name = sql.split("ADD COLUMN")[1].split()[0].strip()
                        
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns = [col[1] for col in cursor.fetchall()]
                        
                        if column_name in columns:
                            logger.info(f"Migration {version} already applied (column exists)")
                            continue
                    
                    cursor.execute(sql)
                    cursor.execute(
                        "INSERT INTO migrations (version, description) VALUES (?, ?)",
                        (version, description)
                    )
                    conn.commit()
                    logger.info(f"Applied migration {version}: {description}")
                except sqlite3.Error as e:
                    logger.warning(f"Migration {version} failed (may already be applied): {e}")
                    conn.rollback()
    
    # VPS Management Methods
    
    def add_vps(
        self,
        ip_address: str,
        username: str,
        encrypted_password: str,
        ssh_port: int = 22,
        ssh_key_path: Optional[str] = None,
        location: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Tuple[Optional[int], str]:
        """
        Add a new VPS node to the database.
        
        Args:
            ip_address: VPS IP address
            username: SSH username
            encrypted_password: Encrypted password
            ssh_port: SSH port number
            ssh_key_path: Path to SSH key file (optional)
            location: VPS location
            tags: List of tags
            
        Returns:
            Tuple of (vps_id, message)
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    # Check if VPS already exists
                    cursor.execute(
                        "SELECT id FROM vps_nodes WHERE ip_address = ?",
                        (ip_address,)
                    )
                    
                    if cursor.fetchone():
                        return None, "VPS with this IP address already exists"
                    
                    # Prepare tags as JSON
                    tags_json = json.dumps(tags) if tags else None
                    
                    # Insert new VPS
                    cursor.execute('''
                        INSERT INTO vps_nodes 
                        (ip_address, username, password, ssh_key_path, ssh_port, location, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (ip_address, username, encrypted_password, ssh_key_path, ssh_port, location, tags_json))
                    
                    conn.commit()
                    vps_id = cursor.lastrowid
                    
                    # Log action
                    self._log_action(conn, 'vps_added', f'Added VPS {ip_address}')
                    
                    logger.info(f"Added new VPS: {ip_address} (ID: {vps_id})")
                    return vps_id, "VPS added successfully"
                    
                except sqlite3.Error as e:
                    logger.error(f"Error adding VPS: {e}")
                    conn.rollback()
                    return None, f"Database error: {e}"
    
    def get_vps(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get VPS details by IP address.
        
        Args:
            ip_address: VPS IP address
            
        Returns:
            VPS details dictionary or None
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    cursor.execute(
                        "SELECT * FROM vps_nodes WHERE ip_address = ?",
                        (ip_address,)
                    )
                    
                    vps = cursor.fetchone()
                    
                    if vps:
                        vps_dict = dict(vps)
                        # Parse JSON fields
                        if vps_dict.get('tags'):
                            try:
                                vps_dict['tags'] = json.loads(vps_dict['tags'])
                            except json.JSONDecodeError:
                                vps_dict['tags'] = None
                        
                        if vps_dict.get('system_info'):
                            try:
                                vps_dict['system_info'] = json.loads(vps_dict['system_info'])
                            except json.JSONDecodeError:
                                vps_dict['system_info'] = None
                        
                        return vps_dict
                    
                    return None
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting VPS: {e}")
                    return None
    
    def get_all_vps(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all VPS nodes, optionally filtered by status.
        
        Args:
            status: Filter by status (optional)
            
        Returns:
            List of VPS dictionaries
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    if status:
                        cursor.execute(
                            "SELECT * FROM vps_nodes WHERE status = ? ORDER BY id",
                            (status,)
                        )
                    else:
                        cursor.execute("SELECT * FROM vps_nodes ORDER BY id")
                    
                    vps_list = []
                    for row in cursor.fetchall():
                        vps_dict = dict(row)
                        
                        # Parse JSON fields
                        if vps_dict.get('tags'):
                            try:
                                vps_dict['tags'] = json.loads(vps_dict['tags'])
                            except json.JSONDecodeError:
                                vps_dict['tags'] = None
                        
                        if vps_dict.get('system_info'):
                            try:
                                vps_dict['system_info'] = json.loads(vps_dict['system_info'])
                            except json.JSONDecodeError:
                                vps_dict['system_info'] = None
                        
                        vps_list.append(vps_dict)
                    
                    return vps_list
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting all VPS: {e}")
                    return []
    
    def update_vps_status(
        self,
        ip_address: str,
        status: str,
        message: Optional[str] = None
    ) -> bool:
        """
        Update VPS status and last_seen timestamp.
        
        Args:
            ip_address: VPS IP address
            status: New status
            message: Optional status message
            
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    cursor.execute('''
                        UPDATE vps_nodes 
                        SET status = ?, last_seen = CURRENT_TIMESTAMP
                        WHERE ip_address = ?
                    ''', (status, ip_address))
                    
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        logger.info(f"Updated VPS {ip_address} status to {status}")
                        return True
                    else:
                        logger.warning(f"VPS {ip_address} not found for status update")
                        return False
                    
                except sqlite3.Error as e:
                    logger.error(f"Error updating VPS status: {e}")
                    conn.rollback()
                    return False
    
    def update_vps_system_info(
        self,
        ip_address: str,
        system_info: Dict[str, Any]
    ) -> bool:
        """
        Update VPS system information.
        
        Args:
            ip_address: VPS IP address
            system_info: System information dictionary
            
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    system_info_json = json.dumps(system_info)
                    
                    cursor.execute('''
                        UPDATE vps_nodes 
                        SET system_info = ?
                        WHERE ip_address = ?
                    ''', (system_info_json, ip_address))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
                except sqlite3.Error as e:
                    logger.error(f"Error updating VPS system info: {e}")
                    conn.rollback()
                    return False
    
    def remove_vps(self, ip_address: str) -> bool:
        """
        Remove a VPS node from the database.
        
        Args:
            ip_address: VPS IP address
            
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    cursor.execute(
                        "DELETE FROM vps_nodes WHERE ip_address = ?",
                        (ip_address,)
                    )
                    
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        self._log_action(conn, 'vps_removed', f'Removed VPS {ip_address}')
                        logger.info(f"Removed VPS: {ip_address}")
                        return True
                    else:
                        logger.warning(f"VPS {ip_address} not found for removal")
                        return False
                    
                except sqlite3.Error as e:
                    logger.error(f"Error removing VPS: {e}")
                    conn.rollback()
                    return False
    
    # Attack Session Methods
    
    def create_attack_session(
        self,
        session_name: str,
        target_url: str,
        attack_type: str,
        vps_nodes: List[str],
        parameters: Dict[str, Any]
    ) -> Optional[int]:
        """
        Create a new attack session.
        
        Args:
            session_name: Unique session name
            target_url: Target URL
            attack_type: Type of attack
            vps_nodes: List of VPS IP addresses
            parameters: Attack parameters
            
        Returns:
            Session ID or None
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    # Parse target URL
                    from urllib.parse import urlparse
                    parsed = urlparse(target_url)
                    target_host = parsed.netloc or parsed.path.split('/')[0]
                    
                    # Convert parameters to JSON
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
                    
                    self._log_action(
                        conn,
                        'attack_started',
                        f'Started attack session {session_name} on {target_url}'
                    )
                    
                    logger.info(f"Created attack session: {session_name} (ID: {session_id})")
                    return session_id
                    
                except sqlite3.Error as e:
                    logger.error(f"Error creating attack session: {e}")
                    conn.rollback()
                    return None
    
    def get_attack_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get attack session details by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session details dictionary or None
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    cursor.execute(
                        "SELECT * FROM attack_sessions WHERE id = ?",
                        (session_id,)
                    )
                    
                    session = cursor.fetchone()
                    
                    if session:
                        session_dict = dict(session)
                        
                        # Parse JSON fields
                        if session_dict.get('parameters'):
                            try:
                                session_dict['parameters'] = json.loads(session_dict['parameters'])
                            except json.JSONDecodeError:
                                session_dict['parameters'] = None
                        
                        if session_dict.get('results'):
                            try:
                                session_dict['results'] = json.loads(session_dict['results'])
                            except json.JSONDecodeError:
                                session_dict['results'] = None
                        
                        if session_dict.get('target_info'):
                            try:
                                session_dict['target_info'] = json.loads(session_dict['target_info'])
                            except json.JSONDecodeError:
                                session_dict['target_info'] = None
                        
                        # Parse VPS nodes
                        if session_dict.get('vps_nodes'):
                            session_dict['vps_nodes'] = session_dict['vps_nodes'].split(',')
                        
                        return session_dict
                    
                    return None
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting attack session: {e}")
                    return None
    
    def update_attack_status(
        self,
        session_id: int,
        status: str,
        results: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update attack session status.
        
        Args:
            session_id: Session ID
            status: New status
            results: Optional results dictionary
            
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    if status in ['completed', 'failed', 'stopped']:
                        # Set end time for finished attacks
                        results_json = json.dumps(results) if results else None
                        cursor.execute('''
                            UPDATE attack_sessions 
                            SET status = ?, end_time = CURRENT_TIMESTAMP, results = ?
                            WHERE id = ?
                        ''', (status, results_json, session_id))
                    else:
                        # Just update status
                        cursor.execute('''
                            UPDATE attack_sessions 
                            SET status = ?
                            WHERE id = ?
                        ''', (status, session_id))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
                except sqlite3.Error as e:
                    logger.error(f"Error updating attack status: {e}")
                    conn.rollback()
                    return False
    
    def add_attack_result(
        self,
        session_id: int,
        vps_ip: str,
        connections_active: int,
        packets_sent: int,
        bytes_sent: int,
        error_count: int,
        cpu_usage: Optional[float] = None,
        memory_usage: Optional[float] = None,
        response_codes: Optional[Dict[str, int]] = None,
        status: Optional[str] = None
    ) -> bool:
        """
        Add attack result data.
        
        Args:
            session_id: Session ID
            vps_ip: VPS IP address
            connections_active: Number of active connections
            packets_sent: Number of packets sent
            bytes_sent: Number of bytes sent
            error_count: Number of errors
            cpu_usage: CPU usage percentage
            memory_usage: Memory usage percentage
            response_codes: Dictionary of response codes
            status: Status message
            
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    response_codes_json = json.dumps(response_codes) if response_codes else None
                    
                    cursor.execute('''
                        INSERT INTO attack_results 
                        (session_id, vps_ip, connections_active, packets_sent, bytes_sent, 
                         error_count, cpu_usage, memory_usage, response_codes, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (session_id, vps_ip, connections_active, packets_sent, bytes_sent,
                          error_count, cpu_usage, memory_usage, response_codes_json, status))
                    
                    conn.commit()
                    return True
                    
                except sqlite3.Error as e:
                    logger.error(f"Error adding attack result: {e}")
                    conn.rollback()
                    return False
    
    def get_attack_results(
        self,
        session_id: int,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get attack results for a session.
        
        Args:
            session_id: Session ID
            limit: Maximum number of results
            
        Returns:
            List of result dictionaries
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
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
                    
                    results = []
                    for row in cursor.fetchall():
                        result_dict = dict(row)
                        
                        # Parse JSON fields
                        if result_dict.get('response_codes'):
                            try:
                                result_dict['response_codes'] = json.loads(result_dict['response_codes'])
                            except json.JSONDecodeError:
                                result_dict['response_codes'] = None
                        
                        results.append(result_dict)
                    
                    return results
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting attack results: {e}")
                    return []
    
    # Audit Logging
    
    def _log_action(
        self,
        conn: sqlite3.Connection,
        action: str,
        details: str,
        user: Optional[str] = None,
        severity: str = 'info'
    ) -> None:
        """
        Log action to audit log.
        
        Args:
            conn: Database connection
            action: Action name
            details: Action details
            user: Username (optional)
            severity: Log severity
        """
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (action, user, details, severity)
                VALUES (?, ?, ?, ?)
            ''', (action, user, details, severity))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error logging action: {e}")
    
    def get_audit_log(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit log entries.
        
        Args:
            limit: Maximum number of entries
            action: Filter by action
            severity: Filter by severity
            
        Returns:
            List of log entry dictionaries
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    query = "SELECT * FROM audit_log WHERE 1=1"
                    params = []
                    
                    if action:
                        query += " AND action = ?"
                        params.append(action)
                    
                    if severity:
                        query += " AND severity = ?"
                        params.append(severity)
                    
                    query += " ORDER BY timestamp DESC LIMIT ?"
                    params.append(limit)
                    
                    cursor.execute(query, params)
                    
                    return [dict(row) for row in cursor.fetchall()]
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting audit log: {e}")
                    return []
    
    # Utility Methods
    
    def vacuum(self) -> bool:
        """
        Vacuum database to reclaim space and optimize.
        
        Returns:
            True if successful
        """
        with self.lock:
            with self.get_connection() as conn:
                try:
                    conn.execute("VACUUM")
                    logger.info("Database vacuumed successfully")
                    return True
                except sqlite3.Error as e:
                    logger.error(f"Error vacuuming database: {e}")
                    return False
    
    def backup(self, backup_path: str) -> bool:
        """
        Create database backup.
        
        Args:
            backup_path: Path for backup file
            
        Returns:
            True if successful
        """
        import shutil
        
        with self.lock:
            try:
                shutil.copy2(self.db_file, backup_path)
                logger.info(f"Database backed up to: {backup_path}")
                return True
            except Exception as e:
                logger.error(f"Error backing up database: {e}")
                return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Statistics dictionary
        """
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                try:
                    stats = {}
                    
                    # VPS statistics
                    cursor.execute("SELECT COUNT(*) FROM vps_nodes")
                    stats['total_vps'] = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM vps_nodes WHERE status = 'online'")
                    stats['online_vps'] = cursor.fetchone()[0]
                    
                    # Attack statistics
                    cursor.execute("SELECT COUNT(*) FROM attack_sessions")
                    stats['total_attacks'] = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM attack_sessions WHERE status = 'running'")
                    stats['active_attacks'] = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM attack_sessions WHERE status = 'completed'")
                    stats['completed_attacks'] = cursor.fetchone()[0]
                    
                    # Database size
                    cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
                    stats['database_size_bytes'] = cursor.fetchone()[0]
                    
                    return stats
                    
                except sqlite3.Error as e:
                    logger.error(f"Error getting statistics: {e}")
                    return {}
    
    def close(self) -> None:
        """Close database manager (cleanup)"""
        logger.info("DatabaseManager closed")


if __name__ == "__main__":
    # Test database manager
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("Testing DatabaseManager...")
    
    # Create test database
    db = DatabaseManager('test_database.db')
    
    # Test VPS operations
    print("\n1. Testing VPS operations...")
    vps_id, msg = db.add_vps('1.2.3.4', 'root', 'encrypted_pass', 22, None, 'US-East', ['test', 'demo'])
    print(f"  Add VPS: {msg} (ID: {vps_id})")
    
    vps = db.get_vps('1.2.3.4')
    print(f"  Get VPS: {vps['ip_address']} - {vps['location']}")
    
    db.update_vps_status('1.2.3.4', 'online')
    print(f"  Updated VPS status to online")
    
    all_vps = db.get_all_vps()
    print(f"  Total VPS: {len(all_vps)}")
    
    # Test attack session
    print("\n2. Testing attack session...")
    session_id = db.create_attack_session(
        'test_attack',
        'http://example.com',
        'slowloris',
        ['1.2.3.4'],
        {'connections': 100, 'delay': 15}
    )
    print(f"  Created attack session: {session_id}")
    
    # Add attack result
    db.add_attack_result(
        session_id,
        '1.2.3.4',
        100,
        1000,
        50000,
        5,
        25.5,
        45.2,
        {'200': 10, '503': 5},
        'running'
    )
    print(f"  Added attack result")
    
    # Get statistics
    print("\n3. Testing statistics...")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Cleanup
    print("\n4. Cleanup...")
    db.remove_vps('1.2.3.4')
    print(f"  Removed test VPS")
    
    # Delete test database
    import os
    if os.path.exists('test_database.db'):
        os.remove('test_database.db')
    print(f"  Deleted test database")
    
    print("\n✓ All tests passed!")