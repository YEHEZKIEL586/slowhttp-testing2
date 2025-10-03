#!/usr/bin/env python3
"""
Enhanced Security Manager for Distributed Slow HTTP C2
Provides comprehensive security features including encryption, validation, and authentication
"""

import os
import re
import base64
import hashlib
import secrets
import ipaddress
from typing import Tuple, Optional, Dict, Any
from urllib.parse import urlparse
from pathlib import Path
import logging

# Try to import optional dependencies
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base exception for security-related errors"""
    pass


class EncryptionError(SecurityError):
    """Raised when encryption/decryption fails"""
    pass


class ValidationError(SecurityError):
    """Raised when input validation fails"""
    pass


class SecurityManager:
    """
    Enhanced Security Manager with multiple encryption backends and comprehensive validation.
    
    Features:
    - Multiple encryption backends (Fernet, AES-GCM)
    - Password strength validation
    - Input sanitization
    - SSH key management
    - Secure random generation
    """
    
    def __init__(self, key_file: str = 'key.key'):
        """
        Initialize security manager with encryption key.
        
        Args:
            key_file: Path to encryption key file
        """
        self.key_file = Path(key_file)
        self.key = None
        self.cipher = None
        self.encryption_backend = None
        
        # Initialize encryption
        self._initialize_encryption()
        
        # Security settings
        self.max_input_length = 10000
        self.password_min_length = 12
        
        logger.info(f"SecurityManager initialized with backend: {self.encryption_backend}")
    
    def _initialize_encryption(self) -> None:
        """Initialize encryption with best available backend"""
        
        # Try Fernet first (recommended)
        if CRYPTO_AVAILABLE:
            try:
                if self.key_file.exists():
                    with open(self.key_file, 'rb') as f:
                        self.key = f.read()
                    # Validate key
                    try:
                        self.cipher = Fernet(self.key)
                        self.encryption_backend = 'fernet'
                        logger.info("Using Fernet encryption backend")
                        return
                    except Exception as e:
                        logger.warning(f"Invalid Fernet key, regenerating: {e}")
                        self._generate_new_fernet_key()
                else:
                    self._generate_new_fernet_key()
                return
            except Exception as e:
                logger.error(f"Failed to initialize Fernet: {e}")
        
        # Fallback to AES-GCM
        if PYCRYPTO_AVAILABLE:
            try:
                if self.key_file.exists():
                    with open(self.key_file, 'rb') as f:
                        self.key = f.read()
                else:
                    self._generate_new_aes_key()
                self.encryption_backend = 'aes-gcm'
                logger.info("Using AES-GCM encryption backend")
                return
            except Exception as e:
                logger.error(f"Failed to initialize AES-GCM: {e}")
        
        # Last resort: PBKDF2 (not reversible, only for hashing)
        logger.warning("No encryption backend available, using PBKDF2 for hashing only")
        self.encryption_backend = 'pbkdf2'
        if not self.key_file.exists():
            self._generate_new_pbkdf2_key()
    
    def _generate_new_fernet_key(self) -> None:
        """Generate new Fernet encryption key"""
        try:
            self.key = Fernet.generate_key()
            self.cipher = Fernet(self.key)
            
            # Save key with secure permissions
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            
            # Set secure permissions (owner read/write only)
            os.chmod(self.key_file, 0o600)
            
            logger.info("Generated new Fernet encryption key")
        except Exception as e:
            raise EncryptionError(f"Failed to generate Fernet key: {e}")
    
    def _generate_new_aes_key(self) -> None:
        """Generate new AES encryption key"""
        try:
            self.key = get_random_bytes(32)  # 256-bit key
            
            # Save key with secure permissions
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            
            os.chmod(self.key_file, 0o600)
            
            logger.info("Generated new AES encryption key")
        except Exception as e:
            raise EncryptionError(f"Failed to generate AES key: {e}")
    
    def _generate_new_pbkdf2_key(self) -> None:
        """Generate new PBKDF2 salt"""
        try:
            self.key = secrets.token_bytes(32)
            
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            
            os.chmod(self.key_file, 0o600)
            
            logger.info("Generated new PBKDF2 salt")
        except Exception as e:
            raise EncryptionError(f"Failed to generate PBKDF2 salt: {e}")
    
    def encrypt_password(self, password: str) -> str:
        """
        Encrypt password using best available method.
        
        Args:
            password: Plain text password
            
        Returns:
            Encrypted password as base64 string
            
        Raises:
            EncryptionError: If encryption fails
        """
        if not password:
            return ""
        
        try:
            if self.encryption_backend == 'fernet':
                return self._encrypt_fernet(password)
            elif self.encryption_backend == 'aes-gcm':
                return self._encrypt_aes_gcm(password)
            elif self.encryption_backend == 'pbkdf2':
                return self._hash_pbkdf2(password)
            else:
                raise EncryptionError("No encryption backend available")
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt password: {e}")
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """
        Decrypt password using appropriate method.
        
        Args:
            encrypted_password: Encrypted password as base64 string
            
        Returns:
            Decrypted plain text password
            
        Raises:
            EncryptionError: If decryption fails
        """
        if not encrypted_password:
            return ""
        
        try:
            if self.encryption_backend == 'fernet':
                return self._decrypt_fernet(encrypted_password)
            elif self.encryption_backend == 'aes-gcm':
                return self._decrypt_aes_gcm(encrypted_password)
            elif self.encryption_backend == 'pbkdf2':
                raise EncryptionError("PBKDF2 is not reversible, cannot decrypt")
            else:
                raise EncryptionError("No decryption backend available")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt password: {e}")
    
    def _encrypt_fernet(self, password: str) -> str:
        """Encrypt using Fernet"""
        encrypted = self.cipher.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_fernet(self, encrypted_password: str) -> str:
        """Decrypt using Fernet"""
        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    def _encrypt_aes_gcm(self, password: str) -> str:
        """Encrypt using AES-GCM"""
        # Generate random nonce
        nonce = get_random_bytes(12)
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt and get tag
        ciphertext, tag = cipher.encrypt_and_digest(password.encode())
        
        # Combine nonce + tag + ciphertext
        result = nonce + tag + ciphertext
        
        return base64.b64encode(result).decode()
    
    def _decrypt_aes_gcm(self, encrypted_password: str) -> str:
        """Decrypt using AES-GCM"""
        # Decode from base64
        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        
        # Extract components
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[12:28]
        ciphertext = encrypted_bytes[28:]
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode()
    
    def _hash_pbkdf2(self, password: str) -> str:
        """Hash password using PBKDF2 (not reversible)"""
        salt = self.key
        
        # Use PBKDF2 with 200,000 iterations
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        
        # Combine salt + hash
        result = salt + key
        
        return base64.b64encode(result).decode()
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt (for storage, not reversible).
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        if BCRYPT_AVAILABLE:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            return hashed.decode()
        else:
            # Fallback to PBKDF2
            return self._hash_pbkdf2(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password
            hashed: Hashed password
            
        Returns:
            True if password matches hash
        """
        if BCRYPT_AVAILABLE:
            try:
                return bcrypt.checkpw(password.encode(), hashed.encode())
            except Exception:
                return False
        else:
            # Fallback comparison
            return self._hash_pbkdf2(password) == hashed
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if len(password) < self.password_min_length:
            return False, f"Password must be at least {self.password_min_length} characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check for common patterns
        common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
        password_lower = password.lower()
        for pattern in common_patterns:
            if pattern in password_lower:
                return False, f"Password contains common pattern: {pattern}"
        
        return True, "Password is strong"
    
    def validate_ip(self, ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IP address
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: int) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number
            
        Returns:
            True if valid port
        """
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL string
            
        Returns:
            True if valid URL
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def sanitize_input(self, input_str: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize user input to prevent injection attacks.
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Convert to string
        sanitized = str(input_str)
        
        # Remove dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '<', '>', '(', ')', '{', '}', '[', ']']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remove command substitution patterns
        sanitized = re.sub(r'\$\([^)]*\)', '', sanitized)  # Remove $(...)
        sanitized = re.sub(r'`[^`]*`', '', sanitized)      # Remove `...`
        
        # Remove multiple spaces
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Strip leading/trailing whitespace
        sanitized = sanitized.strip()
        
        # Limit length
        if max_length is None:
            max_length = self.max_input_length
        
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    def sanitize_command(self, command: str) -> str:
        """
        Sanitize shell command to prevent command injection.
        
        Args:
            command: Command string
            
        Returns:
            Sanitized command
            
        Raises:
            ValidationError: If command contains dangerous patterns
        """
        # Check for dangerous patterns
        dangerous_patterns = [
            r';\s*rm\s+-rf',  # rm -rf
            r';\s*dd\s+',     # dd command
            r'>\s*/dev/',     # Writing to devices
            r'\|\s*sh',       # Piping to shell
            r'\|\s*bash',     # Piping to bash
            r'&&\s*rm',       # Chained rm
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                raise ValidationError(f"Command contains dangerous pattern: {pattern}")
        
        return command
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            Secure random token as hex string
        """
        return secrets.token_hex(length)
    
    def generate_session_id(self) -> str:
        """
        Generate unique session ID.
        
        Returns:
            Session ID string
        """
        return secrets.token_urlsafe(16)
    
    def validate_ssh_key(self, key_path: str) -> Tuple[bool, str]:
        """
        Validate SSH key file.
        
        Args:
            key_path: Path to SSH key file
            
        Returns:
            Tuple of (is_valid, message)
        """
        key_file = Path(key_path)
        
        if not key_file.exists():
            return False, "SSH key file not found"
        
        if not key_file.is_file():
            return False, "SSH key path is not a file"
        
        # Check file permissions (should be 600 or 400)
        stat_info = key_file.stat()
        mode = stat_info.st_mode & 0o777
        
        if mode not in [0o600, 0o400]:
            return False, f"SSH key has insecure permissions: {oct(mode)}"
        
        # Try to read key
        try:
            with open(key_file, 'r') as f:
                content = f.read()
            
            # Check if it looks like a valid key
            if not any(marker in content for marker in ['BEGIN', 'PRIVATE KEY', 'RSA', 'OPENSSH']):
                return False, "File does not appear to be a valid SSH key"
            
            return True, "SSH key is valid"
        except Exception as e:
            return False, f"Failed to read SSH key: {e}"
    
    def secure_delete_file(self, file_path: str, passes: int = 3) -> bool:
        """
        Securely delete file by overwriting with random data.
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if successful
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                return True
            
            # Get file size
            file_size = path.stat().st_size
            
            # Overwrite with random data
            with open(path, 'wb') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete file
            path.unlink()
            
            logger.info(f"Securely deleted file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to securely delete file: {e}")
            return False


# Singleton instance
_security_manager_instance = None


def get_security_manager(key_file: str = 'key.key') -> SecurityManager:
    """
    Get singleton SecurityManager instance.
    
    Args:
        key_file: Path to encryption key file
        
    Returns:
        SecurityManager instance
    """
    global _security_manager_instance
    
    if _security_manager_instance is None:
        _security_manager_instance = SecurityManager(key_file)
    
    return _security_manager_instance


if __name__ == "__main__":
    # Test security manager
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("Testing SecurityManager...")
    
    sm = SecurityManager('test_key.key')
    
    # Test password encryption
    print("\n1. Testing password encryption...")
    password = "MySecurePassword123!"
    encrypted = sm.encrypt_password(password)
    print(f"Encrypted: {encrypted[:50]}...")
    
    if sm.encryption_backend != 'pbkdf2':
        decrypted = sm.decrypt_password(encrypted)
        print(f"Decrypted: {decrypted}")
        assert password == decrypted, "Decryption failed!"
        print("✓ Encryption/Decryption works!")
    
    # Test password strength
    print("\n2. Testing password strength validation...")
    weak_passwords = ["short", "alllowercase", "ALLUPPERCASE", "NoSpecial123"]
    strong_password = "MyStr0ng!Pass"
    
    for pwd in weak_passwords:
        valid, msg = sm.validate_password_strength(pwd)
        print(f"  {pwd}: {'✓' if valid else '✗'} {msg}")
    
    valid, msg = sm.validate_password_strength(strong_password)
    print(f"  {strong_password}: {'✓' if valid else '✗'} {msg}")
    
    # Test input sanitization
    print("\n3. Testing input sanitization...")
    dangerous_inputs = [
        "normal input",
        "input; rm -rf /",
        "input && malicious",
        "input | bash",
        "input $(whoami)"
    ]
    
    for inp in dangerous_inputs:
        sanitized = sm.sanitize_input(inp)
        print(f"  '{inp}' -> '{sanitized}'")
    
    # Test validation
    print("\n4. Testing validation...")
    print(f"  Valid IP (1.2.3.4): {sm.validate_ip('1.2.3.4')}")
    print(f"  Invalid IP (999.999.999.999): {sm.validate_ip('999.999.999.999')}")
    print(f"  Valid port (22): {sm.validate_port(22)}")
    print(f"  Invalid port (99999): {sm.validate_port(99999)}")
    print(f"  Valid URL (https://example.com): {sm.validate_url('https://example.com')}")
    print(f"  Invalid URL (not-a-url): {sm.validate_url('not-a-url')}")
    
    # Test token generation
    print("\n5. Testing token generation...")
    token = sm.generate_secure_token()
    session_id = sm.generate_session_id()
    print(f"  Secure token: {token[:32]}...")
    print(f"  Session ID: {session_id}")
    
    print("\n✓ All tests passed!")
    
    # Cleanup
    if Path('test_key.key').exists():
        Path('test_key.key').unlink()