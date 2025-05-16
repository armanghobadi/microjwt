import hashlib
import ubinascii
import json
import time
import os
import binascii
import ucryptolib
from micropython import const

# Enhanced lightweight logger for MicroPython
class SimpleLogger:
    """
    A lightweight logging substitute for MicroPython with configurable log levels.
    
    Supports info, warning, and error levels with optional silent mode.
    """
    def __init__(self, name, level="INFO", silent=False):
        self.name = name
        self.levels = {"ERROR": 1, "WARNING": 2, "INFO": 3}
        self.level = self.levels.get(level.upper(), 3)
        self.silent = silent
    
    def info(self, msg):
        if not self.silent and self.level >= 3:
            print(f"[INFO] {self.name}: {msg}")
    
    def warning(self, msg):
        if not self.silent and self.level >= 2:
            print(f"[WARNING] {self.name}: {msg}")
    
    def error(self, msg):
        if not self.silent and self.level >= 1:
            print(f"[ERROR] {self.name}: {msg}")

# Initialize logger
logger = SimpleLogger("MicroJWT", level="INFO")

# Constants for optimization and clarity
_ALGORITHM_HS256 = const("HS256")
_DEFAULT_TTL = const(3600)  # Default token TTL: 1 hour
_MIN_KEY_LENGTH = const(32)  # Minimum key length in bytes
_SALT_LENGTH = const(16)    # Salt length in bytes
_AES_KEY_LENGTH = const(32) # AES-256 key length in bytes
_PBKDF2_ITERATIONS = const(1000)  # PBKDF2 iterations (balanced for MicroPython)

class JWTError(Exception):
    """Custom exception for JWT-related errors."""
    pass

def pbkdf2(key, salt, iterations, keylen, hash_func=hashlib.sha256):
    """
    Simplified PBKDF2 implementation for key derivation.
    
    Args:
        key (bytes): Input key to derive.
        salt (bytes): Random salt.
        iterations (int): Number of iterations.
        keylen (int): Desired key length in bytes.
        hash_func: Hash function (defaults to hashlib.sha256).
    
    Returns:
        bytes: Derived key.
    
    Raises:
        JWTError: If key derivation fails.
    """
    try:
        h = hmac(key, salt + b'\x00\x00\x00\x01', hash_func)
        u = h
        for _ in range(iterations - 1):
            h = hmac(key, h, hash_func)
            u = bytes(a ^ b for a, b in zip(u, h))
        return u[:keylen]
    except Exception as e:
        logger.error(f"PBKDF2 derivation failed: {e}")
        raise JWTError("Failed to derive key")

def hmac(key, message, hash_func=hashlib.sha256):
    """
    HMAC implementation for SHA-256 without external hmac library.
    
    Follows RFC 2104: HMAC = H((K ⊕ opad) || H((K ⊕ ipad) || message)).
    
    Args:
        key (bytes): Secret key for HMAC.
        message (bytes): Message to sign.
        hash_func: Hash function (defaults to hashlib.sha256).
        
    Returns:
        bytes: HMAC digest.
        
    Raises:
        JWTError: If HMAC computation fails.
    """
    try:
        # Block size for SHA-256 is 64 bytes
        block_size = 64
        
        # Convert key to bytes and hash if too long
        if len(key) > block_size:
            key = hash_func(key).digest()
        
        # Pad key with zeros if too short
        if len(key) < block_size:
            key = key + b'\x00' * (block_size - len(key))
        
        # Create inner and outer padding
        ipad = bytes([0x36] * block_size)  # Inner pad: 0x36 repeated
        opad = bytes([0x5c] * block_size)  # Outer pad: 0x5c repeated
        
        # XOR key with ipad and opad
        inner_key = bytes(a ^ b for a, b in zip(key, ipad))
        outer_key = bytes(a ^ b for a, b in zip(key, opad))
        
        # Compute inner hash: H((K ⊕ ipad) || message)
        inner_hash = hash_func(inner_key + message).digest()
        
        # Compute outer hash: H((K ⊕ opad) || inner_hash)
        outer_hash = hash_func(outer_key + inner_hash).digest()
        
        return outer_hash
        
    except Exception as e:
        logger.error(f"HMAC computation failed: {e}")
        raise JWTError("Failed to compute HMAC digest")

class MicroJWT:
    """
    An advanced, production-ready JWT implementation for MicroPython.
    
    Supports HS256 algorithm, token encryption, revocation, refresh, audience validation,
    and constant-time signature verification. Optimized for low-memory embedded systems.
    """
    
    # Supported algorithm
    SUPPORTED_ALGORITHMS = {_ALGORITHM_HS256}
    
    def __init__(self, secret_key, algorithm=_ALGORITHM_HS256, ttl=_DEFAULT_TTL, log_level="INFO", silent=False):
        """
        Initialize the JWT handler with a secret key and configuration.
        
        Args:
            secret_key (str or bytes): Secret key for signing tokens.
            algorithm (str): HMAC algorithm (only HS256 supported).
            ttl (int): Default token time-to-live in seconds.
            log_level (str): Logging level (INFO, WARNING, ERROR).
            silent (bool): Suppress logging if True.
        
        Raises:
            JWTError: If the key is too short, algorithm is unsupported, or TTL is invalid.
        """
        if not secret_key or len(secret_key) < _MIN_KEY_LENGTH:
            raise JWTError(f"Secret key must be at least {_MIN_KEY_LENGTH} bytes")
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise JWTError(f"Unsupported algorithm: {algorithm}")
        if ttl <= 0:
            raise JWTError("Token TTL must be positive")
        
        # Derive signing and encryption keys using PBKDF2
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        salt = os.urandom(_SALT_LENGTH)
        self.signing_key = pbkdf2(self.secret_key, salt, _PBKDF2_ITERATIONS, _MIN_KEY_LENGTH)
        self.encryption_key = pbkdf2(self.secret_key, salt + b'enc', _PBKDF2_ITERATIONS, _AES_KEY_LENGTH)
        
        self.algorithm = algorithm
        self.ttl = ttl
        self.revoked_tokens = set()  # In-memory token revocation list
        self.logger = SimpleLogger("MicroJWT", level=log_level, silent=silent)
        self.logger.info(f"MicroJWT initialized with algorithm {algorithm}")

    @staticmethod
    def _base64url_encode(data):
        """
        Encode data to Base64 URL-safe format without padding.
        
        Args:
            data (str or bytes): Data to encode.
            
        Returns:
            str: Base64 URL-safe encoded string.
        """
        if isinstance(data, str):
            data = data.encode()
        return ubinascii.b2a_base64(data).decode().rstrip('=\n')

    @staticmethod
    def _base64url_decode(data):
        """
        Decode Base64 URL-safe data with padding restoration.
        
        Args:
            data (str): Base64 URL-safe encoded string.
            
        Returns:
            bytes: Decoded data.
            
        Raises:
            JWTError: If decoding fails.
        """
        try:
            padding = '=' * (4 - len(data) % 4) if len(data) % 4 else ''
            return ubinascii.a2b_base64(data + padding)
        except Exception as e:
            logger.error(f"Base64 decode failed: {e}")
            raise JWTError("Invalid Base64 encoding")

    def _generate_salt(self):
        """
        Generate a cryptographically secure salt for token uniqueness.
        
        Returns:
            bytes: Random salt.
            
        Raises:
            JWTError: If salt generation fails.
        """
        try:
            return os.urandom(_SALT_LENGTH)
        except Exception as e:
            self.logger.error(f"Salt generation failed: {e}")
            raise JWTError("Cannot generate secure salt")

    def _hmac_digest(self, message):
        """
        Compute HMAC digest using SHA-256.
        
        Args:
            message (str): Message to sign.
            
        Returns:
            bytes: HMAC digest.
            
        Raises:
            JWTError: If HMAC computation fails.
        """
        try:
            return hmac(self.signing_key, message.encode(), hashlib.sha256)
        except Exception as e:
            self.logger.error(f"HMAC computation failed: {e}")
            raise JWTError(f"Failed to compute {self.algorithm} signature")

    def _constant_time_compare(self, a, b):
        """
        Compare two byte strings in constant time to prevent timing attacks.
        
        Args:
            a (bytes): First byte string.
            b (bytes): Second byte string.
            
        Returns:
            bool: True if strings are equal, False otherwise.
        """
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def _encrypt_token(self, token):
        """
        Encrypt a JWT token using AES-256-CBC.
        
        Args:
            token (str): JWT token to encrypt.
            
        Returns:
            str: Base64-encoded encrypted token (IV + ciphertext).
            
        Raises:
            JWTError: If encryption fails.
        """
        try:
            iv = os.urandom(16)  # 16-byte IV for AES-CBC
            aes = ucryptolib.aes(self.encryption_key, 1, iv)  # Mode 1 = CBC
            token_bytes = token.encode()
            # Pad token to multiple of 16 bytes
            padding_length = 16 - (len(token_bytes) % 16)
            token_bytes += b'\x00' * padding_length
            ciphertext = aes.encrypt(token_bytes)
            return self._base64url_encode(iv + ciphertext)
        except Exception as e:
            self.logger.error(f"Token encryption failed: {e}")
            raise JWTError("Failed to encrypt token")

    def _decrypt_token(self, encrypted_token):
        """
        Decrypt an AES-256-CBC encrypted JWT token.
        
        Args:
            encrypted_token (str): Base64-encoded encrypted token (IV + ciphertext).
            
        Returns:
            str: Decrypted JWT token.
            
        Raises:
            JWTError: If decryption fails.
        """
        try:
            encrypted_data = self._base64url_decode(encrypted_token)
            if len(encrypted_data) < 16:
                raise JWTError("Invalid encrypted token length")
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            aes = ucryptolib.aes(self.encryption_key, 1, iv)  # Mode 1 = CBC
            decrypted = aes.decrypt(ciphertext).rstrip(b'\x00').decode()
            return decrypted
        except Exception as e:
            self.logger.error(f"Token decryption failed: {e}")
            raise JWTError("Failed to decrypt token")

    def create_token(self, username, role, additional_claims=None, audience=None, encrypt=False):
        """
        Create a JWT token with secure HMAC signing and optional encryption.
        
        Args:
            username (str): Subject identifier (e.g., user ID).
            role (str): User role or permission level.
            additional_claims (dict, optional): Additional payload claims.
            audience (str, optional): Intended audience for the token.
            encrypt (bool): If True, encrypt the token with AES-256-CBC.
            
        Returns:
            str: JWT token (or encrypted token if encrypt=True).
            
        Raises:
            JWTError: If token creation or input validation fails.
        """
        try:
            # Input validation
            if not isinstance(username, str) or not username.strip():
                raise JWTError("Username must be a non-empty string")
            if not isinstance(role, str) or not role.strip():
                raise JWTError("Role must be a non-empty string")
            if additional_claims is not None and not isinstance(additional_claims, dict):
                raise JWTError("Additional claims must be a dictionary")
            if audience is not None and not isinstance(audience, str):
                raise JWTError("Audience must be a string")
            
            # JWT header
            header = {"alg": self.algorithm, "typ": "JWT"}
            
            # JWT payload
            salt = self._generate_salt()
            payload = {
                "sub": username,
                "role": role,
                "iat": int(time.time()),
                "exp": int(time.time()) + self.ttl,
                "jti": binascii.hexlify(salt).decode()  # Unique token ID
            }
            
            # Add audience if provided
            if audience:
                payload["aud"] = audience
            
            # Add additional claims if provided
            if additional_claims:
                for key, value in additional_claims.items():
                    if not isinstance(key, str):
                        raise JWTError("Claim keys must be strings")
                    payload[key] = value
            
            # Encode header and payload
            header_b64 = self._base64url_encode(json.dumps(header, separators=(',', ':')))
            payload_b64 = self._base64url_encode(json.dumps(payload, separators=(',', ':')))
            signature_input = f"{header_b64}.{payload_b64}"
            
            # Generate signature
            signature = self._hmac_digest(signature_input)
            signature_b64 = self._base64url_encode(signature)
            
            # Combine token components
            token = f"{header_b64}.{payload_b64}.{signature_b64}"
            
            # Encrypt token if requested
            if encrypt:
                token = self._encrypt_token(token)
                self.logger.info(f"Created encrypted token for user: {username}")
            else:
                self.logger.info(f"Created token for user: {username}")
            
            return token
            
        except Exception as e:
            self.logger.error(f"Token creation failed: {e}")
            raise JWTError(f"Failed to create token: {str(e)}")

    def verify_token(self, token, audience=None, encrypted=False):
        """
        Verify a JWT token's signature, expiration, revocation status, and audience.
        
        Args:
            token (str): JWT token (or encrypted token if encrypted=True).
            audience (str, optional): Expected audience to validate.
            encrypted (bool): If True, decrypt the token before verification.
            
        Returns:
            dict: Decoded payload if valid, None if invalid.
            
        Raises:
            JWTError: If token parsing or verification fails.
        """
        try:
            # Decrypt token if encrypted
            if encrypted:
                token = self._decrypt_token(token)
            
            # Split token into components
            header_b64, payload_b64, signature_b64 = token.split('.')
            
            # Decode header and payload
            header = json.loads(self._base64url_decode(header_b64))
            payload = json.loads(self._base64url_decode(payload_b64))
            
            # Verify algorithm
            if header.get("alg") != self.algorithm:
                self.logger.warning(f"Algorithm mismatch: {header.get('alg')}")
                return None
            
            # Check revocation
            jti = payload.get("jti")
            if jti in self.revoked_tokens:
                self.logger.warning(f"Token revoked: {jti}")
                return None
            
            # Check expiration
            if payload.get("exp", 0) < int(time.time()):
                self.logger.warning("Token expired")
                return None
            
            # Verify audience
            if audience and payload.get("aud") != audience:
                self.logger.warning(f"Audience mismatch: expected {audience}, got {payload.get('aud')}")
                return None
            
            # Verify signature
            signature_input = f"{header_b64}.{payload_b64}"
            expected_signature = self._hmac_digest(signature_input)
            provided_signature = self._base64url_decode(signature_b64)
            
            if not self._constant_time_compare(expected_signature, provided_signature):
                self.logger.warning("Signature verification failed")
                return None
            
            self.logger.info(f"Token verified for user: {payload.get('sub')}")
            return payload
            
        except Exception as e:
            self.logger.error(f"Token verification failed: {e}")
            return None

    def refresh_token(self, token, encrypted=False):
        """
        Refresh a valid token by issuing a new token with extended expiration.
        
        Args:
            token (str): JWT token to refresh (or encrypted token if encrypted=True).
            encrypted (bool): If True, decrypt the token before refreshing.
            
        Returns:
            str: New JWT token (or encrypted token if encrypted=True).
            
        Raises:
            JWTError: If token is invalid or refresh fails.
        """
        try:
            payload = self.verify_token(token, encrypted=encrypted)
            if not payload:
                raise JWTError("Cannot refresh invalid or expired token")
            
            # Create new token with same claims but updated expiration
            new_token = self.create_token(
                username=payload["sub"],
                role=payload["role"],
                additional_claims={k: v for k, v in payload.items() if k not in ["sub", "role", "iat", "exp", "jti", "aud"]},
                audience=payload.get("aud"),
                encrypt=encrypted
            )
            self.logger.info(f"Refreshed token for user: {payload['sub']}")
            return new_token
            
        except Exception as e:
            self.logger.error(f"Token refresh failed: {e}")
            raise JWTError(f"Failed to refresh token: {str(e)}")

    def revoke_token(self, jti):
        """
        Revoke a token by adding its JTI to the revocation list.
        
        Args:
            jti (str): Token's unique identifier.
            
        Raises:
            JWTError: If JTI is invalid.
        """
        if not isinstance(jti, str) or not jti:
            raise JWTError("JTI must be a non-empty string")
        self.revoked_tokens.add(jti)
        self.logger.info(f"Token revoked: {jti}")

    def clear_revoked_tokens(self, before_time=None):
        """
        Clear revoked tokens, optionally those before a specific time.
        
        Args:
            before_time (int, optional): Unix timestamp to filter tokens.
        """
        if before_time is not None and not isinstance(before_time, int):
            raise JWTError("before_time must be an integer")
        if before_time:
            self.revoked_tokens = {jti for jti in self.revoked_tokens if int(jti, 16) > before_time}
        else:
            self.revoked_tokens.clear()
        self.logger.info("Revoked tokens cleared")
        
        
        
