import hashlib
import ubinascii
import json
import time
import os




# Get current Unix timestamp in milliseconds for higher precision
def get_current_time():
    """Get the current Unix timestamp in seconds"""
    return int(time.time())


# Generate a secure random salt
def generate_salt():
    """Generate a secure random salt for key derivation"""
    return os.urandom(16)  # 16 bytes of random data

# Define hmac_sha256 function (manual implementation of HMAC)
def hmac_sha256(key, message):
    """Generate HMAC-SHA256 hash for message with the key"""
    block_size = 64  # Block size for SHA-256 (64 bytes)
    
    if isinstance(key, str):  # Check if key is a string
        key = key.encode()  # Encode the key as bytes
        
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()  # Hash the key if it's too long
    
    # Use bytearray to pad the key if it's too short
    key = bytearray(key)
    if len(key) < block_size:
        key.extend(b'\0' * (block_size - len(key)))  # Pad with zero bytes to the block size

    # Create the inner and outer padding
    opad = bytes([0x5c] * block_size)  # Outer pad: 0x5c repeated 64 times
    ipad = bytes([0x36] * block_size)  # Inner pad: 0x36 repeated 64 times

    # XOR the key with the pads
    inner_key = bytes([key[i] ^ ipad[i] for i in range(block_size)])
    outer_key = bytes([key[i] ^ opad[i] for i in range(block_size)])

    # Perform HMAC: outer_key + SHA256(inner_key + message)
    inner_hash = hashlib.sha256(inner_key + message.encode()).digest()
    hmac_result = hashlib.sha256(outer_key + inner_hash).digest()  # Return raw bytes

    return hmac_result

# JWT class for creating and verifying tokens
class microjwt:
    @staticmethod
    def create_token(username, role, secret_key):
        """Create a JWT token with HMAC for signing"""
        salt = generate_salt()

        # JWT Header (Base64 URL encoded JSON)
        header = {
            "alg": "HS256",  # HMAC with SHA-256
            "typ": "JWT"
        }

        # JWT Payload (User information + expiration time)
        payload = {
            "sub": username,  # Subject (username)
            "role": role,     # User's role
            "iat": get_current_time(),  # Issued At (current time)
            "exp": get_current_time() + 3600,  # Expiry (1 hour from issuance)
            "salt": salt.hex()  # Store the salt in the payload (not in header)
        }

        # Convert header and payload to JSON strings
        header_json = json.dumps(header)
        payload_json = json.dumps(payload)

        # Create the string for signing: Header + "." + Payload
        signature_input = f"{header_json}.{payload_json}"

        # Use HMAC to generate the signature with the secret key and salt (for extra security)
        signature = hmac_sha256(secret_key, signature_input)

        # Combine the Header, Payload, and Signature to create the JWT token
        token = f"{header_json}.{payload_json}.{ubinascii.b2a_base64(signature).decode().strip()}"
        return token

    @staticmethod
    def verify_token(token, secret_key):
        """Verify the JWT token with HMAC signature and expiration check"""
        try:
            # Split the token into Header, Payload, and Signature
            header_json, payload_json, signature_b64 = token.split('.')

            # Decode the JSON string into Python dictionaries
            header = json.loads(header_json)
            payload = json.loads(payload_json)

            # Check if the token has expired
            if get_current_time() > payload['exp']:
                return False  # Token has expired

            # Generate the expected signature from Header and Payload using the secret key
            signature_input = f"{header_json}.{payload_json}"
            expected_signature = hmac_sha256(secret_key, signature_input)

            # Compare the expected signature with the provided signature
            if ubinascii.b2a_base64(expected_signature).decode().strip() != signature_b64:
                return False  # Signature mismatch

            return True  # Token is valid

        except Exception as e:
            return False  # Any error means the token is invalid

