
from microjwt.jwt import MicroJWT


# Initialize the JWT handler
jwt = MicroJWT(
    secret_key="your-very-secure-secret-key-32bytes+",
    algorithm="HS256",
    ttl=3600,
    log_level="INFO",
    silent=False
)

# Create a standard token
token = jwt.create_token(
    username="user123",
    role="admin",
    additional_claims={"scope": "read:write"},
    audience="api.example.com",
    encrypt=False
)
print("Standard token:", token)

# Create an encrypted token for session storage
encrypted_token = jwt.create_token(
    username="user123",
    role="admin",
    additional_claims={"scope": "read:write"},
    audience="api.example.com",
    encrypt=True
)
print("Encrypted token:", encrypted_token)

# Verify a standard token
payload = jwt.verify_token(token, audience="api.example.com", encrypted=False)
if payload:
    print("Standard token is valid:", payload)
else:
    print("Standard token is invalid")

# Verify an encrypted token
payload = jwt.verify_token(encrypted_token, audience="api.example.com", encrypted=True)
if payload:
    print("Encrypted token is valid:", payload)
else:
    print("Encrypted token is invalid")

# Refresh an encrypted token
new_token = jwt.refresh_token(encrypted_token, encrypted=True)
print("Refreshed encrypted token:", new_token)

# Revoke a token
jwt.revoke_token(payload["jti"])

# Verify revoked token (should fail)
payload = jwt.verify_token(new_token, encrypted=True)
if payload:
    print("Revoked token is valid:", payload)
else:
    print("Revoked token is invalid")      



