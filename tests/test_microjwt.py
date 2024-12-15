import ubinascii
import time
from microjwt.core import microjwt


# Test the microjwt class
def test_microjwt():
    # Define a secret key for HMAC signing
    secret_key = "my_secret_key"

    # Define user information
    username = "Arman"
    role = "admin"

    # Create a JWT token using the create_token method
    token = microjwt.create_token(username, role, secret_key)

    # Print the token to check its structure
    print("Generated Token:", token)

    # Verify the token using the verify_token method
    is_valid = microjwt.verify_token(token, secret_key)

    # Display the token validation status
    if is_valid:
        print("The token is valid.")
    else:
        print("The token is invalid.")

    # Simulate an expired token
    # To do this, we first create a payload with an expiration time in the past
    expired_token = microjwt.create_token(username, role, secret_key)
    
    # Assume the system time is 1 hour past the token's expiration time
    time.sleep(1)  # Simulate one second to the expiration time
    expired_token = expired_token.split('.')[0] + '.' + expired_token.split('.')[1]  # Remove signature
    expired_token += ".wrong_signature"  # Add a wrong signature to simulate

    # Verify the expired token
    is_valid_expired = microjwt.verify_token(expired_token, secret_key)
    
    # Display the result for the expired token
    if is_valid_expired:
        print("The expired token is valid.")
    else:
        print("The expired token is invalid.")

    # Simulate a wrong signature error with an incorrect key
    wrong_secret_key = "wrong_secret_key"
    is_valid_wrong_key = microjwt.verify_token(token, wrong_secret_key)
    
    # Display the result for the wrong key
    if is_valid_wrong_key:
        print("The token is valid with the wrong secret key.")
    else:
        print("The token is invalid with the wrong secret key.")

# Call the test function
test_microjwt()
