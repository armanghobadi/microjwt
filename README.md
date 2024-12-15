
# MicroJWT

**MicroJWT** is a simple implementation of JSON Web Tokens (JWT) specifically designed for use in **MicroPython**. This project utilizes **HMAC-SHA256** for signing tokens and employs basic user information (such as username and role) within the token itself. It allows you to create secure authentication systems on embedded systems, especially microcontrollers running MicroPython, like **ESP8266**, **ESP32**, and other similar devices.

## Goal of the Project

The goal of **MicroJWT** is to provide a lightweight, easy-to-use JWT solution for embedded systems and microcontrollers. With MicroPython being a minimalistic environment, this package aims to deliver a robust authentication mechanism without requiring heavy resources, making it ideal for IoT devices and embedded applications.

JWT is commonly used in web applications for stateless authentication. **MicroJWT** brings this functionality to the world of embedded systems, allowing your devices to securely authenticate with external systems or APIs.

## Features

- **HMAC-SHA256 Signing**: Provides a secure way of signing and verifying tokens using HMAC and SHA-256.
- **Lightweight**: Designed with minimal overhead, making it suitable for resource-constrained devices.
- **Compatibility**: Works seamlessly with MicroPython, making it compatible with popular microcontrollers like ESP8266, ESP32, and others.
- **Security**: Supports secure token creation and verification, including expiration time (exp) to prevent token replay attacks.

## Installation

To install **MicroJWT**, you can use `pip`:

 for MicroPython, use the appropriate package manager like `upip` to install directly on your microcontroller.

```bash
upip install microjwt
```

## Usage

Here is an example of how to create and verify a JWT token:

```python
from microjwt.core import microjwt


# Define the secret key
secret_key = "my_secret_key"

# Create a JWT token
token = microjwt.create_token("Arman", "admin", secret_key)

# Verify the token
is_valid = microjwt.verify_token(token, secret_key)

if is_valid:
    print("The token is valid.")
else:
    print("The token is invalid.")
```



## License

This project is licensed under the MIT License.

## Test Images

![Token in Session](./tests/cookie.png)

![Token in Test-file](./tests/test.png)