# src/aphelion/auth/jwt.py

import jwt
import time
from datetime import timedelta, timezone, datetime
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field

# --- Configuration ---
@dataclass
class JWTConfig:
    """Configuration for JWT generation and validation."""
    secret_key: str = "your-default-super-secret-key"  # IMPORTANT: Change this in production!
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    # Token revocation list (can be replaced with a more robust solution like Redis)
    # For now, a simple in-memory set for demonstration.
    # In a real app, this needs to be persistent and shared across instances.
    revoked_tokens: set[str] = field(default_factory=set)


# Global config instance (can be replaced by a proper config management system)
# This is a placeholder. Real config should be loaded securely.
# Ticket #3: Configuration Management System will address this.
_jwt_config = JWTConfig()

def configure_jwt(config: JWTConfig):
    """Allows global JWT configuration to be updated."""
    global _jwt_config
    _jwt_config = config

# --- Custom Exceptions ---
class MissingTokenError(Exception):
    """Raised when a token is expected but not found."""
    pass

class InvalidTokenError(Exception):
    """Raised when a token is invalid (e.g., malformed, wrong signature)."""
    pass

class ExpiredTokenError(InvalidTokenError):
    """Raised when a token has expired."""
    pass

class RevokedTokenError(InvalidTokenError):
    """Raised when a token has been revoked."""
    pass


# --- Token Creation ---
def _create_token(
    data: Dict[str, Any],
    expires_delta: timedelta,
    token_type: str = "access"
) -> str:
    """
    Helper function to create a JWT.
    """
    to_encode = data.copy()
    expire_at = datetime.now(timezone.utc) + expires_delta

    # Standard claims
    to_encode.update({
        "exp": expire_at,
        "iat": datetime.now(timezone.utc),
        "iss": "aphelion_security_framework", # Issuer
        # "aud": "aphelion_protected_resource", # Audience - can be specific
        "type": token_type, # Custom claim for token type (access/refresh)
    })

    # Ensure 'sub' (subject) is present
    if "sub" not in to_encode:
        raise ValueError("Subject ('sub') claim is required for token creation.")

    encoded_jwt = jwt.encode(
        to_encode,
        _jwt_config.secret_key,
        algorithm=_jwt_config.algorithm
    )
    return encoded_jwt

def create_access_token(subject: Union[str, Any], additional_claims: Optional[Dict[str, Any]] = None) -> str:
    """
    Creates an access token.
    :param subject: Identifier for the token subject (e.g., user ID, agent ID).
    :param additional_claims: Optional dictionary of additional claims to include.
    :return: Encoded JWT string.
    """
    if additional_claims is None:
        additional_claims = {}

    expires_delta = timedelta(minutes=_jwt_config.access_token_expire_minutes)
    data_to_encode = {"sub": str(subject), **additional_claims}
    return _create_token(data_to_encode, expires_delta, token_type="access")

def create_refresh_token(subject: Union[str, Any]) -> str:
    """
    Creates a refresh token.
    :param subject: Identifier for the token subject (e.g., user ID, agent ID).
    :return: Encoded JWT string.
    """
    expires_delta = timedelta(days=_jwt_config.refresh_token_expire_days)
    data_to_encode = {"sub": str(subject)}
    # Refresh tokens typically have fewer claims and longer expiry
    return _create_token(data_to_encode, expires_delta, token_type="refresh")


# --- Token Decoding and Validation ---
def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes a JWT.
    Raises InvalidTokenError or ExpiredTokenError on failure.
    :param token: The JWT string to decode.
    :return: The decoded payload as a dictionary.
    :raises MissingTokenError: If the token is None or empty.
    :raises ExpiredTokenError: If the token has expired.
    :raises InvalidTokenError: If the token is malformed, has an invalid signature, or other JWT errors.
    :raises RevokedTokenError: If the token is in the revocation list.
    """
    if not token:
        raise MissingTokenError("Token is missing.")

    try:
        payload = jwt.decode(
            token,
            _jwt_config.secret_key,
            algorithms=[_jwt_config.algorithm],
            options={"require": ["exp", "iat", "sub", "type"]} # Require standard claims
        )

        # Check if token is revoked (simple in-memory check for now)
        # A more robust solution (e.g., Redis) would be needed for production.
        # The 'jti' (JWT ID) claim would be useful here if we add it during creation.
        # For now, revoking the whole token string if it was e.g. a refresh token.
        if token in _jwt_config.revoked_tokens:
            raise RevokedTokenError("Token has been revoked.")

        return payload
    except jwt.ExpiredSignatureError:
        raise ExpiredTokenError("Token has expired.")
    except jwt.InvalidTokenError as e: # Catches various JWT errors like invalid signature, malformed, etc.
        raise InvalidTokenError(f"Token is invalid: {e}")


def validate_token(token: str, expected_token_type: Optional[str] = "access") -> Dict[str, Any]:
    """
    Validates a token and checks its type.
    :param token: The JWT string to validate.
    :param expected_token_type: The expected type of the token (e.g., "access", "refresh").
                                If None, type check is skipped.
    :return: The decoded payload if the token is valid.
    :raises InvalidTokenError: If the token type does not match or other validation issues.
    """
    payload = decode_token(token) # This already handles expiry, signature, etc.

    if expected_token_type and payload.get("type") != expected_token_type:
        raise InvalidTokenError(
            f"Invalid token type. Expected '{expected_token_type}', got '{payload.get('type')}'."
        )

    # Additional checks can be added here, e.g., audience, issuer if configured.
    # if payload.get("iss") != _jwt_config.issuer:
    #     raise InvalidTokenError("Invalid token issuer.")

    return payload

# --- Token Revocation (Simple Example) ---
def revoke_token(token_jti_or_full_token: str) -> None:
    """
    Adds a token's JTI (JWT ID) or the full token string to the revocation list.
    NOTE: This is a very basic in-memory revocation. Not suitable for production
    without a persistent and shared revocation list (e.g., Redis, database).
    For full tokens, this primarily makes sense for refresh tokens that might be stored.
    Access tokens are short-lived and usually not explicitly revoked this way unless
    they have a JTI.
    """
    _jwt_config.revoked_tokens.add(token_jti_or_full_token)

def is_token_revoked(token_jti_or_full_token: str) -> bool:
    """Checks if a token (by JTI or full string) is in the revocation list."""
    return token_jti_or_full_token in _jwt_config.revoked_tokens

if __name__ == "__main__":
    # Basic usage example (primarily for quick testing during development)
    # In a real app, JWTConfig would be loaded from a secure configuration source.

    # Configure (optional, uses defaults if not called)
    # For testing, we might use a fixed secret.
    test_config = JWTConfig(secret_key="test-secret", access_token_expire_minutes=1, refresh_token_expire_days=1)
    configure_jwt(test_config)

    print(f"Using JWT secret: '{_jwt_config.secret_key}' (for testing only!)")

    # Create tokens
    user_id = "user123"
    custom_claims = {"role": "admin", "permissions": ["read", "write"]}

    try:
        access_token = create_access_token(user_id, additional_claims=custom_claims)
        refresh_token = create_refresh_token(user_id)
        print(f"Access Token: {access_token}")
        print(f"Refresh Token: {refresh_token}")
        print("-" * 20)

        # Validate access token
        print("Validating access token...")
        payload = validate_token(access_token, expected_token_type="access")
        print(f"Access Token Payload: {payload}")
        assert payload["sub"] == user_id
        assert payload["role"] == "admin"
        print("Access token is valid.")
        print("-" * 20)

        # Validate refresh token
        print("Validating refresh token...")
        payload_refresh = validate_token(refresh_token, expected_token_type="refresh")
        print(f"Refresh Token Payload: {payload_refresh}")
        assert payload_refresh["sub"] == user_id
        print("Refresh token is valid.")
        print("-" * 20)

        # Test expiration
        print("Testing token expiration (access token expires in 1 min)...")
        # configured with access_token_expire_minutes=1 for this test block
        print("Waiting for 65 seconds...")
        time.sleep(65)
        try:
            validate_token(access_token)
        except ExpiredTokenError as e:
            print(f"Correctly caught expired token: {e}")
        print("-" * 20)

        # Test invalid token
        print("Testing invalid token (tampered)...")
        tampered_token = access_token[:-5] + "xxxxx" # Tamper the signature part
        try:
            validate_token(tampered_token)
        except InvalidTokenError as e:
            print(f"Correctly caught invalid token: {e}")
        print("-" * 20)

        # Test missing token
        print("Testing missing token...")
        try:
            validate_token("")
        except MissingTokenError as e:
            print(f"Correctly caught missing token: {e}")
        print("-" * 20)

        # Test wrong token type
        print("Testing wrong token type...")
        try:
            validate_token(refresh_token, expected_token_type="access")
        except InvalidTokenError as e:
            print(f"Correctly caught wrong token type: {e}")
        print("-" * 20)

        # Test revocation
        print("Testing token revocation...")
        # Create a new access token for revocation test
        token_to_revoke = create_access_token("user_for_revocation")
        print(f"Token to revoke: {token_to_revoke}")
        revoke_token(token_to_revoke) # Revoke the full token string
        assert is_token_revoked(token_to_revoke) is True
        print(f"Token '{token_to_revoke[:20]}...' is now in revocation list.")
        try:
            validate_token(token_to_revoke)
        except RevokedTokenError as e:
            print(f"Correctly caught revoked token: {e}")

        # Test a non-revoked token
        fresh_token = create_access_token("another_user")
        assert is_token_revoked(fresh_token) is False
        payload_fresh = validate_token(fresh_token)
        print(f"Fresh token for '{payload_fresh['sub']}' validated successfully.")
        print("-" * 20)


    except Exception as e:
        print(f"An error occurred during JWT example: {e}")

    # Reset to default config for other potential uses if this file is imported elsewhere
    # Though typically, this __main__ block is for direct execution only.
    # configure_jwt(JWTConfig())
