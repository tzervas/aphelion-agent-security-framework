# src/aphelion/auth/jwt.py

import jwt
import time
from datetime import timedelta, timezone, datetime
from typing import Dict, Any, Optional, Union, Set

# Import the centralized JWTConfigModel and config getter
from aphelion.config import JWTConfigModel, get_config


# --- State for Revoked Tokens (In-Memory) ---
# This is a simple in-memory set for demonstration of revocation.
# In a production system, this should be replaced by a persistent,
# shared store (e.g., Redis, a database table with TTL).
# This state is module-level and not part of JWTConfigModel directly,
# as JWTConfigModel is for static configuration.
_revoked_tokens_store: Set[str] = set()


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
    jwt_cfg = get_config().jwt

    # Standard claims
    to_encode.update({
        "exp": expire_at,
        "iat": datetime.now(timezone.utc),
        "iss": "aphelion_security_framework", # Issuer - could also be configurable
        # "aud": "aphelion_protected_resource", # Audience - can be specific
        "type": token_type, # Custom claim for token type (access/refresh)
    })

    # Ensure 'sub' (subject) is present
    if "sub" not in to_encode:
        raise ValueError("Subject ('sub') claim is required for token creation.")

    encoded_jwt = jwt.encode(
        to_encode,
        jwt_cfg.secret_key.get_secret_value(), # Use .get_secret_value() for SecretStr
        algorithm=jwt_cfg.algorithm
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
    jwt_cfg = get_config().jwt

    expires_delta = timedelta(minutes=jwt_cfg.access_token_expire_minutes)
    data_to_encode = {"sub": str(subject), **additional_claims}
    return _create_token(data_to_encode, expires_delta, token_type="access")

def create_refresh_token(subject: Union[str, Any]) -> str:
    """
    Creates a refresh token.
    :param subject: Identifier for the token subject (e.g., user ID, agent ID).
    :return: Encoded JWT string.
    """
    jwt_cfg = get_config().jwt
    expires_delta = timedelta(days=jwt_cfg.refresh_token_expire_days)
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
    jwt_cfg = get_config().jwt

    try:
        payload = jwt.decode(
            token,
            jwt_cfg.secret_key.get_secret_value(),
            algorithms=[jwt_cfg.algorithm],
            options={"require": ["exp", "iat", "sub", "type"]} # Require standard claims
        )

        # Check if token is revoked using the module-level store
        if token in _revoked_tokens_store: # Check against _revoked_tokens_store
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
    # jwt_cfg = get_config().jwt # If needed for issuer/audience checks
    # if payload.get("iss") != jwt_cfg.issuer: # Assuming issuer is part of JWTConfigModel
    #     raise InvalidTokenError("Invalid token issuer.")

    return payload

# --- Token Revocation (Simple Example using module-level store) ---
def revoke_token(token_jti_or_full_token: str) -> None:
    """
    Adds a token's JTI (JWT ID) or the full token string to the in-memory revocation list.
    NOTE: This is a very basic in-memory revocation. Not suitable for production
    without a persistent and shared revocation list (e.g., Redis, database).
    """
    _revoked_tokens_store.add(token_jti_or_full_token)

def is_token_revoked(token_jti_or_full_token: str) -> bool:
    """Checks if a token (by JTI or full string) is in the in-memory revocation list."""
    return token_jti_or_full_token in _revoked_tokens_store

def clear_revoked_tokens_store() -> None:
    """Clears all tokens from the in-memory revocation list. Useful for testing."""
    _revoked_tokens_store.clear()


if __name__ == "__main__":
    # Basic usage example (primarily for quick testing during development)
    # This will use the configuration loading mechanism (dummy files created in config.py's main)

    # Ensure config is loaded (normally happens on first get_config() call)
    # For this main block, let's explicitly load a test config if needed,
    # or rely on the default loading mechanism.
    # For jwt.py's own __main__, it's better if it can run somewhat independently
    # for basic jwt checks without complex config file setups.
    # However, now it depends on get_config().

    # To make this __main__ runnable for quick checks, we might need a way to
    # use a very default config if the main config system isn't fully set up,
    # or ensure that get_config() provides usable defaults.
    # The get_config() already provides defaults if files are missing.

    app_config = get_config() # Load config using default mechanism
    jwt_cfg_for_main = app_config.jwt

    print(f"Using JWT secret: '{jwt_cfg_for_main.secret_key.get_secret_value()}' (from config)")
    print(f"Access token expiry: {jwt_cfg_for_main.access_token_expire_minutes} minutes")

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
