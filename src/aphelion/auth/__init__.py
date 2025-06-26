# src/aphelion/auth/__init__.py

"""
Authentication sub-package for Aphelion.
Handles JWT creation, validation, and related security concerns.
"""

from .jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_token,
    JWTConfig,
    InvalidTokenError,
    ExpiredTokenError,
    MissingTokenError,
    RevokedTokenError, # Placeholder for future use
)

__all__ = [
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "validate_token",
    "JWTConfig",
    "InvalidTokenError",
    "ExpiredTokenError",
    "MissingTokenError",
    "RevokedTokenError",
]
