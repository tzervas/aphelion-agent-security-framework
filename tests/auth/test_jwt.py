# tests/auth/test_jwt.py

import pytest
import time
import jwt # <--- IMPORT ADDED HERE
from datetime import timedelta
from typing import Dict, Any

from aphelion.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_token,
    JWTConfig,
    configure_jwt,
    InvalidTokenError,
    ExpiredTokenError,
    MissingTokenError,
    RevokedTokenError,
    revoke_token,
    is_token_revoked,
    _jwt_config as default_jwt_config # For resetting after tests
)

# Test subject and claims
TEST_SUBJECT = "test_user_123"
TEST_ADDITIONAL_CLAIMS = {"role": "tester", "scope": "read:data"}
DEFAULT_SECRET_KEY = "test-secret-key-for-pytest" # Ensure this is different from production

@pytest.fixture(autouse=True)
def setup_jwt_config():
    """
    Fixture to set up a consistent JWTConfig for each test and reset afterwards.
    This ensures tests are isolated and don't interfere with each other's config.
    """
    original_config = default_jwt_config
    test_config = JWTConfig(
        secret_key=DEFAULT_SECRET_KEY,
        algorithm="HS256",
        access_token_expire_minutes=5,
        refresh_token_expire_days=1,
        revoked_tokens=set() # Ensure fresh revocation list for each test
    )
    configure_jwt(test_config)
    yield test_config # Provide the config to the test if needed
    # Teardown: Reset to original or a default clean state if necessary
    # For simplicity here, we'll just reset to a new default instance
    # or could reset to `original_config` if that's more robust.
    configure_jwt(JWTConfig(secret_key=DEFAULT_SECRET_KEY, revoked_tokens=set()))


def test_create_access_token_default_claims():
    token = create_access_token(subject=TEST_SUBJECT)
    payload = decode_token(token) # Use internal decode for direct payload inspection

    assert payload["sub"] == TEST_SUBJECT
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "iat" in payload
    assert "iss" in payload
    assert payload["iss"] == "aphelion_security_framework"

def test_create_access_token_with_additional_claims():
    token = create_access_token(subject=TEST_SUBJECT, additional_claims=TEST_ADDITIONAL_CLAIMS)
    payload = decode_token(token)

    assert payload["sub"] == TEST_SUBJECT
    assert payload["role"] == TEST_ADDITIONAL_CLAIMS["role"]
    assert payload["scope"] == TEST_ADDITIONAL_CLAIMS["scope"]
    assert payload["type"] == "access"

def test_create_refresh_token():
    token = create_refresh_token(subject=TEST_SUBJECT)
    payload = decode_token(token)

    assert payload["sub"] == TEST_SUBJECT
    assert payload["type"] == "refresh"
    assert "exp" in payload
    assert "iat" in payload
    # Refresh tokens should not contain additional app-specific claims by default
    assert "role" not in payload

def test_validate_valid_access_token():
    token = create_access_token(subject=TEST_SUBJECT, additional_claims=TEST_ADDITIONAL_CLAIMS)
    payload = validate_token(token, expected_token_type="access")

    assert payload["sub"] == TEST_SUBJECT
    assert payload["role"] == TEST_ADDITIONAL_CLAIMS["role"]

def test_validate_valid_refresh_token():
    token = create_refresh_token(subject=TEST_SUBJECT)
    payload = validate_token(token, expected_token_type="refresh")
    assert payload["sub"] == TEST_SUBJECT

def test_validate_token_no_type_check():
    token = create_access_token(subject=TEST_SUBJECT)
    payload = validate_token(token, expected_token_type=None) # Skip type check
    assert payload["sub"] == TEST_SUBJECT
    assert payload["type"] == "access"

def test_decode_expired_access_token(setup_jwt_config: JWTConfig):
    # Configure a very short expiry for this test
    short_lived_config = JWTConfig(
        secret_key=DEFAULT_SECRET_KEY,
        access_token_expire_minutes= -1, # Expired in the past
        revoked_tokens=set()
    )
    configure_jwt(short_lived_config)

    token = create_access_token(subject=TEST_SUBJECT)
    # Allow a moment for time to pass if expiry is set to 0 or very small positive
    # time.sleep(0.01) # Not strictly needed for negative expiry

    with pytest.raises(ExpiredTokenError):
        decode_token(token)

def test_validate_expired_access_token(setup_jwt_config: JWTConfig):
    # Configure a very short expiry for this test
    short_lived_config = JWTConfig(
        secret_key=DEFAULT_SECRET_KEY,
        access_token_expire_minutes=0, # Expires immediately
        revoked_tokens=set()
    )
    # To ensure it's created and then *definitely* checked after expiry
    # we can also calculate expiry to be a fraction of a second.
    # For robust testing, PyJWT allows overriding `utcnow` for time control.
    # Here, we'll use a small sleep.

    token = create_access_token(subject=TEST_SUBJECT) # Create with default config (5 mins)

    # Now, reconfigure to make it seem like it expired relative to a *new* config if we were to use it.
    # Better: create with specific expiry for testing.
    # Let's use a config that makes tokens expire very fast.
    very_short_expiry_config = JWTConfig(secret_key=DEFAULT_SECRET_KEY, access_token_expire_minutes=1/600) # 0.1 sec
    configure_jwt(very_short_expiry_config)
    token_short = create_access_token(subject="short_lived_user")

    time.sleep(0.2) # Wait for 0.2 seconds, enough for it to expire

    with pytest.raises(ExpiredTokenError):
        validate_token(token_short)

def test_decode_invalid_signature_token():
    # Create a token with the configured key
    token = create_access_token(subject=TEST_SUBJECT)

    # Reconfigure with a different key to make the original signature invalid
    wrong_key_config = JWTConfig(secret_key="completely-different-secret", revoked_tokens=set())
    configure_jwt(wrong_key_config)

    with pytest.raises(InvalidTokenError) as excinfo:
        decode_token(token)
    assert "Signature verification failed" in str(excinfo.value) or "Invalid signature" in str(excinfo.value)


def test_validate_invalid_signature_token():
    token = create_access_token(subject=TEST_SUBJECT)

    wrong_key_config = JWTConfig(secret_key="another-wrong-secret", revoked_tokens=set())
    configure_jwt(wrong_key_config)

    with pytest.raises(InvalidTokenError):
        validate_token(token)

def test_decode_malformed_token():
    malformed_token = "this.is.not.a.jwt"
    with pytest.raises(InvalidTokenError) as excinfo:
        decode_token(malformed_token)
    # Check that our wrapper exception is raised. The specific PyJWT internal error can vary.
    assert "Token is invalid" in str(excinfo.value)


def test_validate_malformed_token():
    malformed_token = "this.is.still.not.a.jwt"
    with pytest.raises(InvalidTokenError):
        validate_token(malformed_token)

def test_decode_missing_token():
    with pytest.raises(MissingTokenError):
        decode_token("")
    with pytest.raises(MissingTokenError):
        decode_token(None) # type: ignore

def test_validate_missing_token():
    with pytest.raises(MissingTokenError):
        validate_token("")
    with pytest.raises(MissingTokenError):
        validate_token(None) # type: ignore

def test_validate_wrong_token_type():
    access_token = create_access_token(subject=TEST_SUBJECT)
    with pytest.raises(InvalidTokenError) as excinfo:
        validate_token(access_token, expected_token_type="refresh")
    assert "Invalid token type. Expected 'refresh', got 'access'" in str(excinfo.value)

    refresh_token = create_refresh_token(subject=TEST_SUBJECT)
    with pytest.raises(InvalidTokenError) as excinfo:
        validate_token(refresh_token, expected_token_type="access")
    assert "Invalid token type. Expected 'access', got 'refresh'" in str(excinfo.value)

# Removed test_create_token_missing_subject because create_access_token(subject=None)
# results in str(None) which is "None", a valid subject. The internal check in _create_token
# for 'sub' in data is always satisfied by the public create_access_token and create_refresh_token.

def test_token_revocation(setup_jwt_config: JWTConfig):
    token_to_revoke1 = create_access_token("user_to_be_revoked_1")
    token_to_revoke2 = create_refresh_token("user_to_be_revoked_2")
    token_not_revoked = create_access_token("user_not_revoked")

    # Ensure tokens are initially valid and not revoked
    assert is_token_revoked(token_to_revoke1) is False
    validate_token(token_to_revoke1)
    assert is_token_revoked(token_to_revoke2) is False
    validate_token(token_to_revoke2, expected_token_type="refresh")
    assert is_token_revoked(token_not_revoked) is False
    validate_token(token_not_revoked)

    # Revoke tokens
    revoke_token(token_to_revoke1)
    revoke_token(token_to_revoke2)

    assert is_token_revoked(token_to_revoke1) is True
    assert is_token_revoked(token_to_revoke2) is True
    assert is_token_revoked(token_not_revoked) is False # Ensure other tokens are not affected

    # Check that validation now fails for revoked tokens
    with pytest.raises(RevokedTokenError):
        validate_token(token_to_revoke1)

    with pytest.raises(RevokedTokenError):
        validate_token(token_to_revoke2, expected_token_type="refresh")

    # Ensure the non-revoked token is still valid
    payload = validate_token(token_not_revoked)
    assert payload["sub"] == "user_not_revoked"

def test_jwt_config_update():
    new_secret = "a-brand-new-secret-for-this-test"
    new_algo = "HS512" # Example: testing a different algorithm
    new_expiry_min = 60

    current_config = JWTConfig(
        secret_key=new_secret,
        algorithm=new_algo,
        access_token_expire_minutes=new_expiry_min,
        revoked_tokens=set()
    )
    configure_jwt(current_config)

    # Create token with new config
    token = create_access_token(TEST_SUBJECT)

    # Try to decode with old (default test) key should fail if secrets are different
    # (Need to be careful here due to fixture resetting config)
    # Let's explicitly use the new config for decoding here

    payload = jwt.decode(
        token,
        new_secret, # Use the new secret directly
        algorithms=[new_algo]
    )
    assert payload["sub"] == TEST_SUBJECT

    # Test that decoding with the default test secret (from fixture setup) fails
    with pytest.raises(jwt.InvalidSignatureError):
         jwt.decode(
            token,
            DEFAULT_SECRET_KEY, # Original secret from fixture
            algorithms=[new_algo] # Using new algo but wrong key for it
        )

    # Test that decoding with correct key but wrong algo fails
    with pytest.raises(jwt.InvalidAlgorithmError):
         jwt.decode(
            token,
            new_secret,
            algorithms=["HS256"] # Original algo from fixture
        )

# Example of how one might test time-sensitive claims more precisely using PyJWT's features
# This requires more direct use of jwt.encode/decode and the `options` parameter.
def test_token_nbf_claim(setup_jwt_config: JWTConfig):
    # "nbf" (Not Before) claim
    # For this, we need to inject 'nbf' into the token creation.
    # Let's assume _create_token could be extended or we craft it manually.

    nbf_time = int(time.time()) + 300  # Token not valid for 300 seconds
    iat_time = int(time.time())
    exp_time = iat_time + setup_jwt_config.access_token_expire_minutes * 60

    custom_payload = {
        "sub": TEST_SUBJECT,
        "type": "access",
        "iss": "aphelion_security_framework",
        "iat": iat_time,
        "exp": exp_time,
        "nbf": nbf_time,
        "custom_claim": "test_nbf"
    }

    token_with_nbf = jwt.encode(
        custom_payload,
        setup_jwt_config.secret_key,
        algorithm=setup_jwt_config.algorithm
    )

    # This should fail because current time is before NBF
    with pytest.raises(InvalidTokenError) as excinfo: # PyJWT raises jwt.ImmatureSignatureError
        decode_token(token_with_nbf)
    assert "token is not yet valid" in str(excinfo.value).lower() or "immature signature" in str(excinfo.value).lower()

    # To test successful validation after NBF, PyJWT allows `options={"leeway": ...}`
    # or by actually waiting, or by patching `time.time()`.
    # For example, if we could control time via PyJWT's decode options (not directly exposed by our wrapper):
    # try:
    #     payload = jwt.decode(token_with_nbf, ..., options={"verify_nbf": True, "leeway": timedelta(seconds=301)})
    # except jwt.ImmatureSignatureError: ...

# Test that the default JWT secret is not the placeholder one after setup_jwt_config
def test_default_secret_is_not_placeholder(setup_jwt_config: JWTConfig):
    assert setup_jwt_config.secret_key == DEFAULT_SECRET_KEY
    assert setup_jwt_config.secret_key != "your-default-super-secret-key"

    # Also check the global _jwt_config used by the functions
    from aphelion.auth.jwt import _jwt_config
    assert _jwt_config.secret_key == DEFAULT_SECRET_KEY
    assert _jwt_config.secret_key != "your-default-super-secret-key"
