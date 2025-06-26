# tests/auth/test_jwt.py

import pytest
import time
import jwt
from datetime import timedelta
from typing import Dict, Any
from unittest.mock import patch, MagicMock

# Now importing AppConfigModel and JWTConfigModel for type hinting and test setup
from aphelion.config import AppConfigModel, JWTConfigModel
from aphelion.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_token,
    # JWTConfig, # This is now JWTConfigModel from aphelion.config
    # configure_jwt, # This is removed
    InvalidTokenError,
    ExpiredTokenError,
    MissingTokenError,
    RevokedTokenError,
    revoke_token,
    is_token_revoked,
    clear_revoked_tokens_store # New helper for test cleanup
    # _jwt_config as default_jwt_config # This global is removed
)

# Test subject and claims
TEST_SUBJECT = "test_user_123"
TEST_ADDITIONAL_CLAIMS = {"role": "tester", "scope": "read:data"}
DEFAULT_TEST_SECRET_KEY = "test-secret-key-for-pytest"

@pytest.fixture
def mocked_jwt_config_model() -> JWTConfigModel:
    """Provides a consistent JWTConfigModel instance for tests."""
    return JWTConfigModel(
        secret_key=DEFAULT_TEST_SECRET_KEY, # type: ignore [arg-type] # pydantic handles SecretStr
        algorithm="HS256",
        access_token_expire_minutes=5,
        refresh_token_expire_days=1,
    )

@pytest.fixture(autouse=True)
def mock_aphelion_config_for_jwt_tests(mocked_jwt_config_model: JWTConfigModel):
    """
    Patches get_config() within the aphelion.auth.jwt module to return a
    test-specific AppConfigModel containing the mocked_jwt_config_model.
    Also clears the JWT revocation store before and after each test.
    """
    clear_revoked_tokens_store() # Clear before test runs

    # Create a full AppConfigModel instance, embedding the mocked JWT config
    test_app_config = AppConfigModel(jwt=mocked_jwt_config_model)

    # The crucial part is to patch 'get_config' in the *module where it's used* (aphelion.auth.jwt)
    with patch('aphelion.auth.jwt.get_config') as mocked_get_config_func:
        mocked_get_config_func.return_value = test_app_config
        yield mocked_get_config_func # The mock object itself, can be used by tests if needed

    clear_revoked_tokens_store() # Clear after test runs


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

def test_decode_expired_access_token(mock_aphelion_config_for_jwt_tests: MagicMock, mocked_jwt_config_model: JWTConfigModel):
    # Override the global mock for this specific test to set a past expiry
    expired_jwt_config = mocked_jwt_config_model.model_copy(update={"access_token_expire_minutes": -1})
    expired_app_config = AppConfigModel(jwt=expired_jwt_config)
    mock_aphelion_config_for_jwt_tests.return_value = expired_app_config

    token = create_access_token(subject=TEST_SUBJECT)
    with pytest.raises(ExpiredTokenError):
        decode_token(token)

def test_validate_expired_access_token(mock_aphelion_config_for_jwt_tests: MagicMock, mocked_jwt_config_model: JWTConfigModel):
    # Override the global mock for this specific test for very short expiry
    short_expiry_jwt_config = mocked_jwt_config_model.model_copy(
        update={"access_token_expire_minutes": 1/6000} # Approx 0.01 seconds
    )
    short_expiry_app_config = AppConfigModel(jwt=short_expiry_jwt_config)
    mock_aphelion_config_for_jwt_tests.return_value = short_expiry_app_config

    token_short = create_access_token(subject="short_lived_user")
    time.sleep(0.1) # Wait for 0.1 seconds, should be enough for it to expire

    with pytest.raises(ExpiredTokenError):
        validate_token(token_short)

def test_decode_invalid_signature_token(mock_aphelion_config_for_jwt_tests: MagicMock, mocked_jwt_config_model: JWTConfigModel):
    # Create a token with the current (mocked) key
    token = create_access_token(subject=TEST_SUBJECT)

    # Now, change the config that get_config() will return for the decode step
    # Pydantic should convert the string "completely-different-secret" to SecretStr
    # Explicitly create SecretStr for the update to be certain.
    from pydantic import SecretStr
    wrong_key_jwt_config = mocked_jwt_config_model.model_copy(
        update={"secret_key": SecretStr("completely-different-secret")}
    )
    wrong_key_app_config = AppConfigModel(jwt=wrong_key_jwt_config)
    mock_aphelion_config_for_jwt_tests.return_value = wrong_key_app_config

    with pytest.raises(InvalidTokenError) as excinfo:
        decode_token(token)
    assert "Signature verification failed" in str(excinfo.value) or "Invalid signature" in str(excinfo.value)


def test_validate_invalid_signature_token(mock_aphelion_config_for_jwt_tests: MagicMock, mocked_jwt_config_model: JWTConfigModel):
    # Create a token with the current (mocked) key
    token = create_access_token(subject=TEST_SUBJECT)

    # Change the config for the validation step
    from pydantic import SecretStr
    another_wrong_key_jwt_config = mocked_jwt_config_model.model_copy(
        update={"secret_key": SecretStr("another-wrong-secret")}
    )
    another_wrong_key_app_config = AppConfigModel(jwt=another_wrong_key_jwt_config)
    mock_aphelion_config_for_jwt_tests.return_value = another_wrong_key_app_config

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

def test_token_revocation(): # Removed setup_jwt_config: JWTConfig argument
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

def test_jwt_behavior_with_changed_config_algorithm(
    mock_aphelion_config_for_jwt_tests: MagicMock,
    mocked_jwt_config_model: JWTConfigModel
):
    # 1. Create token with default HS256 algorithm (from main fixture)
    token_hs256 = create_access_token(TEST_SUBJECT)

    # Validate it works with HS256
    payload_hs256 = validate_token(token_hs256)
    assert payload_hs256["sub"] == TEST_SUBJECT

    # 2. Change the live JWT config to use HS512 for subsequent operations
    hs512_jwt_config = mocked_jwt_config_model.model_copy(
        update={"algorithm": "HS512"}
    )
    hs512_app_config = AppConfigModel(jwt=hs512_jwt_config)
    mock_aphelion_config_for_jwt_tests.return_value = hs512_app_config

    # 3. Try to validate the HS256 token with the new HS512 config active
    # This should fail because decode_token will now expect HS512
    with pytest.raises(InvalidTokenError) as excinfo:
        validate_token(token_hs256) # This will use get_config() which now returns HS512 config
    # PyJWT error for this case is "The specified alg value is not allowed"
    assert "The specified alg value is not allowed" in str(excinfo.value)


    # 4. Create a new token, it should now be HS512
    token_hs512 = create_access_token(TEST_SUBJECT + "_hs512")

    # Directly decode with PyJWT to check its actual algorithm without relying on our validate_token
    header = jwt.get_unverified_header(token_hs512)
    assert header["alg"] == "HS512"

    # And our validate_token should work for this HS512 token
    payload_hs512_new = validate_token(token_hs512)
    assert payload_hs512_new["sub"] == TEST_SUBJECT + "_hs512"

    # 5. Revert mock to original (HS256) to ensure no test interference (though fixture does this on exit)
    # For clarity, explicitly showing how one might reset if needed mid-test, though usually not.
    # For this test, the fixture's teardown is sufficient.
    # mock_aphelion_config_for_jwt_tests.return_value = AppConfigModel(jwt=mocked_jwt_config_model)


# Example of how one might test time-sensitive claims more precisely using PyJWT's features
# This requires more direct use of jwt.encode/decode and the `options` parameter.
def test_token_nbf_claim(mock_aphelion_config_for_jwt_tests: MagicMock, mocked_jwt_config_model: JWTConfigModel):
    # "nbf" (Not Before) claim
    # For this, we need to inject 'nbf' into the token creation.
    # Let's assume _create_token could be extended or we craft it manually.

    nbf_time = int(time.time()) + 300  # Token not valid for 300 seconds
    iat_time = int(time.time())
    # Use the mocked_jwt_config_model passed to the test
    exp_time = iat_time + mocked_jwt_config_model.access_token_expire_minutes * 60

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
        mocked_jwt_config_model.secret_key.get_secret_value(), # Use mocked config
        algorithm=mocked_jwt_config_model.algorithm # Use mocked config
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

# Test that the default JWT secret used in tests is not the application's default placeholder
def test_default_test_secret_is_not_app_placeholder(mock_aphelion_config_for_jwt_tests: MagicMock):
    # The mock_aphelion_config_for_jwt_tests fixture sets up get_config() to return
    # an AppConfigModel containing a JWTConfigModel with DEFAULT_TEST_SECRET_KEY.

    # We access this through the mock of get_config if we want to inspect its return_value,
    # or by calling get_config() itself (which will return the mocked value).
    from aphelion.auth.jwt import get_config # Import it here to ensure it's the one from jwt module

    current_jwt_config = get_config().jwt # This will use the mocked get_config

    assert current_jwt_config.secret_key.get_secret_value() == DEFAULT_TEST_SECRET_KEY
    assert current_jwt_config.secret_key.get_secret_value() != "your-default-super-secret-key-please-change"
    # Also check the algorithm to be sure we have the right test config
    assert current_jwt_config.algorithm == "HS256"
