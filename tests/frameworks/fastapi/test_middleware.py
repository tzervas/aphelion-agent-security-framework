# tests/frameworks/fastapi/test_middleware.py

import pytest
import time
from typing import Any, Optional
from unittest.mock import patch, MagicMock

from fastapi import FastAPI, Request, Depends, HTTPException, Response
from httpx import AsyncClient
from starlette.types import ASGIApp # Import ASGIApp

from aphelion.auth.jwt import create_access_token
from aphelion.config import AppConfigModel, JWTConfigModel, get_config
from aphelion.frameworks.fastapi.middleware import AphelionFastAPIMiddleware, get_current_subject

# --- Test App Setup ---

TEST_SUBJECT_ID = "test_fastapi_user"
DEFAULT_TEST_FASTAPI_SECRET_KEY = "fastapi-middleware-test-secret"

@pytest.fixture
def test_jwt_config_for_fastapi() -> JWTConfigModel:
    """Provides a consistent JWTConfigModel for FastAPI middleware tests."""
    return JWTConfigModel(
        secret_key=DEFAULT_TEST_FASTAPI_SECRET_KEY, # type: ignore
        algorithm="HS256",
        access_token_expire_minutes=5, # Short expiry for testing is good
    )

@pytest.fixture(scope="function") # Use function scope for test isolation
def mock_aphelion_config_for_fastapi_tests(test_jwt_config_for_fastapi: JWTConfigModel):
    """
    Patches get_config() for the duration of a test function to return a
    test-specific AppConfig, primarily for JWT settings.
    This fixture ensures that JWT creation and validation within the middleware
    and token generation utilities use a consistent, test-specific secret key and settings.
    """
    test_app_config = AppConfigModel(jwt=test_jwt_config_for_fastapi)

    # Patch get_config in the 'aphelion.auth.jwt' module, as this is where
    # create_access_token and validate_aphelion_token (used by the middleware)
    # will look it up.
    with patch('aphelion.auth.jwt.get_config') as mock_get_config_for_jwt_module:
        mock_get_config_for_jwt_module.return_value = test_app_config
        yield mock_get_config_for_jwt_module

def create_test_app(public_paths: Optional[set[str]] = None) -> FastAPI:
    """Helper to create a FastAPI app instance with the middleware."""
    app = FastAPI(title="TestAppWithAphelionMiddleware")
    app.add_middleware(AphelionFastAPIMiddleware, public_paths=public_paths or {"/public"})

    @app.get("/public")
    async def public_route():
        return {"message": "Public access granted"}

    @app.get("/protected_state")
    async def protected_route_state(request: Request):
        subject = getattr(request.state, "subject", None)
        if not subject:
            raise HTTPException(status_code=403, detail="Forbidden: No subject in state.")
        return {"message": f"Protected access granted to {subject} (via request.state)"}

    @app.get("/protected_depends")
    async def protected_route_depends(current_user: Any = Depends(get_current_subject)):
        return {"message": f"Protected access granted to {current_user} (via Depends)"}

    @app.get("/always_401_for_options_test")
    async def options_test_route():
        # This route is just a placeholder for testing options like public_paths.
        # It will always be protected unless path is in public_paths.
        return {"message": "You should not see this unless public or authed."}

    return app

import pytest_asyncio # Import the asyncio fixture decorator

@pytest_asyncio.fixture # Use pytest_asyncio.fixture for async fixtures
async def client(mock_aphelion_config_for_fastapi_tests: MagicMock): # Depends on the config mock
    """Provides an AsyncClient for the test FastAPI app."""
    app = create_test_app(public_paths={"/public", "/openapi.json", "/docs"})
    from httpx import AsyncClient, ASGITransport # Import ASGITransport
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

# --- Test Cases ---

@pytest.mark.asyncio
async def test_public_path_accessible_without_token(client: AsyncClient):
    response = await client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "Public access granted"}

@pytest.mark.asyncio
async def test_protected_path_denied_without_token(client: AsyncClient):
    response = await client.get("/protected_state")
    assert response.status_code == 401 # Middleware should return 401
    assert "Token missing" in response.text

@pytest.mark.asyncio
async def test_protected_path_denied_with_malformed_header(client: AsyncClient):
    response = await client.get("/protected_state", headers={"Authorization": "Bear testtoken"})
    assert response.status_code == 401 # HTTPBearer scheme expects "Bearer <token>"
    # The middleware's bearer_scheme(request) will return None if header is malformed.
    assert "Token missing" in response.text # Or FastAPI might return 403 if bearer_scheme has auto_error=True

@pytest.mark.asyncio
async def test_protected_path_accessible_with_valid_token(client: AsyncClient, mock_aphelion_config_for_fastapi_tests: MagicMock):
    # mock_aphelion_config_for_fastapi_tests ensures create_access_token uses the test secret
    token = create_access_token(subject=TEST_SUBJECT_ID)
    headers = {"Authorization": f"Bearer {token}"}

    # Test /protected_state
    response_state = await client.get("/protected_state", headers=headers)
    assert response_state.status_code == 200
    assert response_state.json() == {"message": f"Protected access granted to {TEST_SUBJECT_ID} (via request.state)"}

    # Test /protected_depends
    response_depends = await client.get("/protected_depends", headers=headers)
    assert response_depends.status_code == 200
    assert response_depends.json() == {"message": f"Protected access granted to {TEST_SUBJECT_ID} (via Depends)"}

@pytest.mark.asyncio
async def test_protected_path_denied_with_expired_token(client: AsyncClient, test_jwt_config_for_fastapi: JWTConfigModel, mock_aphelion_config_for_fastapi_tests: MagicMock):
    # To test expiry, we need to generate a token that's already expired or expires quickly.
    # The mock_aphelion_config_for_fastapi_tests fixture already sets up get_config.
    # We can create a token with very short life by temporarily altering the config it returns.

    original_return_value = mock_aphelion_config_for_fastapi_tests.return_value

    # Configure for immediate expiry for token creation
    expired_config = test_jwt_config_for_fastapi.model_copy(update={"access_token_expire_minutes": -1})
    mock_aphelion_config_for_fastapi_tests.return_value = AppConfigModel(jwt=expired_config)
    token = create_access_token(subject=TEST_SUBJECT_ID)

    # Restore config for validation by middleware (which uses the same mocked get_config)
    # The middleware will validate against the config active when it runs.
    # So, if we want it to see the token as expired against its *own* config,
    # the config during validation should be the "normal" one.
    # For this test, the token is created already expired.
    # The middleware will use the config from the fixture (5 min expiry) to validate.
    # But PyJWT checks expiry based on 'exp' claim in token, not current config's minutes.
    # So, an expired token (exp in past) will always be seen as expired.
    mock_aphelion_config_for_fastapi_tests.return_value = original_return_value # Restore for middleware's validation call

    headers = {"Authorization": f"Bearer {token}"}
    response = await client.get("/protected_state", headers=headers)
    assert response.status_code == 401
    assert "Token has expired" in response.text

@pytest.mark.asyncio
async def test_protected_path_denied_with_invalid_signature_token(client: AsyncClient, mock_aphelion_config_for_fastapi_tests: MagicMock):
    # Generate token with one key
    token_good_key = create_access_token(subject=TEST_SUBJECT_ID)

    # Now, simulate middleware validating with a *different* key
    # Change the secret key in the config that the middleware's validate_aphelion_token will see
    from pydantic import SecretStr # Import SecretStr for explicit typing
    current_app_config: AppConfigModel = mock_aphelion_config_for_fastapi_tests.return_value
    wrong_key_jwt_config = current_app_config.jwt.model_copy(
        update={"secret_key": SecretStr("a-completely-different-key-for-validation")}
    )
    mock_aphelion_config_for_fastapi_tests.return_value = AppConfigModel(jwt=wrong_key_jwt_config)

    headers = {"Authorization": f"Bearer {token_good_key}"}
    response = await client.get("/protected_state", headers=headers)
    assert response.status_code == 401
    assert "Token is invalid" in response.text # Should mention signature or general invalidity

@pytest.mark.asyncio
async def test_get_current_subject_dependency_failure_if_no_subject_in_state(mock_aphelion_config_for_fastapi_tests: MagicMock):
    # This tests the get_current_subject dependency directly if middleware somehow fails
    # or a route is misconfigured (e.g., public but uses Depends(get_current_subject)).
    app_no_mw = FastAPI() # App without the Aphelion middleware

    @app_no_mw.get("/test_dependency")
    async def route_with_dependency(user: Any = Depends(get_current_subject)):
        return {"user": user}

    # Re-import locally for sanity check
    from httpx import AsyncClient, ASGITransport
    transport = ASGITransport(app=app_no_mw)
    async with AsyncClient(transport=transport, base_url="http://testserver") as local_client:
        response = await local_client.get("/test_dependency")
        assert response.status_code == 401 # HTTPException from get_current_subject
        assert "Not authenticated or subject not available" in response.json()["detail"]

def test_path_matching_in_middleware():
    # Test the path matching logic of the middleware (not via HTTP client)
    # This is a unit test for a part of the middleware logic.

    # Dummy request and call_next for synchronous testing of this part
    class DummyRequest:
        def __init__(self, path):
            class URL:
                def __init__(self, path_str):
                    self.path = path_str
            self.url = URL(path)
            self.state = MagicMock() # To allow setting request.state.subject

    async def dummy_call_next(request: Request) -> Response:
        return Response("OK", status_code=200)

    public_paths = {"/public/exact", "/public/with_trailing_slash/"}
    middleware = AphelionFastAPIMiddleware(app=MagicMock(ASGIApp), public_paths=public_paths)

    # Test exact match
    req_public_exact = DummyRequest("/public/exact")
    # dispatch is async, so this test would need to be async or use a sync wrapper if testing dispatch directly.
    # For now, just conceptually testing the set lookup.
    assert req_public_exact.url.path in middleware.public_paths

    # Test non-match
    req_protected = DummyRequest("/protected/path")
    assert req_protected.url.path not in middleware.public_paths

    # Test trailing slash sensitivity (sets are exact)
    req_public_no_slash = DummyRequest("/public/with_trailing_slash") # No trailing slash
    assert req_public_no_slash.url.path not in middleware.public_paths # Should fail if set has slash

    req_public_with_slash = DummyRequest("/public/with_trailing_slash/")
    assert req_public_with_slash.url.path in middleware.public_paths

# TODO: Add tests for Casbin integration into middleware when that part is implemented.
# For example, a path might be authenticated but then require specific permissions.
