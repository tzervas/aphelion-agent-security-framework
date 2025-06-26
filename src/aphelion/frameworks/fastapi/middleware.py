# src/aphelion/frameworks/fastapi/middleware.py

from typing import Optional, Any, Callable, Awaitable

from typing import Callable, Awaitable # Added for direct type hint

from fastapi import HTTPException, Depends
# Using starlette's own Request and Response for type hinting call_next
from starlette.requests import Request
from starlette.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


from aphelion.auth.jwt import (
    validate_token as validate_aphelion_token,
    InvalidTokenError,
    ExpiredTokenError,
    MissingTokenError
)
# from aphelion.authz.casbin_enforcer import enforce as aphelion_casbin_enforce # For later

# --- Bearer Token Scheme ---
# This can be used as a dependency in path operations for more granular control if needed,
# but the middleware will handle global auth.
bearer_scheme = HTTPBearer(auto_error=False) # auto_error=False to handle errors in middleware

# --- Subject Retriever for Path Operations ---
async def get_current_subject(request: Request) -> Any:
    """
    FastAPI dependency to get the authenticated subject from request.state.
    This should be used in path operations that are protected by the middleware.
    Returns the subject (e.g., user_id) if authentication was successful.
    Raises HTTPException if the subject is not available (shouldn't happen if middleware is effective).
    """
    if not hasattr(request.state, "subject") or request.state.subject is None:
        # This case should ideally be prevented by the middleware denying access earlier.
        # If this is reached, it implies a route was accessed without proper auth by middleware.
        raise HTTPException(
            status_code=401,
            detail="Not authenticated or subject not available in request state."
        )
    return request.state.subject

class AphelionFastAPIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for Aphelion security.
    Handles JWT authentication. Authorization can be added later or handled by dependencies.
    """
    def __init__(
        self,
        app: ASGIApp,
        public_paths: Optional[set[str]] = None, # Paths that do not require authentication
        # authz_enforcer: Optional[Callable] = None # Placeholder for Casbin enforcer integration
    ):
        super().__init__(app)
        self.public_paths = public_paths if public_paths is not None else set()
        # self.authz_enforcer = authz_enforcer # Store if/when Casbin is integrated here

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.subject = None # Initialize subject in request state

        # Check if the current path is public
        if request.url.path in self.public_paths:
            response = await call_next(request)
            return response

        # Try to get the token using FastAPI's HTTPBearer logic manually
        auth_header: Optional[HTTPAuthorizationCredentials] = await bearer_scheme(request)

        token: Optional[str] = None
        if auth_header:
            token = auth_header.credentials

        if not token:
            # You could return a JSONResponse directly here, or raise HTTPException
            # which would then be handled by FastAPI's exception handlers.
            # For consistency with how FastAPI handles dependencies, HTTPException is often used.
            # However, middleware often returns Response objects directly.
            # Let's return a Response for now.
            return Response("Not authenticated: Token missing.", status_code=401, media_type="text/plain")

        try:
            payload = validate_aphelion_token(token, expected_token_type="access")
            subject = payload.get("sub")
            if not subject:
                # This should ideally be caught by validate_aphelion_token if 'sub' is required
                return Response("Not authenticated: Subject missing in token.", status_code=401, media_type="text/plain")

            request.state.subject = subject # Store subject for access in path operations
            # request.state.token_payload = payload # Optionally store full payload

            # --- Placeholder for Casbin authorization ---
            # if self.authz_enforcer:
            #     # Example: Define obj and act based on request, or use a separate dependency
            #     # This is a simplified example; real obj/act would be more context-aware.
            #     obj = request.url.path
            #     act = request.method.lower()
            #     if not self.authz_enforcer(subject, obj, act):
            #         return Response(f"Forbidden: Subject '{subject}' not authorized for {act} on {obj}.",
            #                         status_code=403, media_type="text/plain")
            # --- End Placeholder ---

        except MissingTokenError: # Should be caught by the `if not token:` above
             return Response("Not authenticated: Token missing.", status_code=401, media_type="text/plain")
        except ExpiredTokenError:
            return Response("Not authenticated: Token has expired.", status_code=401, media_type="text/plain")
        except InvalidTokenError as e:
            # print(f"DEBUG MIDDLEWARE: Caught InvalidTokenError: {type(e)}, {str(e)}") # DEBUG
            return Response(f"Not authenticated: Token is invalid. {str(e)}", status_code=401, media_type="text/plain")
        except Exception as ex_generic: # Catch any other unexpected errors during token validation
            # print(f"DEBUG MIDDLEWARE: Caught generic Exception: {type(ex_generic)}, {str(ex_generic)}") # DEBUG
            # Log the exception here
            return Response("Internal server error during authentication.", status_code=500, media_type="text/plain")

        response = await call_next(request)
        return response


# Example usage (illustrative, real app setup would be in a main.py)
if __name__ == "__main__":
    from fastapi import FastAPI
    import uvicorn
    from aphelion.auth.jwt import create_access_token # For generating test tokens
    from aphelion.config import get_config # Ensure config is loaded for JWT

    # Ensure JWT config is loaded (uses defaults if no files/env vars)
    jwt_cfg = get_config().jwt
    print(f"Middleware example using JWT Secret: {jwt_cfg.secret_key.get_secret_value()[:10]}...")

    app = FastAPI()

    # Add the middleware
    # Example public path:
    app.add_middleware(AphelionFastAPIMiddleware, public_paths={"/public", "/docs", "/openapi.json"})

    @app.get("/public")
    async def public_route():
        return {"message": "This is a public route."}

    @app.get("/protected_implicit")
    async def protected_route_implicit(request: Request):
        # Access subject directly from request.state if needed
        subject = request.state.subject if hasattr(request.state, "subject") else None
        if not subject:
             # This should not be reached if middleware is working, as it would 401.
            raise HTTPException(status_code=403, detail="Access forbidden (no subject).")
        return {"message": f"Hello, {subject}! This is a protected route (implicit subject)."}

    @app.get("/protected_explicit")
    async def protected_route_explicit(current_user: Any = Depends(get_current_subject)):
        return {"message": f"Hello, {current_user}! This is a protected route (explicit subject via Depends)."}

    @app.get("/generate_token/{user_id}")
    async def generate_test_token(user_id: str):
        # This is an insecure way to generate tokens, for testing only!
        token = create_access_token(subject=user_id, additional_claims={"role": "test_user"})
        return {"user_id": user_id, "access_token": token}

    print("To test the middleware:")
    print("1. Generate a token: GET /generate_token/your_user_id")
    print("2. Access public route: GET /public (should work without token)")
    print("3. Access protected route without token: GET /protected_implicit (should 401)")
    print("4. Access protected route with token: GET /protected_implicit (Header: 'Authorization: Bearer <your_token>')")
    print("5. Access protected route with explicit dependency: GET /protected_explicit (Header: 'Authorization: Bearer <your_token>')")

    # Note: Running this __main__ block directly will use default JWT settings
    # unless config files or environment variables are set up.
    # uvicorn.run(app, host="0.0.0.0", port=8000)
    # Commented out uvicorn.run as it blocks in this non-interactive environment.
    # To run: save this as part of the app and run `uvicorn main:app --reload` (assuming app is defined in main.py)

    pass # End of __main__ block for non-interactive execution
