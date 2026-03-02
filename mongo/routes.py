"""Authentication routes for login, logout, OAuth, and token refresh."""

import os
import requests
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from mongo.models import User
from mongo.auth import (
    create_jwt_token,
    verify_jwt_token,
    blacklist_token,
    get_google_oauth_config,
)

router = APIRouter()


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    """Login request schema."""
    email: str
    password: str


class SignupRequest(BaseModel):
    """Signup request schema."""
    email: str
    password: str
    subscription_level: str = "free"


class LoginResponse(BaseModel):
    """Login response schema."""
    token: str
    user: dict


class UserResponse(BaseModel):
    """User response schema."""
    user: dict


# ──────────────────────────────────────────────────────────────────────────────
# Dependency: Get current user from token
# ──────────────────────────────────────────────────────────────────────────────


def get_current_user(authorization: str = Header(None)):
    """Extract and verify JWT from Authorization header.

    Args:
        authorization: Authorization header (Bearer <token>)

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is missing or invalid
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")

    payload = verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL/PASSWORD AUTHENTICATION
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/signup", response_model=LoginResponse)
async def signup(credentials: SignupRequest):
    """Create a new user.

    Args:
        credentials: Email and password

    Returns:
        JWT token and user info

    Raises:
        HTTPException: If user already exists
    """
    # Check if user already exists
    existing_user = User.find_by_email(credentials.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    user = User.create_user(
        email=credentials.email,
        password=credentials.password,
        subscription_level=credentials.subscription_level,
    )

    # Create JWT token
    token = create_jwt_token(
        user["_id"],
        user["email"],
        user["subscription_level"],
        user["auth_provider"],
    )

    return LoginResponse(
        token=token,
        user=User.user_to_dict(user),
    )


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """Login with email and password.

    Args:
        credentials: Email and password

    Returns:
        JWT token and user info

    Raises:
        HTTPException: If credentials are invalid
    """
    # Find user by email
    user = User.find_by_email(credentials.email)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Check if password is None (e.g., Google OAuth account)
    if not user.get("password"):
        raise HTTPException(status_code=401, detail="This account uses Google Sign-In")

    # Verify password
    if not User.verify_password(user["password"], credentials.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Create JWT token
    token = create_jwt_token(
        user["_id"],
        user["email"],
        user["subscription_level"],
        user["auth_provider"],
    )

    return LoginResponse(
        token=token,
        user=User.user_to_dict(user),
    )


@router.post("/logout")
async def logout(authorization: str = Header(None)):
    """Logout and blacklist the current token.

    Args:
        authorization: Authorization header

    Returns:
        Success message
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.split(" ")[-1]
    blacklist_token(token)

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info.

    Args:
        current_user: Current authenticated user

    Returns:
        User info

    Raises:
        HTTPException: If user not found
    """
    user_id = current_user["user_id"]
    user = User.find_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(user=User.user_to_dict(user))


# ──────────────────────────────────────────────────────────────────────────────
# GOOGLE OAUTH
# ──────────────────────────────────────────────────────────────────────────────


@router.get("/google")
async def google_oauth_login():
    """Redirect to Google's OAuth consent screen.

    This initiates the Google OAuth 2.0 flow.
    """
    config = get_google_oauth_config()

    if not config["client_id"]:
        raise HTTPException(status_code=400, detail="Google OAuth not configured")

    # Google authorization endpoint
    google_auth_uri = "https://accounts.google.com/o/oauth2/v2/auth"

    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
    }

    # Build the authorization URL
    auth_url = f"{google_auth_uri}?"
    auth_url += "&".join([f"{key}={value}" for key, value in params.items()])

    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_oauth_callback(code: str = None, error: str = None):
    """Handle Google OAuth callback.

    Exchanges authorization code for tokens, creates/finds user, and returns JWT.

    Args:
        code: Authorization code from Google
        error: Error message if authorization failed

    Returns:
        Redirect to frontend with token

    Raises:
        HTTPException: If OAuth flow fails
    """
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="No authorization code received")

    config = get_google_oauth_config()

    # Exchange authorization code for access token
    token_endpoint = "https://oauth2.googleapis.com/token"

    token_data = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "redirect_uri": config["redirect_uri"],
        "grant_type": "authorization_code",
    }

    try:
        token_response = requests.post(token_endpoint, data=token_data, timeout=10)
        token_response.raise_for_status()
        token_json = token_response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to exchange token: {str(e)}")

    access_token = token_json.get("access_token")

    if not access_token:
        raise HTTPException(status_code=500, detail="Failed to obtain access token")

    # Fetch user info from Google
    userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"

    try:
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_response.raise_for_status()
        userinfo = userinfo_response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user info: {str(e)}")

    email = userinfo.get("email")

    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from Google")

    # Find or create user
    user = User.find_by_email(email)

    if not user:
        # Create new user with Google provider
        user = User.create_user(
            email=email,
            password=None,  # No password for Google users
            subscription_level="free",
            auth_provider="google",
        )

    # Create JWT token
    token = create_jwt_token(
        user["_id"],
        user["email"],
        user["subscription_level"],
        user["auth_provider"],
    )

    # Redirect to frontend with token.
    # NOTE: We always redirect to the root URL (?token=...) so the pre-mount
    # interception in frontend/src/main.jsx can catch it synchronously before
    # React renders, regardless of which environment is running.
    base = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    redirect_url = f"{base}?token={token}"

    return RedirectResponse(url=redirect_url)


@router.post("/refresh-token", response_model=LoginResponse)
async def refresh_token(current_user: dict = Depends(get_current_user)):
    """Refresh an expired or soon-to-expire token.

    Args:
        current_user: Current authenticated user

    Returns:
        New JWT token and user info

    Raises:
        HTTPException: If user not found
    """
    user_id = current_user["user_id"]
    user = User.find_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create new token
    new_token = create_jwt_token(
        user["_id"],
        user["email"],
        user["subscription_level"],
        user["auth_provider"],
    )

    return LoginResponse(
        token=new_token,
        user=User.user_to_dict(user),
    )
