"""Main FastAPI application for HackX backend on Vercel."""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import requests

# Load environment variables from Vercel / .env
load_dotenv()

# Imported AFTER logging is configured so their module-level loggers work too
from api.client import db, ensure_indexes          # noqa: E402
from api.auth import (                              # noqa: E402
    create_jwt_token,
    verify_jwt_token,
    blacklist_token,
    get_google_oauth_config,
)
from api.models import User                        # noqa: E402

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="HackX Backend",
    description="MongoDB + OAuth authentication service",
    version="1.0.0",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
_frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
_extra_origins = [o.strip() for o in os.getenv("EXTRA_CORS_ORIGINS", "").split(",") if o.strip()]

ALLOWED_ORIGINS = list({
    _frontend_url,
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    *_extra_origins,
})

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ───────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: dict


class UserResponse(BaseModel):
    user: dict


# ── Auth dependency ───────────────────────────────────────────────────────────


def get_current_user(authorization: str = Header(None)):
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


# ── Email / password auth ─────────────────────────────────────────────────────


@app.post("/api/auth/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    if db is None:
        logger.error("[login] No database connection.")
        raise HTTPException(status_code=503, detail="Database unavailable")

    user = User.find_by_email(credentials.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("password"):
        raise HTTPException(status_code=401, detail="This account uses Google Sign-In")
    if not User.verify_password(user["password"], credentials.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_jwt_token(
        user["_id"], user["email"], user["subscription_level"], user["auth_provider"]
    )
    return LoginResponse(token=token, user=User.user_to_dict(user))


@app.post("/api/auth/signup", response_model=LoginResponse)
async def signup(credentials: SignupRequest):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    existing = User.find_by_email(credentials.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User.create_user(
        email=credentials.email,
        password=credentials.password,
        subscription_level="free",
        auth_provider="local",
    )
    token = create_jwt_token(
        user["_id"], user["email"], user["subscription_level"], user["auth_provider"]
    )
    return LoginResponse(token=token, user=User.user_to_dict(user))


@app.post("/api/auth/logout")
async def logout(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    token = authorization.split(" ")[-1]
    blacklist_token(token)
    return {"message": "Logged out successfully"}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    user = User.find_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(user=User.user_to_dict(user))


# ── Google OAuth ──────────────────────────────────────────────────────────────


@app.get("/api/auth/google")
async def google_oauth_login():
    config = get_google_oauth_config()

    if not config["client_id"]:
        logger.error("[google_oauth_login] GOOGLE_CLIENT_ID not set.")
        raise HTTPException(status_code=500, detail="Google OAuth not configured — GOOGLE_CLIENT_ID missing")
    if not config["client_secret"]:
        logger.error("[google_oauth_login] GOOGLE_CLIENT_SECRET not set.")
        raise HTTPException(status_code=500, detail="Google OAuth not configured — GOOGLE_CLIENT_SECRET missing")

    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + "&".join(
        f"{k}={v}" for k, v in params.items()
    )
    return RedirectResponse(url=auth_url)


@app.get("/api/auth/google/callback")
async def google_oauth_callback(code: str = None, error: str = None):
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="No authorization code received")

    config = get_google_oauth_config()

    # Exchange code → tokens
    try:
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "redirect_uri": config["redirect_uri"],
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
        token_response.raise_for_status()
        token_json = token_response.json()
    except requests.exceptions.HTTPError as exc:
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {exc}")
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {exc}")

    access_token = token_json.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Failed to obtain access token")

    # Fetch user info from Google
    try:
        userinfo_response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_response.raise_for_status()
        userinfo = userinfo_response.json()
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user info: {exc}")

    email = userinfo.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from Google")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # Find or create user
    user = User.find_by_email(email)
    if not user:
        user = User.create_user(email=email, password=None, subscription_level="free", auth_provider="google")

    jwt_token = create_jwt_token(
        user["_id"], user["email"], user["subscription_level"], user["auth_provider"]
    )

    # Redirect to frontend root with token — main.jsx intercepts it synchronously
    base = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    redirect_url = f"{base}?token={jwt_token}"
    return RedirectResponse(url=redirect_url)


# ── Token refresh ─────────────────────────────────────────────────────────────


@app.post("/api/auth/refresh-token", response_model=LoginResponse)
async def refresh_token(current_user: dict = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    user = User.find_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_token = create_jwt_token(
        user["_id"], user["email"], user["subscription_level"], user["auth_provider"]
    )
    return LoginResponse(token=new_token, user=User.user_to_dict(user))


# ── Health / startup ──────────────────────────────────────────────────────────


@app.on_event("startup")
def startup():
    """Best-effort index creation on cold start. Never crashes the function."""
    try:
        ensure_indexes()
    except Exception:
        pass


@app.get("/api/health")
def health():
    db_ok = db is not None
    return {
        "status": "ok",
        "message": "HackX backend is running",
        "db_connected": db_ok,
        "frontend_url": os.getenv("FRONTEND_URL", "NOT SET"),
        "google_client_id_set": bool(os.getenv("GOOGLE_CLIENT_ID")),
        "google_redirect_uri": os.getenv("GOOGLE_REDIRECT_URI", "NOT SET"),
    }


@app.get("/api")
def root():
    return {"message": "HackX API", "docs": "/docs"}

# Vercel natively serves the `app` instance.
