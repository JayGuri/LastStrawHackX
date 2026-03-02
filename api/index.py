"""Main FastAPI application for HackX backend on Vercel."""

import logging
import os
import sys

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import requests

# ── Logging — set up early so all modules below benefit ──────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("hackx.api")
logger.info("[BOOT] api/index.py loading — Python %s", sys.version)

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

logger.info("[BOOT] All internal modules imported successfully.")

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
logger.info("[BOOT] CORS allowed origins: %s", ALLOWED_ORIGINS)

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
    logger.info("[login] Attempt for email=%s", credentials.email)
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
    logger.info("[login] Success for email=%s", credentials.email)
    return LoginResponse(token=token, user=User.user_to_dict(user))


@app.post("/api/auth/signup", response_model=LoginResponse)
async def signup(credentials: SignupRequest):
    logger.info("[signup] Attempt for email=%s", credentials.email)
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
    logger.info("[signup] Created user email=%s", credentials.email)
    return LoginResponse(token=token, user=User.user_to_dict(user))


@app.post("/api/auth/logout")
async def logout(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    token = authorization.split(" ")[-1]
    blacklist_token(token)
    logger.info("[logout] Token blacklisted.")
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
    logger.info("[google_oauth_login] Initiating OAuth redirect.")
    config = get_google_oauth_config()

    logger.debug(
        "[google_oauth_login] client_id=%s redirect_uri=%s",
        config["client_id"][:8] + "..." if config["client_id"] else "MISSING",
        config["redirect_uri"],
    )

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
    logger.info("[google_oauth_login] Redirecting to Google: %s", auth_url)
    return RedirectResponse(url=auth_url)


@app.get("/api/auth/google/callback")
async def google_oauth_callback(code: str = None, error: str = None):
    logger.info("[google_callback] Received. code=%s error=%s", bool(code), error)

    if error:
        logger.error("[google_callback] OAuth error from Google: %s", error)
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        logger.error("[google_callback] No authorization code in request.")
        raise HTTPException(status_code=400, detail="No authorization code received")

    config = get_google_oauth_config()
    logger.debug("[google_callback] redirect_uri=%s", config["redirect_uri"])

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
        logger.info("[google_callback] Token exchange successful.")
    except requests.exceptions.HTTPError as exc:
        logger.error("[google_callback] Token exchange HTTP error: %s  body=%s", exc, exc.response.text if exc.response else "")
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {exc}")
    except requests.exceptions.RequestException as exc:
        logger.exception("[google_callback] Token exchange network error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {exc}")

    access_token = token_json.get("access_token")
    if not access_token:
        logger.error("[google_callback] No access_token in token response: %s", token_json)
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
        logger.info("[google_callback] Got userinfo email=%s", userinfo.get("email"))
    except requests.exceptions.RequestException as exc:
        logger.exception("[google_callback] userinfo fetch failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch user info: {exc}")

    email = userinfo.get("email")
    if not email:
        logger.error("[google_callback] No email in userinfo response: %s", userinfo)
        raise HTTPException(status_code=400, detail="Could not retrieve email from Google")

    if db is None:
        logger.error("[google_callback] No database connection — cannot create/find user.")
        raise HTTPException(status_code=503, detail="Database unavailable")

    # Find or create user
    user = User.find_by_email(email)
    if not user:
        logger.info("[google_callback] Creating new Google user: %s", email)
        user = User.create_user(email=email, password=None, subscription_level="free", auth_provider="google")
    else:
        logger.info("[google_callback] Found existing user: %s", email)

    jwt_token = create_jwt_token(
        user["_id"], user["email"], user["subscription_level"], user["auth_provider"]
    )

    # Redirect to frontend root with token — main.jsx intercepts it synchronously
    base = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    redirect_url = f"{base}?token={jwt_token}"
    logger.info("[google_callback] Redirecting to frontend: %s", base + "?token=<jwt>")
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
    logger.info("[startup] Running startup tasks.")
    try:
        ensure_indexes()
    except Exception as exc:
        logger.warning("[startup] ensure_indexes raised (non-fatal): %s", exc)


@app.get("/api/health")
def health():
    db_ok = db is not None
    logger.info("[health] db_ok=%s", db_ok)
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
