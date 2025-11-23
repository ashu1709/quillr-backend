# app/routers/auth.py

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.db.session import get_session
from app.db.models import User
from app.utils.auth import create_jwt, verify_token
import os
from urllib.parse import urlencode
import requests

router = APIRouter()

# ------------------------------
# ENVIRONMENT VARIABLES
# ------------------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BACKEND_URL = os.getenv("BACKEND_URL")  # e.g. https://quillr-backend.onrender.com
FRONTEND_URL = os.getenv("FRONTEND_URL")  # e.g. https://quillr-frontend-zeta.vercel.app

# Validate
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in environment")

if not BACKEND_URL or not FRONTEND_URL:
    raise RuntimeError("Missing BACKEND_URL or FRONTEND_URL in environment")


# ------------------------------------------------------
# STEP 1 — Redirect user to Google OAuth login
# ------------------------------------------------------
@router.get("/google/login")
def google_login():
    redirect_uri = f"{BACKEND_URL}/auth/google/callback"

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }

    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    )

    return RedirectResponse(google_auth_url)


# ------------------------------------------------------
# STEP 2 — Google redirects here with the ?code=
# ------------------------------------------------------
@router.get("/google/callback")
def google_callback(request: Request, session: Session = Depends(get_session)):

    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")

    redirect_uri = f"{BACKEND_URL}/auth/google/callback"

    # Exchange `code` for access token
    token_data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    token_res = requests.post("https://oauth2.googleapis.com/token", data=token_data)

    if token_res.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange code")

    tokens = token_res.json()
    access_token = tokens.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access token")

    # Fetch Google User Info
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    google_id = user_info.get("sub")
    email = user_info.get("email")
    name = user_info.get("name")
    picture = user_info.get("picture")

    if not google_id or not email:
        raise HTTPException(status_code=400, detail="Invalid Google user info")

    # Check if user exists
    user = session.query(User).filter(
        (User.google_id == google_id) | (User.email == email)
    ).first()

    # Create user if not found
    if not user:
        user = User(
            google_id=google_id,
            email=email,
            name=name,
            picture=picture
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    # Generate JWT
    token = create_jwt({"user_id": user.id})

    # Redirect to frontend with HTTP-only cookie
    response = RedirectResponse(f"{FRONTEND_URL}/dashboard")

    response.set_cookie(
        key="quillr_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7 * 24 * 3600,
    )

    return response


# ------------------------------------------------------
# WHO AM I (Frontend checks session)
# ------------------------------------------------------
@router.get("/me")
def get_me(request: Request, session: Session = Depends(get_session)):

    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = verify_token(token)
    if not payload:
        return {"user": None}

    user = session.query(User).filter(User.id == payload.get("user_id")).first()

    if not user:
        return {"user": None}

    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    }
