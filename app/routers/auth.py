from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.db.session import get_session
from app.db.models import User
from app.utils.auth import create_jwt
import os
from urllib.parse import urlencode
import requests

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BACKEND_URL = os.getenv("BACKEND_URL")
FRONTEND_URL = os.getenv("FRONTEND_URL")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render Env")


# -------------------------------------------
# STEP 1 — Redirect to Google OAuth login
# -------------------------------------------
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


# -------------------------------------------
# STEP 2 — Google redirects here with `code`
# -------------------------------------------
@router.get("/google/callback")
def google_callback(request: Request, session: Session = Depends(get_session)):
    code = request.query_params.get("code")

    if not code:
        raise HTTPException(status_code=400, detail="No authorization code provided")

    token_url = "https://oauth2.googleapis.com/token"
    redirect_uri = f"{BACKEND_URL}/auth/google/callback"

    token_data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    token_response = requests.post(token_url, data=token_data).json()
    access_token = token_response.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="Failed to get access token")

    # Fetch Google profile
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    google_id = user_info.get("sub")
    email = user_info.get("email")
    name = user_info.get("name")
    picture = user_info.get("picture")

    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email")

    # Find existing user
    user = session.query(User).filter(
        (User.email == email) | (User.google_id == google_id)
    ).first()

    # Create new user if needed
    if not user:
        user = User(
            email=email,
            name=name,
            google_id=google_id,
            picture=picture
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    # Generate JWT
    token = create_jwt({"user_id": user.id})

    # Set cookie and redirect
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


# -------------------------------------------
# WHO AM I
# -------------------------------------------
@router.get("/me")
def get_me(request: Request, session: Session = Depends(get_session)):
    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = create_jwt.verify(token)
    user = session.query(User).filter(User.id == payload["user_id"]).first()

    if not user:
        return {"user": None}

    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture
        }
    }
