# ==========================================
# main.py — FINAL WORKING VERSION
# ==========================================

import os
from typing import Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from jose import jwt, JWTError
from authlib.integrations.starlette_client import OAuth, OAuthError
from sqlmodel import Session, select, SQLModel
from dotenv import load_dotenv

# DB imports
from app.db.session import engine
from app.db.models import User
from app.routers import articles

# Load env
load_dotenv()

# ==================================================
# ENV VARIABLES (REQUIRED)
# ==================================================
SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# IMPORTANT — THESE MUST MATCH RENDER & VERCEL
BASE_URL = os.getenv("BASE_URL", "https://quillr-backend.onrender.com")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://quillr-frontend-zeta.vercel.app")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY missing in environment!")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Google OAuth credentials missing")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7     # 7 days

# ==================================================
# OAUTH CONFIG
# ==================================================
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ==================================================
# FASTAPI APP
# ==================================================
app = FastAPI(title="Quillr API")

# Session middleware required for Authlib
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="quillr_session",
    same_site="lax",
    https_only=False,
)

# CORS (ONLY allow frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(articles.router, prefix="/articles", tags=["Articles"])

# Create DB tables at startup
@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)

# ==================================================
# JWT HELPERS
# ==================================================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ==================================================
# GOOGLE LOGIN
# ==================================================
@app.get("/auth/google/login")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

# ==================================================
# GOOGLE CALLBACK
# ==================================================
@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return JSONResponse({"error": "OAuth error", "detail": str(e)}, status_code=400)

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)

    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name")
    picture = userinfo.get("picture")

    if not google_id:
        return JSONResponse({"error": "Google profile missing"}, status_code=400)

    # Save user to DB
    with Session(engine) as session:
        user = session.exec(select(User).where(User.google_id == google_id)).first()
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

    # Create JWT
    access_token = create_access_token({"user_id": user.id})

    # Set cookie — MUST BE SECURE + NONE FOR VERCEL
    response = RedirectResponse(url=f"{FRONTEND_URL}/dashboard")
    response.set_cookie(
        key="quillr_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=7 * 24 * 3600,
    )
    return response

# ==================================================
# WHO AM I
# ==================================================
@app.get("/auth/me")
def auth_me(request: Request):
    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = verify_token(token)
    if not payload:
        return {"user": None}

    user_id = payload.get("user_id")
    if not user_id:
        return {"user": None}

    with Session(engine) as session:
        user = session.get(User, user_id)
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

# ==================================================
# LOGOUT
# ==================================================
@app.post("/auth/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("quillr_token")
    return response

# ==================================================
# USER ARTICLES (Optional)
# ==================================================
@app.get("/api/me/articles")
def my_articles(request: Request):
    token = request.cookies.get("quillr_token")
    payload = verify_token(token) if token else None

    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {"articles": [], "user_id": payload["user_id"]}

# ==================================================
# END OF FILE
# ==================================================
