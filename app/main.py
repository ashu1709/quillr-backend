# app/main.py
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from authlib.integrations.starlette_client import OAuth, OAuthError
from sqlmodel import Session, SQLModel, select

from dotenv import load_dotenv

from app.db.session import engine
from app.db.models import User

load_dotenv()

# ==========================
# ENV VARIABLES
# ==========================
SECRET_KEY = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL")
BASE_URL = os.getenv("BASE_URL")  # VERY IMPORTANT → NO TRAILING SLASH

if BASE_URL.endswith("/"):
    BASE_URL = BASE_URL[:-1]     # Auto-fix double slash issue

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ==========================
# OAUTH SETUP
# ==========================
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ==========================
# FASTAPI
# ==========================
app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB Init
@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)

# ==========================
# JWT UTILS
# ==========================
from jose import jwt, JWTError

def create_jwt(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ==========================
# GOOGLE LOGIN
# ==========================
@app.get("/auth/google/login")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

# ==========================
# GOOGLE CALLBACK
# ==========================
@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        return JSONResponse({"error": "OAuth failed"}, status_code=400)

    userinfo = token.get("userinfo")

    google_id = userinfo["sub"]
    email = userinfo["email"]
    name = userinfo["name"]
    picture = userinfo["picture"]

    with Session(engine) as db:
        q = select(User).where(User.google_id == google_id)
        user = db.exec(q).first()

        if not user:
            user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

    jwt_token = create_jwt({"user_id": user.id})

    response = RedirectResponse(f"{FRONTEND_URL}/dashboard")
    response.set_cookie(
        key="quillr_token",
        value=jwt_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return response

# ==========================
# WHO AM I
# ==========================
@app.get("/auth/me")
def auth_me(request: Request):
    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = decode_jwt(token)
    if not payload:
        return {"user": None}

    user_id = payload["user_id"]

    with Session(engine) as db:
        user = db.get(User, user_id)
        if not user:
            return {"user": None}

        return {"user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture
        }}

# ==========================
# LOGOUT
# ==========================
@app.post("/auth/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("quillr_token")
    return response
