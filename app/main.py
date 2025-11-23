# app/main.py
import os
from typing import Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from sqlmodel import Session, select, SQLModel
from dotenv import load_dotenv

from app.db.session import engine
from app.db.models import User
from app.routers import articles

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
FRONTEND_URL = os.getenv("FRONTEND_URL")
BASE_URL = os.getenv("BACKEND_URL")      # IMPORTANT: no trailing slash

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# --------------------------
# FastAPI App
# --------------------------
app = FastAPI()

# --------------------------
# CORS (correct settings)
# --------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------
# Startup: DB table creation
# --------------------------
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# --------------------------
# JWT util
# --------------------------
def create_jwt(data: dict):
    expire = datetime.utcnow() + timedelta(days=7)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        return None

# --------------------------
# GOOGLE LOGIN
# --------------------------
from authlib.integrations.starlette_client import OAuth, OAuthError

oauth = OAuth()
CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={"scope": "openid email profile"},
)

@app.get("/auth/google/login")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"  # FIXED
    return await oauth.google.authorize_redirect(request, redirect_uri)

# --------------------------
# GOOGLE CALLBACK
# --------------------------
@app.get("/auth/google/callback")
async def google_callback(request: Request):

    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        return JSONResponse({"error": "OAuth failed"}, status_code=400)

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)

    google_id = userinfo["sub"]
    email = userinfo.get("email")
    name = userinfo.get("name")
    picture = userinfo.get("picture")

    # DB store
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

    jwt_token = create_jwt({"user_id": user.id})

    # The MOST IMPORTANT PART (FIXED)
    response = RedirectResponse(url=f"{FRONTEND_URL}/dashboard")

    response.set_cookie(
        key="quillr_token",
        value=jwt_token,
        httponly=True,
        secure=True,        # REQUIRED FOR PRODUCTION
        samesite="none",    # REQUIRED FOR CROSS-SITE
        max_age=7 * 24 * 3600,
    )

    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_URL

    return response

# --------------------------
# Current User
# --------------------------
@app.get("/auth/me")
def auth_me(request: Request):
    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = verify_jwt(token)
    if not payload:
        return {"user": None}

    with Session(engine) as session:
        user = session.get(User, payload["user_id"])
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

# --------------------------
# Logout
# --------------------------
@app.post("/auth/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("quillr_token")
    return response

# --------------------------
# Routers
# --------------------------
app.include_router(articles.router, prefix="/articles")
