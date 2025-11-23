# app/main.py
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

# PostgreSQL engine & models from your db package
from app.db.session import engine
from app.db.models import User  # <- use model defined in app/db/models.py
from app.routers import articles

load_dotenv()

# ===============================
# CONFIG
# ===============================
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-please-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://quillr-frontend-zeta.vercel.app")
BASE_URL = os.getenv("BASE_URL", "https://quillr-backend.onrender.com/")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env")

# ===============================
# OAUTH SETUP
# ===============================
oauth = OAuth()
CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={"scope": "openid email profile"},
)

# ===============================
# FASTAPI INIT
# ===============================
app = FastAPI(title="Quillr API")

# Sessions for Authlib (must be installed before routes that use oauth)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="quillr_session",
    same_site="lax",
    https_only=False,
)

# CORS
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
def on_startup():
    # Create tables (based on models in app.db.models)
    SQLModel.metadata.create_all(engine)


# ===============================
# TOKEN UTILS
# ===============================
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


# ===============================
# GOOGLE LOGIN / CALLBACK
# ===============================
@app.get("/auth/google/login")
async def google_login(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return JSONResponse({"error": "OAuth error", "detail": str(e)}, status_code=400)

    # token may include id_token or userinfo
    userinfo = token.get("userinfo")
    if not userinfo:
        # parse id token if userinfo not present
        userinfo = await oauth.google.parse_id_token(request, token)

    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name")
    picture = userinfo.get("picture")

    if not google_id:
        return JSONResponse({"error": "No google id returned"}, status_code=400)

    # Store or get user in PostgreSQL
    with Session(engine) as session:
        statement = select(User).where(User.google_id == google_id)
        user = session.exec(statement).first()

        if not user:
            user = User(google_id=google_id, email=email, name=name, picture=picture)
            session.add(user)
            session.commit()
            session.refresh(user)

    # Create JWT
    token_data = {"user_id": user.id, "email": user.email}
    access_token = create_access_token(token_data)

    # Set cookie and redirect to frontend dashboard
    response = RedirectResponse(url=f"{FRONTEND_URL}/dashboard")
    response.set_cookie(
        key="quillr_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response


# ===============================
# AUTH CHECK
# ===============================
@app.get("/auth/me")
def auth_me(request: Request):
    token = request.cookies.get("quillr_token")
    if not token:
        return {"user": None}

    payload = verify_token(token)
    if not payload:
        response = JSONResponse({"user": None})
        response.delete_cookie("quillr_token")
        return response

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
                "picture": user.picture,
            }
        }


# ===============================
# LOGOUT
# ===============================
@app.post("/auth/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("quillr_token")
    return response


# ===============================
# USER'S ARTICLES (placeholder)
# ===============================
@app.get("/api/me/articles")
def my_articles(request: Request):
    token = request.cookies.get("quillr_token")
    payload = verify_token(token) if token else None
    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {"articles": [], "user_id": payload.get("user_id")}
