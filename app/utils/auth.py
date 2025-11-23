# app/utils/auth.py
import os
from typing import Optional, Dict
from fastapi import Request
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

# Secret key & algorithm
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-please-change")
ALGORITHM = "HS256"


# ----------------------------------------------------
# CREATE JWT
# ----------------------------------------------------
def create_jwt(data: Dict) -> str:
    """
    Create and return a signed JWT token.
    """
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# ----------------------------------------------------
# VERIFY TOKEN
# ----------------------------------------------------
def verify_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    Return decoded payload or None if invalid.
    """
    if not token:
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ----------------------------------------------------
# GET CURRENT USER ID FROM COOKIE OR HEADER
# ----------------------------------------------------
def get_current_user_id(request: Request) -> Optional[int]:
    """
    Get user_id from cookie 'quillr_token'
    If not in cookies, fallback to Authorization: Bearer <token>
    """
    token = None

    # Try HTTP-only cookie
    cookie_token = request.cookies.get("quillr_token")
    if cookie_token:
        token = cookie_token

    # Try Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        return None

    payload = verify_token(token)
    if not payload:
        return None

    return payload.get("user_id")
