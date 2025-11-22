from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class User(BaseModel):
    name: str
    email: str

@router.post("/login")
def login_user(user: User):
    return {
        "message": "User logged in",
        "user": user
    }
