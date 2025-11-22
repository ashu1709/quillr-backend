from fastapi import APIRouter
from app.routers.articles import fake_articles_db

router = APIRouter()

@router.get("/latest")
def latest_articles():
    return list(fake_articles_db.values())[::-1]
