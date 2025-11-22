# app/routers/articles.py

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session, select
from datetime import datetime

from app.db.session import get_session
from app.db.models import Article
from app.utils.auth import get_current_user_id

router = APIRouter()


# ------------------------------
# Fetch all articles of logged-in user
# ------------------------------
@router.get("/me/all")
def get_my_articles(request: Request, session: Session = Depends(get_session)):
    user_id = get_current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    query = select(Article).where(Article.author_id == user_id)
    articles = session.exec(query).all()

    return {"articles": articles}


# ------------------------------
# Create new article
# ------------------------------
@router.post("/")
def create_article(
    data: dict,
    request: Request,
    session: Session = Depends(get_session)
):
    user_id = get_current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    title = data.get("title")
    content = data.get("content")
    cover_image = data.get("cover_image")  # optional

    if not title or not content:
        raise HTTPException(status_code=400, detail="Title and content required")

    article = Article(
        title=title,
        content=content,
        cover_image=cover_image,
        author_id=user_id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    session.add(article)
    session.commit()
    session.refresh(article)

    return {"success": True, "article": article}


# ------------------------------
# Fetch single article + auto-increment views
# ------------------------------
@router.get("/{article_id}")
def get_article(article_id: int, session: Session = Depends(get_session)):
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Increment views + update timestamp
    article.views += 1
    article.last_viewed_at = datetime.utcnow()
    session.add(article)
    session.commit()
    session.refresh(article)

    return article


# ------------------------------
# Trending Articles (Top 10)
# Weighted by: views + likes + created_at
# ------------------------------
@router.get("/trending")
def get_trending_articles(session: Session = Depends(get_session)):
    statement = (
        select(Article)
        .order_by(
            Article.views.desc(),
            Article.likes.desc(),
            Article.created_at.desc()
        )
        .limit(10)
    )

    trending = session.exec(statement).all()
    return {"trending": trending}


# ------------------------------
# Like an Article
# ------------------------------
@router.post("/{article_id}/like")
def like_article(article_id: int, session: Session = Depends(get_session)):
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    article.likes += 1
    session.add(article)
    session.commit()
    session.refresh(article)

    return {"success": True, "likes": article.likes}

# ------------------------------
# Update Article
# ------------------------------
@router.put("/{article_id}")
def update_article(article_id: int, data: dict, request: Request, session: Session = Depends(get_session)):
    user_id = get_current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    # User cannot update others' articles
    if article.author_id != user_id:
        raise HTTPException(status_code=403, detail="Not allowed")

    title = data.get("title")
    content = data.get("content")

    if not title or not content:
        raise HTTPException(status_code=400, detail="Title and content required")

    article.title = title
    article.content = content
    article.updated_at = datetime.utcnow()

    session.add(article)
    session.commit()
    session.refresh(article)

    return {"success": True, "article": article}
