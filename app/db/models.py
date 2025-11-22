# app/db/models.py
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    google_id: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    articles: List["Article"] = Relationship(back_populates="author")


class Article(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    content: str
    cover_image: Optional[str] = None

    # 🔥 TRENDING + ANALYTICS FIELDS
    views: int = Field(default=0)
    likes: int = Field(default=0)
    last_viewed_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    created_at: datetime = Field(default_factory=datetime.utcnow)

    author_id: int = Field(foreign_key="user.id")
    author: Optional[User] = Relationship(back_populates="articles")
