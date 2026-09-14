"""
CloudGuard Database Module
Supports SQLite for local development and PostgreSQL for production.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# Build connect args based on DB type
connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

# PostgreSQL: fix 'postgres://' → 'postgresql://' (Render/Heroku compat)
db_url = settings.database_url
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    db_url,
    connect_args=connect_args,
    echo=settings.app_env == "development",
    # PostgreSQL connection pool settings for production
    **({"pool_size": 5, "max_overflow": 10, "pool_pre_ping": True}
       if not db_url.startswith("sqlite") else {}),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables."""
    from app import models  # noqa: F401 - import to register models
    Base.metadata.create_all(bind=engine)
