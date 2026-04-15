"""
QuShield-PnB Database Setup

SQLAlchemy engine, session factory, Base class, and dependency injection.
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from typing import Generator

from app.config import settings


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,           # Increased for production load
    max_overflow=20,        # Increased for burst traffic
    pool_timeout=30,        # Wait up to 30 seconds for a connection
    pool_recycle=1800,      # Recycle connections after 30 minutes (prevent stale connections)
    pool_use_lifo=True,     # LIFO pattern for better connection reuse
    echo=False,             # Set True to see SQL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a DB session, auto-closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> list[str]:
    """
    Create all tables defined in models (dev only).
    Returns list of table names created.
    """
    from app.models import Base  # noqa: ensure all models are imported
    Base.metadata.create_all(bind=engine)
    return list(Base.metadata.tables.keys())


def check_connection() -> bool:
    """Test database connectivity. Returns True if connection succeeds."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
