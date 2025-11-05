from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Create a single Base instance that will be used by all models
Base = declarative_base()

# Database configuration
from app.config import settings

# For SQLite (you can change this to PostgreSQL or MySQL as needed)
SQLALCHEMY_DATABASE_URL = "sqlite:///./ids.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()