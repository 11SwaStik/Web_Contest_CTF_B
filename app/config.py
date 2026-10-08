"""Application configuration.

Values come from environment variables where sensible, with safe local
defaults so the project runs unchanged after being copied to another machine.
"""
import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-not-secret-change-in-prod")

    # SQLite file path (relative → portable). Reseeded on startup.
    DB_PATH = os.environ.get(
        "DB_PATH", os.path.join(os.path.dirname(__file__), "contest.db")
    )

    # Store presentation
    STORE_NAME = "Birchwood"
    PRODUCTS_PER_PAGE = 8

    JSON_SORT_KEYS = False
