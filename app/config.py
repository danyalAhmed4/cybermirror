"""Load app settings from environment (.env)."""
import os
from dotenv import load_dotenv

# Resolve .env next to the CyberMirror project root
_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(_BASE_DIR, ".env"), override=True)


def _as_bool(value, default=True):
    """Parse common truthy/falsey env strings."""
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Flask and lab service configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT = int(os.getenv("FLASK_PORT", "8080"))

    # Session cookie hardening + lab flag for fixation tests
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_REGENERATE_ON_LOGIN = _as_bool(
        os.getenv("SESSION_REGENERATE_ON_LOGIN"), default=True
    )

    # MySQL (OrbitMart register / login)
    MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
    MYSQL_USER = os.getenv("MYSQL_USER", "")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "")

    # Lab-only SQLi target page (isolated SQLite; never touches MySQL)
    ENABLE_VULNERABLE_PAGE = _as_bool(
        os.getenv("ENABLE_VULNERABLE_PAGE"), default=False
    )

    # Detection mode seed (OFF | MONITOR | BLOCK). Runtime value lives in monitor.db.
    DETECTION_MODE = os.getenv("DETECTION_MODE", "OFF").strip().upper()
    MODELS_DIR = os.getenv(
        "MODELS_DIR",
        os.path.join(_BASE_DIR, "models"),
    )
    SESSION_DETECT_MIN_REQUESTS = int(os.getenv("SESSION_DETECT_MIN_REQUESTS", "5"))
    # Lab-only: trust X-Forwarded-For for simulated multi-client attacks
    LAB_TRUST_FORWARDED_FOR = _as_bool(
        os.getenv("LAB_TRUST_FORWARDED_FOR"), default=False
    )

    # Runtime alert thresholds (cut false positives; tune via evaluation)
    SQLI_MIN_PROBA = float(os.getenv("SQLI_MIN_PROBA", "0.65"))
    XSS_MIN_PROBA = float(os.getenv("XSS_MIN_PROBA", "0.85"))
    SESSION_MIN_PROBA = float(os.getenv("SESSION_MIN_PROBA", "0.70"))
    XSS_MIN_TEXT_LEN = int(os.getenv("XSS_MIN_TEXT_LEN", "4"))


    # Built-in dashboard admin login
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

    @classmethod
    def mysql_config(cls):
        """Return kwargs for mysql.connector.connect()."""
        return {
            "host": cls.MYSQL_HOST,
            "user": cls.MYSQL_USER,
            "password": cls.MYSQL_PASSWORD,
            "database": cls.MYSQL_DATABASE,
        }
