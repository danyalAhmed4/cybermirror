"""Runnable entry point for CyberMirror."""
import os

from app import create_app
from app.config import Config

app = create_app()

if __name__ == "__main__":
    # Default off: watchdog reloader was serving stale detector code during eval.
    # Set FLASK_DEBUG=1 only when actively developing (still disables reloader).
    debug = os.getenv("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes", "on")
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=debug,
        use_reloader=False,
    )
