"""CyberMirror Flask application factory."""
import os
from flask import Flask

from app.config import Config


def create_app(config_class=Config):
    """Create and configure the Flask app."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )
    app.config.from_object(config_class)

    # Request logging (SQLite monitor.db); skips /static and /dashboard
    from app.monitoring.logger import init_request_logging
    from app.monitoring.detector import init_detector
    from app.monitoring.store import get_store

    store = get_store()
    init_request_logging(app)
    init_detector(app, store=store)

    # Seed runtime vulnerable-page flag from config (dashboard can toggle later)
    store.set_vulnerable_page_enabled(
        bool(app.config.get("ENABLE_VULNERABLE_PAGE", False))
    )

    # Auth routes (register / login / logout / home)
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.vulnerable import vulnerable_bp
    from viz.routes import viz_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    # Always register; route checks runtime enable flag from monitor.db
    app.register_blueprint(vulnerable_bp)
    # Attack simulation replay UI (reads local JSONL only)
    app.register_blueprint(viz_bp)

    @app.context_processor
    def _inject_lab_flags():
        return {
            "vulnerable_page_enabled": store.is_vulnerable_page_enabled(
                default=bool(app.config.get("ENABLE_VULNERABLE_PAGE", False))
            )
        }

    return app
