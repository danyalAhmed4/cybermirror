"""Register, login, logout, and protected home routes (MySQL auth only)."""
from functools import wraps

import bcrypt
import mysql.connector
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.config import Config

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    """Redirect anonymous users to the login page."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def _create_session(username):
    """Establish a Flask session after a successful login."""
    import secrets

    # When False, keep ``_cm_sid`` so fixation labs share one stable session id
    if current_app.config.get("SESSION_REGENERATE_ON_LOGIN", True):
        session.clear()
    if not session.get("_cm_sid"):
        session["_cm_sid"] = secrets.token_hex(16)
    session["logged_in"] = True
    session["username"] = username
    session.modified = True


@auth_bp.route("/")
def index():
    """Landing page."""
    return render_template("index.html")


@auth_bp.route("/home")
@login_required
def home():
    """Protected home page (requires login)."""
    from app.monitoring.store import get_store

    store = get_store()
    mode = store.get_detection_mode()
    alert_count = store.count_alerts()
    vuln_on = store.is_vulnerable_page_enabled(
        default=bool(current_app.config.get("ENABLE_VULNERABLE_PAGE", False))
    )
    return render_template(
        "home.html",
        username=session.get("username"),
        detection_mode=mode,
        alert_count=alert_count,
        vulnerable_page_enabled=vuln_on,
    )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Create a user in MySQL."""
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    if not username or not email or not password:
        flash("Registration failed. Please try again.", "error")
        return render_template("register.html"), 400

    # Hash once; never log the plaintext password
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    db = None
    cursor = None
    try:
        db = mysql.connector.connect(**Config.mysql_config())
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password),
        )
        db.commit()
    except Exception:
        flash("Registration failed. Please try again.", "error")
        return render_template("register.html"), 500
    finally:
        if cursor is not None:
            cursor.close()
        if db is not None:
            db.close()

    flash("Registration successful. You can log in now.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate against MySQL."""
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Invalid credentials.", "error")
        return render_template("login.html"), 400

    db = None
    cursor = None
    try:
        db = mysql.connector.connect(**Config.mysql_config())
        cursor = db.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = %s",
            (username,),
        )
        row = cursor.fetchone()
        if not row:
            flash("Invalid credentials.", "error")
            return render_template("login.html"), 401
        stored_password = row[0]
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")
        if not bcrypt.checkpw(password.encode("utf-8"), stored_password):
            flash("Invalid credentials.", "error")
            return render_template("login.html"), 401
        _create_session(username)
        return redirect(url_for("auth.home"))
    except Exception:
        flash("Invalid credentials.", "error")
        return render_template("login.html"), 500
    finally:
        if cursor is not None:
            cursor.close()
        if db is not None:
            db.close()


@auth_bp.route("/logout")
def logout():
    """Clear the session and return to the landing page."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.index"))
