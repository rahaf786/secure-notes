from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
import bcrypt
from time import time

from .models import User
from . import db
from .security import log_action

auth_bp = Blueprint("auth", __name__)

FAILED_LOGINS = {}  # {email: [timestamps]}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("auth.register"))

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("auth.register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("auth.register"))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Email already registered. Please log in.")
            return redirect(url_for("auth.login"))

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        user = User(email=email, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        log_action("register + login")

        return redirect(url_for("notes.dashboard"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        now = time()
        attempts = [t for t in FAILED_LOGINS.get(email, []) if now - t < WINDOW_SECONDS]
        FAILED_LOGINS[email] = attempts

        if len(attempts) >= MAX_ATTEMPTS:
            flash("Too many login attempts. Try again in 1 minute.")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            FAILED_LOGINS[email].append(now)
            flash("Invalid email or password.")
            return redirect(url_for("auth.login"))

        ok = bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8"))
        if not ok:
            FAILED_LOGINS[email].append(now)
            flash("Invalid email or password.")
            return redirect(url_for("auth.login"))

        # success
        FAILED_LOGINS.pop(email, None)
        login_user(user)
        log_action("login")

        return redirect(url_for("notes.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_action("logout")
    logout_user()
    return redirect(url_for("auth.login"))
