from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from .models import Note
from . import db
from .security import encrypt_text, decrypt_text, log_action

notes_bp = Blueprint("notes", __name__)


@notes_bp.route("/")
def home():
    return redirect(url_for("notes.dashboard"))


@notes_bp.route("/dashboard")
@login_required
def dashboard():
    notes = (
        Note.query
        .filter_by(user_id=current_user.id)
        .order_by(Note.updated_at.desc())
        .all()
    )

    # Decrypt note contents for display
    secret = current_app.config["SECRET_KEY"]
    for n in notes:
        try:
            n.content = decrypt_text(secret, n.content)
        except:
            # If a note was created before encryption was enabled, it may not decrypt.
            pass

    return render_template("dashboard.html", notes=notes)


@notes_bp.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Title and content are required.")
            return redirect(url_for("notes.new_note"))

        if len(title) > 120:
            flash("Title must be 120 characters or less.")
            return redirect(url_for("notes.new_note"))

        # Encrypt before saving
        secret = current_app.config["SECRET_KEY"]
        encrypted = encrypt_text(secret, content)

        note = Note(user_id=current_user.id, title=title, content=encrypted)
        db.session.add(note)
        db.session.commit()
        log_action("created note")

        return redirect(url_for("notes.dashboard"))

    return render_template("note_form.html", mode="Create", note=None)


def _get_user_note_or_404(note_id: int) -> Note:
    note = Note.query.get(note_id)
    if note is None:
        abort(404)
    if note.user_id != current_user.id:
        abort(403)  # security: cannot access others' notes
    return note


@notes_bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = _get_user_note_or_404(note_id)
    secret = current_app.config["SECRET_KEY"]

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("Title and content are required.")
            return redirect(url_for("notes.edit_note", note_id=note_id))

        if len(title) > 120:
            flash("Title must be 120 characters or less.")
            return redirect(url_for("notes.edit_note", note_id=note_id))

        note.title = title
        note.content = encrypt_text(secret, content)
        db.session.commit()
        log_action("edited note")

        return redirect(url_for("notes.dashboard"))

    # Decrypt before showing in form
    try:
        note.content = decrypt_text(secret, note.content)
    except:
        pass

    return render_template("note_form.html", mode="Edit", note=note)


@notes_bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    note = _get_user_note_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    log_action("deleted note")
    return redirect(url_for("notes.dashboard"))
