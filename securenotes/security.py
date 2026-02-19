from cryptography.fernet import Fernet
import base64
import os
from . import db
from .models import AuditLog
from flask_login import current_user

# Derive a stable key from the app secret
def _get_key(secret: str) -> bytes:
    key = secret.encode("utf-8")
    key = key.ljust(32, b"0")[:32]  # ensure 32 bytes
    return base64.urlsafe_b64encode(key)

def get_cipher(secret_key: str):
    return Fernet(_get_key(secret_key))

def encrypt_text(secret_key: str, text: str) -> str:
    cipher = get_cipher(secret_key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(secret_key: str, token: str) -> str:
    cipher = get_cipher(secret_key)
    return cipher.decrypt(token.encode()).decode()

def log_action(action: str):
    if current_user.is_authenticated:
        entry = AuditLog(user_id=current_user.id, action=action)
        db.session.add(entry)
        db.session.commit()