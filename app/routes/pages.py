"""
Static page routes for WhisPI application.
"""

import os
from flask import Blueprint, send_from_directory, current_app

pages_bp = Blueprint('pages', __name__)

@pages_bp.route("/")
def home():
    """Serve main page."""
    current_app.limiter.limit("10 per minute")(lambda: None)()
    return send_from_directory("static", "index.html")

@pages_bp.route("/chat.html")
def chat():
    """Serve chat page."""
    current_app.limiter.limit("10 per minute")(lambda: None)()
    return send_from_directory("static", "chat.html")

@pages_bp.route("/get_public_key")
def get_public_key():
    """Serve server's public key."""
    current_app.limiter.limit("20 per minute")(lambda: None)()
    public_key_path = os.getenv('PUBLIC_KEY_PATH', 'public.pem')
    return send_from_directory(".", public_key_path)