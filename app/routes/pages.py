import os
from flask import Blueprint, send_from_directory, current_app , send_file

pages_bp = Blueprint('pages', __name__)

@pages_bp.route("/")
def home():

    current_app.limiter.limit("10 per minute")(lambda: None)()
    return send_from_directory("static", "login.html")

@pages_bp.route("/chat.html")
def chat():

    current_app.limiter.limit("10 per minute")(lambda: None)()
    return send_from_directory("static", "chat.html")

@pages_bp.route("/policy.html")
def chat():

    current_app.limiter.limit("100 per minute")(lambda: None)()
    return send_from_directory("static", "policy.html")

@pages_bp.route("/get_public_key")
def get_public_key():

    current_app.limiter.limit("20 per minute")(lambda: None)()
    public_key_path = os.getenv('PUBLIC_KEY_PATH', '/home/pi/certs/public.pem')
    return send_file(public_key_path, mimetype='application/octet-stream')