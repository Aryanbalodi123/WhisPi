#!/usr/bin/env python3

import os
import logging
from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.secret_key = os.urandom(32)

    # Flask compatibility fix
    if not hasattr(Flask, "ensure_sync"):
        def ensure_sync(self, fn):
            return fn
        Flask.ensure_sync = ensure_sync
    
    # Configure CORS
    CORS(app, supports_credentials=True)
    
    # Configure Flask-Session with security improvements
    app.config.update(
        SESSION_TYPE='filesystem',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true',
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_PERMANENT=True,
        SESSION_USE_SIGNER=True,
        SESSION_FILE_DIR=os.getenv('SESSION_FILE_DIR', '/tmp/flask_session'),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
    )
    
    # Initialize session
    Session(app)
    
    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
        headers_enabled=True
    )
    
    # Store limiter in app context for use in routes
    app.limiter = limiter
    
    # Initialize database
    from app.database import init_database, cleanup_expired_sessions
    init_database()
    cleanup_expired_sessions()
    
    # Register blueprints
    from app.routes.pages import pages_bp
    from app.routes.auth import auth_bp  
    from app.routes.chat import chat_bp
    
    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        from flask import jsonify
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        from flask import jsonify
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(423)
    def locked(error):
        from flask import jsonify
        return jsonify({"error": "Account locked"}), 423

    @app.errorhandler(429)
    def rate_limit_handler(e):
        from flask import jsonify
        return jsonify({"error": "Rate limit exceeded", "message": str(e.description)}), 429

    @app.errorhandler(500)
    def internal_error(error):
        from flask import jsonify
        return jsonify({"error": "Internal server error"}), 500
    
    return app

def main():
    """Main entry point."""
    # Check for required files
    private_key_path = os.getenv('PRIVATE_KEY_PATH', 'private.pem')
    public_key_path = os.getenv('PUBLIC_KEY_PATH', 'public.pem')
    required_files = [private_key_path, public_key_path]
    
    for file in required_files:
        if not os.path.exists(file):
            print(f"ERROR: {file} not found. Please generate your RSA key pair first.")
            exit(1)
    
    # Ensure session directory exists
    session_dir = os.getenv('SESSION_FILE_DIR', '/tmp/flask_session')
    os.makedirs(session_dir, exist_ok=True)
    
    # Create Flask app
    app = create_app()
    
    # Get SSL configuration from environment variables
    ssl_cert = os.getenv('SSL_CERT_PATH', '/home/pi/certs/whispi.secure.pem')
    ssl_key = os.getenv('SSL_KEY_PATH', '/home/pi/certs/whispi.secure-key.pem')
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '443'))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Run server with SSL
    app.run(
        host=host,
        port=port,
        ssl_context=(ssl_cert, ssl_key),
        debug=debug
    )

if __name__ == "__main__":
    main()