import os
import logging

from flask import Flask
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from redis import Redis
from werkzeug.middleware.proxy_fix import ProxyFix

def load_env_file(filepath=".env"):
    if not os.path.exists(filepath):
        return
    with open(filepath) as f:
        for line in f:
            if line.strip() == '' or line.startswith('#'):
                continue
            key, sep, value = line.strip().partition('=')
            if sep == '=':
                os.environ[key] = value

load_env_file()

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ['SECRET_KEY']

    if not hasattr(Flask, "ensure_sync"):
        def ensure_sync(self, fn):
            return fn
        Flask.ensure_sync = ensure_sync

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    CORS(app, supports_credentials=True)

    app.config.update(
        SESSION_TYPE='redis',
        SESSION_REDIS=Redis(host=os.environ['REDIS_HOST'], port=int(os.environ['REDIS_PORT'])),
        SESSION_PERMANENT=True,
        SESSION_USE_SIGNER=True,
        SESSION_KEY_PREFIX=os.environ['SESSION_KEY_PREFIX'],
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ['SESSION_LIFETIME_HOURS']))
    )   

    Session(app)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[],
        storage_uri=f"redis://{os.environ['REDIS_HOST']}:{os.environ['REDIS_PORT']}",
        headers_enabled=True
    )
    
    app.limiter = limiter

    from app.database import init_database, cleanup_expired_sessions
    init_database()
    cleanup_expired_sessions()
    
    from app.routes.pages import pages_bp
    from app.routes.auth import auth_bp  
    from app.routes.chat import chat_bp
    
    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    
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
    private_key_path = os.environ['PRIVATE_KEY_PATH']
    public_key_path = os.environ['PUBLIC_KEY_PATH']
    required_files = [private_key_path, public_key_path]
    
    for file in required_files:
        if not os.path.exists(file):
            print(f"ERROR: {file} not found. Please generate your RSA key pair first.")
            exit(1)
    
    session_dir = os.environ['SESSION_FILE_DIR']
    os.makedirs(session_dir, exist_ok=True)
    
    app = create_app()
    
    ssl_cert = os.environ['SSL_CERT_PATH']
    ssl_key = os.environ['SSL_KEY_PATH']
    host = os.environ['HOST']
    port = int(os.environ['PORT'])
    debug = os.environ['DEBUG'].lower() == 'true'
    
    app.run(
        host=host,
        port=port,
        ssl_context=(ssl_cert, ssl_key),
        debug=debug
    )

if __name__ == "__main__":
    main()
