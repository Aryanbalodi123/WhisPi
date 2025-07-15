from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os
import json
import sqlite3
import bcrypt
import base64
import logging
import time
import secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(32)

if not hasattr(Flask, "ensure_sync"):
    def ensure_sync(self, fn):
        return fn
    Flask.ensure_sync = ensure_sync
    
    
CORS(app, supports_credentials=True)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    headers_enabled=True
)

# Configure Flask-Session with security improvements
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = os.getenv('SESSION_FILE_DIR', '/tmp/flask_session')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # 24 hour session timeout

# Initialize session
Session(app)

DATABASE_PATH = os.getenv('DATABASE_PATH', 'database.db')

# Get environment variables
secret = os.getenv("PRIVATE_KEY_PASSWORD")
if not secret:
    logging.error("PRIVATE_KEY_PASSWORD not found in environment variables")
    exit(1)

def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            password TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    """)
    
    # Create messages table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            message TEXT NOT NULL,
            signature TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    """)
    
    # Create IP login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address)
        )
    """)

    
    # Check for existing columns and add if missing
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    missing_columns = [
        ('last_login', 'TIMESTAMP'),
        ('failed_login_attempts', 'INTEGER DEFAULT 0'),
        ('locked_until', 'TIMESTAMP')
    ]
    
    for col_name, col_type in missing_columns:
        if col_name not in columns:
            logging.info(f"Adding {col_name} column to users table")
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
    
    conn.commit()
    conn.close()
    logging.info("Database initialized successfully")

def get_db():
    return sqlite3.connect(DATABASE_PATH)

def validate_username(username):
    """Validate username format and constraints."""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not username.replace("_", "").replace("-", "").isalnum():
        return False, "Username can only contain letters, numbers, hyphens, and underscores"
    return True, ""

def validate_password(password):
    """Validate password format and constraints."""
    if not password:
        return False, "Password is required"
    if len(password) < 8:  # Increased minimum length
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    return True, ""

def validate_public_key(public_key):
    """Validate public key format."""
    if not public_key:
        return False, "Public key is required"
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        return False, "Invalid public key format - must be PEM format"
    if not public_key.endswith("-----END PUBLIC KEY-----"):
        return False, "Invalid public key format - must be PEM format"
    return True, ""

def is_user_locked(username):
    """Check if user account is locked due to failed login attempts."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_login_attempts, locked_until FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    failed_attempts, locked_until = result
    
    # Check if account is locked
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if datetime.now() < locked_until_dt:
            return True
    
    return False

def increment_failed_login(username):
    """Increment failed login attempts and lock account if necessary."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get current failed attempts
    cursor.execute(
        "SELECT failed_login_attempts FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    
    if result:
        failed_attempts = result[0] + 1
        locked_until = None
        
        # Lock account after 5 failed attempts for 30 minutes
        if failed_attempts >= 5:
            locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            logging.warning(f"Account locked for user: {username}")
        
        cursor.execute(
            "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE username = ?",
            (failed_attempts, locked_until, username)
        )
        conn.commit()
    
    conn.close()

def reset_failed_login(username):
    """Reset failed login attempts after successful login."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()

def create_user_session(username):
    """Create a new user session."""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO user_sessions (session_id, username, expires_at) VALUES (?, ?, ?)",
        (session_id, username, expires_at.isoformat())
    )
    conn.commit()
    conn.close()
    
    return session_id

def validate_session(session_id):
    """Validate and refresh user session."""
    if not session_id:
        return None
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT username, expires_at FROM user_sessions 
        WHERE session_id = ? AND is_active = TRUE
        """,
        (session_id,)
    )
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return None
    
    username, expires_at = result
    expires_at_dt = datetime.fromisoformat(expires_at)
    
    # Check if session is expired
    if datetime.now() > expires_at_dt:
        # Mark session as inactive
        cursor.execute(
            "UPDATE user_sessions SET is_active = FALSE WHERE session_id = ?",
            (session_id,)
        )
        conn.commit()
        conn.close()
        return None
    
    # Update last activity
    cursor.execute(
        "UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = ?",
        (session_id,)
    )
    conn.commit()
    conn.close()
    
    return username

def invalidate_session(session_id):
    """Invalidate a user session."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE user_sessions SET is_active = FALSE WHERE session_id = ?",
        (session_id,)
    )
    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    """Clean up expired sessions."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE user_sessions SET is_active = FALSE WHERE expires_at < ?",
        (datetime.now().isoformat(),)
    )
    conn.commit()
    conn.close()

def decrypt_hybrid_payload(encrypted_payload):
    """
    Decrypt hybrid encrypted payload using server's private key.
    Payload format: {encrypted_aes_key, iv, encrypted_data}
    """
    try:
        encrypted_aes_key = base64.b64decode(encrypted_payload["encrypted_aes_key"])
        iv = base64.b64decode(encrypted_payload["iv"])
        encrypted_data = base64.b64decode(encrypted_payload["encrypted_data"])
        
        # Load server's private key
        private_key_path = os.getenv('PRIVATE_KEY_PATH', 'private.pem')
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=secret.encode(), backend=default_backend()
            )
        
        # Decrypt AES key with RSA-OAEP
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with AES-GCM
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]
        cipher = Cipher(
            algorithms.AES(aes_key), 
            modes.GCM(iv, tag), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_bytes
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

def require_auth(f):
    """Decorator to require valid session authentication."""
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        username = validate_session(session_id)
        
        if not username:
            return jsonify({"error": "Authentication required"}), 401
        
        # Update session username for consistency
        session['username'] = username
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


def is_ip_locked(ip_address):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_attempts, locked_until FROM ip_login_attempts WHERE ip_address = ?",
        (ip_address,)
    )
    
    result = cursor.fetchone()  
    conn.close()
    if not result:
        return False
    
    failed_attempts, locked_until = result  
    
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if datetime.now() < locked_until_dt:
            return True 
        
    return False    


def increment_ip_failed_attempt(ip_address):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_attempts FROM ip_login_attempts WHERE ip_address = ?",
        (ip_address,)
    )
    
    result = cursor.fetchone()
    if result:
        failed_attempts  = result[0] + 1 ;
        locked_until = None
        
        if failed_attempts >= 10:
            locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            logging.warning(f"IP address locked: {ip_address}")
    
        cursor.execute("UPDATE ip_login_attempts SET failed_attempts = ?, locked_until = ? WHERE ip_address = ?",
                       (failed_attempts, locked_until, ip_address))
        
    else:
        cursor.execute(
            "INSERT INTO ip_login_attempts (ip_address, failed_attempts) VALUES (?, 1)",
            (ip_address,)
        )   
    
    conn.commit()
    conn.close()    
    
    

def reset_ip_failed_login(ip_address):

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ip_login_attempts SET failed_attempts = 0, locked_until = NULL WHERE ip_address = ?",
        (ip_address,)
    )
    conn.commit()
    conn.close()
    
    
def cleanup_expired_ip_locks():

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ip_login_attempts SET locked_until = NULL WHERE locked_until < ?",
        (datetime.now().isoformat(),)
    )
    conn.commit()
    conn.close()    
        
         
# Routes
@app.route("/")
@limiter.limit("10 per minute")
def home():
    """Serve main page."""
    return send_from_directory("static", "index.html")

@app.route("/chat.html")
@limiter.limit("10 per minute")
def chat():
    """Serve chat page."""
    return send_from_directory("static", "chat.html")

@app.route("/get_public_key")
@limiter.limit("20 per minute")
def get_public_key():
    """Serve server's public key."""
    public_key_path = os.getenv('PUBLIC_KEY_PATH', 'public.pem')
    return send_from_directory(".", public_key_path)

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    """Register new user with hybrid encrypted payload."""
    try:
        payload_data = request.json.get("payload", {})
        decrypted_bytes = decrypt_hybrid_payload(payload_data)
        data = json.loads(decrypted_bytes.decode("utf-8"))
        
        username = data.get("username", "").strip()
        password = data.get("password", "")
        public_key = data.get("public_key", "").strip()
        private_key = data.get("private_key", "")
        
        # Validate inputs
        valid, error_msg = validate_username(username)
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        valid, error_msg = validate_password(password)
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        valid, error_msg = validate_public_key(public_key)
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        # Check if username already exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Username already exists"}), 400
        
        # Hash password and store user
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, public_key, password, private_key) VALUES (?, ?, ?, ?)",
            (username, public_key, hashed_password, private_key)
        )
        conn.commit()
        conn.close()
        
        logging.info(f"User registered: {username}")
        return jsonify({"status": "User registered successfully"})
        
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():

    try:
        
        client_ip = get_remote_address()
        
        if is_ip_locked(client_ip):
            logging.warning(f"Login attempt from locked IP: {client_ip}")
            
            return jsonify({"error": "IP address temporarily locked due to multiple failed login attempts"}), 423
            
        payload_data = request.json.get("payload", {})
        decrypted_bytes = decrypt_hybrid_payload(payload_data)
        data = json.loads(decrypted_bytes.decode("utf-8"))
        
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        # Validate inputs
        valid, error_msg = validate_username(username)
        if not valid:
            increment_ip_failed_attempt(client_ip)
            return jsonify({"error": error_msg}), 400
        
        valid, error_msg = validate_password(password)
        if not valid:
            increment_ip_failed_attempt(client_ip)
            return jsonify({"error": error_msg}), 400
        
        # Check if user is locked
        if is_user_locked(username):
            increment_ip_failed_attempt(client_ip)
            return jsonify({"error": "Account temporarily locked due to multiple failed login attempts"}), 423
        
        # Retrieve user from database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password, public_key, private_key FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        conn.close()
        
        # Use constant-time comparison to prevent timing attacks
        if not row:
            # Still hash the password to prevent timing attacks
            bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            increment_failed_login(username)  
            increment_ip_failed_attempt(client_ip)# This will do nothing if user doesn't exist
            time.sleep(0.1)  # Add small delay
            return jsonify({"error": "Invalid username or password"}), 401
        
        hashed_password, public_key, private_key = row
        
        # Verify password
        if not bcrypt.checkpw(password.encode(), hashed_password):
            increment_failed_login(username)
            increment_ip_failed_attempt(client_ip)
            time.sleep(0.1)  # Add small delay
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Reset failed login attempts
        reset_failed_login(username)
        reset_ip_failed_login(client_ip)
        # Create new session
        session_id = create_user_session(username)
        
        # Clear previous session and create new one
        session.clear()
        session['username'] = username
        session['session_id'] = session_id
        session.permanent = True
        
        # Handle private key format (JSON or string)
        try:
            encrypted_private_key = json.loads(private_key)
        except json.JSONDecodeError:
            encrypted_private_key = private_key
        
        logging.info(f"User logged in: {username}")
        return jsonify({
            "status": "Login successful",
            "username": username,
            "public_key": public_key,
            "encrypted_private_key": encrypted_private_key,
            "session_expires": (datetime.now() + timedelta(hours=24)).isoformat()
        })
        
    except Exception as e:
        client_ip = get_remote_address()
        increment_ip_failed_attempt(client_ip)
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route("/logout", methods=["POST"])
@limiter.limit("20 per minute")
def logout():

    username = session.get('username')
    session_id = session.get('session_id')
    
    # Invalidate server-side session
    if session_id:
        invalidate_session(session_id)
    
    # Clear client-side session
    session.clear()
    
    if username:
        logging.info(f"User logged out: {username}")
    
    return jsonify({"status": "Logged out successfully"})

@app.route("/get_key/<username>", methods=["GET"])
@limiter.limit("30 per minute")
@require_auth
def get_key(username):
    """Get public key for specified user."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({"public_key": row[0]})
        
    except Exception as e:
        logging.error(f"Error fetching key for {username}: {e}")
        return jsonify({"error": "Failed to fetch key"}), 500

@app.route("/users", methods=["GET"])
@limiter.limit("20 per minute")
@require_auth
def users():

    try:
        current_user = session['username']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username != ?", (current_user,))
        rows = cursor.fetchall()
        conn.close()
        
        usernames = [row[0] for row in rows]
        return jsonify({"users": usernames})
        
    except Exception as e:
        logging.error(f"Error fetching users: {e}")
        return jsonify({"error": "Failed to fetch users"}), 500

@app.route("/send", methods=["POST"])
@limiter.limit("30 per minute")
@require_auth
def send():

    try:
        payload_data = request.json
        from_user = session['username']  # Override with session username
        to_user = payload_data.get("to_user")
        message = payload_data.get("message")
        signature = payload_data.get("signature", "")
        
        # Validate required fields
        if not to_user or not message:
            return jsonify({"error": "Missing required fields"}), 400
        
        # Validate message format (encrypted object)
        if not isinstance(message, dict) or not all(
            key in message for key in ["encrypted_aes_key", "iv", "encrypted_data"]
        ):
            return jsonify({"error": "Invalid message format"}), 400
        
        # Verify recipient exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (to_user,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Recipient not found"}), 400
        
        # Store encrypted message
        cursor.execute(
            "INSERT INTO messages (from_user, to_user, message, signature) VALUES (?, ?, ?, ?)",
            (from_user, to_user, json.dumps(message), signature)
        )
        conn.commit()
        conn.close()
        
        logging.info(f"Message sent from {from_user} to {to_user}")
        return jsonify({"status": "Message sent"})
        
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return jsonify({"error": "Failed to send message"}), 500

@app.route("/inbox/<username>", methods=["GET"])
@limiter.limit("60 per minute")
@require_auth
def inbox(username):
    """Get encrypted messages for user (only if session username matches)."""
    try:
        # Ensure user can only access their own inbox
        if session['username'] != username:
            return jsonify({"error": "Access denied"}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT from_user, to_user, message, signature, created_at 
            FROM messages 
            WHERE to_user = ? 
            ORDER BY created_at ASC
            """,
            (username,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        messages = []
        for row in rows:
            try:
                encrypted_message = json.loads(row[2])
                message_data = {
                    "from_user": row[0],
                    "to_user": row[1],
                    "encrypted_message": encrypted_message,
                    "signature": row[3] or "",
                    "timestamp": row[4]
                }
                messages.append(message_data)
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse message from {row[0]}: {e}")
                continue
        
        return jsonify(messages)
        
    except Exception as e:
        logging.error(f"Error in inbox endpoint: {e}")
        return jsonify({"error": "Failed to retrieve messages"}), 500

@app.route("/session/status", methods=["GET"])
@limiter.limit("30 per minute")
@require_auth
def session_status():
    try:
        session_id = session.get('session_id')
        username = session.get('username')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT expires_at, last_activity FROM user_sessions WHERE session_id = ? AND is_active = TRUE",
            (session_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "Invalid session"}), 401 
        
        expires_at, last_activity = result
        
        return jsonify({
            "username": username,
            "session_id": session_id,
            "expires_at": expires_at,
            "last_activity": last_activity
        })
        
    except Exception as e:
        logging.error(f"Error getting session status: {e}")
        return jsonify({"error": "Failed to get session status"}), 500


@app.route("/admin/cleanup", methods=["POST"])
@limiter.limit("1 per hour")
def cleanup():
    try:
        cleanup_expired_sessions()
        cleanup_expired_ip_locks()
        return jsonify({"status": "Cleanup completed"})
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")
        return jsonify({"error": "Cleanup failed"}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(423)
def locked(error):
    return jsonify({"error": "Account locked"}), 423

@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({"error": "Rate limit exceeded", "message": str(e.description)}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
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
    
    # Initialize database
    init_database()
    
    # Clean up expired sessions on startup
    cleanup_expired_sessions()
    
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