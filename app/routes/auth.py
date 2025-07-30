import bcrypt
import logging
from flask import Blueprint, request, jsonify, session, current_app
from flask_limiter.util import get_remote_address
from app.database import (
    get_db, is_user_locked, increment_failed_login, reset_failed_login,
    is_ip_locked, increment_ip_failed_attempt, reset_ip_failed_login,
    create_user_session, validate_session, invalidate_session,
    cleanup_expired_sessions, cleanup_expired_ip_locks
)
from app.utils import (
    validate_username, validate_password, validate_public_key,
    decrypt_hybrid_payload, require_auth
)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/register", methods=["POST"])
def register():

    current_app.limiter.limit("5 per minute")(lambda: None)()
    
    try:
        ip_address = get_remote_address()
        
        if is_ip_locked(ip_address):
            return jsonify({"error": "IP address temporarily locked"}), 423
        
        encrypted_payload = request.json
        if not encrypted_payload:
            return jsonify({"error": "No data provided"}), 400
        
        # Decrypt the payload
        try:
            decrypted_data = decrypt_hybrid_payload(encrypted_payload)
            import json
            user_data = json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to decrypt registration data: {e}")
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Invalid encrypted data"}), 400
        
        username = user_data.get("username")
        password = user_data.get("password")
        public_key = user_data.get("public_key")
        private_key = user_data.get("private_key")
        
        is_valid, error = validate_username(username)
        if not is_valid:
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": error}), 400
        
        is_valid, error = validate_password(password)
        if not is_valid:
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": error}), 400
        
        is_valid, error = validate_public_key(public_key)
        if not is_valid:
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": error}), 400
        
        if not private_key:
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Private key is required"}), 400
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, public_key, password, private_key) VALUES (?, ?, ?, ?)",
                (username, public_key, password_hash.decode('utf-8'), private_key)
            )
            conn.commit()
            
            reset_ip_failed_login(ip_address)
            
            logging.info(f"User {username} registered successfully")
            return jsonify({"message": "User registered successfully"})
            
        except Exception as e:
            conn.rollback()
            if "UNIQUE constraint failed" in str(e):
                increment_ip_failed_attempt(ip_address)
                return jsonify({"error": "Username already exists"}), 409
            else:
                logging.error(f"Registration error: {e}")
                increment_ip_failed_attempt(ip_address)
                return jsonify({"error": "Registration failed"}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@auth_bp.route("/login", methods=["POST"])
def login():

    current_app.limiter.limit("10 per minute")(lambda: None)()
    
    try:
        ip_address = get_remote_address()
        
        if is_ip_locked(ip_address):
            return jsonify({"error": "IP address temporarily locked"}), 423
        
        encrypted_payload = request.json
        if not encrypted_payload:
            return jsonify({"error": "No data provided"}), 400
        
        try:
            decrypted_data = decrypt_hybrid_payload(encrypted_payload)
            import json
            login_data = json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to decrypt login data: {e}")
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Invalid encrypted data"}), 400
        
        username = login_data.get("username")
        password = login_data.get("password")
        
        if not username or not password:
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Username and password are required"}), 400
        
        if is_user_locked(username):
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Account temporarily locked"}), 423
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, password, private_key FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            increment_failed_login(username)
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Invalid credentials"}), 401
        
        stored_password_hash = user[1]
        if isinstance(stored_password_hash, str):
            stored_password_hash = stored_password_hash.encode('utf-8')
        
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
            increment_failed_login(username)
            increment_ip_failed_attempt(ip_address)
            return jsonify({"error": "Invalid credentials"}), 401
        
        reset_failed_login(username)
        reset_ip_failed_login(ip_address)
        
        session_id = create_user_session(username)
        session['session_id'] = session_id
        session['username'] = username
        session.permanent = True
        
        logging.info(f"User {username} logged in successfully")
        return jsonify({
            "message": "Login successful",
            "username": username,
            "private_key": user[2]  
        })
        
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():

    current_app.limiter.limit("10 per minute")(lambda: None)()
    
    try:
        session_id = session.get('session_id')
        username = session.get('username')
        
        if session_id:
            invalidate_session(session_id)
        
        session.clear()
        
        logging.info(f"User {username} logged out successfully")
        return jsonify({"message": "Logout successful"})
        
    except Exception as e:
        logging.error(f"Logout error: {e}")
        return jsonify({"error": "Logout failed"}), 500

@auth_bp.route("/session/status", methods=["GET"])
@require_auth
def session_status():

    current_app.limiter.limit("30 per minute")(lambda: None)()
    
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

@auth_bp.route("/admin/cleanup", methods=["POST"])
def cleanup():

    current_app.limiter.limit("1 per hour")(lambda: None)()
    
    try:
        cleanup_expired_sessions()
        cleanup_expired_ip_locks()
        return jsonify({"status": "Cleanup completed"})
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")
        return jsonify({"error": "Cleanup failed"}), 500