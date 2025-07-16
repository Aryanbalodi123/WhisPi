"""
Chat and messaging routes for WhisPI application.
"""

import json
import logging
from flask import Blueprint, request, jsonify, session, current_app
from app.database import get_db
from app.utils import require_auth

chat_bp = Blueprint('chat', __name__)

@chat_bp.route("/get_key/<username>", methods=["GET"])
@require_auth
def get_key(username):
    """Get public key for specified user."""
    current_app.limiter.limit("30 per minute")(lambda: None)()
    
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

@chat_bp.route("/users", methods=["GET"])
@require_auth
def users():
    """Get list of all users except current user."""
    current_app.limiter.limit("20 per minute")(lambda: None)()
    
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

@chat_bp.route("/send", methods=["POST"])
@require_auth
def send():
    """Send an encrypted message to another user."""
    current_app.limiter.limit("30 per minute")(lambda: None)()
    
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

@chat_bp.route("/inbox/<username>", methods=["GET"])
@require_auth
def inbox(username):
    """Get encrypted messages for user (only if session username matches)."""
    current_app.limiter.limit("60 per minute")(lambda: None)()
    
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