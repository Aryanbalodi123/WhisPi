import datetime
import json
import logging
from flask import Blueprint, request, jsonify, session, current_app
from app.database import get_db
from app.utils import require_auth

chat_bp = Blueprint('chat', __name__)

@chat_bp.route("/get_key/<username>", methods=["GET"])
@require_auth
def get_key(username):

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

def get_current_utc_timestamp():

    return datetime.now(datetime.timezone.utc).isoformat()

@chat_bp.route("/send", methods=["POST"])
@require_auth
def send():

    current_app.limiter.limit("30 per minute")(lambda: None)()
    
    try:
        payload_data = request.json
        from_user = session['username']
        to_user = payload_data.get("to_user")
        encrypted_message = payload_data.get("encrypted_message")
        iv = payload_data.get("iv")
        encrypted_key_for_sender = payload_data.get("encrypted_key_for_sender")
        encrypted_key_for_recipient = payload_data.get("encrypted_key_for_recipient")
        signature = payload_data.get("signature", "")
        
        client_timestamp = payload_data.get("client_timestamp")
        if client_timestamp:
            message_timestamp = client_timestamp
            logging.info(f"Using client timestamp: {client_timestamp}")
        else:
            message_timestamp = get_current_utc_timestamp()
            logging.info(f"Using server timestamp (fallback): {message_timestamp}")
        
        if not all([to_user, encrypted_message, iv, encrypted_key_for_sender, encrypted_key_for_recipient]):
            return jsonify({"error": "Missing required fields"}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (to_user,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Recipient not found"}), 400
        
        cursor.execute(
            """INSERT INTO messages 
               (from_user, to_user, encrypted_message, iv, encrypted_key_for_sender, encrypted_key_for_recipient, signature, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (from_user, to_user, encrypted_message, iv, encrypted_key_for_sender, encrypted_key_for_recipient, signature, message_timestamp)
        )
        
        message_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logging.info(f"Message sent from {from_user} to {to_user} with timestamp {message_timestamp}")
        
        return jsonify({
            "status": "Message sent",
            "timestamp": message_timestamp,
            "message_id": message_id,
            "success": True
        })
        
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return jsonify({"error": "Failed to send message"}), 500

@chat_bp.route("/inbox/<username>", methods=["GET"])
@require_auth
def inbox(username):

    current_app.limiter.limit("60 per minute")(lambda: None)()

    try:
        if session['username'] != username:
            return jsonify({"error": "Access denied"}), 403

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT from_user, to_user, encrypted_message, iv, encrypted_key_for_sender, 
                   encrypted_key_for_recipient, signature, created_at, id
            FROM messages 
            WHERE to_user = ? OR from_user = ?
            ORDER BY created_at ASC, id ASC
            """,
            (username, username)
        )
        rows = cursor.fetchall()

        messages = []

        for row in rows:
            from_user = row[0]
            to_user = row[1]
            encrypted_message = row[2]
            iv = row[3]
            encrypted_key_for_sender = row[4]
            encrypted_key_for_recipient = row[5]
            signature = row[6] or ""
            timestamp = row[7]  
            message_id = row[8]

            try:
                # Check if sender is online
                cursor.execute(
                    "SELECT is_active FROM user_sessions WHERE username = ? AND is_active = 1",
                    (from_user,)
                )
                result = cursor.fetchone()
                is_online = bool(result and result[0])

                message_data = {
                    "from_user": from_user,
                    "to_user": to_user,
                    "encrypted_message": encrypted_message,
                    "iv": iv,
                    "encrypted_key_for_sender": encrypted_key_for_sender,
                    "encrypted_key_for_recipient": encrypted_key_for_recipient,
                    "signature": signature,
                    "timestamp": timestamp, 
                    "created_at": timestamp,  
                    "is_online": is_online,
                    "message_id": message_id
                }
                messages.append(message_data)

            except Exception as e:
                logging.error(f"Failed to process message from {from_user}: {e}")
                continue

        conn.close()
        
        logging.info(f"Retrieved {len(messages)} messages for {username}")
        return jsonify(messages)

    except Exception as e:
        logging.error(f"Error in inbox endpoint: {e}")
        return jsonify({"error": "Failed to retrieve messages"}), 500
