import os
import base64
import logging
from functools import wraps
from flask import session, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.database import validate_session

def validate_username(username):

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
    
    if not password:
        return False, "Password is required"
    if len(password) < 8:  
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    return True, ""

def validate_public_key(public_key):
  
    if not public_key:
        return False, "Public key is required"
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        return False, "Invalid public key format - must be PEM format"
    if not public_key.endswith("-----END PUBLIC KEY-----"):
        return False, "Invalid public key format - must be PEM format"
    return True, ""

def decrypt_hybrid_payload(encrypted_payload):

    try:
        encrypted_aes_key = base64.b64decode(encrypted_payload["encrypted_aes_key"])
        iv = base64.b64decode(encrypted_payload["iv"])
        encrypted_data = base64.b64decode(encrypted_payload["encrypted_data"])
        

        secret = os.getenv("PRIVATE_KEY_PASSWORD")
        if not secret:
            raise ValueError("PRIVATE_KEY_PASSWORD not found in environment variables")
        
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

    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        username = validate_session(session_id)
        
        if not username:
            return jsonify({"error": "Authentication required"}), 401
        
        session['username'] = username
        return f(*args, **kwargs)
    
    return decorated_function