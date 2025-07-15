"""
Database operations and session management for WhisPI application.
"""

import os
import sqlite3
import logging
import secrets
from datetime import datetime, timedelta

DATABASE_PATH = os.getenv('DATABASE_PATH', 'database.db')

def init_database():
    """Initialize the database with required tables."""
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
    """Get database connection."""
    return sqlite3.connect(DATABASE_PATH)

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

def is_ip_locked(ip_address):
    """Check if IP address is locked due to failed login attempts."""
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
    """Increment failed login attempts for IP address."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_attempts FROM ip_login_attempts WHERE ip_address = ?",
        (ip_address,)
    )
    
    result = cursor.fetchone()
    if result:
        failed_attempts = result[0] + 1
        locked_until = None
        
        if failed_attempts >= 10:
            locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            logging.warning(f"IP address locked: {ip_address}")
    
        cursor.execute(
            "UPDATE ip_login_attempts SET failed_attempts = ?, locked_until = ? WHERE ip_address = ?",
            (failed_attempts, locked_until, ip_address)
        )
        
    else:
        cursor.execute(
            "INSERT INTO ip_login_attempts (ip_address, failed_attempts) VALUES (?, 1)",
            (ip_address,)
        )   
    
    conn.commit()
    conn.close()    

def reset_ip_failed_login(ip_address):
    """Reset failed login attempts for IP address."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ip_login_attempts SET failed_attempts = 0, locked_until = NULL WHERE ip_address = ?",
        (ip_address,)
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

def cleanup_expired_ip_locks():
    """Clean up expired IP locks."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE ip_login_attempts SET locked_until = NULL WHERE locked_until < ?",
        (datetime.now().isoformat(),)
    )
    conn.commit()
    conn.close()