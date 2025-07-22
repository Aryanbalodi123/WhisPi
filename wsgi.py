# wsgi.py
from main import create_app
import os

# Ensure session dir exists
os.makedirs(os.getenv('SESSION_FILE_DIR', '/tmp/flask_session'), exist_ok=True)

app = create_app()
