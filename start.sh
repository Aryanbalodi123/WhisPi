#!/bin/bash

# Activate venv if using one
# source venv/bin/activate

# Load environment variables from .env
export $(grep -v '^#' .env | xargs)

# Run the server with SSL
gunicorn wsgi:app \
  --bind $HOST:$PORT \
  --workers 2 \
  --threads 4 \
  --timeout 120 \
  --log-level info
