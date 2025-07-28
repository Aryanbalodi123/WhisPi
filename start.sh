#!/bin/bash

# Change to the directory where this script resides
cd "$(dirname "$0")"

# Activate virtual environment
source ~/envs/whispi/bin/activate

# Load environment variables from .env
export $(grep -v '^#' .env | xargs)

# Run the Flask app via Gunicorn with SSL
gunicorn wsgi:app \
  --bind "$HOST:$PORT" \
  --workers 2 \
  --threads 4 \
  --timeout 120 \
  --log-level info

  