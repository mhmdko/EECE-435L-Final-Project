"""
Entry point: starts the API server.

Usage:
    python run.py
The API is then available at http://127.0.0.1:5000

Author: Mohammad Kourani
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # FLASK_DEBUG=1 in .env turns on auto-reload while developing.
    debug_mode = os.getenv("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
