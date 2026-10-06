"""
PhishGuard - Single-Command Launcher
Runs both the Flask backend and serves the frontend dashboard in one command.
Automatically opens your browser to http://127.0.0.1:5000.
"""

import os
import sys
import threading
import time
import webbrowser

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
VENV_PYTHON = os.path.join(ROOT_DIR, "venv312", "Scripts", "python.exe")

# Re-exec with venv312 python if invoked with external python and venv312 exists
if os.path.exists(VENV_PYTHON) and os.path.normcase(sys.executable) != os.path.normcase(VENV_PYTHON):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

sys.path.insert(0, BACKEND_DIR)

# 1. Ensure trained model exists; if not, train it automatically
MODEL_PATH = os.path.join(BACKEND_DIR, "model.pkl")
if not os.path.exists(MODEL_PATH):
    print("=" * 60)
    print(" model.pkl not found. Auto-training model first...")
    print("=" * 60)
    import subprocess
    subprocess.run([sys.executable, os.path.join(BACKEND_DIR, "train_model.py")], check=True)

# 2. Function to automatically open web browser
def open_browser():
    time.sleep(1.2)
    url = "http://127.0.0.1:5000"
    print(f"\n[Browser] Opening PhishGuard Dashboard at {url} ...")
    webbrowser.open(url)

# 3. Start Flask app
if __name__ == "__main__":
    print("=" * 60)
    print(" STARTING PHISHGUARD INTELLIGENT PHISHING DETECTION SYSTEM ")
    print("=" * 60)
    print("Serving Backend API & Frontend Dashboard together at:")
    print("-> http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server at any time.\n")

    # Launch browser in a background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Import and run Flask app
    from app import app
    app.run(host="127.0.0.1", port=5000, debug=False)
