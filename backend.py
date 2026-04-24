# ============================================================
# Phishing Detection Backend API
# CSCI 401 - John Jay Seniors
# Author: Michael Cruz - Database & Backend Engineer
# ============================================================
#
# Flask REST API that ties the whole system together:
#   - Tries Fatima's ML model (ml_model.predict) first.
#   - Falls back to Imdadul's rule-based detector
#     (threat_analysis.analyze_email) when model.pkl is missing
#     or the ML call fails.
#   - Persists every scan to SQLite via Michael's database_sql.
#   - Serves Muhammad's frontend.html at /.
#
# Endpoints:
#   GET  /          -> frontend.html
#   POST /analyze   -> classify an email {sender, subject, body}
#   GET  /history   -> last N scans
#   GET  /stats     -> totals by label
#   GET  /health    -> {"status": "ok", ...}
#
# Run:
#   pip install -r requirements.txt
#   python database_sql.py    # one-time, creates phishing.db
#   python ml_model.py --train  # optional, trains Fatima's classifier
#   python backend.py
#   open http://127.0.0.1:5000
# ============================================================

from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

import database_sql as db
import threat_analysis

# Try to import the ML model. If scikit-learn or model.pkl is missing,
# the backend just uses the rule-based detector.
try:
    import ml_model
    ML_AVAILABLE = True
except Exception as e:
    ml_model = None
    ML_AVAILABLE = False
    print(f"[!] ml_model not importable ({e}); using rule-based detector only.")

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
CORS(app)

# Create tables on first run
db.init_db()


# ------------------------------------------------------------------
# Serve the frontend
# ------------------------------------------------------------------

@app.route("/")
def home():
    for candidate in ("frontend.html", "PhishGuard.html"):
        if (BASE_DIR / candidate).exists():
            return send_from_directory(str(BASE_DIR), candidate)
    return "<h1>PhishGuard backend is running</h1><p>No frontend file found.</p>"


# ------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ml_available": ML_AVAILABLE,
        "model_file_exists": (BASE_DIR / "model.pkl").exists(),
    })


# ------------------------------------------------------------------
# Analyze an email
# ------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}

    # Accept either the structured form {sender, subject, body}
    # or the older {email: "..."} blob (for backwards compatibility
    # with the first frontend prototype).
    if "email" in data and not any(k in data for k in ("sender", "subject", "body")):
        sender, subject, body = "", "", data.get("email", "")
    else:
        sender  = data.get("sender", "")
        subject = data.get("subject", "")
        body    = data.get("body", "")

    result = None
    detector = "rules"

    # 1) Try the ML model
    if ML_AVAILABLE:
        try:
            result = ml_model.predict(sender=sender, subject=subject, body=body)
            detector = "ml"
        except FileNotFoundError:
            result = None  # model.pkl not trained yet, fall back
        except Exception as e:
            db.log_event("ml_error", str(e))
            result = None

    # 2) Fall back to Imdadul's rule-based detector
    if result is None:
        result = threat_analysis.analyze_email(subject, sender, body)
        detector = "rules"

    # Persist
    email_id = db.save_analysis(sender, subject, body, result, detector=detector)
    db.log_event(
        "analyze",
        f"email_id={email_id} detector={detector} "
        f"label={str(result.get('classification','')).lower()}"
    )

    # Build response — normalize label to lowercase so the frontend
    # and the DB agree on casing.
    response = {
        "email_id": email_id,
        "detector": detector,
        "risk_level":     result.get("risk_level", "LOW"),
        "classification": str(result.get("classification", "legitimate")).lower(),
        "score":          int(result.get("score", 0)),
        "confidence":     float(result.get("confidence",
                            min(0.5 + 0.07 * int(result.get("score", 0)), 0.95))),
        "indicators":     result.get("indicators", []),
    }
    return jsonify(response)


# ------------------------------------------------------------------
# History + stats
# ------------------------------------------------------------------

@app.route("/history", methods=["GET"])
def history():
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        limit = 50
    return jsonify(db.get_history(limit=limit))


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(db.get_stats())


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  PhishGuard backend starting at http://127.0.0.1:5000")
    print(f"  ML model available: {ML_AVAILABLE and (BASE_DIR / 'model.pkl').exists()}")
    print("  Endpoints: /  /analyze  /history  /stats  /health")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
