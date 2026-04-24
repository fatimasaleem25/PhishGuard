# ============================================================
# Phishing Detection Backend API
# CSCI 401 - John Jay Seniors
# Author: Michael Cruz — Database & Backend Engineer
#         Fatima Saleem — AI System Integration
# ============================================================
#
# Flask REST API that ties the whole system together.
#   - /analyze          : hybrid (ML first, rule-based fallback)
#   - /mailbox/imap     : fetch recent mail from a live IMAP inbox
#                         (Gmail, Outlook, iCloud, ...) and scan each
#                         with the ML model
#   - /mailbox/upload   : upload a .eml file and scan it
#   - /history, /stats  : persistence layer (SQLite)
#
# Run:
#   pip install -r requirements.txt
#   python database_sql.py    # one-time
#   python ml_model.py --train  # one-time (auto-runs on first /analyze)
#   python backend.py
#   open http://127.0.0.1:5000
# ============================================================

from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

import database_sql as db
import mailbox_service
import threat_analysis

# Load ML model module (and auto-train if model.pkl is missing)
try:
    import ml_model
    ML_AVAILABLE = True
except Exception as e:
    ml_model = None
    ML_AVAILABLE = False
    print(f"[!] ml_model not importable ({e}); rule-based detector only.")

BASE_DIR   = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
CORS(app)

db.init_db()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _ensure_ml_model():
    """Train the classifier on the starter dataset if model.pkl is missing."""
    if ML_AVAILABLE and not MODEL_PATH.exists():
        print("[!] model.pkl not found — training now from the starter dataset...")
        ml_model.train()


def _normalize(result: dict) -> dict:
    """Common output shape for both ML and rule detectors."""
    label = str(result.get("classification", "legitimate")).lower()
    if label not in ("legitimate", "suspicious", "phishing"):
        label = "legitimate"
    score = int(result.get("score", 0))
    return {
        "risk_level":     result.get("risk_level", "LOW"),
        "classification": label,
        "score":          score,
        "confidence":     float(result.get("confidence",
                            min(0.5 + 0.07 * score, 0.95))),
        "indicators":     result.get("indicators", []),
    }


def _scan_ml_only(sender, subject, body):
    """Force the ML model (auto-train if needed)."""
    if not ML_AVAILABLE:
        return _normalize(threat_analysis.analyze_email(subject, sender, body)), "rules"
    _ensure_ml_model()
    try:
        return _normalize(ml_model.predict(sender=sender, subject=subject, body=body)), "ml"
    except Exception as e:
        db.log_event("ml_error", str(e))
        return _normalize(threat_analysis.analyze_email(subject, sender, body)), "rules"


def _scan_hybrid(sender, subject, body):
    """Try ML, fall back to rules."""
    if ML_AVAILABLE:
        try:
            _ensure_ml_model()
            return _normalize(ml_model.predict(sender=sender, subject=subject, body=body)), "ml"
        except FileNotFoundError:
            pass
        except Exception as e:
            db.log_event("ml_error", str(e))
    return _normalize(threat_analysis.analyze_email(subject, sender, body)), "rules"


# ------------------------------------------------------------------
# Static frontend
# ------------------------------------------------------------------
@app.route("/")
def home():
    for candidate in ("frontend.html", "PhishGuard.html"):
        if (BASE_DIR / candidate).exists():
            return send_from_directory(str(BASE_DIR), candidate)
    return "<h1>PhishGuard backend is running</h1><p>No frontend file found.</p>"


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ml_available":       ML_AVAILABLE,
        "model_file_exists":  MODEL_PATH.exists(),
    })


# ------------------------------------------------------------------
# Core /analyze (hybrid)
# ------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    # Accept both the structured payload and the older {email:"..."} blob.
    if "email" in data and not any(k in data for k in ("sender", "subject", "body")):
        sender, subject, body = "", "", data.get("email", "")
    else:
        sender  = data.get("sender", "")
        subject = data.get("subject", "")
        body    = data.get("body", "")

    result, detector = _scan_hybrid(sender, subject, body)
    email_id = db.save_analysis(sender, subject, body, result, detector=detector)
    db.log_event("analyze",
                 f"email_id={email_id} detector={detector} label={result['classification']}")

    out = dict(result)
    out["email_id"] = email_id
    out["detector"] = detector
    return jsonify(out)


# ------------------------------------------------------------------
# Mailbox: IMAP fetch (Gmail / Outlook / iCloud / ...)
# ------------------------------------------------------------------
@app.route("/mailbox/imap", methods=["POST"])
def mailbox_imap():
    """Connect to a real inbox and scan the most recent messages.

    Body:
      { "server":   "imap.gmail.com",
        "port":     993,
        "username": "you@gmail.com",
        "password": "<app password>",
        "limit":    10,
        "folder":   "INBOX" }
    """
    data = request.get_json(silent=True) or {}
    try:
        emails = mailbox_service.fetch_imap(
            server   = data.get("server", "imap.gmail.com"),
            port     = data.get("port", 993),
            username = data.get("username", ""),
            password = data.get("password", ""),
            limit    = data.get("limit", 10),
            folder   = data.get("folder", "INBOX"),
        )
    except (ValueError,) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        # Covers IMAP auth errors, socket errors, etc.
        db.log_event("imap_error", str(e))
        return jsonify({"error": f"IMAP error: {e}"}), 400

    results = []
    for em in emails:
        result, detector = _scan_ml_only(em["sender"], em["subject"], em["body"])
        email_id = db.save_analysis(em["sender"], em["subject"], em["body"],
                                     result, detector=detector)
        out = dict(result)
        out.update({
            "email_id": email_id,
            "detector": detector,
            "sender":   em["sender"],
            "subject":  em["subject"],
            "date":     em["date"],
            "preview":  (em["body"] or "")[:240],
        })
        results.append(out)

    db.log_event("mailbox_imap", f"fetched={len(results)} user={data.get('username','')}")
    return jsonify({"count": len(results), "results": results})


# ------------------------------------------------------------------
# Mailbox: .eml file upload
# ------------------------------------------------------------------
@app.route("/mailbox/upload", methods=["POST"])
def mailbox_upload():
    """Upload a single .eml file (multipart field name 'file')."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded (expected multipart field 'file')."}), 400

    raw = request.files["file"].read()
    if not raw:
        return jsonify({"error": "Uploaded file is empty."}), 400

    try:
        em = mailbox_service.parse_eml_bytes(raw)
    except Exception as e:
        return jsonify({"error": f"Could not parse .eml: {e}"}), 400

    result, detector = _scan_ml_only(em["sender"], em["subject"], em["body"])
    email_id = db.save_analysis(em["sender"], em["subject"], em["body"],
                                 result, detector=detector)

    out = dict(result)
    out.update({
        "email_id": email_id,
        "detector": detector,
        "sender":   em["sender"],
        "subject":  em["subject"],
        "date":     em["date"],
        "preview":  (em["body"] or "")[:240],
    })
    db.log_event("mailbox_upload", f"email_id={email_id} from={em['sender']}")
    return jsonify(out)


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
    _ensure_ml_model()  # train at boot so ML-only endpoints always work
    print("=" * 60)
    print("  PhishGuard backend starting at http://127.0.0.1:5000")
    print(f"  ML model available: {ML_AVAILABLE and MODEL_PATH.exists()}")
    print("  Endpoints: /  /analyze  /mailbox/imap  /mailbox/upload")
    print("             /history  /stats  /health")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
