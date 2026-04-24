# ============================================================
# Phishing Database Module
# CSCI 401 - John Jay Seniors
# Author: Michael Cruz - Database & Backend Engineer
# ============================================================
#
# Schema + CRUD helpers for PhishGuard.
# Tables: emails, classifications, analysis_reports, logs.
# Running this file directly (python database_sql.py) initializes
# the database file. backend.py imports init_db() / save_analysis()
# / get_history() / get_stats() / log_event() from here.
# ============================================================

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "phishing.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------
# SCHEMA
# ------------------------------------------------------------------

SCHEMA = '''
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    subject TEXT,
    body TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS classifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER REFERENCES emails(id),
    label TEXT CHECK(label IN ('legitimate', 'suspicious', 'phishing')),
    confidence REAL,
    classified_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER REFERENCES emails(id),
    indicators TEXT,
    summary TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    detail TEXT,
    logged_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
'''


def init_db():
    """Create the database and tables if they don't exist yet."""
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# WRITES
# ------------------------------------------------------------------

def save_analysis(sender, subject, body, result, detector="rules"):
    """
    Persist an email + its classification + its indicator report.
    `result` is the dict returned by threat_analysis.analyze_email()
    or ml_model.predict(). Returns the new email_id.
    """
    # Normalize label to lowercase to match the schema's CHECK constraint.
    label = str(result.get("classification", "legitimate")).lower()
    if label not in ("legitimate", "suspicious", "phishing"):
        label = "legitimate"

    score = int(result.get("score", 0))
    # Imdadul's rule scorer doesn't return confidence; derive from score.
    confidence = float(result.get("confidence", min(0.5 + 0.07 * score, 0.95)))

    indicators = result.get("indicators", [])
    # Indicators can be strings (rules) or dicts (ML); store as JSON either way.
    indicators_json = json.dumps(indicators)
    summary = f"{result.get('risk_level','')} risk — {label} (detector={detector})"

    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO emails (sender, subject, body) VALUES (?, ?, ?)",
            (sender, subject, body),
        )
        email_id = cur.lastrowid

        cur.execute(
            "INSERT INTO classifications (email_id, label, confidence) VALUES (?, ?, ?)",
            (email_id, label, confidence),
        )

        cur.execute(
            "INSERT INTO analysis_reports (email_id, indicators, summary) VALUES (?, ?, ?)",
            (email_id, indicators_json, summary),
        )

        conn.commit()
        return email_id
    finally:
        conn.close()


def log_event(event, detail=""):
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO logs (event, detail) VALUES (?, ?)",
            (event, detail),
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# READS
# ------------------------------------------------------------------

def get_history(limit=50):
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT e.id, e.sender, e.subject, e.timestamp,
                      c.label, c.confidence,
                      r.indicators, r.summary
                 FROM emails e
                 LEFT JOIN classifications c ON c.email_id = e.id
                 LEFT JOIN analysis_reports  r ON r.email_id = e.id
                 ORDER BY e.id DESC
                 LIMIT ?""",
            (limit,),
        ).fetchall()

        out = []
        for r in rows:
            d = dict(r)
            try:
                d["indicators"] = json.loads(d["indicators"] or "[]")
            except Exception:
                d["indicators"] = []
            out.append(d)
        return out
    finally:
        conn.close()


def get_stats():
    conn = _connect()
    try:
        row = conn.execute(
            """SELECT
                 COUNT(*)                                            AS total,
                 SUM(CASE WHEN label='phishing'   THEN 1 ELSE 0 END) AS phishing,
                 SUM(CASE WHEN label='suspicious' THEN 1 ELSE 0 END) AS suspicious,
                 SUM(CASE WHEN label='legitimate' THEN 1 ELSE 0 END) AS legitimate
               FROM classifications"""
        ).fetchone()
        return {
            "total": row["total"] or 0,
            "phishing": row["phishing"] or 0,
            "suspicious": row["suspicious"] or 0,
            "legitimate": row["legitimate"] or 0,
        }
    finally:
        conn.close()


# ------------------------------------------------------------------
# Run this file directly to create the DB
# ------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print(f"Database created successfully at {DB_PATH}")
    print(f"Current stats: {get_stats()}")
