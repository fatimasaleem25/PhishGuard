# PhishGuard — Autonomous Phishing Email Detector

**CSCI 401 · John Jay Seniors · Spring 2026**

A hybrid phishing email detector combining a trained machine-learning
classifier (TF-IDF + Logistic Regression) with a rule-based MITRE
ATT&CK T1566 scorer. Connects to real mailboxes (Gmail, Outlook,
iCloud, Yahoo) over IMAP, accepts `.eml` file uploads, and ships with
a local SMTP test server for classroom demos.

---

## Team

| Member | Role | Owns |
|---|---|---|
| Michael Cruz | Database & Backend Engineer | `backend.py`, `database_sql.py` |
| Fatima Saleem | AI System Lead | `ml_model.py`, `mailbox_service.py`, `local_mailserver.py` |
| Muhammad H. Kardar | Frontend & Development Engineer | `frontend.html`, Chrome extension |
| Imdadul Meraz | Security & Threat Analysis Specialist | `threat_analysis.py` |
| Kevin Minchala | Data Engineering Lead | `phishing_dataset.csv` |

---

## What each file does

```
PhishGuard/
├── backend.py              Flask REST API. Serves the UI, wires ML + rules + DB.
├── ml_model.py             Fatima's classifier. TF-IDF + Logistic Regression.
│                           Exposes train() and predict(). Saves model.pkl.
├── threat_analysis.py      Imdadul's rule-based MITRE T1566 scorer (fallback).
├── database_sql.py         Michael's SQLite schema + CRUD helpers.
├── mailbox_service.py      Fatima's IMAP + .eml parser.
├── local_mailserver.py     Local test SMTP server on port 1025.
├── send_test_email.py      CLI: sends sample phish/legit emails to the local server.
├── frontend.html           Muhammad's UI. Served by backend.py at /.
├── phishing_dataset.csv    Kevin's labeled training data.
├── model.pkl               Trained ML model (auto-generated).
├── phishing.db             SQLite DB (auto-generated on first run).
└── requirements.txt        Python dependencies.
```

---

## Setup (first time)

You need **Python 3.9+**. On macOS the command is `python3`; on
Windows it's usually just `python`.

### 1. Clone the repo

```bash
git clone <your-repo-url>
cd PhishGuard
```

### 2. Create and activate a virtual environment

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

Your prompt should now start with `(venv)`. All further commands assume
this.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create the database (one-time)

```bash
python database_sql.py
```

You should see: `Database created successfully at .../phishing.db`.

### 5. (Optional) Train the ML model

```bash
python ml_model.py --train
```

Prints **Precision / Recall / F1** on the held-out test set and saves
`model.pkl`. The backend auto-trains on first launch if you skip this,
so it's optional — but run it yourself if you want to screenshot the
metrics for the final report.

---

## Running the app

### Main UI (one terminal)

```bash
source venv/bin/activate
python backend.py
```

Open **http://127.0.0.1:5000** in your browser. You'll see three tabs:

1. **Paste & Analyze** — paste any email, see risk score + indicators.
2. **Connect Mailbox** — three ways to test on real email (below).
3. **History & Stats** — Chart.js summary + scan table.

Press `Ctrl+C` in the terminal to stop the server.

---

## Testing on real email

### Option A — Gmail / Outlook / iCloud via IMAP

**Gmail setup (one time):**

1. Turn on 2-Step Verification at <https://myaccount.google.com/security>.
2. Create an **App Password** at <https://myaccount.google.com/apppasswords>
   (Mail → Other → "PhishGuard"). Copy the 16-character password.

In the PhishGuard UI, go to the **Connect Mailbox** tab:

- Server: `imap.gmail.com` · Port: `993`
- Email address: your Gmail
- Password: the 16-character app password (not your normal Google password)
- Fetch last N: 10
- Click **Fetch & Scan Inbox**.

Outlook / iCloud / Yahoo are in the same dropdown — they all work the
same way with their own app-password systems.

Credentials are sent only to `127.0.0.1` (your own machine) and are
never written to disk.

### Option B — Upload a .eml file (no credentials)

In Gmail: open any email → three-dot menu → **Download message** →
save the `.eml` file. In PhishGuard → **Connect Mailbox** → **Upload a
.eml file** → pick the file → **Upload & Scan**.

### Option C — Local SMTP test server (for classroom demos)

This needs **three terminal tabs**, all with `source venv/bin/activate`
run first.

**Terminal 1 — backend:**
```bash
python backend.py
```

**Terminal 2 — local SMTP server:**
```bash
python local_mailserver.py
```

**Terminal 3 — send a test email:**
```bash
python send_test_email.py phish      # obvious phishing
python send_test_email.py subtle     # medium-risk
python send_test_email.py legit      # legitimate
```

Terminal 2 prints a live verdict for every email it receives (risk
level, score, confidence, top ML indicator tokens). All scans also
show up in the **History & Stats** tab of the UI.

---

## API reference

Base URL: `http://127.0.0.1:5000`

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET  | `/`               | — | Serves `frontend.html` |
| GET  | `/health`         | — | `{"status":"ok", "ml_available":bool, "model_file_exists":bool}` |
| POST | `/analyze`        | `{sender, subject, body}` | Hybrid scan (ML first, rules fallback) |
| POST | `/mailbox/imap`   | `{server, port, username, password, limit}` | Fetch and scan IMAP inbox |
| POST | `/mailbox/upload` | multipart `file=<.eml>` | Parse and scan a `.eml` file |
| GET  | `/history?limit=N`| — | Last N scans |
| GET  | `/stats`          | — | Counts by label |

### Sample `/analyze` response

```json
{
  "email_id": 1,
  "risk_level": "HIGH",
  "classification": "phishing",
  "score": 8,
  "confidence": 0.85,
  "detector": "ml",
  "indicators": [
    { "type": "ML_FEATURE", "detail": "Token 'verify' (weight=0.332)" },
    { "type": "ML_FEATURE", "detail": "Token 'password' (weight=0.256)" }
  ]
}
```

---

## Troubleshooting

### `zsh: command not found: python` (macOS)

On macOS the system command is `python3`, not `python`. But inside an
activated venv, `python` works. If you haven't activated yet:

```bash
source venv/bin/activate
```

### `ModuleNotFoundError: No module named 'flask'`

You didn't activate the venv, or you didn't install dependencies.

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Port 5000 already in use (macOS)

Mac's AirPlay Receiver uses port 5000 by default. Either turn it off
in System Settings → General → AirDrop & Handoff → "AirPlay Receiver",
or change the last line of `backend.py` to `port=5001` and use
<http://127.0.0.1:5001>.

### `bquote>` or `dquote>` appears in the terminal

You pasted something with an unclosed quote. Press `Ctrl+C` to cancel
and get your prompt back.

### IMAP returns "Invalid credentials"

Gmail (and most providers) no longer allow IMAP login with your real
password. You must use an **App Password**. See the Gmail setup above.

### `model.pkl` not found

The backend auto-trains on first boot. If something went wrong, just
run it manually:

```bash
python ml_model.py --train
```

---

## Deliverables map (grading rubric)

| Rubric item | Where to find it |
|---|---|
| Problem + technical design | Project Proposal PDF + this README |
| Cybersecurity coverage | `threat_analysis.py` (MITRE T1566) |
| ML model + evaluation (precision/recall/F1) | `python ml_model.py --train` output |
| Working code | `backend.py` + `frontend.html` + integrated modules |
| Dataset | `phishing_dataset.csv` |
| Real-world integration | `/mailbox/imap`, `/mailbox/upload`, `local_mailserver.py` |

---

## License & notes

Academic project for CSCI 401 at John Jay College (CUNY), Spring 2026.
Not for production use. Handle mailbox credentials responsibly — the
app only transmits them to `127.0.0.1` and never stores them, but you
should revoke the app password after your demo.
