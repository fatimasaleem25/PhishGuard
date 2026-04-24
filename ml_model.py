"""
PhishGuard ML Model
-------------------
Author: Fatima Saleem (AI System Lead)
Course: CSCI 401 — John Jay Seniors Project

Trains a phishing email classifier using TF-IDF vectorization and
Logistic Regression on scikit-learn. Evaluates with precision,
recall, and F1-score. Saves the trained model + vectorizer to
model.pkl and exposes a predict() function that returns the same
dict format as threat_analysis.py, so backend.py can use either
detector interchangeably.

Usage:
    # Train from a dataset CSV
    python ml_model.py --train phishing_dataset.csv

    # Predict on a single email
    python ml_model.py --predict

    # Programmatic use
    from ml_model import predict
    result = predict(sender="...", subject="...", body="...")
"""

import argparse
import os
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"
DEFAULT_DATASET = BASE_DIR / "phishing_dataset.csv"


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------
URL_RE = re.compile(r"https?://\S+|www\.\S+")
EMAIL_RE = re.compile(r"\S+@\S+")
NON_ALPHA_RE = re.compile(r"[^a-zA-Z\s]")


def clean_text(text: str) -> str:
    """Lowercase, strip urls/emails, collapse whitespace."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = URL_RE.sub(" URL ", text)
    text = EMAIL_RE.sub(" EMAIL ", text)
    text = NON_ALPHA_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def combine_fields(sender: str, subject: str, body: str) -> str:
    """Join sender + subject + body into a single string for TF-IDF."""
    parts = [sender or "", subject or "", body or ""]
    return clean_text(" ".join(parts))


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------
def load_dataset(csv_path: Path) -> pd.DataFrame:
    """Load a labeled email CSV. Expected columns: sender, subject, body, label.

    `label` should be 1 for phishing, 0 for legitimate. If a `label` column
    isn't found, this falls back to common alternatives (type, class, target).
    """
    df = pd.read_csv(csv_path)

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Map common alternative names
    rename_map = {
        "from": "sender",
        "text": "body",
        "email": "body",
        "message": "body",
        "type": "label",
        "class": "label",
        "target": "label",
    }
    for old, new in rename_map.items():
        if old in df.columns and new not in df.columns:
            df = df.rename(columns={old: new})

    # Ensure required columns exist
    for col in ("sender", "subject", "body"):
        if col not in df.columns:
            df[col] = ""

    if "label" not in df.columns:
        raise ValueError(
            f"Dataset is missing a 'label' column. Found: {list(df.columns)}"
        )

    # Normalize labels to 0/1
    if df["label"].dtype == object:
        df["label"] = (
            df["label"]
            .astype(str)
            .str.lower()
            .map(
                {
                    "phishing": 1,
                    "phish": 1,
                    "spam": 1,
                    "malicious": 1,
                    "1": 1,
                    "legitimate": 0,
                    "legit": 0,
                    "ham": 0,
                    "safe": 0,
                    "0": 0,
                }
            )
        )

    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    df["text"] = df.apply(
        lambda r: combine_fields(r.get("sender", ""), r.get("subject", ""), r.get("body", "")),
        axis=1,
    )
    df = df[df["text"].str.len() > 0].reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Training + evaluation
# ---------------------------------------------------------------------------
def build_pipeline() -> Pipeline:
    """TF-IDF (1-2 grams) + Logistic Regression."""
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=0.95,
                    sublinear_tf=True,
                    stop_words="english",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    C=4.0,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )


def train(csv_path: Path = DEFAULT_DATASET, test_size: float = 0.2, seed: int = 42):
    """Train the classifier, print evaluation metrics, and save model.pkl."""
    if not csv_path.exists():
        print(f"[!] Dataset not found at {csv_path}. Generating sample dataset...")
        build_sample_dataset(csv_path)

    df = load_dataset(csv_path)
    print(f"[+] Loaded {len(df)} labeled emails ({df['label'].sum()} phishing, "
          f"{len(df) - df['label'].sum()} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=test_size,
        random_state=seed,
        stratify=df["label"] if df["label"].nunique() > 1 else None,
    )

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n=== Evaluation on held-out test set ===")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("\nConfusion matrix (rows=true, cols=pred):")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"],
                                zero_division=0))

    joblib.dump(pipe, MODEL_PATH)
    print(f"\n[+] Model saved to {MODEL_PATH}")

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
    }


# ---------------------------------------------------------------------------
# Sample dataset (bootstrap so the script runs end-to-end before Kevin's pipeline)
# ---------------------------------------------------------------------------
SAMPLE_ROWS = [
    # Phishing (label=1)
    ("security@paypa1.net", "URGENT: Verify your account NOW",
     "Your account will be suspended in 24 hours. Click here to verify: http://paypa1-login.ru/verify",
     1),
    ("no-reply@amaz0n-support.com", "Suspicious sign-in attempt",
     "We detected a login from a new device. Confirm your password immediately or your account will be locked.",
     1),
    ("hr-dept@mycompany-benefits.co", "Action required: Update payroll info",
     "Please re-enter your bank details within 12 hours to continue receiving paychecks. https://bit.ly/payroll-upd",
     1),
    ("admin@secure-update.org", "Your mailbox is full",
     "Click the link below to verify your identity and restore mailbox access or lose all data.",
     1),
    ("it-helpdesk@support-portal.info", "Password expires today",
     "Immediate action required. Reset your password within 1 hour using this secure link: http://reset-now.xyz",
     1),
    ("billing@netfl1x-accounts.com", "We couldn't process your payment",
     "Update your credit card info within 24 hours to avoid service interruption. Click verify.",
     1),
    ("ceo@yourcomp4ny.com", "Quick favor",
     "Are you at your desk? I need you to purchase gift cards for a client. Keep this confidential.",
     1),
    ("alert@chase-online.security-check.com", "Unusual activity detected",
     "We have temporarily frozen your account. Verify now to restore access: http://chase-verify.tk",
     1),
    ("docusign@doc-sign-secure.net", "You have a document to sign",
     "Important document awaiting your signature. Login here to review before deadline today.",
     1),
    ("wellsfargo@w3llsfargo-notify.com", "Your wire transfer is pending",
     "Confirm your routing number and password to release the pending wire.",
     1),
    ("fedex-delivery@track-package.co", "Package delivery failed",
     "Please pay a $2.99 redelivery fee here to receive your package: http://fedex-redeliver.shop",
     1),
    ("support@apple-id-secure.com", "Apple ID locked",
     "Your Apple ID has been locked due to suspicious activity. Unlock now to prevent termination.",
     1),
    ("hr@onboarding-portal.click", "Complete onboarding paperwork",
     "Urgent: sign the attached forms within 2 hours or your start date will be cancelled.",
     1),
    ("irs-refund@tax-refund-gov.us", "You have a tax refund of $1,284.00",
     "Claim your refund by providing your SSN and banking details at the secure link below.",
     1),
    ("office365@microsft-alerts.com", "Email quota exceeded",
     "Your account will be deactivated in 6 hours unless you validate credentials here.",
     1),
    ("linked1n@jobs-connect.cf", "Someone viewed your profile",
     "Login now to see who is interested in hiring you. Verify password to continue.",
     1),
    ("invoice@pay-remit.biz", "Invoice #48217 overdue",
     "Please wire the outstanding balance to the new account details attached. Urgent.",
     1),
    ("it-admin@corp-it-support.me", "Two-factor reset required",
     "To keep your account active, re-enroll in 2FA by entering your current password here.",
     1),
    ("bank-alerts@boa-secure.review", "Debit card temporarily disabled",
     "Reactivate your card by entering the full card number and pin at this secure portal.",
     1),
    ("no-reply@googIe-drive-share.com", "A file was shared with you",
     "Login with your Google password to view the confidential document before it expires.",
     1),

    # Legitimate (label=0)
    ("newsletter@medium.com", "Your weekly digest",
     "Here are the top stories from writers you follow this week. Enjoy reading.",
     0),
    ("noreply@github.com", "[repo] Pull request #42 opened",
     "A new pull request was opened on your repository. Review the changes when you have a moment.",
     0),
    ("team@slack.com", "Your Slack workspace activity",
     "You had 12 new messages in channels you follow this week. Sign in to Slack to catch up.",
     0),
    ("receipts@uber.com", "Your Tuesday morning trip with Uber",
     "Thanks for riding. Your fare was $14.20 charged to your card ending in 1234.",
     0),
    ("professor.jones@jjay.cuny.edu", "Office hours moved to Thursday",
     "Hi class, I'm moving this week's office hours to Thursday 2-4pm in NB 6.64. See you then.",
     0),
    ("orders@amazon.com", "Your order has shipped",
     "Your package will arrive Thursday. Track it anytime from Your Orders on amazon.com.",
     0),
    ("calendar-notification@google.com", "Reminder: team standup at 10am",
     "This is a reminder for your event team standup tomorrow at 10:00am.",
     0),
    ("no-reply@zoom.us", "Recording ready: CSCI 401 lecture",
     "Your cloud recording is now available. View it from your Zoom account dashboard.",
     0),
    ("alerts@nytimes.com", "Morning Briefing: Friday",
     "Here's what you need to know to start your day. Read the full briefing on nytimes.com.",
     0),
    ("notifications@stackoverflow.com", "Answer to your question",
     "Someone posted an answer to your question about Flask CORS. View it on stackoverflow.com.",
     0),
    ("michael.cruz@jjay.cuny.edu", "Backend endpoints merged",
     "Hey team, I just merged the /analyze and /history endpoints into main. Let me know if anything breaks.",
     0),
    ("kevin.minchala@jjay.cuny.edu", "Dataset notes",
     "I'm looking at the CLAIR corpus for our phishing samples. Will share a cleaned CSV by Friday.",
     0),
    ("billing@spotify.com", "Your receipt from Spotify",
     "Thanks for being a Premium member. Your $9.99 payment was successful.",
     0),
    ("noreply@canvas.instructure.com", "New announcement in CSCI 401",
     "Your instructor posted an announcement about next week's assignment. Log in to Canvas to read it.",
     0),
    ("friends@meetup.com", "Events you might like this weekend",
     "Here are three events near you based on your interests. RSVP any time from the Meetup app.",
     0),
    ("hello@duolingo.com", "Keep your streak alive!",
     "You're on a 14-day streak. A quick 5-minute lesson will keep it going today.",
     0),
    ("news@theverge.com", "The Verge: today's top stories",
     "Catch up on the biggest tech news of the day, curated by our editors.",
     0),
    ("info@jjay.cuny.edu", "Library hours update",
     "The Lloyd Sealy Library will have extended hours during finals week. See the schedule on our site.",
     0),
    ("no-reply@dropbox.com", "Your files are backed up",
     "All files in your Dropbox have been synced. You have 42GB available of your 2TB plan.",
     0),
    ("tickets@eventbrite.com", "Your ticket confirmation",
     "Your order for the TechConf panel is confirmed. Present this QR code at check-in.",
     0),
]


def build_sample_dataset(path: Path) -> None:
    """Write a tiny labeled dataset so the pipeline runs before Kevin's real data lands."""
    df = pd.DataFrame(SAMPLE_ROWS, columns=["sender", "subject", "body", "label"])
    df.to_csv(path, index=False)
    print(f"[+] Wrote sample dataset with {len(df)} rows to {path}")


# ---------------------------------------------------------------------------
# Prediction interface (matches threat_analysis.py output shape)
# ---------------------------------------------------------------------------
def _load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run `python ml_model.py --train` first."
        )
    return joblib.load(MODEL_PATH)


def _top_indicators(model: Pipeline, text: str, k: int = 5):
    """Return the top tokens pushing the prediction toward 'phishing'."""
    vec: TfidfVectorizer = model.named_steps["tfidf"]
    clf: LogisticRegression = model.named_steps["clf"]
    feature_names = vec.get_feature_names_out()
    x = vec.transform([text])
    # Per-token contribution = tfidf_weight * coefficient
    contributions = x.multiply(clf.coef_[0]).toarray()[0]
    top_idx = np.argsort(contributions)[::-1][:k]
    indicators = []
    for i in top_idx:
        if contributions[i] <= 0:
            continue
        indicators.append(
            {
                "type": "ML_FEATURE",
                "detail": f"Token '{feature_names[i]}' (weight={contributions[i]:.3f})",
            }
        )
    return indicators


def predict(sender: str = "", subject: str = "", body: str = "") -> dict:
    """Classify an email and return the same dict shape as threat_analysis.py.

    Returns:
        {
            "risk_level": "LOW" | "MEDIUM" | "HIGH",
            "classification": "phishing" | "suspicious" | "legitimate",
            "score": int (0-10),
            "confidence": float (0-1),
            "indicators": [{"type": ..., "detail": ...}, ...]
        }
    """
    model = _load_model()
    text = combine_fields(sender, subject, body)

    proba = float(model.predict_proba([text])[0][1])  # probability of phishing
    score = int(round(proba * 10))

    if proba >= 0.7:
        risk_level = "HIGH"
        classification = "phishing"
    elif proba >= 0.4:
        risk_level = "MEDIUM"
        classification = "suspicious"
    else:
        risk_level = "LOW"
        classification = "legitimate"

    # confidence = how far from the decision boundary (0.5)
    confidence = round(abs(proba - 0.5) * 2, 3)

    return {
        "risk_level": risk_level,
        "classification": classification,
        "score": score,
        "confidence": confidence,
        "indicators": _top_indicators(model, text),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli_predict_interactive():
    print("\n--- Predict a single email (leave fields blank to skip) ---")
    sender = input("Sender:  ")
    subject = input("Subject: ")
    print("Body (end with a blank line):")
    body_lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        body_lines.append(line)
    body = "\n".join(body_lines)

    result = predict(sender=sender, subject=subject, body=body)
    print("\n=== Prediction ===")
    for k, v in result.items():
        if k == "indicators":
            print("indicators:")
            for ind in v:
                print(f"  - [{ind['type']}] {ind['detail']}")
        else:
            print(f"{k}: {v}")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard ML model.")
    parser.add_argument(
        "--train",
        nargs="?",
        const=str(DEFAULT_DATASET),
        help="Train the model. Optionally pass a dataset CSV path.",
    )
    parser.add_argument(
        "--predict",
        action="store_true",
        help="Interactively classify an email using the saved model.",
    )
    parser.add_argument(
        "--sample-dataset",
        action="store_true",
        help=f"Write a small sample dataset to {DEFAULT_DATASET}.",
    )
    args = parser.parse_args()

    if args.sample_dataset:
        build_sample_dataset(DEFAULT_DATASET)
        return

    if args.train is not None:
        train(Path(args.train))
        return

    if args.predict:
        _cli_predict_interactive()
        return

    parser.print_help()


if __name__ == "__main__":
    main()
