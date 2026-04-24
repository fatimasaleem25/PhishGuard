# ============================================================
# PhishGuard Mailbox Service
# CSCI 401 - John Jay Seniors
# Author: Fatima Saleem — AI System Integration
# ============================================================
#
# Connects PhishGuard to real mailboxes so we can test the ML
# model on live email data. Two import paths:
#   - IMAP fetch  (Gmail, Outlook, iCloud, any IMAP provider)
#   - .eml file   (drag-and-drop into the UI)
#
# Gmail setup:
#   1. Turn on 2-Step Verification at myaccount.google.com/security
#   2. Create an App Password at myaccount.google.com/apppasswords
#   3. Use imap.gmail.com / 993 / your email / the 16-char app password
# ============================================================

import imaplib
import ssl
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.policy import default as default_policy


# ------------------------------------------------------------------
# Header decoding (handles UTF-8, MIME-encoded subjects, etc.)
# ------------------------------------------------------------------
def _decode_header(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


# ------------------------------------------------------------------
# Body extraction — prefer text/plain, fall back to stripped HTML
# ------------------------------------------------------------------
def _extract_body(msg):
    """Return the plain-text body of an email.message.Message."""
    plain, html = None, None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp:
                continue
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode("utf-8", errors="replace")
            if ctype == "text/plain" and plain is None:
                plain = content
            elif ctype == "text/html" and html is None:
                html = content
    else:
        try:
            plain = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            plain = payload.decode("utf-8", errors="replace")

    body = plain or html or ""
    # Strip the crudest HTML if we had to use it
    if plain is None and html:
        import re
        body = re.sub(r"<[^>]+>", " ", body)
        body = re.sub(r"\s+", " ", body).strip()

    return body


# ------------------------------------------------------------------
# IMAP fetch
# ------------------------------------------------------------------
def fetch_imap(server: str, port: int, username: str, password: str,
               limit: int = 10, folder: str = "INBOX"):
    """
    Connect to an IMAP server and return the `limit` most recent emails.
    Returns a list of dicts: {id, sender, subject, date, body}
    """
    if not username or not password:
        raise ValueError("IMAP username and password are required.")
    limit = max(1, min(int(limit), 25))  # cap so we don't hammer the server

    ctx = ssl.create_default_context()
    mail = imaplib.IMAP4_SSL(server, int(port), ssl_context=ctx)
    try:
        mail.login(username, password)
        mail.select(folder, readonly=True)
        typ, data = mail.search(None, "ALL")
        if typ != "OK" or not data or not data[0]:
            return []

        ids = data[0].split()
        recent = ids[-limit:]  # most recent N
        emails = []

        for eid in reversed(recent):
            typ, msg_data = mail.fetch(eid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            msg = BytesParser(policy=default_policy).parsebytes(raw)
            emails.append({
                "id":      eid.decode("utf-8", errors="replace"),
                "sender":  _decode_header(msg.get("From", "")),
                "subject": _decode_header(msg.get("Subject", "")),
                "date":    msg.get("Date", ""),
                "body":    _extract_body(msg),
            })
        return emails
    finally:
        try: mail.logout()
        except Exception: pass


# ------------------------------------------------------------------
# .eml file parsing
# ------------------------------------------------------------------
def parse_eml_bytes(raw_bytes: bytes) -> dict:
    """Parse a raw .eml file (bytes) into {sender, subject, date, body}."""
    msg = BytesParser(policy=default_policy).parsebytes(raw_bytes)
    return {
        "sender":  _decode_header(msg.get("From", "")),
        "subject": _decode_header(msg.get("Subject", "")),
        "date":    msg.get("Date", ""),
        "body":    _extract_body(msg),
    }


if __name__ == "__main__":
    # Quick sanity check for parse_eml_bytes
    sample = (
        b"From: phisher@paypa1.ru\r\n"
        b"Subject: URGENT verify your account\r\n"
        b"Date: Fri, 24 Apr 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Your account will be suspended. Enter your password now."
    )
    print(parse_eml_bytes(sample))
