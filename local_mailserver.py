# ============================================================
# PhishGuard Local Test Mail Server
# CSCI 401 - John Jay Seniors
# Author: Fatima Saleem — AI System Integration
# ============================================================
#
# Tiny SMTP server that receives test emails on 127.0.0.1:1025
# and forwards each one to the /analyze endpoint of backend.py.
# No real mailbox needed — purely for demoing the ML model on
# synthetic phishing samples in a controlled environment.
#
# Run alongside backend.py in a SECOND terminal:
#   python local_mailserver.py
#
# Then send a test email:
#   python send_test_email.py phish
#   python send_test_email.py legit
#
# Or from any SMTP client pointing at 127.0.0.1:1025.
# ============================================================

import asyncio
import email
import json
import urllib.request
from email.policy import default as default_policy

from aiosmtpd.controller import Controller

BACKEND = "http://127.0.0.1:5000/analyze"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1025


def _extract_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    pass
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


class PhishGuardHandler:
    async def handle_DATA(self, server, session, envelope):
        raw = envelope.content
        msg = email.message_from_bytes(raw, policy=default_policy)

        sender  = str(msg.get("From", envelope.mail_from or ""))
        subject = str(msg.get("Subject", ""))
        body    = _extract_body(msg)

        payload = json.dumps({
            "sender":  sender,
            "subject": subject,
            "body":    body,
        }).encode("utf-8")

        req = urllib.request.Request(
            BACKEND, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
        except Exception as e:
            print(f"\n[!] Could not reach backend at {BACKEND}: {e}")
            print("    Is backend.py running?")
            return "250 Message accepted for delivery"

        print("\n" + "─" * 60)
        print(f"  From    : {sender}")
        print(f"  Subject : {subject}")
        print(f"  Risk    : {result.get('risk_level')}  →  {result.get('classification','').upper()}")
        print(f"  Score   : {result.get('score')}   "
              f"Confidence: {result.get('confidence', 0) * 100:.0f}%   "
              f"Detector: {result.get('detector')}")
        for ind in (result.get("indicators") or [])[:5]:
            text = ind if isinstance(ind, str) else f"[{ind.get('type')}] {ind.get('detail')}"
            print(f"    • {text}")
        print("─" * 60)

        return "250 Message accepted for delivery"


def main():
    controller = Controller(PhishGuardHandler(), hostname=LISTEN_HOST, port=LISTEN_PORT)
    controller.start()
    print("=" * 60)
    print(f"  PhishGuard local SMTP test server")
    print(f"  Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  Forwarding every received email to {BACKEND}")
    print("=" * 60)
    print("  Send test emails with:")
    print("    python send_test_email.py phish")
    print("    python send_test_email.py legit")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopping server.")
        controller.stop()


if __name__ == "__main__":
    main()
