# ============================================================
# Send Test Emails to PhishGuard's Local SMTP Server
# CSCI 401 - John Jay Seniors
# ============================================================
#
# Sends a canned phishing or legitimate email to 127.0.0.1:1025
# (local_mailserver.py) so you can watch PhishGuard classify it
# in real time.
#
# Usage:
#   python send_test_email.py phish
#   python send_test_email.py legit
#   python send_test_email.py subtle
# ============================================================

import smtplib
import sys
from email.message import EmailMessage

SAMPLES = {
    "phish": {
        "from":    "PayPal Security <support@paypa1-secure.net>",
        "subject": "URGENT: Your PayPal account has been suspended",
        "body": (
            "Dear customer, your account has been suspended due to unusual activity.\n"
            "You must verify your account immediately or it will be permanently closed.\n"
            "Click here to confirm your identity: http://192.168.1.45/paypal-login\n"
            "Please enter your password and credit card number to restore access.\n"
        ),
    },
    "subtle": {
        "from":    "Amazon Billing <billing@amaz0n-support.com>",
        "subject": "Action Required: Update your billing information",
        "body": (
            "Hello, we noticed an issue with your recent order.\n"
            "Please update your billing information within 24 hours to avoid cancellation.\n"
            "Visit: http://bit.ly/amzn-update to confirm your bank account number.\n"
        ),
    },
    "legit": {
        "from":    "Amazon <no-reply@amazon.com>",
        "subject": "Your order has shipped!",
        "body": (
            "Hi there, great news! Your order #113-4592011 has shipped.\n"
            "Expected delivery: next Tuesday. Track your package at amazon.com/orders.\n"
            "Thank you for shopping with us.\n"
        ),
    },
}


def main():
    kind = (sys.argv[1] if len(sys.argv) > 1 else "phish").lower()
    if kind not in SAMPLES:
        print(f"Unknown sample '{kind}'. Choose from: {', '.join(SAMPLES)}")
        sys.exit(1)

    sample = SAMPLES[kind]
    msg = EmailMessage()
    msg["From"]    = sample["from"]
    msg["To"]      = "victim@test.local"
    msg["Subject"] = sample["subject"]
    msg.set_content(sample["body"])

    with smtplib.SMTP("127.0.0.1", 1025) as s:
        s.send_message(msg)

    print(f"[+] Sent '{kind}' sample to 127.0.0.1:1025")
    print(f"    Check the local_mailserver.py terminal for the verdict.")


if __name__ == "__main__":
    main()
