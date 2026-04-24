# ============================================================
# Phishing Threat Analysis Module
# CSCI 401 - John Jay Seniors
# Author: Imdadul Meraz - Security & Threat Analysis Specialist
# ============================================================

import re

# ------------------------------------------------------------------
# PHISHING INDICATOR TAXONOMY
# Defined based on MITRE ATT&CK T1566 and CISA phishing guidance
# ------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "verify now", "account suspended", "immediate action", "act now",
    "urgent", "login immediately", "confirm your identity", "within 24 hours",
    "your account will be closed", "verify your account", "limited time"
]

SENSITIVE_REQUEST_KEYWORDS = [
    "enter your password", "provide your ssn", "confirm your credit card",
    "update your billing", "enter your social security", "bank account number",
    "submit your credentials", "verify your payment"
]

SUSPICIOUS_LINK_PATTERNS = [
    r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP-based URL
    r"bit\.ly|tinyurl|t\.co|goo\.gl",                    # URL shorteners
    r"@.+\..+/",                                          # @ in URL (redirect trick)
    r"secure.*login.*\.(?!com$|org$|gov$)\w+",           # fake secure-login domains
]

SPOOFED_DOMAIN_PATTERNS = [
    r"paypa[l1]", r"g[o0]{2}gle", r"arnazon", r"micros0ft",
    r"app[l1]e", r"netf[l1]ix", r"[a4]mazon"
]


# ------------------------------------------------------------------
# RISK SCORER
# ------------------------------------------------------------------

def analyze_email(subject: str, sender: str, body: str) -> dict:
    """
    Analyzes an email and returns a risk report with detected indicators.
    Risk levels: LOW (0-2) | MEDIUM (3-5) | HIGH (6+)
    """
    score = 0
    indicators = []
    combined_text = (subject + " " + body).lower()

    # Check urgency language
    for phrase in URGENCY_KEYWORDS:
        if phrase in combined_text:
            score += 1
            indicators.append(f"[URGENCY] Found phrase: '{phrase}'")
            break  # count urgency once

    # Check sensitive information requests
    for phrase in SENSITIVE_REQUEST_KEYWORDS:
        if phrase in combined_text:
            score += 2
            indicators.append(f"[SENSITIVE REQUEST] Found phrase: '{phrase}'")
            break

    # Check suspicious links
    for pattern in SUSPICIOUS_LINK_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            score += 2
            indicators.append(f"[SUSPICIOUS LINK] Pattern matched: '{match.group()}'")

    # Check spoofed sender domains
    for pattern in SPOOFED_DOMAIN_PATTERNS:
        if re.search(pattern, sender, re.IGNORECASE):
            score += 3
            indicators.append(f"[DOMAIN SPOOF] Suspicious sender domain: '{sender}'")
            break

    # Determine risk level
    if score >= 6:
        risk = "HIGH"
        classification = "PHISHING"
    elif score >= 3:
        risk = "MEDIUM"
        classification = "SUSPICIOUS"
    else:
        risk = "LOW"
        classification = "LEGITIMATE"

    return {
        "subject": subject,
        "sender": sender,
        "score": score,
        "risk_level": risk,
        "classification": classification,
        "indicators": indicators if indicators else ["No suspicious indicators detected."]
    }


def print_report(report: dict):
    print("=" * 60)
    print(f"  SUBJECT      : {report['subject']}")
    print(f"  FROM         : {report['sender']}")
    print(f"  RISK SCORE   : {report['score']}")
    print(f"  RISK LEVEL   : {report['risk_level']}")
    print(f"  CLASSIFICATION: {report['classification']}")
    print("-" * 60)
    print("  DETECTED INDICATORS:")
    for indicator in report["indicators"]:
        print(f"    -> {indicator}")
    print("=" * 60)
    print()


# ------------------------------------------------------------------
# SAMPLE TEST EMAILS
# Created by Imdadul Meraz for system validation
# ------------------------------------------------------------------

test_emails = [
    {
        "label": "Test Case 1 - Obvious Phishing",
        "subject": "URGENT: Your PayPal account has been suspended",
        "sender": "support@paypa1-secure.net",
        "body": (
            "Dear customer, your account has been suspended due to unusual activity. "
            "You must verify your account immediately or it will be permanently closed. "
            "Click here to confirm your identity: http://192.168.1.45/paypal-login "
            "Please enter your password and credit card number to restore access."
        )
    },
    {
        "label": "Test Case 2 - Subtle Phishing (Spear Phishing Style)",
        "subject": "Action Required: Update your billing information",
        "sender": "billing@amaz0n-support.com",
        "body": (
            "Hello, we noticed an issue with your recent order. "
            "Please update your billing information within 24 hours to avoid cancellation. "
            "Visit: http://bit.ly/amzn-update to confirm your bank account number."
        )
    },
    {
        "label": "Test Case 3 - Legitimate Email",
        "subject": "Your order has shipped!",
        "sender": "no-reply@amazon.com",
        "body": (
            "Hi there, great news! Your order #113-4592011-2938476 has shipped. "
            "Expected delivery: March 30, 2026. Track your package at amazon.com/orders. "
            "Thank you for shopping with us."
        )
    },
    {
        "label": "Test Case 4 - Suspicious (Medium Risk)",
        "subject": "Verify your account to continue",
        "sender": "security@google-mail-support.info",
        "body": (
            "We detected a sign-in attempt on your account. "
            "If this was not you, act now to secure your account. "
            "Visit our support page for help."
        )
    }
]


# ------------------------------------------------------------------
# MAIN - Run all test cases
# ------------------------------------------------------------------

if __name__ == "__main__":
    print("\n PHISHING THREAT ANALYSIS - TEST RUN")
    print(" CSCI 401 | Security & Threat Analysis Module\n")

    for email in test_emails:
        print(f">>> {email['label']}")
        report = analyze_email(email["subject"], email["sender"], email["body"])
        print_report(report)
