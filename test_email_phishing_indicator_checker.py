import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import check_email

def row(email_id, sender, display, subject, body):
    return {"email_id": email_id, "from_address": sender,
            "display_name": display, "subject": subject, "body": body}

class TestPhishingChecker(unittest.TestCase):
    def test_urgency_flagged(self):
        r = check_email(row("E-1", "a@company.local", "IT", "Urgent: act now", "Please read"))
        self.assertIn("URGENCY", r[3])

    def test_link_mismatch_flagged(self):
        r = check_email(row("E-1", "a@secure-login.example", "IT", "Hello",
                            "Click https://company-login.example/verify"))
        self.assertIn("LINK MISMATCH", r[3])

    def test_link_same_domain_ok(self):
        r = check_email(row("E-1", "a@company.local", "IT", "Hello",
                            "See https://company.local/docs for details"))
        self.assertEqual(r[3], [])

    def test_lookalike_domain_flagged(self):
        r = check_email(row("E-1", "admin@companny.local", "Admin",
                            "Password expiry notice", "Your password expires soon"),
                        internal_domains=["company.local"])
        self.assertIn("LOOKALIKE DOMAIN", r[3])

    def test_exact_internal_domain_not_lookalike(self):
        r = check_email(row("E-1", "a@company.local", "IT", "Hello", "Hi"),
                        internal_domains=["company.local"])
        self.assertEqual(r[3], [])

    def test_two_indicators_phishing_likely(self):
        r = check_email(row("E-1", "a@secure-login.example", "IT", "Urgent: verify now",
                            "Click https://evil.example/reset"))
        self.assertEqual(r[2], "PHISHING LIKELY")

    def test_one_indicator_suspicious(self):
        r = check_email(row("E-1", "a@company.local", "IT", "Urgent: read this", "Hello"))
        self.assertEqual(r[2], "SUSPICIOUS")

    def test_clean_email(self):
        r = check_email(row("E-1", "sara@company.local", "Sara", "Team lunch", "See you at noon"))
        self.assertEqual((r[2], r[3]), ("CLEAN", []))
