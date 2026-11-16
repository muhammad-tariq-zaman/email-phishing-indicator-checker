"""Check emails for phishing indicators and score them.

Usage: python3 main.py emails.csv [--internal-domains company.local]
CSV columns: email_id,from_address,display_name,subject,body.
Three indicators are checked (documented, heuristic only):
- URGENCY: the subject or body contains a pressure phrase
  (urgent, act now, verify immediately, account suspended,
  immediate action, password expiring).
- LINK MISMATCH: the body contains a link whose domain differs
  from the sender's domain.
- LOOKALIKE DOMAIN: the sender's domain is not an internal
  domain but is very similar to one (difflib ratio 0.8 or more),
  e.g. companny.local vs company.local.
Verdict: PHISHING LIKELY with 2 or more indicators, SUSPICIOUS
with 1, CLEAN with none.
"""
import argparse, csv, difflib, re, sys

URGENCY_PHRASES = ["urgent", "act now", "verify immediately",
                   "account suspended", "immediate action",
                   "password expiring"]

def check_email(row, internal_domains=()):
    text = (row["subject"] + " " + row["body"]).lower()
    indicators = []
    if any(phrase in text for phrase in URGENCY_PHRASES):
        indicators.append("URGENCY")
    sender_domain = row["from_address"].strip().rsplit("@", 1)[-1].lower()
    link_domains = [d.lower() for d in re.findall(r"https?://([A-Za-z0-9.-]+)", row["body"])]
    if any(domain != sender_domain for domain in link_domains):
        indicators.append("LINK MISMATCH")
    for internal in internal_domains:
        internal = internal.strip().lower()
        if sender_domain != internal and difflib.SequenceMatcher(
                None, sender_domain, internal).ratio() >= 0.8:
            indicators.append("LOOKALIKE DOMAIN")
            break
    if len(indicators) >= 2:
        verdict = "PHISHING LIKELY"
    elif len(indicators) == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return (row["email_id"].strip(), row["from_address"].strip(),
            verdict, indicators)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--internal-domains", default="",
                        help="comma-separated internal email domains")
    args = parser.parse_args(argv)
    internal = [d for d in args.internal_domains.split(",") if d.strip()]
    with open(args.path, newline="", encoding="utf-8") as f:
        results = [check_email(row, internal) for row in csv.DictReader(f)]
    for email_id, sender, verdict, indicators in results:
        detail = ", ".join(indicators) if indicators else "no indicators"
        print(f"{email_id} [{sender}]: {verdict} "
              f"({len(indicators)} indicator(s): {detail})")
    print(f"{sum(1 for *_, v, _ in results if v == 'PHISHING LIKELY')} phishing likely, "
          f"{sum(1 for *_, v, _ in results if v == 'SUSPICIOUS')} suspicious, "
          f"{sum(1 for *_, v, _ in results if v == 'CLEAN')} clean.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
