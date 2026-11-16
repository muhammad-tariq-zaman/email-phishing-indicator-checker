# email-phishing-indicator-checker

Check emails for phishing indicators and score them (documented heuristic, not a verdict on its own): URGENCY for pressure phrases in the subject or body, LINK MISMATCH when a body link's domain differs from the sender's domain, LOOKALIKE DOMAIN when the sender's domain is very similar to an internal domain (difflib ratio 0.8+) — PHISHING LIKELY with 2+ indicators, SUSPICIOUS with 1, CLEAN with none.

Sample input is included (sample.csv with three emails).

## How to run

```sh
python3 main.py sample.csv --internal-domains company.local
```

## Example output

```
E-1 [support@secure-login.example]: PHISHING LIKELY (2 indicator(s): URGENCY, LINK MISMATCH)
E-2 [sara@company.local]: CLEAN (0 indicator(s): no indicators)
E-3 [admin@companny.local]: SUSPICIOUS (1 indicator(s): LOOKALIKE DOMAIN)
1 phishing likely, 1 suspicious, 1 clean.
```

Standard library only. Run the tests with `python3 -m unittest discover`.
