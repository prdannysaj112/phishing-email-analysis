# phishing-email-analysis

Cybersecurity project that analyzes email text samples and flags phishing indicators using explainable, rule-based heuristics.

## Features
- Extracts URLs and identifies suspicious link patterns (IP URLs, non-HTTPS, credential paths)
- Detects urgency/social engineering language
- Produces a risk score and a clear explanation of why an email was flagged
- Exports results to JSON for reporting

## Tech
- Python (no external dependencies)

## Run
```bash
python phishing_detector.py
