#!/usr/bin/env python3
"""
Phishing Email Analysis & Detection Lab (college-level)

What it does:
- Reads .txt email samples in ./samples
- Extracts URLs
- Scores phishing risk based on simple, explainable heuristics
- Outputs a readable console report + a JSON report in ./output
"""

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Tuple

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"From:\s*.*<([^>]+)>", re.IGNORECASE)

SUSPICIOUS_TERMS = [
    "urgent", "immediately", "verify", "password expiring", "account lock",
    "confirm", "login", "reset", "security alert"
]

CRED_TERMS = ["password", "login", "verify", "reset", "confirm"]


@dataclass
class Finding:
    file: str
    score: int
    risk: str
    reasons: List[str]
    urls: List[str]


def extract_urls(text: str) -> List[str]:
    return URL_RE.findall(text)


def extract_sender_domain(text: str) -> str | None:
    m = EMAIL_RE.search(text)
    if not m:
        return None
    addr = m.group(1).strip().lower()
    if "@" in addr:
        return addr.split("@", 1)[1]
    return None


def score_email(text: str) -> Tuple[int, List[str], List[str]]:
    reasons: List[str] = []
    score = 0
    lower = text.lower()
    urls = extract_urls(text)

    # Language manipulation / urgency
    for term in SUSPICIOUS_TERMS:
        if term in lower:
            score += 6
            reasons.append(f"Urgency / social engineering term detected: '{term}'")

    # URL checks
    if urls:
        for u in urls:
            ul = u.lower()

            # IP-based URL (common phishing sign)
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", ul):
                score += 30
                reasons.append(f"IP-based URL detected: {u}")

            # Non-HTTPS
            if ul.startswith("http://"):
                score += 10
                reasons.append(f"Non-HTTPS link detected: {u}")

            # Suspicious TLDs (light heuristic)
            if any(tld in ul for tld in [".zip", ".click", ".top", ".xyz"]):
                score += 12
                reasons.append(f"Potentially suspicious TLD detected: {u}")

            # "login" in URL path
            if any(x in ul for x in ["/login", "/verify", "/reset"]):
                score += 10
                reasons.append(f"Credential-related URL path detected: {u}")
    else:
        reasons.append("No links detected.")

    # Credential harvesting pattern (keywords)
    if any(t in lower for t in CRED_TERMS) and ("click" in lower or "link" in lower):
        score += 18
        reasons.append("Credential-harvesting pattern: credentials + action to click/link.")

    # Sender domain sanity (very basic)
    sender_domain = extract_sender_domain(text)
    if sender_domain:
        if any(bad in sender_domain for bad in ["secure-", "helpdesk", "verify", "login"]):
            score += 8
            reasons.append(f"Sender domain looks suspicious: {sender_domain}")

    score = min(score, 100)
    return score, reasons, urls


def risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def main():
    sample_dir = Path("samples")
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    files = sorted(sample_dir.glob("*.txt"))
    if not files:
        print("No email samples found in ./samples (add .txt files).")
        return

    findings: List[Finding] = []
    print("\n=== Phishing Email Analysis Report ===\n")

    for f in files:
        text = f.read_text(errors="replace")
        score, reasons, urls = score_email(text)
        risk = risk_label(score)
        finding = Finding(file=f.name, score=score, risk=risk, reasons=reasons, urls=urls)
        findings.append(finding)

        print(f"{f.name}  ->  Risk: {risk} ({score}/100)")
        for r in reasons[:6]:
            print(f"  - {r}")
        if len(reasons) > 6:
            print("  - ...")
        print()

    report = {"findings": [asdict(x) for x in findings]}
    (out_dir / "phishing_report.json").write_text(json.dumps(report, indent=2))
    print("Saved JSON report to: output/phishing_report.json\n")


if __name__ == "__main__":
    main()
