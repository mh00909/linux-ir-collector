from __future__ import annotations
from typing import Dict, Tuple, List


def calculate_severity(all_results: Dict) -> Tuple[str, List[str]]:

    score = 0
    reasons = []

    logs = all_results.get("logs", {})
    failed_count = logs.get("findings", {}).get("failed_password_count", 0)

    if failed_count > 50:
        score += 3
        reasons.append(f"High number of failed SSH attempts ({failed_count})")
    elif failed_count > 10:
        score += 2
        reasons.append(f"Moderate failed SSH attempts ({failed_count})")
    elif failed_count > 0:
        score += 1
        reasons.append(f"Low failed SSH attempts ({failed_count})")

    persistence = all_results.get("persistence", {})
    findings = persistence.get("findings", {})

    suspicious_cron = findings.get("suspicious_cron_entries", [])
    suspicious_systemd = findings.get("suspicious_systemd_entries", [])

    if len(suspicious_cron) > 5:
        score += 3
        reasons.append("Multiple suspicious cron entries detected")
    elif len(suspicious_cron) > 0:
        score += 2
        reasons.append("Suspicious cron entries detected")

    if len(suspicious_systemd) > 5:
        score += 3
        reasons.append("Multiple suspicious systemd entries detected")
    elif len(suspicious_systemd) > 0:
        score += 2
        reasons.append("Suspicious systemd entries detected")

    if score >= 5:
        level = "HIGH"
    elif score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No significant suspicious indicators detected")

    return level, reasons
