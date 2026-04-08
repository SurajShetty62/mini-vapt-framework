"""
CVSS-inspired Risk Score Calculator for Mini VAPT Framework
Calculates a 0-10 security score based on findings from all modules.
Based on CVSS v3.1 severity ratings:
  Critical: 9.0-10.0
  High:     7.0-8.9
  Medium:   4.0-6.9
  Low:      0.1-3.9
  None:     0.0
"""

# Base scores for each finding type (CVSS-inspired)
FINDING_SCORES = {
    # SQL Injection
    "Error-Based SQL Injection":          9.8,
    "Potential Blind SQL Injection":       7.5,

    # XSS
    "Reflected XSS":                       8.8,
    "Partial XSS Reflection (Tags Stripped)": 4.3,
    "Missing Content-Security-Policy":     5.4,

    # Headers
    "Missing Security Header: Strict-Transport-Security":  7.5,
    "Missing Security Header: Content-Security-Policy":    6.1,
    "Missing Security Header: X-Frame-Options":            6.5,
    "Missing Security Header: X-Content-Type-Options":     5.3,
    "Missing Security Header: Referrer-Policy":            3.1,
    "Missing Security Header: Permissions-Policy":         3.1,
    "Missing Security Header: X-XSS-Protection":           3.1,
    "Information Disclosure Header":                       4.3,
    "Cookie Missing HttpOnly Flag":                        6.5,
    "Cookie Missing Secure Flag":                          6.5,
    "Cookie Missing SameSite Attribute":                   5.4,
    "No HTTPS Redirect":                                   7.5,

    # Ports
    "Open HIGH Risk Port":                 8.5,
    "Open MEDIUM Risk Port":               5.5,
    "Open LOW Risk Port":                  2.5,
}

SEVERITY_BASE = {
    "HIGH":   8.0,
    "MEDIUM": 5.5,
    "LOW":    2.5,
    "INFO":   1.0,
}

def get_finding_score(finding: dict) -> float:
    """Get CVSS base score for a specific finding."""
    ftype = finding.get("type", "")

    # Try exact match first
    if ftype in FINDING_SCORES:
        return FINDING_SCORES[ftype]

    # Try partial match for port findings
    for key in FINDING_SCORES:
        if key in ftype or ftype in key:
            return FINDING_SCORES[key]

    # Fall back to severity-based score
    sev = finding.get("severity", "LOW").upper()
    return SEVERITY_BASE.get(sev, 2.5)

def calculate_cvss_score(results: dict) -> dict:
    """
    Calculate overall CVSS-inspired security score for the target.
    Returns score (0-10), rating, breakdown per module, and per-finding scores.
    """
    all_findings = []
    module_scores = {}

    module_map = {
        "sql_injection": "SQL Injection",
        "xss":           "XSS Scanner",
        "headers":       "Header Audit",
        "ports":         "Port Scanner",
    }

    for key, label in module_map.items():
        module = results.get(key, {})
        findings = module.get("findings", [])
        scored = []

        for f in findings:
            score = get_finding_score(f)
            scored.append({
                "type":     f.get("type", "Unknown"),
                "severity": f.get("severity", "LOW"),
                "score":    score,
            })
            all_findings.append(score)

        if scored:
            module_max = max(s["score"] for s in scored)
            module_avg = round(sum(s["score"] for s in scored) / len(scored), 1)
        else:
            module_max = 0.0
            module_avg = 0.0

        module_scores[label] = {
            "findings_count": len(scored),
            "max_score":      round(module_max, 1),
            "avg_score":      module_avg,
            "findings":       scored,
            "risk_level":     module.get("risk_level", "NONE"),
        }

    # Overall score calculation
    # Uses highest score with penalty multiplier for multiple findings
    if not all_findings:
        overall_score = 0.0
    else:
        max_score = max(all_findings)
        count_penalty = min(len(all_findings) * 0.1, 1.5)  # max +1.5 for many findings
        overall_score = min(round(max_score + count_penalty, 1), 10.0)

    # CVSS rating
    if overall_score >= 9.0:
        rating = "CRITICAL"
        color  = "#7c3aed"
        description = "Immediate action required. Critical vulnerabilities present."
    elif overall_score >= 7.0:
        rating = "HIGH"
        color  = "#ef4444"
        description = "Serious vulnerabilities found. Remediate as soon as possible."
    elif overall_score >= 4.0:
        rating = "MEDIUM"
        color  = "#f97316"
        description = "Moderate risk. Schedule fixes in near future."
    elif overall_score > 0.0:
        rating = "LOW"
        color  = "#eab308"
        description = "Minor issues found. Low immediate risk."
    else:
        rating = "NONE"
        color  = "#22c55e"
        description = "No vulnerabilities detected. Good security posture."

    # Counts
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for key in module_map:
        module = results.get(key, {})
        for f in module.get("findings", []):
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

    return {
        "overall_score":   overall_score,
        "rating":          rating,
        "color":           color,
        "description":     description,
        "total_findings":  len(all_findings),
        "counts":          counts,
        "module_scores":   module_scores,
        "cvss_version":    "CVSS v3.1 inspired",
        "target":          results.get("target", "N/A"),
        "timestamp":       results.get("timestamp", "N/A"),
    }


def get_remediation_priority(results: dict) -> list:
    """Return findings sorted by CVSS score — highest first."""
    prioritized = []

    module_map = {
        "sql_injection": "SQL Injection",
        "xss":           "XSS Scanner",
        "headers":       "Header Audit",
        "ports":         "Port Scanner",
    }

    for key, label in module_map.items():
        module = results.get(key, {})
        for f in module.get("findings", []):
            score = get_finding_score(f)
            prioritized.append({
                "module":         label,
                "type":           f.get("type", "Unknown"),
                "severity":       f.get("severity", "LOW"),
                "cvss_score":     score,
                "recommendation": f.get("recommendation", f.get("description", "")),
            })

    # Sort by severity first (HIGH > MEDIUM > LOW), then by score within each group
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    prioritized.sort(key=lambda x: (sev_order.get(x["severity"], 4), -x["cvss_score"]))
    return prioritized
