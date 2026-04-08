import requests
import time

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS).",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks.",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Content-Security-Policy": {
        "description": "Restricts resource loading to prevent XSS and injection attacks.",
        "severity": "HIGH",
        "recommendation": "Define a strict CSP policy, e.g.: default-src 'self'",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent with requests.",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: no-referrer-when-downgrade",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, geolocation, etc.).",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "description": "Legacy browser XSS filter (deprecated but still checked).",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block  (or rely on CSP instead)",
    },
}

INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
]

def check_cookie_security(response) -> list:
    """Analyze Set-Cookie headers for security flags."""
    findings = []
    cookies = response.headers.get("Set-Cookie", "")
    if not cookies:
        return findings
    cookie_list = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else [cookies]
    for cookie in cookie_list:
        name = cookie.split("=")[0].strip()
        cookie_lower = cookie.lower()
        if "httponly" not in cookie_lower:
            findings.append({
                "type": "Cookie Missing HttpOnly Flag",
                "severity": "MEDIUM",
                "header": "Set-Cookie",
                "detail": f"Cookie '{name}' lacks HttpOnly — accessible via JavaScript.",
                "recommendation": "Add HttpOnly flag to prevent JS cookie theft.",
            })
        if "secure" not in cookie_lower:
            findings.append({
                "type": "Cookie Missing Secure Flag",
                "severity": "MEDIUM",
                "header": "Set-Cookie",
                "detail": f"Cookie '{name}' lacks Secure flag — may be sent over HTTP.",
                "recommendation": "Add Secure flag so cookie is only sent over HTTPS.",
            })
        if "samesite" not in cookie_lower:
            findings.append({
                "type": "Cookie Missing SameSite Attribute",
                "severity": "LOW",
                "header": "Set-Cookie",
                "detail": f"Cookie '{name}' lacks SameSite — vulnerable to CSRF.",
                "recommendation": "Add SameSite=Strict or SameSite=Lax.",
            })
    return findings

def check_headers(url: str) -> dict:
    """
    Audit HTTP response headers for security misconfigurations,
    missing protections, and information disclosure.
    """
    findings = []
    start_time = time.time()

    req_headers = {
        "User-Agent": "Mozilla/5.0 (VAPT-Scanner/1.0) Security Assessment Tool"
    }

    try:
        resp = requests.get(url, headers=req_headers, timeout=10, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return {
            "module": "Broken Auth / Header Security Checker",
            "status": "error",
            "error": str(e),
            "findings": [],
            "risk_level": "unknown",
            "duration": 0,
        }

    response_headers = dict(resp.headers)
    present_headers = {k.lower(): v for k, v in response_headers.items()}

    # 1. Check for missing/weak security headers
    header_audit = []
    for header_name, meta in SECURITY_HEADERS.items():
        present = header_name.lower() in present_headers
        value = response_headers.get(header_name, "")
        header_entry = {
            "header": header_name,
            "present": present,
            "value": value if present else None,
            "description": meta["description"],
            "severity": meta["severity"] if not present else "INFO",
            "recommendation": None if present else meta["recommendation"],
        }
        header_audit.append(header_entry)
        if not present:
            findings.append({
                "type": f"Missing Security Header: {header_name}",
                "severity": meta["severity"],
                "header": header_name,
                "detail": f"Header '{header_name}' is absent. {meta['description']}",
                "recommendation": meta["recommendation"],
            })

    # 2. Check for information disclosure headers
    info_disclosure = []
    for h in INFORMATION_DISCLOSURE_HEADERS:
        if h.lower() in present_headers:
            val = response_headers.get(h, "")
            info_disclosure.append({"header": h, "value": val})
            findings.append({
                "type": "Information Disclosure Header",
                "severity": "LOW",
                "header": h,
                "detail": f"Header '{h}: {val}' reveals server/technology info.",
                "recommendation": f"Remove or mask the '{h}' header to reduce fingerprinting.",
            })

    # 3. Check cookie security
    cookie_findings = check_cookie_security(resp)
    findings.extend(cookie_findings)

    # 4. Check HTTPS redirect
    if url.startswith("http://"):
        final_url = resp.url
        if final_url.startswith("https://"):
            http_redirect = {"redirects_to_https": True}
        else:
            http_redirect = {"redirects_to_https": False}
            findings.append({
                "type": "No HTTPS Redirect",
                "severity": "HIGH",
                "header": "N/A",
                "detail": "Site served over HTTP without redirecting to HTTPS.",
                "recommendation": "Configure 301 redirect from HTTP to HTTPS.",
            })
    else:
        http_redirect = {"redirects_to_https": True}

    duration = round(time.time() - start_time, 2)

    # Sort findings: HIGH first, then MEDIUM, then LOW
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

    severities = [f["severity"] for f in findings]
    if "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    elif "LOW" in severities:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    return {
        "module": "Broken Auth / Header Security Checker",
        "status": "completed",
        "target": url,
        "status_code": resp.status_code,
        "findings": findings,
        "header_audit": header_audit,
        "info_disclosure": info_disclosure,
        "https_check": http_redirect,
        "risk_level": risk_level,
        "duration": duration,
        "summary": f"{len(findings)} header/cookie issue(s) found. {len(info_disclosure)} disclosure header(s).",
    }
