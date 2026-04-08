import requests
import urllib.parse
import time
import re

# XSS payloads covering reflected, DOM-based indicators
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
    "\"><img src=\"\" onerror=\"alert('XSS')\">",
    "<details open ontoggle=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
]

def check_csp_header(headers: dict) -> dict:
    """Check if Content-Security-Policy header is present and strong."""
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        return {"present": False, "value": None, "issues": ["No CSP header found — browser has no XSS mitigation policy."]}
    issues = []
    if "unsafe-inline" in csp:
        issues.append("CSP allows 'unsafe-inline' which weakens XSS protection.")
    if "unsafe-eval" in csp:
        issues.append("CSP allows 'unsafe-eval' which can be exploited.")
    if "*" in csp:
        issues.append("CSP uses wildcard '*' which is overly permissive.")
    return {"present": True, "value": csp, "issues": issues}

def scan_xss(url: str) -> dict:
    """
    Test URL for reflected XSS by injecting payloads into query parameters
    and checking if they appear unencoded in the response.
    """
    findings = []
    tested_params = []
    total_tests = 0
    start_time = time.time()

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"]}
        base_url = url.rstrip("/")
    else:
        base_url = parsed.scheme + "://" + parsed.netloc + parsed.path

    headers_req = {
        "User-Agent": "Mozilla/5.0 (VAPT-Scanner/1.0) Security Assessment Tool"
    }

    # Grab response headers for CSP check
    csp_result = {"present": False, "value": None, "issues": ["Could not fetch headers."]}
    try:
        head_resp = requests.get(url, headers=headers_req, timeout=8, verify=False)
        csp_result = check_csp_header(dict(head_resp.headers))
    except requests.RequestException:
        pass

    for param_name in params:
        tested_params.append(param_name)
        original_value = params[param_name][0]

        for payload in XSS_PAYLOADS:
            total_tests += 1
            test_params = dict(params)
            test_params[param_name] = [payload]
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = base_url + "?" + query_string

            try:
                resp = requests.get(test_url, headers=headers_req, timeout=8, verify=False)
                response_text = resp.text

                # Check if payload is reflected unencoded
                if payload in response_text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Payload reflected verbatim in response body.",
                        "url": test_url,
                        "description": f"Unencoded XSS payload found in response for parameter '{param_name}'.",
                    })
                    break  # One confirmed finding per param is enough

                # Check if partially reflected (tag stripped but content present)
                stripped = re.sub(r"<[^>]+>", "", payload)
                if stripped and stripped in response_text and payload not in response_text:
                    findings.append({
                        "type": "Partial XSS Reflection (Tags Stripped)",
                        "severity": "LOW",
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": "Payload content reflected but HTML tags were stripped.",
                        "url": test_url,
                        "description": "Input is reflected but HTML is being filtered — may be bypassable.",
                    })

            except requests.RequestException:
                continue

    duration = round(time.time() - start_time, 2)

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["parameter"], f["type"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Sort findings: HIGH first, then MEDIUM, then LOW
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    unique_findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

    risk_level = "NONE"
    if unique_findings:
        severities = [f["severity"] for f in unique_findings]
        if "HIGH" in severities:
            risk_level = "HIGH"
        elif "MEDIUM" in severities:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

    # CSP absence is also a finding
    csp_finding = None
    if not csp_result["present"]:
        csp_finding = {
            "type": "Missing Content-Security-Policy",
            "severity": "MEDIUM",
            "parameter": "HTTP Header",
            "payload": "N/A",
            "evidence": "CSP header missing from HTTP response, browsers cannot block malicious scripts.",
            "description": "No CSP header found. This increases XSS risk.",
                "recommendation": "Add Content-Security-Policy: default-src 'self' to block malicious scripts.",
        }
        if risk_level == "NONE":
            risk_level = "MEDIUM"

    return {
        "module": "XSS Scanner",
        "status": "completed",
        "target": url,
        "findings": unique_findings + ([csp_finding] if csp_finding else []),
        "csp_analysis": csp_result,
        "risk_level": risk_level,
        "tested_params": tested_params,
        "total_tests": total_tests,
        "duration": duration,
        "summary": f"{len(unique_findings)} XSS vulnerabilities found. CSP {'present' if csp_result['present'] else 'missing'}.",
    }
