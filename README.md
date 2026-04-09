Mini VAPT Framework
Web Application Vulnerability Assessment Tool
---

Project Overview
---
A lightweight, modular web application penetration testing framework built with Python (Flask) and HTML/CSS/JS. It provides automated scanning for common web vulnerabilities through an interactive browser-based dashboard.

Working Project link: https://suraj-mini-vapt-framework.onrender.com

Modules Included:
---
 **SQL Injection Scanner:**	Tests URL parameters for error-based & blind SQL injection using 15+ payloads. Findings sorted HIGH → MEDIUM → LOW

 **XSS Scanner:**	Detects reflected XSS, analyzes Content-Security-Policy headers with full recommendations

 **Header Security Auditor:**	Checks for missing security headers, insecure cookies, information disclosure. Sorted by severity

 **Port Scanner:**	Multithreaded TCP port scanner with service detection and banner grabbing

 **CVSS Risk Score Calculator:**	CVSS v3.1 inspired score (0-10) with remediation priority table sorted by severity

 **Report Generator:**	Exports full HTML or JSON assessment reports including CVSS score section

---
---
Testing (Legal Test Targets)
Only scan websites you own or have explicit written permission to test.
Unauthorized scanning is illegal under IT Act 2000 (India) and similar laws worldwide.
Safe practice targets:
`http://testphp.vulnweb.com/artists.php?artist=1` — SQL Injection testing
`http://testphp.vulnweb.com/search.php?test=query` — XSS testing
`http://testphp.vulnweb.com` — Header & Port scanning

---
API Endpoints
Method	Endpoint	Description
GET	`/`	Dashboard homepage
POST	`/api/scan/sql`	SQL injection scan
POST	`/api/scan/xss`	XSS scan
POST	`/api/scan/headers`	Header audit
POST	`/api/scan/ports`	Port scan
POST	`/api/scan/full`	Full scan — all modules
POST	`/api/cvss`	CVSS score calculation
POST	`/api/report`	Generate HTML/JSON report
GET	`/download/<filename>`	Download generated report

---
Working of each module
---
 
SQL Injection Scanner

Parses GET parameters from the URL
Injects 15 SQL payloads per parameter (', OR 1=1--, UNION SELECT etc.)
Detects error-based SQLi via 15 database error patterns
Detects blind SQLi via response size/status code changes
Findings sorted: HIGH → MEDIUM → LOW

 XSS Scanner
 
Injects 15 XSS payloads into GET parameters
Checks if payloads reflected verbatim (Reflected XSS)
Audits Content-Security-Policy header
Full remediation recommendations included
Findings sorted by severity

 Header Security Auditor
 
Checks for: HSTS, X-Frame-Options, X-Content-Type-Options, CSP,
Referrer-Policy, Permissions-Policy, X-XSS-Protection,
Cookie flags (HttpOnly, Secure, SameSite), information disclosure headers,
HTTPS enforcement. All findings sorted: HIGH → MEDIUM → LOW

 Port Scanner
 
Multithreaded (100 workers) TCP connect scan
Supports range (1-1024) and list (80,443,8080) formats
Service identification, banner grabbing, risk classification

 CVSS Risk Score Calculator
 
CVSS v3.1 inspired score (0.0 to 10.0)
Base scores per finding: SQL Injection=9.8, Reflected XSS=8.8, Missing HSTS=7.5
Ratings: None / Low / Medium / High / Critical
Remediation priority sorted: HIGH → MEDIUM → LOW
Included in HTML report

 Report Generator
 
Professional HTML reports with executive summary
Per-module findings with severity badges
CVSS Risk Score section with gauge and remediation priority
JSON export for raw data
UTF-8 encoding (Windows compatible)

---
 Fixes Applied
Issue	Fix
UnicodeEncodeError on Windows	Added encoding="utf-8" to all file writes
"See details" in recommendations	Fixed recommendation fallback
Findings not sorted by severity	Added HIGH→MEDIUM→LOW sorting to all modules
CVSS priority not sorted	Sort by severity first, then score

---
 Technologies Used
 ---
**Backend:** Python 3, Flask, requests, socket, concurrent.futures

**Risk Scoring:** Custom CVSS v3.1 inspired calculator

**Frontend:** Vanilla HTML5/CSS3/JS

**Fonts:** JetBrains Mono, Syne (Google Fonts)

---
 Future Scope
 ---
Directory Traversal Scanner
Sensitive File Finder (.env, /admin, /.git)
SSL/TLS Certificate Checker
POST Parameter Testing
Scan History with SQLite database
Web Crawler / Spider
PDF Report Export
Scheduled Scanning with Email Alerts

---
Mini VAPT Framework v1.0 — MSc IT Final Year Project
