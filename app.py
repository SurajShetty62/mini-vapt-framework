from flask import Flask, render_template, request, jsonify, send_file
import json, os, datetime
from modules.sql_scanner import scan_sql_injection
from modules.xss_scanner import scan_xss
from modules.header_checker import check_headers
from modules.port_scanner import scan_ports
from modules.report_generator import generate_report
from modules.risk_calculator import calculate_cvss_score, get_remediation_priority

app = Flask(__name__)
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan/sql", methods=["POST"])
def sql_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = scan_sql_injection(url)
    return jsonify(result)

@app.route("/api/scan/xss", methods=["POST"])
def xss_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = scan_xss(url)
    return jsonify(result)

@app.route("/api/scan/headers", methods=["POST"])
def header_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = check_headers(url)
    return jsonify(result)

@app.route("/api/scan/ports", methods=["POST"])
def port_scan():
    data = request.get_json()
    host = data.get("host", "").strip()
    port_range = data.get("port_range", "1-1024")
    if not host:
        return jsonify({"error": "Host is required"}), 400
    result = scan_ports(host, port_range)
    return jsonify(result)

@app.route("/api/scan/full", methods=["POST"])
def full_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    from urllib.parse import urlparse
    host = urlparse(url).hostname or url

    results = {
        "target": url,
        "timestamp": datetime.datetime.now().isoformat(),
        "sql_injection": scan_sql_injection(url),
        "xss": scan_xss(url),
        "headers": check_headers(url),
        "ports": scan_ports(host, "1-1024"),
    }
    return jsonify(results)

@app.route("/api/cvss", methods=["POST"])
def cvss_score():
    data = request.get_json()
    results = data.get("results")
    if not results:
        return jsonify({"error": "No scan results provided"}), 400
    score = calculate_cvss_score(results)
    priority = get_remediation_priority(results)
    return jsonify({"cvss": score, "remediation_priority": priority})

@app.route("/api/report", methods=["POST"])
def create_report():
    data = request.get_json()
    results = data.get("results")
    fmt = data.get("format", "html")
    if not results:
        return jsonify({"error": "No results provided"}), 400
    filepath = generate_report(results, fmt, REPORTS_DIR)
    filename = os.path.basename(filepath)
    return jsonify({"filename": filename, "path": f"/download/{filename}"})

@app.route("/download/<filename>")
def download_report(filename):
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
