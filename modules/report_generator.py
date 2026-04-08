import os
import json
import datetime
from modules.risk_calculator import calculate_cvss_score, get_remediation_priority

def get_risk_color(risk: str) -> str:
    return {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#eab308", "NONE": "#22c55e", "INFO": "#3b82f6"}.get(risk.upper(), "#6b7280")

def generate_report(results: dict, fmt: str = "html", output_dir: str = ".") -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = results.get("target", "target").replace("://", "_").replace("/", "_").replace(":", "_")[:30]
    filename = f"vapt_report_{target_safe}_{timestamp}.{fmt}"
    filepath = os.path.join(output_dir, filename)

    if fmt == "json":
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:
        html = build_html_report(results)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

    return filepath

def count_all_findings(results: dict) -> dict:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for module_key in ["sql_injection", "xss", "headers", "ports"]:
        module = results.get(module_key, {})
        for f in module.get("findings", []):
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return counts

def build_html_report(results: dict) -> str:
    target = results.get("target", "N/A")
    timestamp = results.get("timestamp", datetime.datetime.now().isoformat())
    counts = count_all_findings(results)
    total = sum(counts.values())

    def module_table(module_data: dict) -> str:
        findings = module_data.get("findings", [])
        if not findings:
            return '<p style="color:#22c55e;padding:12px 0;">✅ No vulnerabilities found for this module.</p>'
        rows = ""
        for f in findings:
            sev = f.get("severity", "INFO")
            color = get_risk_color(sev)
            rows += f"""<tr>
                <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700;">{sev}</span></td>
                <td style="font-weight:600;">{f.get('type','N/A')}</td>
                <td style="color:#94a3b8;">{f.get('parameter', f.get('port', f.get('header','N/A')))}</td>
                <td style="font-family:monospace;font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;">{f.get('evidence', f.get('detail', f.get('description','')))[:80][:120]}</td>
                <td style="font-size:12px;color:#cbd5e1;">{f.get('recommendation','N/A')[:120] if f.get('recommendation') else ' '}</td>
            </tr>"""
        return f"""<table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead><tr style="background:#1e293b;color:#94a3b8;text-transform:uppercase;font-size:11px;letter-spacing:1px;">
                <th style="padding:10px;text-align:left;">Severity</th>
                <th style="padding:10px;text-align:left;">Type</th>
                <th style="padding:10px;text-align:left;">Parameter/Port</th>
                <th style="padding:10px;text-align:left;">Detail</th>
                <th style="padding:10px;text-align:left;">Recommendation</th>
            </tr></thead>
            <tbody style="color:#e2e8f0;">{rows}</tbody>
        </table>"""

    def open_ports_table(ports: list) -> str:
        if not ports:
            return '<p style="color:#22c55e;padding:12px 0;">✅ No open ports found.</p>'
        rows = ""
        for p in ports:
            risk = p.get("risk", "LOW")
            color = get_risk_color(risk)
            rows += f"""<tr>
                <td style="font-weight:700;color:#60a5fa;">{p['port']}</td>
                <td>{p.get('service','Unknown')}</td>
                <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{risk}</span></td>
                <td style="font-family:monospace;font-size:11px;color:#94a3b8;">{p.get('banner','')[:80]}</td>
            </tr>"""
        return f"""<table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead><tr style="background:#1e293b;color:#94a3b8;text-transform:uppercase;font-size:11px;letter-spacing:1px;">
                <th style="padding:10px;text-align:left;">Port</th><th style="padding:10px;text-align:left;">Service</th>
                <th style="padding:10px;text-align:left;">Risk</th><th style="padding:10px;text-align:left;">Banner</th>
            </tr></thead>
            <tbody style="color:#e2e8f0;">{rows}</tbody>
        </table>"""

    sql = results.get("sql_injection", {})
    xss = results.get("xss", {})
    hdrs = results.get("headers", {})
    ports = results.get("ports", {})

    overall_risk = "NONE"
    for mod in [sql, xss, hdrs, ports]:
        rl = mod.get("risk_level", "NONE")
        if rl == "HIGH":
            overall_risk = "HIGH"
            break
        elif rl == "MEDIUM" and overall_risk != "HIGH":
            overall_risk = "MEDIUM"
        elif rl == "LOW" and overall_risk not in ("HIGH", "MEDIUM"):
            overall_risk = "LOW"

    risk_color = get_risk_color(overall_risk)


    # CVSS Score
    cvss = calculate_cvss_score(results)
    priority = get_remediation_priority(results)
    rating_colors = {"CRITICAL":"#7c3aed","HIGH":"#ef4444","MEDIUM":"#f97316","LOW":"#eab308","NONE":"#22c55e"}
    cvss_color = rating_colors.get(cvss["rating"], "#22c55e")
    pct = cvss["overall_score"] / 10 * 100
    dash = 2 * 3.14159 * 65
    offset = dash * (1 - pct/100)

    prio_rows = ""
    for i, p in enumerate(priority[:10]):
        prio_rows += f"""<tr>
            <td style="color:#60a5fa;font-weight:700;">{i+1}</td>
            <td style="color:#e2e8f0;font-weight:600;">{p['type']}</td>
            <td><span style="background:{rating_colors.get(p['severity'],'#64748b')};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">{p['severity']}</span></td>
            <td style="color:{cvss_color};font-weight:700;font-family:monospace;">{p['cvss_score']:.1f}</td>
            <td style="color:#94a3b8;">{p['module']}</td>
        </tr>"""

    cvss_html = f"""
  <div class="section">
    <h2>📊 CVSS Risk Score <span style="background:{cvss_color};color:#fff;padding:4px 14px;border-radius:6px;font-size:16px;margin-left:10px;">{cvss['overall_score']:.1f} / 10.0</span></h2>
    <div class="meta2">Rating: {cvss['rating']} &nbsp;|&nbsp; {cvss['description']}</div>
    <div style="display:flex;align-items:center;gap:40px;flex-wrap:wrap;margin-bottom:24px;">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="65" fill="none" stroke="#1e293b" stroke-width="14"/>
        <circle cx="80" cy="80" r="65" fill="none" stroke="{cvss_color}" stroke-width="14"
          stroke-dasharray="{dash:.1f}" stroke-dashoffset="{offset:.1f}"
          stroke-linecap="round" transform="rotate(-90 80 80)"/>
        <text x="80" y="72" text-anchor="middle" fill="{cvss_color}" font-size="32" font-weight="800" font-family="monospace">{cvss['overall_score']:.1f}</text>
        <text x="80" y="95" text-anchor="middle" fill="#64748b" font-size="13">/ 10.0</text>
        <text x="80" y="115" text-anchor="middle" fill="{cvss_color}" font-size="14" font-weight="700">{cvss['rating']}</text>
      </svg>
      <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <div style="background:rgba(239,68,68,0.1);border:1px solid #ef4444;border-radius:8px;padding:12px 20px;text-align:center;">
          <div style="font-size:28px;font-weight:800;color:#ef4444;">{cvss['counts'].get('HIGH',0)}</div>
          <div style="font-size:11px;color:#64748b;">HIGH</div>
        </div>
        <div style="background:rgba(249,115,22,0.1);border:1px solid #f97316;border-radius:8px;padding:12px 20px;text-align:center;">
          <div style="font-size:28px;font-weight:800;color:#f97316;">{cvss['counts'].get('MEDIUM',0)}</div>
          <div style="font-size:11px;color:#64748b;">MEDIUM</div>
        </div>
        <div style="background:rgba(234,179,8,0.1);border:1px solid #eab308;border-radius:8px;padding:12px 20px;text-align:center;">
          <div style="font-size:28px;font-weight:800;color:#eab308;">{cvss['counts'].get('LOW',0)}</div>
          <div style="font-size:11px;color:#64748b;">LOW</div>
        </div>
        <div style="background:rgba(0,212,255,0.1);border:1px solid #00d4ff;border-radius:8px;padding:12px 20px;text-align:center;">
          <div style="font-size:28px;font-weight:800;color:#00d4ff;">{cvss['total_findings']}</div>
          <div style="font-size:11px;color:#64748b;">TOTAL</div>
        </div>
      </div>
    </div>
    <h3 style="font-size:14px;color:#94a3b8;margin-bottom:12px;">🔧 REMEDIATION PRIORITY</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead><tr style="background:#1e293b;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;">
        <th style="padding:10px;text-align:left;">#</th>
        <th style="padding:10px;text-align:left;">Finding</th>
        <th style="padding:10px;text-align:left;">Severity</th>
        <th style="padding:10px;text-align:left;">CVSS Score</th>
        <th style="padding:10px;text-align:left;">Module</th>
      </tr></thead>
      <tbody>{prio_rows}</tbody>
    </table>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VAPT Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 40px; line-height: 1.6; }}
  .page {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 30px; margin-bottom: 40px; }}
  .header h1 {{ font-size: 32px; font-weight: 800; letter-spacing: -1px; color: #f1f5f9; }}
  .header h1 span {{ color: #ef4444; }}
  .meta {{ color: #64748b; font-size: 13px; margin-top: 8px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 40px; }}
  .stat-card {{ background: #1e293b; border-radius: 12px; padding: 20px; text-align: center; border-top: 3px solid; }}
  .stat-card .num {{ font-size: 36px; font-weight: 800; }}
  .stat-card .lbl {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-top: 4px; }}
  .overall {{ background: #1e293b; border-radius: 12px; padding: 20px 28px; margin-bottom: 40px; display: flex; align-items: center; gap: 16px; }}
  .overall .badge {{ font-size: 22px; font-weight: 800; padding: 6px 20px; border-radius: 8px; color: #fff; }}
  .section {{ background: #1e293b; border-radius: 12px; padding: 28px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 18px; font-weight: 700; margin-bottom: 6px; color: #f1f5f9; }}
  .section .meta2 {{ font-size: 12px; color: #64748b; margin-bottom: 20px; }}
  .risk-badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; color: #fff; margin-left: 8px; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  td {{ padding: 10px; border-bottom: 1px solid #0f172a; vertical-align: top; }}
  .footer {{ text-align: center; color: #334155; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <h1>🛡 <span>VAPT</span> Security Assessment Report</h1>
    <div class="meta">
      <strong>Target:</strong> {target} &nbsp;|&nbsp;
      <strong>Generated:</strong> {timestamp} &nbsp;|&nbsp;
      <strong>Tool:</strong> Mini VAPT Framework v1.0
    </div>
  </div>

  <div class="summary-grid">
    <div class="stat-card" style="border-color:#ef4444;">
      <div class="num" style="color:#ef4444;">{counts['HIGH']}</div>
      <div class="lbl">High Severity</div>
    </div>
    <div class="stat-card" style="border-color:#f97316;">
      <div class="num" style="color:#f97316;">{counts['MEDIUM']}</div>
      <div class="lbl">Medium Severity</div>
    </div>
    <div class="stat-card" style="border-color:#eab308;">
      <div class="num" style="color:#eab308;">{counts['LOW']}</div>
      <div class="lbl">Low Severity</div>
    </div>
    <div class="stat-card" style="border-color:#3b82f6;">
      <div class="num" style="color:#3b82f6;">{total}</div>
      <div class="lbl">Total Findings</div>
    </div>
  </div>

  <div class="overall">
    <span style="font-size:16px;color:#94a3b8;">Overall Risk Level</span>
    <span class="badge" style="background:{risk_color};">{overall_risk}</span>
  </div>

  <div class="section">
    <h2>💉 SQL Injection <span class="risk-badge" style="background:{get_risk_color(sql.get('risk_level','NONE'))};">{sql.get('risk_level','N/A')}</span></h2>
    <div class="meta2">{sql.get('summary','')} | Tests: {sql.get('total_tests',0)} | Duration: {sql.get('duration',0)}s</div>
    {module_table(sql)}
  </div>

  <div class="section">
    <h2>⚡ XSS Scanner <span class="risk-badge" style="background:{get_risk_color(xss.get('risk_level','NONE'))};">{xss.get('risk_level','N/A')}</span></h2>
    <div class="meta2">{xss.get('summary','')} | Tests: {xss.get('total_tests',0)} | Duration: {xss.get('duration',0)}s</div>
    {module_table(xss)}
  </div>

  <div class="section">
    <h2>🔐 Header / Auth Security <span class="risk-badge" style="background:{get_risk_color(hdrs.get('risk_level','NONE'))};">{hdrs.get('risk_level','N/A')}</span></h2>
    <div class="meta2">{hdrs.get('summary','')} | Duration: {hdrs.get('duration',0)}s</div>
    {module_table(hdrs)}
  </div>

  <div class="section">
    <h2>🔌 Port Scanner <span class="risk-badge" style="background:{get_risk_color(ports.get('risk_level','NONE'))};">{ports.get('risk_level','N/A')}</span></h2>
    <div class="meta2">{ports.get('summary','')} | Ports Scanned: {ports.get('ports_scanned',0)} | Duration: {ports.get('duration',0)}s</div>
    {module_table(ports)}
    <h3 style="margin-top:20px;margin-bottom:12px;font-size:14px;color:#94a3b8;">ALL OPEN PORTS</h3>
    {open_ports_table(ports.get('open_ports',[]))}
  </div>


{cvss_html}
  <div class="footer">
    ⚠ This report is generated for authorized security assessment only. Unauthorized scanning is illegal.<br>
    Generated by Mini VAPT Framework — MSc IT Final Year Project
  </div>
</div>
</body>
</html>"""
