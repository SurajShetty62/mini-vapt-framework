import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Color Palette ──────────────────────────────────────────
BG_DARK    = colors.HexColor("#0D1A2E")
ACCENT     = colors.HexColor("#00D4FF")
RED        = colors.HexColor("#EF4444")
ORANGE     = colors.HexColor("#F97316")
YELLOW     = colors.HexColor("#EAB308")
GREEN      = colors.HexColor("#22C55E")
PURPLE     = colors.HexColor("#7C3AED")
WHITE      = colors.HexColor("#F1F5F9")
MUTED      = colors.HexColor("#64748B")
SURFACE    = colors.HexColor("#1E293B")
SURFACE2   = colors.HexColor("#112240")
TEXT_DARK  = colors.HexColor("#1E293B")

def sev_color(sev):
    return {
        "HIGH":     RED,
        "MEDIUM":   ORANGE,
        "LOW":      YELLOW,
        "NONE":     GREEN,
        "CRITICAL": PURPLE,
        "INFO":     ACCENT,
    }.get(str(sev).upper(), MUTED)

def risk_color(risk):
    return sev_color(risk)

def get_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle",
        fontName="Helvetica-Bold",
        fontSize=26,
        textColor=TEXT_DARK,
        spaceAfter=4,
        leading=30,
    ))
    styles.add(ParagraphStyle(
        "ReportSubtitle",
        fontName="Helvetica",
        fontSize=12,
        textColor=MUTED,
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=TEXT_DARK,
        spaceBefore=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "ModuleTitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=TEXT_DARK,
        spaceBefore=10,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "BodyText2",
        fontName="Helvetica",
        fontSize=9,
        textColor=TEXT_DARK,
        spaceAfter=3,
        leading=13,
    ))
    styles.add(ParagraphStyle(
        "SmallMuted",
        fontName="Helvetica",
        fontSize=8,
        textColor=MUTED,
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "CenteredTitle",
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=WHITE,
        alignment=TA_CENTER,
    ))
    return styles

def make_header_footer(canvas, doc):
    """Draw header and footer on every page."""
    canvas.saveState()
    w, h = A4

    # Header bar
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, h - 28*mm, w, 28*mm, fill=1, stroke=0)

    # Accent left bar
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 28*mm, 4*mm, 28*mm, fill=1, stroke=0)

    # Title in header
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(12*mm, h - 14*mm, "Mini VAPT Framework")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(ACCENT)
    canvas.drawString(12*mm, h - 21*mm, "Web Application Vulnerability Assessment Report")

    # Page number right
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 10*mm, h - 18*mm, f"Page {doc.page}")

    # Footer
    canvas.setFillColor(SURFACE)
    canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(12*mm, 4*mm, "CONFIDENTIAL — For authorized security testing only. Mini VAPT Framework v1.0")
    canvas.drawRightString(w - 10*mm, 4*mm, "MSc IT Final Year Project")

    canvas.restoreState()

def build_summary_table(counts, overall_risk):
    """Build the summary stats table."""
    risk_col = risk_color(overall_risk)

    data = [
        [
            Paragraph(f'<font color="#EF4444"><b>{counts.get("HIGH", 0)}</b></font>', ParagraphStyle("s", fontSize=22, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(f'<font color="#F97316"><b>{counts.get("MEDIUM", 0)}</b></font>', ParagraphStyle("s", fontSize=22, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(f'<font color="#EAB308"><b>{counts.get("LOW", 0)}</b></font>', ParagraphStyle("s", fontSize=22, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(f'<font color="#00D4FF"><b>{sum(counts.values())}</b></font>', ParagraphStyle("s", fontSize=22, alignment=TA_CENTER, fontName="Helvetica-Bold")),
        ],
        [
            Paragraph("HIGH", ParagraphStyle("l", fontSize=8, alignment=TA_CENTER, textColor=MUTED, fontName="Helvetica")),
            Paragraph("MEDIUM", ParagraphStyle("l", fontSize=8, alignment=TA_CENTER, textColor=MUTED, fontName="Helvetica")),
            Paragraph("LOW", ParagraphStyle("l", fontSize=8, alignment=TA_CENTER, textColor=MUTED, fontName="Helvetica")),
            Paragraph("TOTAL", ParagraphStyle("l", fontSize=8, alignment=TA_CENTER, textColor=MUTED, fontName="Helvetica")),
        ],
    ]

    t = Table(data, colWidths=[40*mm, 40*mm, 40*mm, 40*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#FEF2F2")),
        ("BACKGROUND",   (1, 0), (1, -1), colors.HexColor("#FFF7ED")),
        ("BACKGROUND",   (2, 0), (2, -1), colors.HexColor("#FEFCE8")),
        ("BACKGROUND",   (3, 0), (3, -1), colors.HexColor("#ECFEFF")),
        ("BOX",          (0, 0), (0, -1), 1, RED),
        ("BOX",          (1, 0), (1, -1), 1, ORANGE),
        ("BOX",          (2, 0), (2, -1), 1, YELLOW),
        ("BOX",          (3, 0), (3, -1), 1, ACCENT),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [None, None]),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("GRID",         (0, 0), (-1, -1), 0, colors.white),
    ]))
    return t

def build_findings_table(findings, styles):
    """Build findings table for a module."""
    if not findings:
        return Paragraph("✅  No vulnerabilities found for this module.", styles["BodyText2"])

    headers = ["Severity", "Type", "Parameter", "Detail", "Recommendation"]
    col_widths = [18*mm, 38*mm, 28*mm, 42*mm, 44*mm]

    header_row = [
        Paragraph(h, ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))
        for h in headers
    ]

    rows = [header_row]
    for f in findings:
        sev = f.get("severity", "INFO")
        sc = sev_color(sev)
        detail = str(f.get("evidence", f.get("detail", f.get("description", ""))))[:100]
        rec = str(f.get("recommendation", ""))[:100]
        param = str(f.get("parameter", f.get("port", f.get("header", "N/A"))))

        rows.append([
            Paragraph(sev, ParagraphStyle("sev", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
            Paragraph(str(f.get("type", "N/A")), ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
            Paragraph(param, ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
            Paragraph(detail, ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
            Paragraph(rec, ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
        ])

    t = Table(rows, colWidths=col_widths, repeatRows=1)

    # Build row styles
    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0),  SURFACE),
        ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]

    # Color severity column per row
    for i, f in enumerate(findings, start=1):
        sev = f.get("severity", "INFO")
        sc = sev_color(sev)
        style_cmds.append(("BACKGROUND", (0, i), (0, i), sc))
        style_cmds.append(("LINEAFTER",  (0, i), (0, i), 2, sc))

    t.setStyle(TableStyle(style_cmds))
    return t

def build_cvss_table(priority, styles):
    """Build CVSS remediation priority table."""
    if not priority:
        return Paragraph("No findings to prioritize.", styles["BodyText2"])

    headers = ["#", "Finding", "Severity", "CVSS Score", "Module"]
    col_widths = [10*mm, 60*mm, 22*mm, 22*mm, 36*mm]

    header_row = [
        Paragraph(h, ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER))
        for h in headers
    ]

    rows = [header_row]
    for i, p in enumerate(priority[:15], 1):
        sev = p.get("severity", "LOW")
        sc = sev_color(sev)
        rows.append([
            Paragraph(str(i), ParagraphStyle("td", fontSize=8, fontName="Helvetica-Bold", textColor=ACCENT, alignment=TA_CENTER)),
            Paragraph(str(p.get("type", "")), ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
            Paragraph(sev, ParagraphStyle("sev", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
            Paragraph(f"{p.get('cvss_score', 0):.1f}", ParagraphStyle("score", fontSize=9, fontName="Helvetica-Bold", textColor=sc, alignment=TA_CENTER)),
            Paragraph(str(p.get("module", "")), ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=MUTED)),
        ])

    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0),  SURFACE),
        ("ALIGN",         (0, 0), (-1, 0),  "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]

    for i, p in enumerate(priority[:15], 1):
        sev = p.get("severity", "LOW")
        sc = sev_color(sev)
        style_cmds.append(("BACKGROUND", (2, i), (2, i), sc))

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style_cmds))
    return t

def generate_pdf_report(results: dict, output_dir: str = ".") -> str:
    """Generate a professional PDF report from scan results."""
    from modules.risk_calculator import calculate_cvss_score, get_remediation_priority

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = results.get("target", "target").replace("://", "_").replace("/", "_").replace(":", "_")[:30]
    filename = f"vapt_report_{target_safe}_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=35*mm,
        bottomMargin=20*mm,
        leftMargin=15*mm,
        rightMargin=15*mm,
    )

    styles = get_styles()
    story = []

    target = results.get("target", "N/A")
    timestamp_str = results.get("timestamp", datetime.datetime.now().isoformat())
    sql  = results.get("sql_injection", {})
    xss  = results.get("xss", {})
    hdrs = results.get("headers", {})
    prts = results.get("ports", {})

    # Count all findings
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for mod in [sql, xss, hdrs, prts]:
        for f in mod.get("findings", []):
            sev = f.get("severity", "LOW").upper()
            if sev in counts:
                counts[sev] += 1

    # Overall risk
    overall_risk = "NONE"
    for mod in [sql, xss, hdrs, prts]:
        rl = mod.get("risk_level", "NONE")
        if rl == "HIGH": overall_risk = "HIGH"; break
        elif rl == "MEDIUM" and overall_risk != "HIGH": overall_risk = "MEDIUM"
        elif rl == "LOW" and overall_risk not in ("HIGH","MEDIUM"): overall_risk = "LOW"

    rc = risk_color(overall_risk)

    # CVSS
    cvss = calculate_cvss_score(results)
    priority = get_remediation_priority(results)

    # ── Title Section ───────────────────────────────────────
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("🛡 VAPT Security Assessment Report", styles["ReportTitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=6))

    # Meta info table
    meta_data = [
        [Paragraph("<b>Target:</b>", styles["SmallMuted"]), Paragraph(target, styles["BodyText2"])],
        [Paragraph("<b>Generated:</b>", styles["SmallMuted"]), Paragraph(timestamp_str[:19].replace("T", " "), styles["BodyText2"])],
        [Paragraph("<b>Tool:</b>", styles["SmallMuted"]), Paragraph("Mini VAPT Framework v1.0 — MSc IT Final Year Project", styles["BodyText2"])],
    ]
    meta_t = Table(meta_data, colWidths=[30*mm, 140*mm])
    meta_t.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 6*mm))

    # ── Summary Stats ───────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    story.append(build_summary_table(counts, overall_risk))
    story.append(Spacer(1, 4*mm))

    # Overall risk pill
    risk_data = [[
        Paragraph("Overall Risk Level", styles["BodyText2"]),
        Paragraph(f'<font color="white"><b>  {overall_risk}  </b></font>',
            ParagraphStyle("rp", fontSize=11, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
    ]]
    risk_t = Table(risk_data, colWidths=[50*mm, 30*mm])
    risk_t.setStyle(TableStyle([
        ("BACKGROUND", (1,0), (1,0), rc),
        ("ALIGN",      (1,0), (1,0), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING",(1,0),(1,0), 8),
        ("RIGHTPADDING",(1,0),(1,0), 8),
    ]))
    story.append(risk_t)
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))

    # ── CVSS Score ──────────────────────────────────────────
    story.append(Paragraph(f"📊 CVSS Risk Score: {cvss['overall_score']:.1f} / 10.0  [{cvss['rating']}]", styles["SectionTitle"]))
    story.append(Paragraph(cvss["description"], styles["BodyText2"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("🔧 Remediation Priority (Fix in this order):", styles["ModuleTitle"]))
    story.append(build_cvss_table(priority, styles))
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))

    # ── Module Results ──────────────────────────────────────
    modules = [
        ("💉 SQL Injection Scanner", sql),
        ("⚡ XSS Scanner",           xss),
        ("🔐 Header / Auth Security", hdrs),
        ("🔌 Port Scanner",           prts),
    ]

    for mod_name, mod_data in modules:
        story.append(Spacer(1, 4*mm))
        risk_lv = mod_data.get("risk_level", "NONE")
        rc2 = risk_color(risk_lv)

        # Module title row
        title_data = [[
            Paragraph(mod_name, styles["ModuleTitle"]),
            Paragraph(f'<font color="white"><b> {risk_lv} </b></font>',
                ParagraphStyle("rp2", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
        ]]
        title_t = Table(title_data, colWidths=[140*mm, 22*mm])
        title_t.setStyle(TableStyle([
            ("BACKGROUND", (1,0), (1,0), rc2),
            ("ALIGN",      (1,0), (1,0), "CENTER"),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ]))
        story.append(title_t)
        story.append(Paragraph(mod_data.get("summary", ""), styles["SmallMuted"]))
        story.append(Spacer(1, 2*mm))
        story.append(build_findings_table(mod_data.get("findings", []), styles))

        # Open ports for port scanner
        open_ports = mod_data.get("open_ports", [])
        if open_ports:
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph(f"Open Ports ({len(open_ports)} found):", styles["ModuleTitle"]))
            port_rows = [[
                Paragraph("Port", ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
                Paragraph("Service", ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
                Paragraph("Risk", ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
                Paragraph("Banner", ParagraphStyle("th", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
            ]]
            for p in open_ports:
                pr = p.get("risk", "LOW")
                port_rows.append([
                    Paragraph(str(p["port"]), ParagraphStyle("td", fontSize=8, fontName="Helvetica-Bold", textColor=ACCENT)),
                    Paragraph(p.get("service",""), ParagraphStyle("td", fontSize=8, fontName="Helvetica", textColor=TEXT_DARK)),
                    Paragraph(pr, ParagraphStyle("td", fontSize=8, fontName="Helvetica-Bold", textColor=sev_color(pr), alignment=TA_CENTER)),
                    Paragraph(str(p.get("banner",""))[:60], ParagraphStyle("td", fontSize=7, fontName="Helvetica", textColor=MUTED)),
                ])
            pt = Table(port_rows, colWidths=[18*mm, 28*mm, 18*mm, 106*mm], repeatRows=1)
            pt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), SURFACE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F8FAFC")]),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING",   (0,0),(-1,-1), 4),
                ("RIGHTPADDING",  (0,0),(-1,-1), 4),
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ]))
            story.append(pt)

        story.append(Spacer(1, 4*mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))

    # ── Disclaimer ──────────────────────────────────────────
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(
        "⚠ This report is generated for authorized security assessment only. "
        "Unauthorized scanning is illegal. Mini VAPT Framework — MSc IT Final Year Project.",
        styles["SmallMuted"]
    ))

    doc.build(story, onFirstPage=make_header_footer, onLaterPages=make_header_footer)
    return filepath
