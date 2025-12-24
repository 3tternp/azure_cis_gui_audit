from __future__ import annotations
from typing import List
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from ..checks.base import Finding, STATUS_PASS, STATUS_FAIL, STATUS_UNKNOWN

def _counts(findings: List[Finding]):
    return (
        sum(1 for f in findings if f.status == STATUS_PASS),
        sum(1 for f in findings if f.status == STATUS_FAIL),
        sum(1 for f in findings if f.status == STATUS_UNKNOWN),
    )

def build_pdf(path: str, findings: List[Finding], tenant_id: str, subscriptions: List[str], tool_version: str = "1.0"):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=28, leftMargin=28, topMargin=28, bottomMargin=28)

    story = []
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    p, f, u = _counts(findings)

    story.append(Paragraph("Azure CIS Configuration Review Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Generated:</b> {now}", styles["Normal"]))
    story.append(Paragraph(f"<b>Tenant:</b> {tenant_id}", styles["Normal"]))
    story.append(Paragraph(f"<b>Subscriptions in scope:</b> {', '.join(subscriptions) if subscriptions else 'None'}", styles["Normal"]))
    story.append(Paragraph(f"<b>Tool version:</b> {tool_version}", styles["Normal"]))
    story.append(Spacer(1, 12))

    summary_data = [
        ["Status", "Count"],
        ["PASS", str(p)],
        ["FAIL", str(f)],
        ["UNKNOWN", str(u)],
        ["TOTAL", str(len(findings))]
    ]
    t = Table(summary_data, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
    ]))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(t)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Findings", styles["Heading2"]))
    story.append(Paragraph("The table below lists each control, its status, scope, and remediation guidance.", styles["Normal"]))
    story.append(Spacer(1, 8))

    table_header = ["Issue ID", "Issue Name", "CIS Ref", "Status", "Scope", "Affected", "Fix Type", "Remediation / Evidence"]
    rows = [table_header]
    for x in findings:
        rem_ev = (x.remediation or "") + ("<br/><br/><b>Evidence:</b> " + (x.evidence or "") if x.evidence else "")
        rows.append([
            x.issue_id,
            x.issue_name,
            x.cis_ref,
            x.status,
            x.scope,
            x.affected or "",
            x.fix_type or "",
            rem_ev
        ])

    tbl = Table(rows, repeatRows=1, colWidths=[55, 110, 95, 45, 95, 70, 55, 170])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 8),
        ("FONTSIZE", (0,1), (-1,-1), 7),
    ]))
    story.append(tbl)

    doc.build(story)
