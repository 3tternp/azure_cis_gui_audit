from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak,
)

from ..checks.base import Finding, STATUS_PASS, STATUS_FAIL, STATUS_UNKNOWN

NAVY = colors.HexColor("#1F3A5F")
GREY_BG = colors.HexColor("#F3F5F8")
GRID = colors.HexColor("#D0D5DD")
STATUS_COLORS = {
    STATUS_PASS: colors.HexColor("#1E8E3E"),
    STATUS_FAIL: colors.HexColor("#D93025"),
    STATUS_UNKNOWN: colors.HexColor("#E37400"),
}
STATUS_LABELS = {STATUS_PASS: "PASS", STATUS_FAIL: "FAIL", STATUS_UNKNOWN: "UNKNOWN"}
STATUS_ORDER = {STATUS_FAIL: 0, STATUS_UNKNOWN: 1, STATUS_PASS: 2}
PAGE_W, _ = A4
MARGIN = 36
CONTENT_W = PAGE_W - 2 * MARGIN

def _counts(findings: List[Finding]):
    return (
        sum(1 for f in findings if f.status == STATUS_PASS),
        sum(1 for f in findings if f.status == STATUS_FAIL),
        sum(1 for f in findings if f.status == STATUS_UNKNOWN),
    )

def _esc(text: str, limit: int = 700) -> str:
    text = (text or "").strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + " ..."
    return escape(text).replace("\n", "<br/>")

def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["Normal"], fontName="Helvetica", fontSize=8.5, leading=11)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=9.5),
        "cell_b": ParagraphStyle("cell_b", parent=base, fontName="Helvetica-Bold"),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=colors.white),
        "sub": ParagraphStyle("sub", parent=base, fontSize=9, textColor=colors.HexColor("#DCE6F5")),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=NAVY, spaceBefore=12, spaceAfter=6),
        "badge": ParagraphStyle("badge", parent=base, fontName="Helvetica-Bold", fontSize=7.5, textColor=colors.white, alignment=1),
        "tile_n": ParagraphStyle("tile_n", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=colors.white, alignment=1),
        "tile_l": ParagraphStyle("tile_l", parent=base, fontSize=8, textColor=colors.white, alignment=1),
        "card_h": ParagraphStyle("card_h", parent=base, fontName="Helvetica-Bold", fontSize=9, textColor=colors.white),
    }

def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#667085"))
    canvas.drawString(MARGIN, 18, "Azure CIS Configuration Review - read-only assessment")
    canvas.drawRightString(PAGE_W - MARGIN, 18, f"Page {doc.page}")
    canvas.restoreState()

def _badge(status: str, st) -> Table:
    t = Table([[Paragraph(STATUS_LABELS.get(status, status), st["badge"])]], colWidths=[52])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), STATUS_COLORS.get(status, colors.grey)),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t

def _card(x: Finding, st) -> KeepTogether:
    color = STATUS_COLORS.get(x.status, colors.grey)
    head = Table(
        [[Paragraph(f"{STATUS_LABELS.get(x.status, x.status)}", st["card_h"]),
          Paragraph(f"{escape(x.issue_id)} &nbsp;|&nbsp; {escape(x.issue_name)}", st["card_h"])]],
        colWidths=[62, CONTENT_W - 62],
    )
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    rows = [
        ("CIS reference", x.cis_ref),
        ("Scope", x.scope),
        ("Affected", x.affected),
        ("Evidence", x.evidence),
        ("Remediation", x.remediation),
        ("Fix effort", x.fix_type),
    ]
    body_rows = [[Paragraph(k, st["cell_b"]), Paragraph(_esc(v), st["base"])] for k, v in rows if v]
    body = Table(body_rows, colWidths=[78, CONTENT_W - 78])
    body.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), GREY_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRID),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return KeepTogether([head, body, Spacer(1, 10)])

def build_pdf(path: str, findings: List[Finding], tenant_id: str, subscriptions: List[str], tool_version: str = "1.0"):
    st = _styles()
    doc = SimpleDocTemplate(
        path, pagesize=A4, rightMargin=MARGIN, leftMargin=MARGIN, topMargin=MARGIN, bottomMargin=36,
        title="Azure CIS Configuration Review", author="Azure CIS GUI Audit",
    )
    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    p, f, u = _counts(findings)
    total = len(findings)
    evaluated = p + f
    score = f"{round(100 * p / evaluated)}%" if evaluated else "n/a"

    # Banner
    banner = Table(
        [[Paragraph("Azure CIS Configuration Review", st["h1"])],
         [Paragraph("Read-only configuration assessment aligned to CIS-style controls", st["sub"])]],
        colWidths=[CONTENT_W],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("TOPPADDING", (0, 0), (0, 0), 14), ("BOTTOMPADDING", (0, -1), (-1, -1), 14),
    ]))
    story += [banner, Spacer(1, 12)]

    subs_text = ", ".join(subscriptions) if subscriptions else "None"
    meta = Table([
        [Paragraph("Generated", st["cell_b"]), Paragraph(now, st["base"])],
        [Paragraph("Tenant", st["cell_b"]), Paragraph(escape(tenant_id or "(from signed-in identity)"), st["base"])],
        [Paragraph("Subscriptions", st["cell_b"]), Paragraph(escape(subs_text), st["base"])],
        [Paragraph("Tool version", st["cell_b"]), Paragraph(escape(tool_version), st["base"])],
    ], colWidths=[85, CONTENT_W - 85])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta)

    # Summary tiles
    story.append(Paragraph("Executive summary", st["h2"]))
    def tile(n, label, color):
        return [Paragraph(str(n), st["tile_n"]), Paragraph(label, st["tile_l"])], color
    tiles = [tile(p, "PASS", STATUS_COLORS[STATUS_PASS]), tile(f, "FAIL", STATUS_COLORS[STATUS_FAIL]),
             tile(u, "UNKNOWN", STATUS_COLORS[STATUS_UNKNOWN]), tile(score, "COMPLIANCE SCORE", NAVY)]
    w = CONTENT_W / 4
    tt = Table([[[c for c in t[0]] for t in tiles]], colWidths=[w] * 4)
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
             ("LINEAFTER", (0, 0), (-2, -1), 4, colors.white)]
    for i, t in enumerate(tiles):
        style.append(("BACKGROUND", (i, 0), (i, 0), t[1]))
    tt.setStyle(TableStyle(style))
    story.append(tt)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"{total} controls evaluated. Compliance score = PASS / (PASS + FAIL), excluding UNKNOWN. "
        f"<b>UNKNOWN</b> means the check could not be evaluated (for example missing permissions) and is not a pass.",
        st["small"]))

    ordered = sorted(findings, key=lambda x: (STATUS_ORDER.get(x.status, 9), x.issue_id, x.scope))

    # Overview table
    story.append(Paragraph("Findings overview", st["h2"]))
    rows = [[Paragraph(h, st["cell_b"]) for h in ("ID", "Control", "Status", "Scope", "Fix")]]
    for x in ordered:
        rows.append([
            Paragraph(escape(x.issue_id), st["small"]),
            Paragraph(escape(x.issue_name), st["small"]),
            _badge(x.status, st),
            Paragraph(escape(x.scope), st["small"]),
            Paragraph(escape(x.fix_type or "-"), st["small"]),
        ])
    cw = [58, 190, 60, 160, CONTENT_W - 58 - 190 - 60 - 160]
    ov = Table(rows, colWidths=cw, repeatRows=1)
    ov.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRID), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFBFC")]),
    ]))
    story.append(ov)

    # Detailed cards for non-passing findings
    detail = [x for x in ordered if x.status != STATUS_PASS]
    if detail:
        story.append(PageBreak())
        story.append(Paragraph("Detailed findings (FAIL and UNKNOWN)", st["h2"]))
        for x in detail:
            story.append(_card(x, st))

    passed = [x for x in ordered if x.status == STATUS_PASS]
    if passed:
        story.append(Paragraph("Passed controls - evidence", st["h2"]))
        rows = [[Paragraph(h, st["cell_b"]) for h in ("ID", "Scope", "Evidence")]]
        for x in passed:
            rows.append([Paragraph(escape(x.issue_id), st["small"]), Paragraph(escape(x.scope), st["small"]),
                         Paragraph(_esc(x.evidence, 300), st["small"])])
        pt = Table(rows, colWidths=[58, 170, CONTENT_W - 228], repeatRows=1)
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(pt)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
