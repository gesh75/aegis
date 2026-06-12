"""Render a sealed evidence bundle to an examiner-ready PDF.

This is the paid artifact: a regulated buyer hands this to an auditor. It restates the
verdict, the verified twin outcome, the framework-mapped control results, the generated
config with its grounding, the rollback plan, and the tamper-evident integrity block
(sha256 + egress=none). reportlab only — no network, air-gap safe.

    from aegis.evidence.pdf import render_pdf
    pdf_bytes = render_pdf(bundle)
"""
from __future__ import annotations
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable)

_VERDICT_COLOR = {
    "ship_ready": colors.HexColor("#1f8f4e"),
    "blocked": colors.HexColor("#c0392b"),
    "needs_approval": colors.HexColor("#b9770e"),
}
_INK = colors.HexColor("#1a2230")
_MUT = colors.HexColor("#5b6b82")
_LINE = colors.HexColor("#c9d3e0")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("AegisH1", parent=ss["Title"], fontSize=20,
                          textColor=_INK, spaceAfter=2))
    ss.add(ParagraphStyle("AegisSub", parent=ss["Normal"], fontSize=8.5,
                          textColor=_MUT, spaceAfter=10))
    ss.add(ParagraphStyle("AegisH2", parent=ss["Heading2"], fontSize=11,
                          textColor=_INK, spaceBefore=12, spaceAfter=4))
    ss.add(ParagraphStyle("AegisBody", parent=ss["Normal"], fontSize=9,
                          textColor=_INK, leading=12))
    ss.add(ParagraphStyle("AegisMono", parent=ss["Code"], fontSize=7.5,
                          textColor=_INK, leading=9.5))
    return ss


def _kv_table(rows, col0=45 * mm):
    t = Table(rows, colWidths=[col0, None])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), _MUT),
        ("TEXTCOLOR", (1, 0), (1, -1), _INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, _LINE),
    ]))
    return t


def render_pdf(bundle: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="AEGIS Evidence Bundle",
                            author="AEGIS", leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    ss = _styles()
    el = []

    # header
    el.append(Paragraph("AEGIS · Evidence Bundle", ss["AegisH1"]))
    el.append(Paragraph(
        f"Air-gapped pre-deployment change validation &nbsp;·&nbsp; run "
        f"{bundle['run_id']} &nbsp;·&nbsp; {bundle['created_utc']} &nbsp;·&nbsp; "
        f"operator {bundle.get('operator','—')}", ss["AegisSub"]))
    el.append(HRFlowable(width="100%", color=_LINE, spaceAfter=8))

    # verdict
    v = bundle["verdict"]
    vc = _VERDICT_COLOR.get(v["decision"], _INK)
    el.append(Paragraph(
        f'<font color="{vc.hexval()}"><b>{v["decision"].replace("_"," ").upper()}'
        f'</b></font>', ParagraphStyle("vd", fontSize=16, leading=18)))
    el.append(Paragraph(v["reason"], ss["AegisBody"]))
    ch = bundle["change"]; br = bundle["validation"]["blast_radius"]
    appr = ch["approval"]
    el.append(Spacer(1, 4))
    el.append(_kv_table([
        ["Risk tier", ch["risk_tier"]],
        ["Blast radius", f"{br['severity']} · {br['devices_affected']} device(s)"],
        ["Approval", ("required — " + (appr.get("granted_by") or "PENDING"))
         if appr["required"] else "not required"],
        ["Change source", ch["source"]],
    ]))

    # digital twin
    tw = bundle["twin"]; bg = tw["bgp_sessions"]; sd = bundle["validation"]["state_diff"]
    el.append(Paragraph("Digital twin", ss["AegisH2"]))
    el.append(_kv_table([
        ["Engine / topology", f"{tw['engine']} · {tw['topology']} · {tw['node_count']} nodes"],
        ["Converged", ("yes" if tw["converged"] else "NO") + f" ({tw['convergence_sec']}s)"],
        ["BGP sessions", f"{bg['before']} → {bg['after']}"
         + ("  (regression)" if bg["after"] < bg["before"] else "")],
        ["Routes / sessions", f"+{len(sd['routes_added'])} / -{len(sd['routes_removed'])}"
         f" routes · dropped: {', '.join(sd['sessions_dropped']) or 'none'}"],
    ]))

    # compliance
    el.append(Paragraph("Compliance (config-derived)", ss["AegisH2"]))
    crows = [["Framework", "Control", "Status", "Evidence"]]
    for c in bundle["validation"]["compliance"]:
        crows.append([c["framework"], c["control"], c["status"].upper(),
                      Paragraph(c["evidence"], ss["AegisBody"])])
    ct = Table(crows, colWidths=[28 * mm, 20 * mm, 18 * mm, None])
    cstyle = [
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, c in enumerate(bundle["validation"]["compliance"], start=1):
        col = (colors.HexColor("#c0392b") if c["status"] == "fail"
               else colors.HexColor("#b8860b") if c["status"] == "not_applicable"
               else colors.HexColor("#1f8f4e"))
        cstyle.append(("TEXTCOLOR", (2, i), (2, i), col))
        cstyle.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    ct.setStyle(TableStyle(cstyle))
    el.append(ct)

    bf = bundle["validation"]["batfish"]
    el.append(Spacer(1, 4))
    el.append(Paragraph(
        f"Static analysis (Batfish): <b>{bf['errors']}</b> errors · "
        f"{bf['warnings']} warnings · {bf['passed']} passed", ss["AegisBody"]))
    for f in bf["findings"][:12]:
        el.append(Paragraph("• " + f, ss["AegisMono"]))

    # generated config
    el.append(Paragraph("Generated configuration (grounded)", ss["AegisH2"]))
    for c in bundle["change"]["generated_configs"]:
        el.append(Paragraph(f"<b>{c['device']}</b> · {c['vendor']}", ss["AegisBody"]))
        for line in (c["config"] or "").splitlines():
            el.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;"),
                                ss["AegisMono"]))
        if c["grounded_commands"]:
            el.append(Paragraph("grounded: " + " · ".join(c["grounded_commands"]),
                                ss["AegisSub"]))

    # rollback
    rb = bundle.get("rollback", {})
    if rb:
        el.append(Paragraph("Rollback plan", ss["AegisH2"]))
        el.append(Paragraph(
            f"{len(rb.get('plan', []))} step(s) · tested in twin: "
            f"{'yes' if rb.get('tested_in_twin') else 'no'}", ss["AegisBody"]))
        for s in rb.get("plan", [])[:12]:
            el.append(Paragraph("• " + s, ss["AegisMono"]))

    # integrity
    ig = bundle["integrity"]
    el.append(Spacer(1, 8))
    el.append(HRFlowable(width="100%", color=_LINE, spaceAfter=4))
    el.append(Paragraph(
        f"<b>Integrity</b> &nbsp; generated_by {ig['generated_by']} &nbsp;·&nbsp; "
        f"egress <b>{ig['egress']}</b> &nbsp;·&nbsp; signed "
        f"{ig.get('signed', False)}", ss["AegisSub"]))
    el.append(Paragraph(f"sha256 {ig['sha256']}", ss["AegisMono"]))

    # bounded-autonomy seal (CROSS-3) — the offline-verifiable receipt, when present
    seal = bundle.get("seal")
    if seal:
        cl = seal.get("claims", {}); m = cl.get("model", {}); au = cl.get("authority", {})
        sig = seal.get("signature", {})
        el.append(Spacer(1, 6))
        el.append(Paragraph("<b>Bounded-autonomy seal</b> &nbsp; (offline-verifiable receipt)",
                            ss["AegisSub"]))
        el.append(_kv_table([
            ["Model", f"{m.get('provider','?')} · {m.get('model','?')} "
             f"({m.get('model_hash_kind','?')})"],
            ["Authority", f"required {au.get('required','?')} · ceiling "
             f"{au.get('max_authorized','?')} · {'within bound' if au.get('allowed') else 'EXCEEDS'}"],
            ["Signature", f"{sig.get('alg','?')} · key {sig.get('key_id','?')}"],
        ]))

    doc.build(el)
    return buf.getvalue()
