from collections import Counter
from io import BytesIO
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    return text or "-"


def _paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text), style)


def _cell(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_text(text)), style)


def _build_summary_rows(findings: List[Dict[str, Any]]) -> List[List[str]]:
    risk_counts = Counter((_text(item.get("risk_level")).lower() for item in findings))
    severity_counts = Counter((_text(item.get("severity")).upper() for item in findings))

    return [
        ["Total Findings", str(len(findings))],
        ["Risk: EXPLOIT", str(risk_counts.get("exploit", 0))],
        ["Risk: MISCONFIG", str(risk_counts.get("misconfig", 0))],
        ["Risk: ENUM", str(risk_counts.get("enum", 0))],
        ["Severity: CRITICAL", str(severity_counts.get("CRITICAL", 0))],
        ["Severity: HIGH", str(severity_counts.get("HIGH", 0))],
        ["Severity: MEDIUM", str(severity_counts.get("MEDIUM", 0))],
        ["Severity: LOW", str(severity_counts.get("LOW", 0))],
    ]


def _finding_sort_key(item: Dict[str, Any]) -> tuple:
    raw_cvss = item.get("cvss_score")
    try:
        cvss_score = float(raw_cvss) if raw_cvss is not None else -1.0
    except (TypeError, ValueError):
        cvss_score = -1.0
    risk = _text(item.get("risk_level")).lower()
    risk_priority = {"exploit": 3, "misconfig": 2, "enum": 1}.get(risk, 0)
    return (risk_priority, cvss_score)


def generate_pdf_report(
    session_id: str,
    scan_metadata: Dict[str, Any],
    findings: List[Dict[str, Any]],
    reasoning: str,
    logs: List[str],
    checklist_coverage: Optional[Dict[str, Any]] = None,
    searchsploit_matches: Optional[List[Dict[str, Any]]] = None,
    zeroday_matches: Optional[List[Dict[str, Any]]] = None,
    remediation: Optional[Dict[str, Any]] = None,
) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"ASTRA Security Report - {session_id}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontSize=8,
        leading=10,
    )
    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
        wordWrap="CJK",
    )
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    story = []
    story.append(_paragraph("ASTRA Security Assessment Report", title_style))
    story.append(_paragraph(f"Session ID: {session_id}", body_style))
    story.append(Spacer(1, 4))

    metadata_rows = [
        [_cell("Target", table_cell_style), _cell(scan_metadata.get("target"), table_cell_style)],
        [_cell("Mode", table_cell_style), _cell(scan_metadata.get("mode"), table_cell_style)],
        [_cell("Scanners", table_cell_style), _cell(scan_metadata.get("scanners"), table_cell_style)],
        [_cell("Status", table_cell_style), _cell(_text(scan_metadata.get("status")).upper(), table_cell_style)],
        [_cell("Started At (UTC)", table_cell_style), _cell(scan_metadata.get("started_at"), table_cell_style)],
        [_cell("Ended At (UTC)", table_cell_style), _cell(scan_metadata.get("ended_at"), table_cell_style)],
    ]
    error_text = _text(scan_metadata.get("error"))
    if error_text != "-":
        metadata_rows.append([_cell("Error", table_cell_style), _cell(error_text, table_cell_style)])

    story.append(_paragraph("Scan Metadata", subtitle_style))
    metadata_table = Table(metadata_rows, colWidths=[40 * mm, 130 * mm], repeatRows=1)
    metadata_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(metadata_table)

    story.append(_paragraph("Findings Summary", subtitle_style))
    summary_rows = [[_cell(row[0], table_cell_style), _cell(row[1], table_cell_style)] for row in _build_summary_rows(findings)]
    summary_table = Table(summary_rows, colWidths=[60 * mm, 25 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eff6ff")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(summary_table)

    if checklist_coverage:
        summary = checklist_coverage.get("summary", {}) or {}
        groups = checklist_coverage.get("groups", []) or []

        story.append(_paragraph("Checklist Coverage", subtitle_style))
        checklist_rows = [
            [_cell("Total Checks", table_cell_style), _cell(summary.get("total", 0), table_cell_style)],
            [_cell("Detected", table_cell_style), _cell(summary.get("detected", 0), table_cell_style)],
            [_cell("Covered", table_cell_style), _cell(summary.get("covered", 0), table_cell_style)],
            [_cell("Uncovered", table_cell_style), _cell(summary.get("uncovered", 0), table_cell_style)],
        ]
        checklist_table = Table(checklist_rows, colWidths=[60 * mm, 25 * mm])
        checklist_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecfeff")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(checklist_table)

        if groups:
            group_rows = [[
                _cell("Group", table_header_style),
                _cell("Detected", table_header_style),
                _cell("Covered", table_header_style),
                _cell("Uncovered", table_header_style),
                _cell("Total", table_header_style),
            ]]
            for group in groups:
                group_rows.append(
                    [
                        _cell(group.get("label"), table_cell_style),
                        _cell(group.get("detected"), table_cell_style),
                        _cell(group.get("covered"), table_cell_style),
                        _cell(group.get("uncovered"), table_cell_style),
                        _cell(group.get("total"), table_cell_style),
                    ]
                )

            group_table = Table(
                group_rows,
                colWidths=[54 * mm, 22 * mm, 22 * mm, 22 * mm, 18 * mm],
                repeatRows=1,
            )
            group_table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(Spacer(1, 3))
            story.append(group_table)

    sorted_findings = sorted(findings, key=_finding_sort_key, reverse=True)
    limited_findings = sorted_findings[:120]
    story.append(_paragraph("Top Findings", subtitle_style))

    findings_header = [
        _cell("CVE", table_header_style),
        _cell("Type", table_header_style),
        _cell("Value", table_header_style),
        _cell("Risk", table_header_style),
        _cell("Target", table_header_style),
        _cell("Tool", table_header_style),
    ]
    findings_rows = [findings_header]
    for item in limited_findings:
        findings_rows.append(
            [
                _cell(item.get("cve_id"), table_cell_style),
                _cell(item.get("finding_type"), table_cell_style),
                _cell(_text(item.get("finding_value"))[:240], table_cell_style),
                _cell(_text(item.get("risk_level")).upper(), table_cell_style),
                _cell(_text(item.get("target"))[:140], table_cell_style),
                _cell(item.get("source_tool"), table_cell_style),
            ]
        )

    findings_table = Table(
        findings_rows,
        colWidths=[26 * mm, 28 * mm, 46 * mm, 18 * mm, 40 * mm, 25 * mm],
        repeatRows=1,
    )
    findings_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(findings_table)

    if searchsploit_matches:
        story.append(_paragraph("SearchSploit Exploit Matches", subtitle_style))
        exploit_rows = [[
            _cell("Query", table_header_style),
            _cell("Title", table_header_style),
            _cell("EDB", table_header_style),
            _cell("Target", table_header_style),
            _cell("Path", table_header_style),
        ]]
        for match in searchsploit_matches[:80]:
            exploit_rows.append(
                [
                    _cell(match.get("query") or match.get("service"), table_cell_style),
                    _cell(_text(match.get("title"))[:180], table_cell_style),
                    _cell(match.get("edb_id"), table_cell_style),
                    _cell(_text(match.get("target"))[:100], table_cell_style),
                    _cell(_text(match.get("path"))[:160], table_cell_style),
                ]
            )

        exploit_table = Table(
            exploit_rows,
            colWidths=[30 * mm, 58 * mm, 16 * mm, 34 * mm, 42 * mm],
            repeatRows=1,
        )
        exploit_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(exploit_table)

    if zeroday_matches:
        nvd_matches = [zd for zd in zeroday_matches if zd.get("intel_type", "nvd") == "nvd"]
        unverified_matches = [zd for zd in zeroday_matches if zd.get("intel_type") == "unverified_web"]

        if nvd_matches:
            story.append(_paragraph("Zero-Day & Recent Threat Intelligence (NVD)", subtitle_style))
            zd_rows = [[
                _cell("CVE ID", table_header_style),
                _cell("Published", table_header_style),
                _cell("CVSS", table_header_style),
                _cell("Description", table_header_style),
                _cell("Source", table_header_style),
            ]]
            for zd in nvd_matches[:60]:
                zd_rows.append([
                    _cell(zd.get("cve_id"), table_cell_style),
                    _cell(zd.get("published"), table_cell_style),
                    _cell(zd.get("cvss_score"), table_cell_style),
                    _cell(_text(zd.get("description"))[:240], table_cell_style),
                    _cell(zd.get("source_url"), table_cell_style),
                ])
            zd_table = Table(
                zd_rows,
                colWidths=[28 * mm, 20 * mm, 14 * mm, 80 * mm, 38 * mm],
                repeatRows=1,
            )
            zd_table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(zd_table)

        if unverified_matches:
            story.append(_paragraph("Unverified External Web Threat Intel", subtitle_style))
            story.append(_paragraph(
                "\u26a0 DISCLAIMER: The following results are UNVERIFIED intelligence gathered from "
                "the open web (GitHub Security Advisories, Google Custom Search). These findings have "
                "NOT been confirmed by NVD or ExploitDB and may contain false positives, "
                "misattributions, or inaccurate severity data. Treat as leads for further investigation only.",
                body_style,
            ))
            story.append(Spacer(1, 3))
            uw_rows = [[
                _cell("ID / GHSA", table_header_style),
                _cell("Published", table_header_style),
                _cell("Description / Snippet", table_header_style),
                _cell("Source", table_header_style),
                _cell("URL", table_header_style),
            ]]
            for uw in unverified_matches[:60]:
                uw_rows.append([
                    _cell(uw.get("cve_id"), table_cell_style),
                    _cell(uw.get("published"), table_cell_style),
                    _cell(_text(uw.get("description"))[:220], table_cell_style),
                    _cell(uw.get("source"), table_cell_style),
                    _cell(_text(uw.get("source_url"))[:120], table_cell_style),
                ])
            uw_table = Table(
                uw_rows,
                colWidths=[26 * mm, 18 * mm, 72 * mm, 32 * mm, 32 * mm],
                repeatRows=1,
            )
            uw_table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c3aed")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(uw_table)

    if remediation:
        story.append(_paragraph("CVE Remediation Details", subtitle_style))
        rem_rows = [[
            _cell("CVE ID", table_header_style),
            _cell("CVSS", table_header_style),
            _cell("Severity", table_header_style),
            _cell("CWE", table_header_style),
            _cell("Description", table_header_style),
            _cell("Patch / References", table_header_style),
        ]]
        for cve_id, d in list(remediation.items())[:50]:
            cwes = ", ".join(d.get("cwes", [])) or "-"
            refs = d.get("references", [])
            patch_refs = [r["url"] for r in refs if any(t in (r.get("tags") or []) for t in ("Patch", "Vendor Advisory", "Mitigation"))]
            patch_text = "\n".join(patch_refs[:3]) if patch_refs else (refs[0]["url"] if refs else "-")
            ghsa = d.get("ghsa")
            if ghsa and ghsa.get("patched_versions"):
                patch_text = "Patched: " + ", ".join(ghsa["patched_versions"][:3]) + ("\n" + patch_text if patch_text != "-" else "")
            rem_rows.append([
                _cell(cve_id, table_cell_style),
                _cell(d.get("cvss_score"), table_cell_style),
                _cell(_text(d.get("cvss_severity")).upper(), table_cell_style),
                _cell(cwes[:60], table_cell_style),
                _cell(_text(d.get("description"))[:200], table_cell_style),
                _cell(patch_text[:200], table_cell_style),
            ])
        rem_table = Table(
            rem_rows,
            colWidths=[26 * mm, 12 * mm, 16 * mm, 18 * mm, 60 * mm, 48 * mm],
            repeatRows=1,
        )
        rem_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#065f46")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(rem_table)

    story.append(_paragraph("AI Reasoning", subtitle_style))
    story.append(_paragraph(reasoning or "No AI reasoning captured for this session.", body_style))

    story.append(_paragraph("Log Excerpt", subtitle_style))
    excerpt = "\n".join(logs[-120:]) if logs else "No logs captured."
    story.append(Preformatted(excerpt, mono_style))

    document.build(story)
    return buffer.getvalue()
