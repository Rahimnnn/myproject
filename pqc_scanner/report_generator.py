"""
report_generator.py

Generates the structured security assessment report in JSON and PDF formats
(Objective 3, Week 8 deliverable).
"""

import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .logging_setup import format_bytes, format_duration, get_logger
from .models import ReplacementRun
from .recommender import SecurityAssessmentReport

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

log = get_logger(__name__)

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#B00020"),
    "High": colors.HexColor("#E07A00"),
    "Medium": colors.HexColor("#B8860B"),
}


def _esc(text: str) -> str:
    """Escape text for reportlab Paragraph markup (which is XML-like)."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_json(
    report: SecurityAssessmentReport,
    target_path: str | None = None,
    replacement: ReplacementRun | None = None,
) -> str:
    """Serialise the report to JSON. Returns the JSON string; optionally writes to disk."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_scanned": report.files_scanned,
        "total_findings": report.total_findings,
        "severity_counts": report.severity_counts,
        "algorithms_detected": [asdict(a) for a in report.algorithms_detected],
        "errors": report.errors,
    }
    if replacement is not None:
        payload["replacement"] = {
            "dry_run": replacement.dry_run,
            "reverted": replacement.reverted,
            "cross_file_notes": replacement.cross_file_notes,
            "validation_summary": replacement.validation_summary,
            "input_tokens": replacement.input_tokens,
            "output_tokens": replacement.output_tokens,
            "estimated_cost_usd": replacement.estimated_cost_usd,
            "files": [asdict(r) for r in replacement.rewrites],
        }
    text = json.dumps(payload, indent=2)
    if target_path:
        Path(target_path).write_text(text, encoding="utf-8")
        log.info("JSON report written: %s (%s)",
                 target_path, format_bytes(len(text.encode("utf-8"))))
    else:
        log.debug("JSON report rendered in memory (%s), not written to disk",
                  format_bytes(len(text.encode("utf-8"))))
    return text


def to_pdf(
    report: SecurityAssessmentReport,
    target_path: str,
    scan_target: str = "",
    replacement: ReplacementRun | None = None,
) -> None:
    """Render the report as a formatted PDF security assessment document."""
    started = time.perf_counter()
    log.debug("Rendering PDF report to %s (%d algorithm section(s)%s)",
              target_path, len(report.algorithms_detected),
              ", plus replacement appendix" if replacement is not None else "")
    doc = SimpleDocTemplate(
        target_path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    story = []
    story.append(Paragraph("Post-Quantum Cryptography Migration Assessment", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        + (f" &nbsp;|&nbsp; Target: {scan_target}" if scan_target else ""),
        small,
    ))
    story.append(Spacer(1, 12))

    # Summary table
    story.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Files scanned", str(report.files_scanned)],
        ["Total findings", str(report.total_findings)],
        ["Critical severity", str(report.severity_counts.get("Critical", 0))],
        ["High severity", str(report.severity_counts.get("High", 0))],
        ["Medium severity", str(report.severity_counts.get("Medium", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[6 * cm, 6 * cm])
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    if not report.algorithms_detected:
        story.append(Paragraph(
            "No legacy cryptographic algorithms were detected in the scanned source code.",
            body,
        ))
    else:
        story.append(Paragraph("Detected Algorithms & Migration Recommendations", h2))
        for algo in report.algorithms_detected:
            sev_color = _SEVERITY_COLORS.get(algo.severity, colors.black)
            header_style = ParagraphStyle(
                "AlgoHeader", parent=styles["Heading3"], textColor=sev_color, spaceBefore=10,
            )
            story.append(Paragraph(f"{algo.algorithm} — {algo.severity} severity", header_style))
            detail_data = [
                ["Category", algo.category],
                ["Quantum threat", algo.quantum_threat],
                ["Occurrences", f"{algo.occurrences} (in {len(algo.files_affected)} file(s))"],
                ["Detection confidence", f"{algo.average_confidence * 100:.0f}%"],
                ["PQC alternative", algo.pqc_alternative],
                ["Standard", algo.standard],
            ]
            t = Table(detail_data, colWidths=[4 * cm, 12 * cm])
            t.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f7f7")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Paragraph(f"<i>{algo.rationale}</i>", small))
            files_str = ", ".join(algo.files_affected[:5])
            if len(algo.files_affected) > 5:
                files_str += f", +{len(algo.files_affected) - 5} more"
            story.append(Paragraph(f"Affected file(s): {files_str}", small))
            story.append(Spacer(1, 6))

    if replacement and replacement.rewrites:
        story.append(PageBreak())
        heading = "Proposed Migrations (dry run)" if replacement.dry_run \
            else "Applied Migrations (LLM-assisted)"
        story.append(Paragraph(heading, h2))
        intro = (
            "Dry run -- no files were changed. " if replacement.dry_run
            else ("All files were rolled back after failed validation. "
                  if replacement.reverted else "")
        )
        story.append(Paragraph(
            intro
            + "This was a single project-aware migration coordinating all files. "
            "Each migration is a suggested starting point and "
            "<b>requires cryptographic review</b> before use.",
            small,
        ))
        def _cell(text: str):
            return Paragraph(_esc(text).replace("\n", "<br/>"), small)

        meta = [
            ["Validation", _cell(replacement.validation_summary or "-")],
            ["Estimated cost", _cell(
                f"${replacement.estimated_cost_usd:.4f} "
                f"({replacement.input_tokens} in / {replacement.output_tokens} out tokens)")],
        ]
        if replacement.cross_file_notes:
            meta.append(["Cross-file coordination", _cell(replacement.cross_file_notes)])
        mt = Table(meta, colWidths=[4 * cm, 12 * cm])
        mt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f7f7")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(mt)
        story.append(Spacer(1, 8))
        for rw in replacement.rewrites:
            if replacement.dry_run:
                status, status_color = "PROPOSED", colors.HexColor("#0B5FA5")
            elif not rw.modified:
                status, status_color = "NOT MODIFIED", colors.HexColor("#666666")
            elif rw.verified:
                status, status_color = "VERIFIED", colors.HexColor("#1B7F3B")
            else:
                status, status_color = "NEEDS REVIEW", colors.HexColor("#B00020")
            header_style = ParagraphStyle(
                "RwHeader", parent=styles["Heading3"], textColor=status_color, spaceBefore=10,
            )
            story.append(Paragraph(f"{_esc(rw.file_path)} — {status}", header_style))
            rw_data = [
                ["Algorithms replaced", ", ".join(rw.algorithms_addressed) or "-"],
                ["Confidence", rw.confidence],
                ["Backup", rw.backup_path or "(none)"],
            ]
            if rw.remaining_algorithms:
                rw_data.append(["Still detected after rewrite", ", ".join(rw.remaining_algorithms)])
            t = Table(rw_data, colWidths=[4 * cm, 12 * cm])
            t.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7f7f7")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            if rw.changes_summary:
                story.append(Paragraph(f"<b>Changes:</b> {_esc(rw.changes_summary)}", small))
            if rw.caveats:
                story.append(Paragraph(f"<b>Caveats:</b> <i>{_esc(rw.caveats)}</i>", small))
            story.append(Spacer(1, 6))

    if report.errors:
        story.append(PageBreak())
        story.append(Paragraph("Scan Errors", h2))
        for err in report.errors:
            story.append(Paragraph(_esc(err), small))

    log.trace("PDF story assembled: %d flowable(s)", len(story))
    doc.build(story)

    try:
        size = Path(target_path).stat().st_size
    except OSError:
        size = 0
    log.info("PDF report written: %s (%s, rendered in %s)", target_path,
             format_bytes(size), format_duration(time.perf_counter() - started))
