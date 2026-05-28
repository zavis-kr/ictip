"""PDF report generation router."""
from io import BytesIO
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.database import get_db
from app.models import Threat, ThreatFeed, ThreatShare, AIAnalysis
from app.auth import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _build_pdf(buffer: BytesIO, draw_fn) -> BytesIO:
    """Generate a PDF using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        draw_fn(buffer, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, getSampleStyleSheet, ParagraphStyle, colors, A4, mm)
    except Exception as e:
        # Fallback: write a simple text-based PDF manually
        buffer.seek(0)
        buffer.truncate(0)
        content = f"Threat Intelligence Report\n\nError generating full report: {e}\n"
        # Minimal valid PDF
        pdf_text = (
            "%PDF-1.4\n"
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
            f"4 0 obj\n<< /Length {len(content) + 50} >>\nstream\nBT /F1 12 Tf 50 750 Td "
            f"({content[:200]}) Tj ET\nendstream\nendobj\n"
            "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
            "xref\n0 6\n0000000000 65535 f\n"
            "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        )
        buffer.write(pdf_text.encode("latin-1", errors="replace"))
    buffer.seek(0)
    return buffer


@router.get("/threat/{threat_id}")
async def get_threat_report(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Generate and download a PDF report for a specific threat."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Load AI analysis if available
    analysis = (await db.execute(
        select(AIAnalysis).where(AIAnalysis.threat_id == threat_id)
    )).scalar_one_or_none()

    # Load share history
    shares_result = await db.execute(
        select(ThreatShare).where(ThreatShare.threat_id == threat_id)
        .order_by(desc(ThreatShare.shared_at)).limit(10)
    )
    shares = shares_result.scalars().all()

    buffer = BytesIO()

    def draw(buf, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
             HRFlowable, getSampleStyleSheet, ParagraphStyle, colors, A4, mm):
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=6)
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceAfter=4)
        normal = styles["Normal"]
        small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=9)

        story = []
        story.append(Paragraph("ICTIP - Threat Intelligence Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", small))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 6*mm))

        # Basic info
        story.append(Paragraph("Threat Overview", h2))
        basic = [
            ["Field", "Value"],
            ["ID", str(threat.id)],
            ["Title", (threat.title or "")[:80]],
            ["Severity", threat.severity or "N/A"],
            ["Type", threat.threat_type or "N/A"],
            ["Source", threat.source or "N/A"],
            ["TLP Level", threat.tlp_level or "WHITE"],
            ["Detected At", str(threat.detected_at)[:19] if threat.detected_at else "N/A"],
            ["Country", threat.country_code or "N/A"],
            ["Actor", threat.actor_tag or "N/A"],
        ]
        t = Table(basic, colWidths=[50*mm, 120*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f0f4f8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # IOC
        story.append(Paragraph("IOC Information", h2))
        ioc_data = [
            ["IOC Type", threat.ioc_type or "N/A"],
            ["IOC Value", (threat.ioc_value or "N/A")[:100]],
            ["IOC Count", str(threat.ioc_count)],
        ]
        t2 = Table(ioc_data, colWidths=[50*mm, 120*mm])
        t2.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
        ]))
        story.append(t2)
        story.append(Spacer(1, 5*mm))

        # MITRE ATT&CK
        story.append(Paragraph("MITRE ATT&CK", h2))
        mitre_data = [
            ["Tactic", f"{threat.mitre_tactic or 'N/A'} ({threat.mitre_tactic_id or ''})"],
            ["Technique", f"{threat.mitre_technique or 'N/A'} ({threat.mitre_technique_id or ''})"],
        ]
        t3 = Table(mitre_data, colWidths=[50*mm, 120*mm])
        t3.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
        ]))
        story.append(t3)
        story.append(Spacer(1, 5*mm))

        # AI Analysis
        if analysis:
            story.append(Paragraph("AI Analysis Results", h2))
            story.append(Paragraph(f"Risk Score: {analysis.risk_score:.1f} / Risk Level: {analysis.risk_level}", normal))
            story.append(Spacer(1, 2*mm))
            if analysis.summary:
                story.append(Paragraph("Summary:", ParagraphStyle("Bold", parent=normal, fontName="Helvetica-Bold")))
                story.append(Paragraph(analysis.summary[:500], small))
            if analysis.recommendations:
                story.append(Spacer(1, 2*mm))
                story.append(Paragraph("Recommendations:", ParagraphStyle("Bold", parent=normal, fontName="Helvetica-Bold")))
                story.append(Paragraph(analysis.recommendations[:500], small))
            story.append(Spacer(1, 5*mm))

        # Share history
        if shares:
            story.append(Paragraph("Sharing History", h2))
            share_rows = [["To Agency", "Status", "TLP", "Shared At"]]
            for s in shares:
                share_rows.append([
                    s.to_agency_name[:30],
                    s.status,
                    s.tlp_level,
                    str(s.shared_at)[:16] if s.shared_at else "N/A",
                ])
            t4 = Table(share_rows, colWidths=[60*mm, 30*mm, 20*mm, 60*mm])
            t4.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(t4)

        doc.build(story)

    _build_pdf(buffer, draw)

    filename = f"threat_report_{threat_id}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/daily")
async def get_daily_report(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Generate and download a daily threat summary PDF report."""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)

    threats_result = await db.execute(
        select(Threat)
        .where(Threat.detected_at >= yesterday_start)
        .where(Threat.is_active == True)
        .order_by(desc(Threat.detected_at))
        .limit(50)
    )
    threats = threats_result.scalars().all()

    # Severity summary
    sev_result = await db.execute(
        select(Threat.severity, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= yesterday_start)
        .where(Threat.is_active == True)
        .group_by(Threat.severity)
    )
    sev_counts = {r.severity: r.cnt for r in sev_result.all()}

    # Type summary
    type_result = await db.execute(
        select(Threat.threat_type, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= yesterday_start)
        .where(Threat.is_active == True)
        .group_by(Threat.threat_type)
        .order_by(desc("cnt"))
        .limit(10)
    )
    type_counts = type_result.all()

    buffer = BytesIO()

    def draw(buf, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
             HRFlowable, getSampleStyleSheet, ParagraphStyle, colors, A4, mm):
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=6)
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceAfter=4)
        normal = styles["Normal"]
        small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=9)

        story = []
        story.append(Paragraph("ICTIP - Daily Threat Summary Report", title_style))
        story.append(Paragraph(f"Date: {yesterday_start.strftime('%Y-%m-%d')} to {today_start.strftime('%Y-%m-%d')}", small))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", small))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 6*mm))

        # Summary stats
        story.append(Paragraph("Executive Summary", h2))
        summary_data = [
            ["Total Threats", str(len(threats))],
            ["Critical", str(sev_counts.get("긴급", 0))],
            ["High", str(sev_counts.get("높음", 0))],
            ["Medium", str(sev_counts.get("중간", 0))],
            ["Low", str(sev_counts.get("낮음", 0))],
        ]
        t = Table(summary_data, colWidths=[60*mm, 60*mm])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # Threat type breakdown
        story.append(Paragraph("Threat Type Breakdown", h2))
        type_rows = [["Threat Type", "Count"]]
        for r in type_counts:
            type_rows.append([r.threat_type or "Unknown", str(r.cnt)])
        t2 = Table(type_rows, colWidths=[100*mm, 40*mm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(t2)
        story.append(Spacer(1, 5*mm))

        # Top threats list
        story.append(Paragraph("Top Threats (Last 24h)", h2))
        threat_rows = [["ID", "Title", "Severity", "Type", "Source"]]
        for th in threats[:20]:
            threat_rows.append([
                str(th.id),
                (th.title or "")[:40],
                th.severity or "N/A",
                (th.threat_type or "N/A")[:20],
                (th.source or "N/A")[:15],
            ])
        t3 = Table(threat_rows, colWidths=[12*mm, 65*mm, 20*mm, 35*mm, 28*mm])
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        story.append(t3)

        doc.build(story)

    _build_pdf(buffer, draw)

    filename = f"daily_report_{yesterday_start.strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
