"""
PhantomNet++ Report Backend — report_backend.py
Port: 8004

Generates PDF + JSON reports for:
  - Threat Detection results   (POST /api/report/threat)
  - XAI Explanation results    (POST /api/report/xai)
  - Attack Simulation results  (POST /api/report/simulation)

PDF is generated server-side using ReportLab with full visualizations
(bar charts, images, tables). JSON is the raw structured data.

Install: pip install reportlab
"""

from __future__ import annotations

import base64
import io
import json
import uuid
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

# PKT = UTC+5 (Pakistan Standard Time)
PKT = timezone(timedelta(hours=5))
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image as RLImage, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="PhantomNet++ Report API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
C_BG        = colors.HexColor("#0d1424")
C_SURFACE   = colors.HexColor("#111827")
C_GREEN     = colors.HexColor("#10b981")
C_RED       = colors.HexColor("#ef4444")
C_AMBER     = colors.HexColor("#f59e0b")
C_BLUE      = colors.HexColor("#3b82f6")
C_PURPLE    = colors.HexColor("#a78bfa")
C_SUBTLE    = colors.HexColor("#334155")
C_TEXT      = colors.HexColor("#e2e8f0")
C_SUBTEXT   = colors.HexColor("#64748b")
C_WHITE     = colors.white
C_BLACK     = colors.black
C_LIGHT_BG  = colors.HexColor("#f8fafc")
C_BORDER    = colors.HexColor("#1e293b")

SEV_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#f59e0b"),
    "low":      colors.HexColor("#3b82f6"),
    "info":     colors.HexColor("#3b82f6"),
    "clean":    colors.HexColor("#10b981"),
}

# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------
PAGE_W, PAGE_H = A4
MARGIN = 20 * mm

def build_styles():
    styles = getSampleStyleSheet()

    def add(name, **kw):
        styles.add(ParagraphStyle(name=name, **kw))

    add("PNTitle",
        fontSize=18, fontName="Helvetica-Bold",
        textColor=C_BLACK, spaceAfter=6, spaceBefore=8, leading=22, alignment=TA_LEFT)

    add("PNSubtitle",
        fontSize=10, fontName="Helvetica",
        textColor=C_SUBTEXT, spaceAfter=8, leading=14, alignment=TA_LEFT)

    add("PNSectionHead",
        fontSize=13, fontName="Helvetica-Bold",
        textColor=C_BLACK, spaceBefore=14, spaceAfter=6,
        borderPad=4, borderColor=C_GREEN, borderWidth=0,
        leftIndent=0)

    add("PNBody",
        fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#1e293b"),
        leading=15, spaceAfter=4)

    add("PNMono",
        fontSize=8, fontName="Courier",
        textColor=colors.HexColor("#334155"),
        leading=11, spaceAfter=2)

    add("PNCaption",
        fontSize=8, fontName="Helvetica",
        textColor=C_SUBTEXT, alignment=TA_CENTER,
        spaceAfter=6)

    add("PNLabel",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=C_SUBTEXT, spaceAfter=2)

    add("PNValue",
        fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#0f172a"), spaceAfter=6)

    return styles

# ---------------------------------------------------------------------------
# Common PDF elements
# ---------------------------------------------------------------------------

def header_block(story, styles, title: str, subtitle: str, report_id: str, timestamp: str):
    """Top header — clean layout with proper spacing."""

    # Brand line
    story.append(Paragraph(
        '<font color="#10b981"><b>PhantomNet++</b></font>'
        '&nbsp;&nbsp;<font color="#94a3b8" size="9">Adversarial Threat Detection Platform</font>',
        styles["PNBody"]
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_GREEN,
                             spaceBefore=4, spaceAfter=10))

    # Title — on its own line with room to breathe
    story.append(Paragraph(title, styles["PNTitle"]))

    # Subtitle — separate paragraph below title
    story.append(Paragraph(subtitle, styles["PNSubtitle"]))

    # Meta row — Report ID and Generated side by side, full usable width
    meta_style_k = ParagraphStyle("MK", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=C_SUBTEXT, leading=11)
    meta_style_v = ParagraphStyle("MV", fontSize=8, fontName="Helvetica",
                                   textColor=colors.HexColor("#334155"), leading=11)
    meta_table = Table(
        [
            [Paragraph("Report ID", meta_style_k), Paragraph(report_id,  meta_style_v),
             Paragraph("Generated", meta_style_k), Paragraph(timestamp,  meta_style_v)],
        ],
        colWidths=[22*mm, 63*mm, 22*mm, 63*mm],
    )
    meta_table.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER,
                             spaceBefore=8, spaceAfter=14))


def section_head(story, styles, title: str):
    story.append(Paragraph(title, styles["PNSectionHead"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=6))


def kv_table(story, rows: List[tuple], col_w=(45, 110)):
    """Two-column key-value table — values use Paragraph so long text wraps."""
    key_style = ParagraphStyle("KVKey",
        fontSize=9, fontName="Helvetica-Bold",
        textColor=C_SUBTEXT, leading=12)
    val_style = ParagraphStyle("KVVal",
        fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#1e293b"), leading=12)

    para_rows = [
        (Paragraph(str(k), key_style), Paragraph(str(v), val_style))
        for k, v in rows
    ]
    table = Table(para_rows, colWidths=[col_w[0] * mm, col_w[1] * mm])
    table.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 6))


def severity_badge(sev: str) -> str:
    """Return coloured HTML-ish text for severity."""
    c = {
        "critical": "#ef4444", "high": "#f97316",
        "medium": "#f59e0b",   "low": "#3b82f6",
        "clean":  "#10b981",   "unknown": "#94a3b8",
    }.get(sev.lower(), "#94a3b8")
    return f'<font color="{c}"><b>{sev.upper()}</b></font>'


def base64_to_image(b64: str, width: float, height: float) -> Optional[RLImage]:
    """Convert base64 image string to ReportLab Image."""
    try:
        if "," in b64:
            b64 = b64.split(",", 1)[1]
        data = base64.b64decode(b64)
        img_io = io.BytesIO(data)
        return RLImage(img_io, width=width, height=height)
    except Exception:
        return None


def feature_bar_chart(features: List[Dict], width=160*mm, height=60*mm) -> Drawing:
    """Horizontal importance bar chart for XAI features."""
    d = Drawing(width, height)
    if not features:
        return d

    n        = min(len(features), 8)
    feats    = features[:n]
    bar_h    = (height - 20) / n
    max_val  = max(f.get("importance", 0) for f in feats)
    max_val  = max_val if max_val > 0 else 1
    bar_area = width - 60 * mm   # space for labels

    for i, f in enumerate(feats):
        y_pos    = height - 16 - i * bar_h
        imp      = f.get("importance", 0)
        bar_w    = (imp / max_val) * bar_area
        pct      = imp * 100

        # Bar
        hue = colors.HexColor("#10b981") if pct > 50 else \
              colors.HexColor("#f59e0b") if pct > 25 else \
              colors.HexColor("#3b82f6")
        d.add(Rect(45 * mm, y_pos, bar_w, bar_h - 2,
                   fillColor=hue, strokeColor=None))

        # Feature name
        d.add(String(0, y_pos + 2,
                     f.get("name", f"Feature {i+1}")[:18],
                     fontSize=7, fillColor=colors.HexColor("#334155")))

        # Percentage label
        d.add(String(45 * mm + bar_w + 2, y_pos + 2,
                     f"{pct:.1f}%",
                     fontSize=7, fillColor=C_SUBTEXT))

    return d


def model_bar_chart(contributions: List[Dict], width=140*mm, height=50*mm) -> Drawing:
    """Vertical bar chart for model ensemble contributions."""
    d = Drawing(width, height)
    if not contributions:
        return d

    n       = len(contributions)
    bar_w   = min(30 * mm, (width - 20) / n)
    gap     = 5 * mm
    max_val = max(c.get("confidence", 0) for c in contributions)
    max_val = max_val if max_val > 0 else 1
    chart_h = height - 20
    x_start = 10

    MODEL_COLORS = [
        colors.HexColor("#10b981"),
        colors.HexColor("#3b82f6"),
        colors.HexColor("#a78bfa"),
    ]

    for i, c in enumerate(contributions):
        x       = x_start + i * (bar_w + gap)
        conf    = c.get("confidence", 0)
        bar_ht  = (conf / max_val) * chart_h
        vote    = c.get("vote", "clean")
        clr     = colors.HexColor("#ef4444") if vote == "adversarial" else MODEL_COLORS[i % len(MODEL_COLORS)]

        d.add(Rect(x, 15, bar_w, bar_ht, fillColor=clr, strokeColor=None))
        name = c.get("model", f"Model {i+1}").replace("YOLOv5", "YOLO").replace("Autoencoder", "AE")[:10]
        d.add(String(x + bar_w / 2 - 15, 4, name, fontSize=7, fillColor=C_SUBTEXT))
        d.add(String(x + bar_w / 2 - 8, 15 + bar_ht + 2,
                     f"{conf*100:.0f}%", fontSize=7, fillColor=colors.HexColor("#334155")))

    return d


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ThreatReportRequest(BaseModel):
    threat_id:       str
    filename:        str
    timestamp:       str
    final_decision:  str
    confidence:      float
    severity:        str
    attack_type:     str
    attack_category: Optional[str] = None
    posture:         Optional[str] = "normal"
    model_contributions: Optional[List[Dict]] = []
    votes:           Optional[Dict] = {}
    weights_used:    Optional[Dict] = {}
    image_b64:       Optional[str] = None   # base64 of scanned image

class XAIReportRequest(BaseModel):
    explanation_id:   str
    scan_id:          str
    timestamp:        str
    method:           str
    prediction:       str
    confidence:       float
    attack_type:      str
    severity:         str
    is_adversarial:   bool
    description:      str
    features:         Optional[List[Dict]] = []
    original_image:   Optional[str] = None   # base64
    explanation_image: Optional[str] = None  # base64
    gradcam_image:    Optional[str] = None   # base64 — GradCAM visual
    lime_image:       Optional[str] = None   # base64 — LIME visual
    shap_image:       Optional[str] = None   # base64 — SHAP visual
    all_methods:      Optional[List[Dict]] = []  # list of {method, description, features, explanation_image, original_image}

class SimulationReportRequest(BaseModel):
    sim_id:      str
    timestamp:   str
    attack_type: str
    strength:    Optional[float] = None
    success_rate: float
    confidence:  float
    before_image: Optional[str] = None   # base64
    after_image:  Optional[str] = None   # base64
    confusion_matrix: Optional[List[Dict]] = []
    top_misclassifications: Optional[List[Dict]] = []


# ---------------------------------------------------------------------------
# PDF generators
# ---------------------------------------------------------------------------

def generate_threat_pdf(req: ThreatReportRequest) -> bytes:
    buf     = io.BytesIO()
    doc     = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=MARGIN, rightMargin=MARGIN,
                                topMargin=MARGIN, bottomMargin=MARGIN)
    styles  = build_styles()
    story   = []
    report_id = f"RPT-TD-{uuid.uuid4().hex[:8].upper()}"
    ts        = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S PKT")

    # Header
    header_block(story, styles, "Threat Detection Report",
                 f"Scan ID: {req.threat_id}  ·  File: {req.filename}", report_id, ts)

    # Decision banner
    decision_color = C_RED if req.final_decision == "adversarial" else C_GREEN
    decision_text  = "ADVERSARIAL THREAT DETECTED" if req.final_decision == "adversarial" else "IMAGE CLASSIFIED AS CLEAN"
    banner = Table([[decision_text]], colWidths=[PAGE_W - 2 * MARGIN])
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), decision_color),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 13),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(banner)
    story.append(Spacer(1, 12))

    # Summary
    section_head(story, styles, "Detection Summary")
    kv_table(story, [
        ("Threat ID",        req.threat_id),
        ("Filename",         req.filename),
        ("Timestamp",        req.timestamp),
        ("Final Decision",   req.final_decision.upper()),
        ("Confidence",       f"{req.confidence * 100:.2f}%"),
        ("Severity",         req.severity.upper()),
        ("Attack Type",      req.attack_type),
        ("Attack Category",  req.attack_category or "N/A"),
        ("Detection Posture",req.posture or "normal"),
    ])

    # Ensemble votes
    if req.votes:
        section_head(story, styles, "Ensemble Voting")
        vote_data = [["Adversarial Votes", "Clean Votes", "Total Models"]]
        vote_data.append([
            str(req.votes.get("adversarial", 0)),
            str(req.votes.get("clean", 0)),
            str(req.votes.get("total", 0)),
        ])
        vt = Table(vote_data, colWidths=[55 * mm, 55 * mm, 55 * mm])
        vt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ]))
        story.append(vt)
        story.append(Spacer(1, 10))

    # Model contributions chart
    if req.model_contributions:
        section_head(story, styles, "Model Contributions")
        story.append(Paragraph(
            "Each bar shows the weighted confidence contribution from each model in the ensemble. "
            "Red bars voted adversarial; coloured bars voted clean.",
            styles["PNBody"]
        ))
        chart = model_bar_chart(req.model_contributions)
        story.append(chart)
        story.append(Spacer(1, 6))

        # Contribution detail table
        _cs = ParagraphStyle("CT", fontSize=9, fontName="Helvetica", leading=11,
                              textColor=colors.HexColor("#1e293b"))
        _ch = ParagraphStyle("CTH", fontSize=9, fontName="Helvetica-Bold", leading=11,
                              textColor=colors.white)
        contrib_data = [[Paragraph(h, _ch) for h in ["Model", "Vote", "Confidence", "Weight"]]]
        for c in req.model_contributions:
            wk = "yolo" if "YOLO" in c.get("model","") else                  "autoencoder" if "Auto" in c.get("model","") else "resnet"
            contrib_data.append([
                Paragraph(c.get("model","Unknown"), _cs),
                Paragraph(c.get("vote","—").upper(), _cs),
                Paragraph(f"{c.get('confidence',0)*100:.1f}%", _cs),
                Paragraph(str(req.weights_used.get(wk,"—")), _cs),
            ])
        ct = Table(contrib_data, colWidths=[70*mm, 30*mm, 37*mm, 28*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ]))
        story.append(ct)
        story.append(Spacer(1, 10))

    # Scanned image
    if req.image_b64:
        section_head(story, styles, "Scanned Image")
        img = base64_to_image(req.image_b64, 80 * mm, 80 * mm)
        if img:
            img_table = Table([[img]], colWidths=[80 * mm])
            img_table.setStyle(TableStyle([
                ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
                ("BORDER", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(img_table)
            story.append(Paragraph("Figure 1: Input image submitted for analysis", styles["PNCaption"]))

    # CVSS note
    section_head(story, styles, "Severity Classification (CVSS v3.1)")
    story.append(Paragraph(
        "Severity is aligned to CVSS v3.1 scoring bands: "
        "<b>Critical</b> (confidence ≥ 0.85, CVSS 9.0–10.0), "
        "<b>High</b> (≥ 0.65, CVSS 7.0–8.9), "
        "<b>Medium</b> (≥ 0.40, CVSS 4.0–6.9), "
        "<b>Low</b> (< 0.40, CVSS 0.1–3.9).",
        styles["PNBody"]
    ))

    # Footer note
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Generated by PhantomNet++ · {ts} · Report ID: {report_id} · "
        "This report is auto-generated and should be reviewed by a qualified security analyst.",
        styles["PNMono"]
    ))

    doc.build(story)
    return buf.getvalue()


def generate_xai_pdf(req: XAIReportRequest) -> bytes:
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=MARGIN, rightMargin=MARGIN,
                               topMargin=MARGIN, bottomMargin=MARGIN)
    styles = build_styles()
    story  = []
    report_id = f"RPT-XAI-{uuid.uuid4().hex[:8].upper()}"
    ts        = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S PKT")

    header_block(story, styles, "XAI Explanation Report",
                 f"Methods: {req.method}  ·  Scan: {req.scan_id}", report_id, ts)

    # Decision banner
    is_adv = req.is_adversarial
    banner = Table(
        [["ADVERSARIAL" if is_adv else "CLEAN IMAGE"]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_RED if is_adv else C_GREEN),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 13),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner)
    story.append(Spacer(1, 12))

    # Summary
    section_head(story, styles, "Explanation Summary")
    kv_table(story, [
        ("Explanation ID",  req.explanation_id),
        ("Scan ID",         req.scan_id),
        ("Timestamp",       req.timestamp),
        ("Methods Used",    req.method),
        ("Prediction",      req.prediction),
        ("Confidence",      f"{req.confidence * 100:.2f}%"),
        ("Attack Type",     req.attack_type),
        ("Severity",        req.severity.upper()),
        ("Is Adversarial",  "YES" if req.is_adversarial else "NO"),
    ])

    # ── All method visuals ────────────────────────────────────────────────────
    methods_to_show = req.all_methods or []
    if not methods_to_show and req.original_image:
        # Fallback: single method
        methods_to_show = [{
            "method":            req.method,
            "description":       req.description,
            "features":          req.features or [],
            "explanation_image": req.explanation_image,
            "original_image":    req.original_image,
        }]

    for m in methods_to_show:
        method_name = m.get("method", "Unknown")
        desc        = m.get("description", "")
        feats       = m.get("features", [])
        orig_b64    = m.get("original_image") or req.original_image
        expl_b64    = m.get("explanation_image")

        section_head(story, styles, f"Method: {method_name}")

        if desc:
            story.append(Paragraph(desc, styles["PNBody"]))
            story.append(Spacer(1, 6))

        # Side-by-side: Original | Explanation
        img_size = 73 * mm
        cells, captions = [], []
        if orig_b64:
            img = base64_to_image(orig_b64, img_size, img_size)
            if img:
                cells.append(img); captions.append("Original Image")
        if expl_b64:
            img = base64_to_image(expl_b64, img_size, img_size)
            if img:
                cells.append(img); captions.append(f"{method_name} Visualization")

        if cells:
            col_w = [img_size + 4*mm] * len(cells)
            img_tbl = Table([cells], colWidths=col_w)
            img_tbl.setStyle(TableStyle([
                ("ALIGN",   (0,0),(-1,-1), "CENTER"),
                ("GRID",    (0,0),(-1,-1), 0.3, colors.HexColor("#cbd5e1")),
                ("PADDING", (0,0),(-1,-1), 4),
            ]))
            story.append(img_tbl)
            cap_tbl = Table([captions], colWidths=col_w)
            cap_tbl.setStyle(TableStyle([
                ("FONTSIZE",  (0,0),(-1,-1), 8),
                ("ALIGN",     (0,0),(-1,-1), "CENTER"),
                ("TEXTCOLOR", (0,0),(-1,-1), C_SUBTEXT),
            ]))
            story.append(cap_tbl)
            story.append(Spacer(1, 8))

        # Feature importance for this method
        if feats:
            story.append(Paragraph("Feature Importance", styles["PNSectionHead"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=4))
            chart = feature_bar_chart(feats)
            story.append(chart)
            story.append(Spacer(1, 4))

            _fs = ParagraphStyle("FT2", fontSize=9, fontName="Helvetica", leading=11,
                                  textColor=colors.HexColor("#1e293b"))
            _fh = ParagraphStyle("FTH2", fontSize=9, fontName="Helvetica-Bold", leading=11,
                                  textColor=colors.white)
            feat_data = [[Paragraph(h, _fh) for h in ["Feature / Region", "Importance", "Contribution %"]]]
            for f in feats[:8]:
                imp = f.get("importance", 0)
                feat_data.append([
                    Paragraph(f.get("name","Unknown"), _fs),
                    Paragraph(f"{imp:.4f}", _fs),
                    Paragraph(f"{imp*100:.1f}%", _fs),
                ])
            ft = Table(feat_data, colWidths=[95*mm, 37*mm, 38*mm])
            ft.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), colors.HexColor("#1e293b")),
                ("FONTSIZE",      (0,0),(-1,-1), 9),
                ("ALIGN",         (1,0),(-1,-1), "CENTER"),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
                ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),
                 [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))
            story.append(ft)
            story.append(Spacer(1, 10))

    # Footer
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Generated by PhantomNet++ · {ts} · Report ID: {report_id}",
        styles["PNMono"]
    ))

    doc.build(story)
    return buf.getvalue()


def generate_simulation_pdf(req: SimulationReportRequest) -> bytes:
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=MARGIN, rightMargin=MARGIN,
                               topMargin=MARGIN, bottomMargin=MARGIN)
    styles = build_styles()
    story  = []
    report_id = f"RPT-SIM-{uuid.uuid4().hex[:8].upper()}"
    ts        = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S PKT")

    header_block(story, styles, "Attack Simulation Report",
                 f"Simulation ID: {req.sim_id}", report_id, ts)

    # Result banner
    success = req.success_rate > 0
    banner = Table(
        [["ATTACK SUCCEEDED — MODEL FOOLED" if success else "ATTACK FAILED — MODEL RESISTED"]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_RED if success else C_GREEN),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 13),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(banner)
    story.append(Spacer(1, 12))

    # Summary
    section_head(story, styles, "Simulation Summary")
    kv_table(story, [
        ("Simulation ID",  req.sim_id),
        ("Timestamp",      req.timestamp),
        ("Attack Type",    req.attack_type),
        ("Attack Strength",f"{req.strength:.1f}/10" if req.strength else "N/A"),
        ("Success Rate",   f"{req.success_rate:.1f}%"),
        ("Confidence",     f"{req.confidence * 100:.2f}%"),
        ("Outcome",        "Model Fooled" if success else "Model Resisted"),
    ])

    # Before / After images
    if req.before_image or req.after_image:
        section_head(story, styles, "Before / After Comparison")
        story.append(Paragraph(
            "Left: original clean image submitted to the model. "
            "Right: adversarially perturbed image after attack.",
            styles["PNBody"]
        ))
        img_size = 75 * mm
        cells, captions = [], []
        if req.before_image:
            img = base64_to_image(req.before_image, img_size, img_size)
            if img:
                cells.append(img); captions.append("Before — Clean Input")
        if req.after_image:
            img = base64_to_image(req.after_image, img_size, img_size)
            if img:
                cells.append(img); captions.append("After — Adversarial Perturbation")

        if cells:
            col_w = [img_size + 4 * mm] * len(cells)
            img_tbl = Table([cells], colWidths=col_w)
            img_tbl.setStyle(TableStyle([
                ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
                ("GRID",    (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(img_tbl)
            cap_tbl = Table([captions], colWidths=col_w)
            cap_tbl.setStyle(TableStyle([
                ("FONTSIZE",  (0, 0), (-1, -1), 8),
                ("ALIGN",     (0, 0), (-1, -1), "CENTER"),
                ("TEXTCOLOR", (0, 0), (-1, -1), C_SUBTEXT),
            ]))
            story.append(cap_tbl)
            story.append(Spacer(1, 10))

    # Confusion matrix
    if req.confusion_matrix:
        section_head(story, styles, "Confusion Matrix")
        cm_data = [["Actual Class", "Predicted Class", "Count"]]
        for row in req.confusion_matrix:
            cm_data.append([
                row.get("actual", "—"),
                row.get("predicted", "—"),
                str(row.get("count", 0)),
            ])
        ct = Table(cm_data, colWidths=[60*mm, 60*mm, 40*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ]))
        story.append(ct)
        story.append(Spacer(1, 8))

    # Top misclassifications
    if req.top_misclassifications:
        section_head(story, styles, "Top Misclassifications")
        mc_data = [["Misclassification", "Count", "Percentage"]]
        for m in req.top_misclassifications:
            mc_data.append([
                m.get("class", "—"),
                str(m.get("count", 0)),
                f"{m.get('percentage', 0):.1f}%",
            ])
        mt = Table(mc_data, colWidths=[100*mm, 30*mm, 40*mm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ]))
        story.append(mt)

    # Footer
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Generated by PhantomNet++ · {ts} · Report ID: {report_id}",
        styles["PNMono"]
    ))

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.post("/api/report/threat/pdf")
def threat_pdf(req: ThreatReportRequest):
    pdf_bytes = generate_threat_pdf(req)
    filename  = f"phantomnet_threat_{req.threat_id}_{datetime.now(PKT).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/report/threat/json")
def threat_json(req: ThreatReportRequest):
    return JSONResponse({
        "report_type":  "threat_detection",
        "report_id":    f"RPT-TD-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.now(PKT).isoformat(),
        "data": req.dict(),
    })


@app.post("/api/report/xai/pdf")
def xai_pdf(req: XAIReportRequest):
    pdf_bytes = generate_xai_pdf(req)
    filename  = f"phantomnet_xai_{req.explanation_id}_{datetime.now(PKT).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/report/xai/json")
def xai_json(req: XAIReportRequest):
    payload = req.dict()
    # Strip base64 images from JSON to keep it readable (they're huge)
    payload["original_image"]    = "[base64 image — omitted from JSON]" if req.original_image    else None
    payload["explanation_image"] = "[base64 image — omitted from JSON]" if req.explanation_image else None
    return JSONResponse({
        "report_type":  "xai_explanation",
        "report_id":    f"RPT-XAI-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.now(PKT).isoformat(),
        "data": payload,
    })


@app.post("/api/report/simulation/pdf")
def simulation_pdf(req: SimulationReportRequest):
    pdf_bytes = generate_simulation_pdf(req)
    filename  = f"phantomnet_simulation_{req.sim_id}_{datetime.now(PKT).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/report/simulation/json")
def simulation_json(req: SimulationReportRequest):
    payload = req.dict()
    payload["before_image"] = "[base64 image — omitted from JSON]" if req.before_image else None
    payload["after_image"]  = "[base64 image — omitted from JSON]" if req.after_image  else None
    return JSONResponse({
        "report_type":  "attack_simulation",
        "report_id":    f"RPT-SIM-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.now(PKT).isoformat(),
        "data": payload,
    })


@app.post("/api/report/siem/pdf")
def siem_pdf(body: dict):
    """Generate a PDF report of SIEM logs."""
    logs       = body.get("logs", [])
    stats      = body.get("stats", {})
    generated  = body.get("generated_at", datetime.now(PKT).isoformat())

    buf     = io.BytesIO()
    doc     = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=MARGIN, rightMargin=MARGIN,
                                topMargin=MARGIN, bottomMargin=MARGIN)
    styles  = build_styles()
    story   = []
    report_id = f"RPT-SIEM-{uuid.uuid4().hex[:8].upper()}"
    ts        = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S PKT")

    header_block(story, styles, "SIEM Security Event Report",
                 "LSE — Logging & SIEM Engine · Elasticsearch · SHA-3 Integrity",
                 report_id, ts)
    
    dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
    pkt_time = dt.astimezone(ZoneInfo("Asia/Karachi"))

    # Stats summary
    section_head(story, styles, "Event Summary")
    kv_table(story, [
        ("Total Events",   str(stats.get("total", len(logs)))),
        ("Critical",       str(stats.get("critical", 0))),
        ("Human Escalation",         str(stats.get("error", 0))),
        ("Warnings",       str(stats.get("warning", 0))),
        ("Info",           str(stats.get("info", 0))),
        ("Report Period", pkt_time.strftime("%Y-%m-%d %H:%M:%S")),
    ])

    # Log table
    section_head(story, styles, f"Event Log ({len(logs)} entries)")
    if logs:
        # Usable width = A4 210mm - 2*20mm margins = 170mm
        # Cols: Timestamp=36, Severity=18, Source=14, EventType=38, Message=64 = 170mm
        COL_W = [36*mm, 18*mm, 14*mm, 38*mm, 64*mm]

        sev_colors_map = {
            "Critical": colors.HexColor("#ef4444"),
            "Error":    colors.HexColor("#f97316"),
            "Warning":  colors.HexColor("#eab308"),
            "Info":     colors.HexColor("#3b82f6"),
        }

        # Cell style for wrapping body text
        cell_style = ParagraphStyle(
            "SIEMCell",
            fontSize=7,
            fontName="Helvetica",
            leading=9,
            textColor=colors.HexColor("#1e293b"),
        )
        hdr_style = ParagraphStyle(
            "SIEMHdr",
            fontSize=7,
            fontName="Helvetica-Bold",
            leading=9,
            textColor=colors.white,
        )

        log_data = [[
            Paragraph("Timestamp",  hdr_style),
            Paragraph("Severity",   hdr_style),
            Paragraph("Source",     hdr_style),
            Paragraph("Event Type", hdr_style),
            Paragraph("Message",    hdr_style),
        ]]

        for log in logs[:200]:
            raw_ts = log.get("timestamp")
            if raw_ts:
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                ts_short = dt.astimezone(ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_short = ""
            sev      = log.get("severity", "")
            sev_label = "Human Escalation" if sev == "Error" else sev
            sev_col  = sev_colors_map.get(sev, colors.HexColor("#64748b"))
            sev_style = ParagraphStyle(
                f"Sev{sev}",
                fontSize=7, fontName="Helvetica-Bold",
                leading=9, textColor=sev_col,
            )
            log_data.append([
                Paragraph(ts_short,                          cell_style),
                Paragraph(sev_label,                         sev_style),
                Paragraph(log.get("source", ""),             cell_style),
                Paragraph(log.get("event_type", ""),         cell_style),
                Paragraph(log.get("message", "")[:120],      cell_style),
            ])

        lt = Table(log_data, colWidths=COL_W, repeatRows=1)
        lt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("GRID",          (0, 0), (-1, -1), 0.2, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(lt)

        if len(logs) > 200:
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                f"Note: {len(logs) - 200} additional events omitted. Export full JSON for complete log.",
                styles["PNBody"]
            ))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Generated by PhantomNet++ · {ts} · Report ID: {report_id}",
        styles["PNMono"]
    ))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    filename  = f"phantomnet_siem_{datetime.now(PKT).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/report/health")
def health():
    return {"status": "ok", "service": "phantomnet-report", "port": 8004}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("report_backend:app", host="0.0.0.0", port=8004, reload=True)