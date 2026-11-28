#!/usr/bin/env python3
"""
Build standalone Semester 1 and Semester 2 Graduation Project Book editions
while leaving the full combined docs/SAD_Book.{md,docx,pdf} untouched.

Reuses the verified OOXML Word builder (scripts/build_sad_docx.py) and
offline headless Chromium PDF builder (scripts/build_sad_pdf.py).

Outputs:
    Semester 1 (Chapters 1–3, Figures 1–14 & Figure 19 — 15 Figures):
        - docs/semester_1/images/01_*.{png,svg} .. 14_*.{png,svg}, 19_*.{png,svg}
        - docs/semester_1/SAD_Semester1_Book.md
        - docs/semester_1/SAD_Semester1_Book.docx
        - docs/semester_1/SAD_Semester1_Book.pdf

    Semester 2 (Chapters 4–6, Figures 15–18 — 4 Figures):
        - docs/semester_2/images/15_*.{png,svg} .. 18_*.{png,svg}
        - docs/semester_2/SAD_Semester2_Book.md
        - docs/semester_2/SAD_Semester2_Book.docx
        - docs/semester_2/SAD_Semester2_Book.pdf
"""

from __future__ import annotations

import html
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_sad_docx import (  # noqa: E402
    BOOK_SUBTITLE,
    BOOK_TITLE,
    CHAPTERS_DIR,
    CONTENT_WIDTH_TWIPS,
    DOCS_DIR,
    IMAGES_DIR,
    W_NS,
    BlockQuoteBlock,
    ChapterData,
    DocxBookBuilder,
    FigureBlock,
    FigureEntry,
    HeadingBlock,
    TocItem,
    make_anchor,
    make_run_xml,
    parse_markdown_blocks,
    strip_md_inline,
    validate_docx,
)
from build_sad_pdf import (  # noqa: E402
    CSS_STYLES,
    render_blocks_html,
    render_html_to_pdf,
    render_table_html,
    validate_pdf,
)


TEAM_MEMBERS_STR = (
    "Seven Members: Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), "
    "Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), "
    "Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), "
    "Ali Ibrahim Elsayed (235332)"
)

TEAM_SIGNOFF_ROWS: list[list[str]] = [
    ["1", "Ahmed Ashraf Ammar", "`235204`", "System Architecture, Orchestrator & FastAPI Core"],
    ["2", "Islam Mohammed", "`235164`", "Scope Guardrail, HTTP Client & BFS Crawler"],
    ["3", "Abdelrhman Mohamed AbdEl-latif", "`235216`", "Passive OWASP Checks & Soft-404 Calibration"],
    ["4", "Ahmed Waleed Mokthar", "`235052`", "Active Safe Injection & Access Control Checks"],
    ["5", "Mohamed Waleed Mokthar", "`235051`", "SQLAlchemy Persistence, Diffing & Report Export"],
    ["6", "Mohamed Ibrahim Elsayed", "`235401`", "Developer Dashboard UI (HTML5/Tailwind/Vanilla JS & SSE)"],
    ["7", "Ali Ibrahim Elsayed", "`235332`", "Remediation KB, `VulnBench` Testbench & Evaluation Suite"],
]


@dataclass
class SemesterConfig:
    slug: str                    # "semester_1" or "semester_2"
    file_stem: str               # "SAD_Semester1_Book" or "SAD_Semester2_Book"
    cover_header: str            # "GRADUATION PROJECT BOOK – SEMESTER 1"
    running_header: str
    abstract: str
    metadata_rows: list[tuple[str, str]]
    chapter_numbers: list[int]   # [1, 2, 3] or [4, 5, 6]
    figure_numbers: list[int]    # [1..14, 19] or [15..18]
    signoff_heading: str
    signoff_intro: str
    signoff_milestone: str
    signoff_status_label: str


SEMESTER_1_CONFIG = SemesterConfig(
    slug="semester_1",
    file_stem="SAD_Semester1_Book",
    cover_header="GRADUATION PROJECT BOOK – SEMESTER 1",
    running_header="GRADUATION PROJECT BOOK (SEMESTER 1) — OWASP Top 10 Vulnerability Scanner",
    abstract=(
        "This Semester 1 Graduation Project Book presents the foundational problem analysis, "
        "System Requirements Specification (SRS), and multi-view software architecture for "
        "a lightweight, developer-first OWASP Top 10 (2021) vulnerability scanner tailored "
        "for web developers and university student teams. Covering Chapters 1 through 3 and "
        "15 figures (Figures 1–14 plus Figure 19), this volume establishes the shift-left "
        "motivation aligned with NIST SSDF (SP 800-218), contrasts enterprise DAST suites "
        "against a zero-config local Docker Compose workflow, presents the classic top-down "
        "master system flowchart (Figure 19), specifies 15 functional requirements (FR-01–FR-15), "
        "9 non-functional requirements (NFR-01–NFR-09), and 6 detailed use cases (UC-01–UC-06), "
        "and models the system across C4 Levels 1–3, Data Flow Diagrams with trust boundaries, "
        "Docker deployment topology, lifecycle sequence and state diagrams, swimlane activity "
        "flows, and the 1-file BaseCheck plugin class hierarchy."
    ),
    metadata_rows=[
        (
            "Project Title",
            "Developing a Lightweight OWASP Top 10 Vulnerability Scanner "
            "(Tailored for Web Developers and Student Projects)",
        ),
        ("Volume Scope", "Semester 1 Edition — Chapters 1–3 & Figures 1–14, 19 (15 Figures)"),
        ("Methodological Reference", "OWASP Top 10 (2021) & NIST SSDF (SP 800-218)"),
        (
            "Target Audience",
            "Junior Web Developers, University Students, and Small Development Teams",
        ),
        ("Project Supervisor", "Dr. Samar"),
        ("Project Team", TEAM_MEMBERS_STR),
        ("Academic Year", "2026–2027"),
        ("Document Status", "Proposed System Analysis and Design – Semester 1 Edition (v1.1)"),
        ("Current Phase", "First Semester – Requirements Analysis and System Architecture"),
        (
            "Next Phase",
            "Second Semester – Data/API Design, Security ADRs, Implementation & Validation",
        ),
    ],
    chapter_numbers=[1, 2, 3],
    figure_numbers=[*range(1, 15), 19],
    signoff_heading="Semester 1 Sign-Off Summary",
    signoff_intro=(
        "This Semester 1 Graduation Project Book (Chapters 1–3, Figures 1–14 and Figure 19) "
        "serves as the formal first-semester academic submission covering Problem Scope, "
        "System Requirements Specification, and Multi-View Software Architecture."
    ),
    signoff_milestone="First Semester Milestone — Requirements Analysis & System Architecture Approval",
    signoff_status_label="Approved — Semester 1 v1.1",
)

SEMESTER_2_CONFIG = SemesterConfig(
    slug="semester_2",
    file_stem="SAD_Semester2_Book",
    cover_header="GRADUATION PROJECT BOOK – SEMESTER 2",
    running_header="GRADUATION PROJECT BOOK (SEMESTER 2) — OWASP Top 10 Vulnerability Scanner",
    abstract=(
        "This Semester 2 Graduation Project Book presents the detailed relational data model, "
        "REST and Server-Sent Events (SSE) API contracts, curated 17-check OWASP Top 10 (2021) "
        "catalog and multi-stack remediation knowledge base, ethical security governance, "
        "Architecture Decision Records (ADR-01–ADR-05), and empirical benchmarking protocol "
        "for the lightweight OWASP Top 10 vulnerability scanner. Covering Chapters 4 through 6 "
        "and Figures 15 through 18, this volume specifies the 3NF SQLAlchemy 2.0 schema "
        "(SQLite default with optional PostgreSQL profile), deterministic risk scoring and "
        "SHA-1 finding deduplication, pre-request local-scope allow-list and DNS-rebinding "
        "guardrails, NIST SSDF (SP 800-218) alignment, the 15-scenario System Verification "
        "Matrix (TC-01–TC-15), and automated evaluation across VulnBench, DVWA, and OWASP "
        "Juice Shop."
    ),
    metadata_rows=[
        (
            "Project Title",
            "Developing a Lightweight OWASP Top 10 Vulnerability Scanner "
            "(Tailored for Web Developers and Student Projects)",
        ),
        ("Volume Scope", "Semester 2 Edition — Chapters 4–6 & Figures 15–18"),
        ("Methodological Reference", "OWASP Top 10 (2021) & NIST SSDF (SP 800-218)"),
        (
            "Target Audience",
            "Junior Web Developers, University Students, and Small Development Teams",
        ),
        ("Project Supervisor", "Dr. Samar"),
        ("Project Team", TEAM_MEMBERS_STR),
        ("Academic Year", "2026–2027"),
        (
            "Document Status",
            "Detailed Design, Security Governance & Validation – Semester 2 Edition (v1.1)",
        ),
        (
            "Current Phase",
            "Second Semester – Data/API Design, Security ADRs, and Validation Strategy",
        ),
        (
            "Next Phase",
            "Full-System Integration, Empirical Testbench Execution, and Graduation Defense",
        ),
    ],
    chapter_numbers=[4, 5, 6],
    figure_numbers=[15, 16, 17, 18],
    signoff_heading="Semester 2 Final Sign-Off Summary",
    signoff_intro=(
        "This Semester 2 Graduation Project Book (Chapters 4–6, Figures 15–18) serves as the "
        "formal second-semester academic submission covering Detailed Data/API Design, Security "
        "Governance & ADRs, and Empirical Validation Strategy."
    ),
    signoff_milestone="Second Semester Milestone — Detailed Design, Security & Validation Final Approval",
    signoff_status_label="Approved — Semester 2 Final v1.1",
)


# ---------------------------------------------------------------------------
# Extraction helpers (References & Sign-Off separation)
# ---------------------------------------------------------------------------


def extract_references_md_from_chapter6() -> str:
    """Pull the exact IEEE References [1]-[12] section cleanly from Chapter 6."""
    ch6_path = CHAPTERS_DIR / "06_validation_and_benchmarking.md"
    raw = ch6_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    m = re.search(
        r"(##\s+References\b.*?)(?=\n---\s*\n+##\s+Document\s+Sign-Off|\n##\s+Document\s+Sign-Off|\Z)",
        raw,
        flags=re.S,
    )
    if not m:
        raise ValueError(f"Could not locate '## References' section in {ch6_path}")
    return m.group(1).strip()


def strip_signoff_section(md_text: str) -> str:
    """Remove trailing Document Sign-Off Summary from Chapter 6 so each edition owns its tailored Sign-Off."""
    raw = md_text.replace("\r\n", "\n")
    cleaned = re.sub(
        r"\n*(?:---\s*\n+)?##\s+Document\s+Sign-Off\s+Summary\b.*\Z",
        "",
        raw,
        flags=re.S,
    )
    return cleaned.strip()


def build_signoff_markdown(cfg: SemesterConfig) -> str:
    """Build formal Semester 1 or Semester 2 Sign-Off Summary Markdown."""
    lines: list[str] = [
        f"## {cfg.signoff_heading}",
        "",
        cfg.signoff_intro,
        "",
        "| Document Attribute | Details |",
        "| :--- | :--- |",
        f"| **Document Edition** | {cfg.cover_header} ({cfg.file_stem}) |",
        "| **Project Title** | Developing a Lightweight OWASP Top 10 Vulnerability Scanner — Tailored for Web Developers and Student Projects (Developer-Experience Focus) |",
        "| **Department** | Department of Cyber Security |",
        "| **Academic Year** | 2026–2027 |",
        "| **Prepared For (Project Supervisor)** | **Dr. Samar**, Project Supervisor |",
        f"| **Review Milestone** | {cfg.signoff_milestone} |",
        "",
        "### Project Team Sign-Off",
        "",
        "| # | Student Name | Student ID | Primary Architectural Ownership | Sign-Off Status |",
        "| :---: | :--- | :---: | :--- | :--- |",
    ]
    for idx, name, sid, role in TEAM_SIGNOFF_ROWS:
        lines.append(f"| {idx} | {name} | {sid} | {role} | {cfg.signoff_status_label} |")

    lines.extend(
        [
            "",
            "### Academic Supervisor Review",
            "",
            "| Reviewer Role | Name | Review Decision | Signature / Date |",
            "| :--- | :--- | :--- | :--- |",
            "| **Project Supervisor** | **Dr. Samar** | `[ ] Approved` / `[ ] Approved with Revisions` | `_______________________` / `____-__-__` |",
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Copy PNG + SVG assets for a semester
# ---------------------------------------------------------------------------


def copy_semester_images(cfg: SemesterConfig, out_images_dir: Path) -> list[Path]:
    """Copy PNG and SVG diagram images listed in cfg.figure_numbers into out_images_dir."""
    out_images_dir.mkdir(parents=True, exist_ok=True)
    # Remove any stale files in out_images_dir first
    for stale in out_images_dir.iterdir():
        if stale.is_file():
            stale.unlink()

    copied_pngs: list[Path] = []
    for num in cfg.figure_numbers:
        prefix = f"{num:02d}_"
        png_matches = sorted(IMAGES_DIR.glob(f"{prefix}*.png"))
        svg_matches = sorted(IMAGES_DIR.glob(f"{prefix}*.svg"))
        if len(png_matches) != 1 or len(svg_matches) != 1:
            raise FileNotFoundError(
                f"Expected exactly 1 PNG and 1 SVG for figure {num:02d} in {IMAGES_DIR}, "
                f"found png={len(png_matches)}, svg={len(svg_matches)}"
            )
        dst_png = out_images_dir / png_matches[0].name
        dst_svg = out_images_dir / svg_matches[0].name
        shutil.copy2(png_matches[0], dst_png)
        shutil.copy2(svg_matches[0], dst_svg)
        copied_pngs.append(dst_png)
    return copied_pngs


# ---------------------------------------------------------------------------
# Load & parse semester chapters + back matter
# ---------------------------------------------------------------------------


def load_semester_content(
    cfg: SemesterConfig,
    semester_dir: Path,
    references_md: str,
) -> tuple[list[ChapterData], list[TocItem], list[FigureEntry], str, list]:
    """
    Load the semester's chapters, extract TOC and Figures, and prepare
    tailored References + Sign-Off back-matter AST blocks.
    """
    chapters: list[ChapterData] = []
    toc: list[TocItem] = []
    figures: list[FigureEntry] = []
    fig_counter = [min(cfg.figure_numbers) - 1]
    has_refs_inline = False

    for ch_num in cfg.chapter_numbers:
        matches = sorted(CHAPTERS_DIR.glob(f"{ch_num:02d}_*.md"))
        if len(matches) != 1:
            raise FileNotFoundError(f"Expected 1 file for chapter {ch_num:02d} in {CHAPTERS_DIR}")
        ch_path = matches[0]
        raw_md = ch_path.read_text(encoding="utf-8").replace("\r\n", "\n")

        # For Chapter 6, strip generic Sign-Off so we append the Semester 2 Final Sign-Off cleanly
        if ch_num == 6:
            raw_md = strip_signoff_section(raw_md)

        blocks = parse_markdown_blocks(raw_md, ch_path.parent, fig_counter)

        # Point FigureBlock image paths to docs/diagrams/png/
        for blk in blocks:
            if isinstance(blk, FigureBlock):
                diag_img = IMAGES_DIR / blk.image_path.name
                if diag_img.exists():
                    blk.image_path = diag_img

        ch_title = f"Chapter {ch_num}"
        for blk in blocks:
            if isinstance(blk, HeadingBlock):
                clean_t = strip_md_inline(blk.text)
                low = clean_t.lower()
                if blk.level == 1:
                    ch_title = clean_t
                    toc.append(TocItem(level=1, title=clean_t, anchor=make_anchor(clean_t)))
                elif blk.level == 2:
                    if low == "references":
                        has_refs_inline = True
                        toc.append(TocItem(level=1, title=clean_t, anchor=make_anchor(clean_t)))
                    else:
                        toc.append(TocItem(level=2, title=clean_t, anchor=make_anchor(clean_t)))
            elif isinstance(blk, FigureBlock):
                short_title = strip_md_inline(blk.alt) or blk.caption
                if not re.match(r"^Figure\s+\d+\s*:", short_title, re.IGNORECASE):
                    short_title = f"Figure {blk.fig_num}: {short_title}"
                figures.append(
                    FigureEntry(
                        fig_num=blk.fig_num,
                        title=short_title,
                        chapter_label=f"Chapter {ch_num}",
                        image_path=blk.image_path,
                        mmd_rel=f"../../diagrams/mmd/{blk.image_path.stem}.mmd",
                    )
                )

        chapters.append(ChapterData(path=ch_path, title=ch_title, raw_md=raw_md, blocks=blocks))

    # Assemble Back Matter Markdown (References if not already inline in Ch 6 + Semester Sign-Off)
    back_parts: list[str] = []
    if not has_refs_inline:
        back_parts.append(references_md)
        toc.append(TocItem(level=1, title="References", anchor="references"))
    signoff_md = build_signoff_markdown(cfg)
    back_parts.append(signoff_md)
    toc.append(
        TocItem(
            level=1,
            title=cfg.signoff_heading,
            anchor=make_anchor(cfg.signoff_heading),
        )
    )
    back_md = "\n\n---\n\n".join(back_parts)
    back_blocks = parse_markdown_blocks(back_md, semester_dir, fig_counter)

    figures.sort(key=lambda f: f.fig_num)
    return chapters, toc, figures, back_md, back_blocks


# ---------------------------------------------------------------------------
# Markdown Edition Writer
# ---------------------------------------------------------------------------


def rewrite_chapter_for_semester_md(raw_md: str) -> str:
    """Rewrite ../diagrams/ links to ../../diagrams/ for docs/books/md/."""
    text = raw_md.replace("../diagrams/png/", "../../diagrams/png/")
    text = text.replace("../diagrams/mmd/", "../../diagrams/mmd/")
    return text.strip()


def build_semester_markdown(
    cfg: SemesterConfig,
    chapters: list[ChapterData],
    toc: list[TocItem],
    figures: list[FigureEntry],
    back_md: str,
) -> str:
    parts: list[str] = [
        f"# {cfg.cover_header}\n",
        f"## {BOOK_TITLE}\n",
        f"*{BOOK_SUBTITLE}*\n",
        "---\n",
        "## Executive Abstract\n",
        f"{cfg.abstract}\n",
        "## Project Metadata\n",
        "| Attribute | Specification |",
        "| :--- | :--- |",
    ]
    for k, v in cfg.metadata_rows:
        parts.append(f"| **{k}** | {v} |")
    parts.append("\n---\n")

    parts.append("## Table of Contents\n")
    for item in toc:
        if item.level == 1:
            parts.append(f"- **[{item.title}](#{item.anchor})**")
        else:
            parts.append(f"  - [{item.title}](#{item.anchor})")
    parts.append("\n---\n")

    parts.append("## List of Figures\n")
    parts.append("| Figure | Title | Chapter | Image Asset | Mermaid Source |")
    parts.append("| :---: | :--- | :---: | :--- | :--- |")
    for fig in figures:
        clean_title = re.sub(r"^Figure\s+\d+\s*:\s*", "", fig.title, flags=re.IGNORECASE)
        img_rel = f"../../diagrams/png/{fig.image_path.name}"
        mmd_name = Path(fig.mmd_rel).name
        parts.append(
            f"| **Figure {fig.fig_num}** | {clean_title} | {fig.chapter_label} | "
            f"[{fig.image_path.name}]({img_rel}) | [{mmd_name}]({fig.mmd_rel}) |"
        )
    parts.append("\n---\n")

    for ch in chapters:
        parts.append(rewrite_chapter_for_semester_md(ch.raw_md))
        parts.append("\n---\n")

    parts.append(back_md.strip())
    parts.append("")
    return "\n".join(parts).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Semester-Aware OOXML .docx Builder (reusing DocxBookBuilder)
# ---------------------------------------------------------------------------


class SemesterDocxBuilder(DocxBookBuilder):
    """Subclass of DocxBookBuilder parameterized with Semester cover & running header."""

    def __init__(self, cfg: SemesterConfig) -> None:
        super().__init__()
        self.cfg = cfg

    def _header_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:hdr xmlns:w="{W_NS}">'
            "<w:p><w:pPr>"
            '<w:jc w:val="right"/>'
            '<w:pBdr><w:bottom w:val="single" w:sz="4" w:space="4" w:color="CBD5E1"/></w:pBdr>'
            '<w:spacing w:before="0" w:after="60"/>'
            "</w:pPr>"
            f'{make_run_xml(self.cfg.running_header, italic=True, color="64748B", size_half_pt=17)}'
            "</w:p>"
            "</w:hdr>"
        )

    def add_semester_cover_page(self) -> None:
        banner_xml = (
            "<w:tbl>"
            "<w:tblPr>"
            f'<w:tblW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:tblLayout w:type="fixed"/>'
            "<w:tblBorders>"
            '<w:top w:val="none"/><w:left w:val="none"/><w:right w:val="none"/>'
            '<w:bottom w:val="single" w:sz="36" w:space="0" w:color="0D9488"/>'
            "</w:tblBorders>"
            "</w:tblPr>"
            f'<w:tblGrid><w:gridCol w:w="{CONTENT_WIDTH_TWIPS}"/></w:tblGrid>'
            "<w:tr><w:tc><w:tcPr>"
            f'<w:tcW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:shd w:val="clear" w:color="auto" w:fill="0F172A"/>'
            '<w:tcMar><w:top w:w="220" w:type="dxa"/><w:bottom w:w="220" w:type="dxa"/>'
            '<w:left w:w="240" w:type="dxa"/><w:right w:w="240" w:type="dxa"/></w:tcMar>'
            "</w:tcPr>"
            '<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="60"/></w:pPr>'
            f'{make_run_xml(self.cfg.cover_header, bold=True, color="5EEAD4", size_half_pt=22)}'
            "</w:p>"
            '<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="40" w:after="80"/></w:pPr>'
            f'{make_run_xml(BOOK_TITLE, bold=True, color="FFFFFF", size_half_pt=40)}'
            "</w:p>"
            '<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="0"/></w:pPr>'
            f'{make_run_xml(BOOK_SUBTITLE, italic=True, color="E2E8F0", size_half_pt=24)}'
            "</w:p>"
            "</w:tc></w:tr></w:tbl>"
            '<w:p><w:pPr><w:spacing w:before="0" w:after="160"/></w:pPr></w:p>'
        )
        self.body_parts.append(banner_xml)

        self.add_paragraph(
            "EXECUTIVE ABSTRACT",
            space_before=80,
            space_after=60,
            base_bold=True,
            color="0F766E",
            size_half_pt=22,
        )
        self.add_blockquote(BlockQuoteBlock(alert_kind="", lines=[self.cfg.abstract]))

        self.add_paragraph(
            "PROJECT METADATA",
            space_before=100,
            space_after=60,
            base_bold=True,
            color="0F766E",
            size_half_pt=22,
        )
        self.add_table(
            headers=["Attribute", "Project Specification"],
            rows=[[k, v] for k, v in self.cfg.metadata_rows],
            col_weights=[28.0, 72.0],
        )
        self.add_page_break()


# ---------------------------------------------------------------------------
# Semester-Aware Offline Print HTML -> PDF Builder
# ---------------------------------------------------------------------------


def build_semester_print_html(
    cfg: SemesterConfig,
    chapters: list[ChapterData],
    toc: list[TocItem],
    figures: list[FigureEntry],
    back_blocks: list,
) -> tuple[str, int]:
    """Generate offline base64-embedded A4 print HTML for one semester book."""
    custom_css = CSS_STYLES.replace(
        "GRADUATION PROJECT BOOK — OWASP Top 10 Vulnerability Scanner (SAD v1.1)",
        cfg.running_header,
    )

    sections: list[str] = []

    # 1. Cover Page
    meta_html = render_table_html(
        headers=["Attribute", "Project Specification"],
        rows=[[k, v] for k, v in cfg.metadata_rows],
        extra_cls="meta-table",
    )
    sections.append(
        '<section class="cover-page">'
        '<div class="cover-banner">'
        f'<div class="cover-kicker">{html.escape(cfg.cover_header)}</div>'
        f'<div class="cover-title">{html.escape(BOOK_TITLE)}</div>'
        f'<div class="cover-subtitle">{html.escape(BOOK_SUBTITLE)}</div>'
        "</div>"
        '<div class="section-label">Executive Abstract</div>'
        f'<div class="abstract-box">{html.escape(cfg.abstract)}</div>'
        '<div class="section-label">Project Metadata</div>'
        f"{meta_html}"
        "</section>"
    )

    # 2. Table of Contents
    toc_rows_html: list[str] = []
    for item in toc:
        td_cls = "toc-l1" if item.level == 1 else "toc-l2"
        kind = "Chapter / Major Section" if item.level == 1 else "Section"
        toc_rows_html.append(
            f'<tr><td class="{td_cls}"><a href="#{html.escape(item.anchor, quote=True)}">'
            f"{html.escape(item.title)}</a></td><td>{kind}</td></tr>"
        )
    sections.append(
        '<section class="front-matter">'
        '<h1 class="front-heading">Table of Contents</h1>'
        '<table class="toc-table"><thead><tr><th>Section Title</th><th style="width:24%;">Level</th></tr></thead>'
        f"<tbody>{''.join(toc_rows_html)}</tbody></table>"
        "</section>"
    )

    # 3. List of Figures
    fig_rows: list[list[str]] = []
    for fig in figures:
        clean_title = re.sub(r"^Figure\s+\d+\s*:\s*", "", fig.title, flags=re.IGNORECASE)
        fig_rows.append([f"**Figure {fig.fig_num}**", clean_title, fig.chapter_label])
    sections.append(
        '<section class="front-matter">'
        '<h1 class="front-heading page-break">List of Figures</h1>'
        f"{render_table_html(['Figure', 'Diagram Title', 'Host Chapter'], fig_rows)}"
        "</section>"
    )

    # 4. Semester Chapters
    total_images = 0
    for ch in chapters:
        ch_html, count = render_blocks_html(ch.blocks)
        total_images += count
        sections.append(f'<section class="chapter">{ch_html}</section>')

    # 5. Back Matter (References + Semester Sign-Off)
    back_html, back_imgs = render_blocks_html(back_blocks)
    total_images += back_imgs
    sections.append(f'<section class="chapter">{back_html}</section>')

    full_html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8" />\n'
        f"<title>{html.escape(cfg.cover_header)} — {html.escape(BOOK_TITLE)}</title>\n"
        f"<style>{custom_css}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{''.join(sections)}\n"
        "</body>\n"
        "</html>\n"
    )
    return full_html, total_images


# ---------------------------------------------------------------------------
# End-to-End Semester Package Builder & Validator
# ---------------------------------------------------------------------------


def build_semester_package(cfg: SemesterConfig, references_md: str) -> None:
    expected_figs = len(cfg.figure_numbers)
    books_dir = DOCS_DIR / "books"
    md_dir = books_dir / "md"
    docx_dir = books_dir / "docx"
    pdf_dir = books_dir / "pdf"
    for d in (md_dir, docx_dir, pdf_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1. Load semester chapters + back matter
    chapters, toc, figures, back_md, back_blocks = load_semester_content(
        cfg, md_dir, references_md
    )
    if len(figures) != expected_figs:
        raise ValueError(
            f"Expected {expected_figs} parsed figures for {cfg.slug}, found {len(figures)}"
        )

    # 2. Write Markdown book
    md_path = md_dir / f"{cfg.file_stem}.md"
    md_text = build_semester_markdown(cfg, chapters, toc, figures, back_md)
    md_path.write_text(md_text, encoding="utf-8")

    # Verify all relative links inside semester Markdown resolve cleanly on disk
    links = re.findall(r"!?\[[^\]]*\]\(([^)#]+)\)", md_text)
    broken = [
        lnk
        for lnk in links
        if not lnk.startswith(("http://", "https://"))
        and not (md_dir / lnk).resolve().exists()
    ]
    if broken:
        raise ValueError(f"Broken relative links in {md_path}: {broken}")
    print(
        f"[OK] {cfg.slug}: Wrote {md_path} ({md_path.stat().st_size:,} bytes, "
        f"{len(links)}/{len(links)} links valid)"
    )

    # 3. Write & validate OOXML .docx
    docx_path = docx_dir / f"{cfg.file_stem}.docx"
    docx_builder = SemesterDocxBuilder(cfg)
    docx_builder.add_semester_cover_page()
    docx_builder.add_front_matter(toc, figures)
    for ch in chapters:
        docx_builder.render_blocks(ch.blocks)
    docx_builder.render_blocks(back_blocks)
    docx_builder.write(docx_path)
    docx_stats = validate_docx(docx_path, expected_figures=expected_figs)
    print(
        f"[OK] {cfg.slug}: Wrote & validated {docx_path} "
        f"({docx_stats['file_size_bytes']:,} bytes, {docx_stats['xml_parts_validated']} XML/rels valid, "
        f"{docx_stats['media_pngs']}/{expected_figs} PNGs embedded, {docx_stats['drawing_embeds']} drawings)"
    )

    # 4. Render & validate offline A4 .pdf
    pdf_path = pdf_dir / f"{cfg.file_stem}.pdf"
    html_doc, html_img_count = build_semester_print_html(
        cfg, chapters, toc, figures, back_blocks
    )
    if html_img_count != expected_figs:
        raise ValueError(
            f"Expected {expected_figs} HTML figures for {cfg.slug}, embedded {html_img_count}"
        )
    browser = render_html_to_pdf(html_doc, pdf_path)
    pdf_stats = validate_pdf(pdf_path, min_bytes=200_000, min_images=expected_figs)
    print(
        f"[OK] {cfg.slug}: Rendered & validated {pdf_path} via {browser.name} "
        f"({pdf_stats['file_size_bytes']:,} bytes, {pdf_stats['page_count']} pages, "
        f"{pdf_stats['embedded_images']} embedded images)"
    )


def main() -> int:
    references_md = extract_references_md_from_chapter6()
    build_semester_package(SEMESTER_1_CONFIG, references_md)
    build_semester_package(SEMESTER_2_CONFIG, references_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
