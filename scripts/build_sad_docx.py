#!/usr/bin/env python3
"""
Build the unified Formal Graduation Project Book in Markdown (docs/SAD_Book.md)
and Microsoft Word OOXML (docs/SAD_Book.docx).

Uses ONLY Python 3.12 standard library (zipfile, xml.etree.ElementTree, re, pathlib)
plus Pillow (PIL) for exact PNG pixel dimension measurement. Zero third-party
docx packages required.

Reads:
    - docs/sad_chapters/01_*.md through 06_*.md (sorted)
    - docs/diagrams/images/01_*.png through 18_*.png

Writes:
    - docs/SAD_Book.md
    - docs/SAD_Book.docx
"""

from __future__ import annotations

import datetime
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

from PIL import Image


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
CHAPTERS_DIR = DOCS_DIR / "sad_chapters"
DIAGRAMS_DIR = DOCS_DIR / "diagrams"
IMAGES_DIR = DIAGRAMS_DIR / "png"
BOOKS_DIR = DOCS_DIR / "books"

OUTPUT_MD_PATH = BOOKS_DIR / "md" / "SAD_Book.md"
OUTPUT_DOCX_PATH = BOOKS_DIR / "docx" / "SAD_Book.docx"

BOOK_HEADER = "GRADUATION PROJECT BOOK – SYSTEM ANALYSIS AND DESIGN"
BOOK_TITLE = "Developing a Lightweight OWASP Top 10 Vulnerability Scanner"
BOOK_SUBTITLE = "Tailored for Web Developers and Student Projects (Developer-Experience Focus)"

EXECUTIVE_ABSTRACT = (
    "Early-stage web developers and university student teams frequently defer application "
    "security testing until immediately prior to submission or deployment, exposing modern "
    "web applications to preventable OWASP Top 10 vulnerabilities. Enterprise Dynamic "
    "Application Security Testing (DAST) suites such as OWASP ZAP and Burp Suite impose "
    "significant operational friction—requiring interception proxy certificates, manual scan "
    "policy tuning, and specialized security knowledge to interpret raw HTTP payloads and "
    "abstract CWE advisories. This System Analysis and Design book specifies a lightweight, "
    "self-contained, developer-first OWASP Top 10 (2021) vulnerability scanner engineered for "
    "continuous local use during active development. Launching through a single Docker Compose "
    "command or native Python virtual environment, the system combines a FastAPI backend, an "
    "in-process concurrent scanning engine built on Requests and BeautifulSoup4, SQLAlchemy 2.0 "
    "persistence (SQLite default with optional PostgreSQL profile), Server-Sent Events (SSE) "
    "progress streaming, and a zero-build HTML5/Tailwind/Vanilla JS dashboard. The platform "
    "executes 17 curated, non-destructive security checks guarded by a mandatory local-scope "
    "allow-list and DNS-rebinding defenses, maps every finding to exact endpoints and "
    "parameters, delivers multi-stack Before/After copy-ready remediation snippets (FastAPI, "
    "Flask, Express, PHP, and HTML), aligns with NIST SSDF (SP 800-218), and establishes an "
    "empirical validation protocol across DVWA, OWASP Juice Shop, and a deterministic local "
    "VulnBench testbench."
)

METADATA_ROWS: list[tuple[str, str]] = [
    (
        "Project Title",
        "Developing a Lightweight OWASP Top 10 Vulnerability Scanner "
        "(Tailored for Web Developers and Student Projects)",
    ),
    ("Methodological Reference", "OWASP Top 10 (2021) & NIST SSDF (SP 800-218)"),
    (
        "Target Audience",
        "Junior Web Developers, University Students, and Small Development Teams",
    ),
    ("Project Supervisor", "Dr. Samar"),
    (
        "Project Team",
        "Seven Members: Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), "
        "Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), "
        "Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), "
        "Ali Ibrahim Elsayed (235332)",
    ),
    ("Academic Year", "2026–2027"),
    ("Document Status", "Proposed System Analysis and Design (Formal Edition v1.1)"),
    (
        "Current Project Phase",
        "First Semester – Requirements Analysis and System Architecture Design",
    ),
    (
        "Next Project Phase",
        "Second Semester – Technical Implementation, Integration, and Testbench Validation",
    ),
]

CANONICAL_REFERENCES: list[str] = [
    "[1] OWASP Foundation, \"OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks,\" Open Worldwide Application Security Project, 2021. [Online]. Available: https://owasp.org/Top10/",
    "[2] OWASP Foundation, \"OWASP Web Security Testing Guide (WSTG), v4.2,\" Open Worldwide Application Security Project, 2023. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/",
    "[3] OWASP Foundation, \"OWASP Application Security Verification Standard (ASVS), v4.0.3,\" Open Worldwide Application Security Project, 2021. [Online]. Available: https://owasp.org/www-project-application-security-verification-standard/",
    "[4] M. Souppaya, K. Scarfone, and D. Dodson, \"Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities,\" NIST Special Publication 800-218, National Institute of Standards and Technology, Feb. 2022.",
    "[5] OWASP Foundation, \"OWASP Cheat Sheet Series,\" Open Worldwide Application Security Project, 2025. [Online]. Available: https://cheatsheetseries.owasp.org/",
    "[6] Checkmarx and OWASP Community, \"Zed Attack Proxy (ZAP) — Open-Source Web Application Security Scanner,\" 2025. [Online]. Available: https://www.zaproxy.org/",
    "[7] PortSwigger Ltd., \"Burp Suite Documentation — Web Security Testing Platform,\" 2025. [Online]. Available: https://portswigger.net/burp/documentation",
    "[8] N. Surribas, \"Wapiti — Web Application Vulnerability Scanner,\" Open-Source Project, 2024. [Online]. Available: https://wapiti-scanner.github.io/",
    "[9] ProjectDiscovery, \"Nuclei — Fast and Customizable Vulnerability Scanner Based on Simple YAML Templates,\" 2025. [Online]. Available: https://docs.projectdiscovery.io/tools/nuclei",
    "[10] R. Dewhurst and EthicalHack3r, \"Damn Vulnerable Web Application (DVWA),\" 2024. [Online]. Available: https://github.com/digininja/DVWA",
    "[11] B. Kimminich and OWASP Foundation, \"OWASP Juice Shop: Probably the Most Modern and Sophisticated Insecure Web Application,\" 2025. [Online]. Available: https://owasp.org/www-project-juice-shop/",
    "[12] S. Ramirez, \"FastAPI Framework Documentation,\" and M. Bayer, \"SQLAlchemy 2.0 Documentation,\" 2025. [Online]. Available: https://fastapi.tiangolo.com/ and https://docs.sqlalchemy.org/",
]

SIGN_OFF_ROWS: list[tuple[str, str]] = [
    ("Document Title", "Graduation Project Book – System Analysis and Design (Formal Edition v1.1)"),
    ("Prepared For", "Dr. Samar, Project Supervisor"),
    (
        "Prepared By",
        "Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), "
        "Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), "
        "Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), "
        "Ali Ibrahim Elsayed (235332)",
    ),
    ("Department", "Department of Cyber Security"),
    ("Academic Year", "2026–2027"),
    ("Review Milestone", "First Semester System Analysis and Design Approval"),
    ("Supervisor Signature / Date", "______________________________________   Date: ____ / ____ / 2026"),
]

# OOXML namespaces
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC_NS = "http://schemas.openxmlformats.org/drawingml/2006/picture"
MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"

# Page geometry (A4 portrait, 1 inch margins)
PAGE_WIDTH_TWIPS = 11906
PAGE_HEIGHT_TWIPS = 16838
MARGIN_TWIPS = 1440
CONTENT_WIDTH_TWIPS = PAGE_WIDTH_TWIPS - 2 * MARGIN_TWIPS  # 9026 twips (~6.27 in)
EMU_PER_INCH = 914400
MAX_IMG_WIDTH_EMU = int(6.2 * EMU_PER_INCH)   # 5,669,280 EMU
MAX_IMG_HEIGHT_EMU = int(7.6 * EMU_PER_INCH)  # 6,949,440 EMU


# ---------------------------------------------------------------------------
# Data structures for parsed Markdown AST
# ---------------------------------------------------------------------------


@dataclass
class HeadingBlock:
    level: int
    text: str


@dataclass
class ParagraphBlock:
    text: str


@dataclass
class FigureBlock:
    alt: str
    image_path: Path
    caption: str
    fig_num: int
    mmd_rel: str = ""


@dataclass
class TableBlock:
    headers: list[str]
    rows: list[list[str]]


@dataclass
class CodeBlock:
    lang: str
    code: str


@dataclass
class ListItem:
    level: int
    text: str


@dataclass
class ListBlock:
    ordered: bool
    items: list[ListItem] = field(default_factory=list)


@dataclass
class BlockQuoteBlock:
    alert_kind: str  # "", "NOTE", "IMPORTANT", "WARNING", "TIP", "CAUTION"
    lines: list[str] = field(default_factory=list)


@dataclass
class HorizontalRuleBlock:
    pass


Block = (
    HeadingBlock
    | ParagraphBlock
    | FigureBlock
    | TableBlock
    | CodeBlock
    | ListBlock
    | BlockQuoteBlock
    | HorizontalRuleBlock
)


@dataclass
class TocItem:
    level: int
    title: str
    anchor: str


@dataclass
class FigureEntry:
    fig_num: int
    title: str
    chapter_label: str
    image_path: Path
    mmd_rel: str


@dataclass
class ChapterData:
    path: Path
    title: str
    raw_md: str
    blocks: list[Block]


# ---------------------------------------------------------------------------
# Text helpers & Markdown parsing
# ---------------------------------------------------------------------------

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def sanitize_xml_text(text: str) -> str:
    """Strip characters disallowed in XML 1.0."""
    return CONTROL_CHAR_RE.sub("", text)


def strip_md_inline(text: str) -> str:
    """Convert inline Markdown to clean plain text (for TOC/captions/sizing)."""
    out = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    out = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", out)
    out = re.sub(r"`([^`]*)`", r"\1", out)
    out = re.sub(r"\*\*\*([^*]+)\*\*\*", r"\1", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"\1", out)
    out = re.sub(r"__([^_]+)__", r"\1", out)
    out = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"\1", out)
    out = re.sub(r"(?<!_)_([^_]+)_(?!_)", r"\1", out)
    return out.strip()


def make_anchor(text: str) -> str:
    plain = strip_md_inline(text).lower()
    plain = re.sub(r"[^a-z0-9\s-]", "", plain)
    plain = re.sub(r"\s+", "-", plain.strip())
    return plain or "section"


def split_table_row(line: str) -> list[str]:
    """Split a GFM markdown table row respecting escaped pipes."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            buf.append("|")
            i += 2
        elif s[i] == "|":
            cells.append("".join(buf).strip())
            buf = []
            i += 1
        else:
            buf.append(s[i])
            i += 1
    cells.append("".join(buf).strip())
    return cells


def is_table_separator(line: str) -> bool:
    s = line.strip()
    if "|" not in s:
        return False
    cells = split_table_row(s)
    if not cells:
        return False
    return all(re.match(r"^:?-{3,}:?$", c.strip()) is not None for c in cells)


IMAGE_LINE_RE = re.compile(r"^!\[([^\]]*)\]\(([^)]+)\)\s*$")
FIG_NUM_RE = re.compile(r"(?:Figure|Diagram)\s+(\d+)", re.IGNORECASE)
ITALIC_CAPTION_RE = re.compile(r"^[*_](.+?)[*_]\s*$")


def resolve_image_path(raw_rel: str, source_dir: Path) -> Path:
    """Resolve a Markdown image path against source_dir or docs/diagrams/images/."""
    clean = raw_rel.strip().strip('"').strip("'")
    candidate = (source_dir / clean).resolve()
    if candidate.exists():
        return candidate
    fallback = (DOCS_DIR / clean.lstrip("./")).resolve()
    if fallback.exists():
        return fallback
    by_name = IMAGES_DIR / Path(clean).name
    if by_name.exists():
        return by_name
    return candidate


def clean_caption_for_print(raw_caption: str, fallback_alt: str) -> tuple[str, str]:
    """
    Normalize a figure caption for DOCX/PDF output while extracting any linked
    .mmd source path for Markdown metadata.
    """
    mmd_match = re.search(r"\(([^)]+\.mmd)\)", raw_caption)
    mmd_rel = ""
    if mmd_match:
        mmd_name = Path(mmd_match.group(1)).name
        mmd_rel = f"../../diagrams/mmd/{mmd_name}"

    text = raw_caption.strip()
    m = ITALIC_CAPTION_RE.match(text)
    if m:
        text = m.group(1).strip()

    # Remove trailing source-link parentheticals or sentences like
    # "([Mermaid Source](...))", "(Source: [04.mmd](...))", or "Diagram source: [01.mmd](...)."
    text = re.sub(
        r"\s*[\(\[—–-]*\s*(?:Mermaid\s+source|Diagram\s+source|Source)\s*:?\s*\[[^\]]+\]\([^)]+\.mmd\)\s*[\)\]]*\.?\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\s*\(\s*\[[^\]]+\]\([^)]+\.mmd\)\s*\)\s*\.?\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = strip_md_inline(text).strip(" —–-")
    if not text:
        text = strip_md_inline(fallback_alt)
    return text, mmd_rel


def parse_markdown_blocks(
    md_text: str,
    source_dir: Path,
    fig_counter: list[int],
) -> list[Block]:
    """Parse a chapter's Markdown into structured AST blocks."""
    lines = md_text.replace("\r\n", "\n").split("\n")
    blocks: list[Block] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # Horizontal rule
        if re.match(r"^(?:---+|\*\*\*+|___+)\s*$", stripped):
            blocks.append(HorizontalRuleBlock())
            i += 1
            continue

        # Fenced code block
        fence_m = re.match(r"^\s*(`{3,}|~{3,})\s*([^\s`~]*)\s*$", line)
        if fence_m:
            fence_char = fence_m.group(1)[0]
            fence_len = len(fence_m.group(1))
            lang = fence_m.group(2).strip().lower()
            i += 1
            code_lines: list[str] = []
            close_re = re.compile(rf"^\s*{re.escape(fence_char)}{{{fence_len},}}\s*$")
            while i < n and not close_re.match(lines[i]):
                code_lines.append(lines[i])
                i += 1
            if i < n:
                i += 1
            blocks.append(CodeBlock(lang=lang, code="\n".join(code_lines)))
            continue

        # Heading (# to ####)
        head_m = re.match(r"^(#{1,4})\s+(.+?)\s*#*\s*$", stripped)
        if head_m:
            blocks.append(HeadingBlock(level=len(head_m.group(1)), text=head_m.group(2).strip()))
            i += 1
            continue

        # Standalone Image / Figure line
        img_m = IMAGE_LINE_RE.match(stripped)
        if img_m:
            alt = img_m.group(1).strip()
            raw_path = img_m.group(2).strip()
            img_path = resolve_image_path(raw_path, source_dir)

            # Determine figure number
            num_m = FIG_NUM_RE.search(alt)
            if num_m:
                fig_num = int(num_m.group(1))
                fig_counter[0] = max(fig_counter[0], fig_num)
            else:
                file_num_m = re.match(r"^(\d+)_", img_path.name)
                if file_num_m:
                    fig_num = int(file_num_m.group(1))
                    fig_counter[0] = max(fig_counter[0], fig_num)
                else:
                    fig_counter[0] += 1
                    fig_num = fig_counter[0]

            caption = strip_md_inline(alt)
            mmd_rel = f"diagrams/{img_path.stem}.mmd"
            i += 1

            # Absorb immediately following italic caption line (skipping at most 1 blank line)
            look = i
            while look < n and not lines[look].strip():
                look += 1
            if look < n:
                cand = lines[look].strip()
                if ITALIC_CAPTION_RE.match(cand) and (
                    "figure" in cand.lower() or "diagram" in cand.lower() or ".mmd" in cand.lower()
                ):
                    parsed_cap, parsed_mmd = clean_caption_for_print(cand, alt)
                    if parsed_cap:
                        caption = parsed_cap
                    if parsed_mmd:
                        mmd_rel = parsed_mmd
                    i = look + 1

            if not re.match(r"^Figure\s+\d+\s*:", caption, re.IGNORECASE):
                caption = f"Figure {fig_num}: {caption}"

            blocks.append(
                FigureBlock(
                    alt=alt,
                    image_path=img_path,
                    caption=caption,
                    fig_num=fig_num,
                    mmd_rel=mmd_rel,
                )
            )
            continue

        # GFM Table
        if "|" in stripped and i + 1 < n and is_table_separator(lines[i + 1]):
            headers = split_table_row(lines[i])
            i += 2
            rows: list[list[str]] = []
            while i < n:
                rline = lines[i].strip()
                if not rline or "|" not in rline:
                    break
                if re.match(r"^(#{1,4})\s+", rline):
                    break
                row_cells = split_table_row(rline)
                # Normalize column count to match headers
                if len(row_cells) < len(headers):
                    row_cells.extend([""] * (len(headers) - len(row_cells)))
                elif len(row_cells) > len(headers):
                    row_cells = row_cells[: len(headers)]
                rows.append(row_cells)
                i += 1
            blocks.append(TableBlock(headers=headers, rows=rows))
            continue

        # Blockquote / Alert
        if stripped.startswith(">"):
            bq_lines: list[str] = []
            alert_kind = ""
            while i < n and lines[i].strip().startswith(">"):
                content = re.sub(r"^\s*>\s?", "", lines[i])
                if not bq_lines:
                    alert_m = re.match(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*)$", content.strip(), re.I)
                    if alert_m:
                        alert_kind = alert_m.group(1).upper()
                        rest = alert_m.group(2).strip()
                        if rest:
                            bq_lines.append(rest)
                        i += 1
                        continue
                if content.strip():
                    bq_lines.append(content.strip())
                i += 1
            if bq_lines or alert_kind:
                blocks.append(BlockQuoteBlock(alert_kind=alert_kind, lines=bq_lines))
            continue

        # Unordered list
        ul_m = re.match(r"^(\s*)[-*+]\s+(.+)$", line)
        if ul_m:
            items: list[ListItem] = []
            while i < n:
                m = re.match(r"^(\s*)[-*+]\s+(.+)$", lines[i])
                if not m:
                    # Continuation line indented under bullet
                    if lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*\d+\.\s+", lines[i]):
                        items[-1].text += " " + lines[i].strip()
                        i += 1
                        continue
                    break
                indent = len(m.group(1).expandtabs(2))
                lvl = min(2, indent // 2)
                items.append(ListItem(level=lvl, text=m.group(2).strip()))
                i += 1
            blocks.append(ListBlock(ordered=False, items=items))
            continue

        # Ordered list
        ol_m = re.match(r"^(\s*)\d+[.)]\s+(.+)$", line)
        if ol_m:
            items = []
            while i < n:
                m = re.match(r"^(\s*)\d+[.)]\s+(.+)$", lines[i])
                if not m:
                    if lines[i].startswith("  ") and lines[i].strip() and not re.match(r"^\s*[-*+]\s+", lines[i]):
                        items[-1].text += " " + lines[i].strip()
                        i += 1
                        continue
                    break
                indent = len(m.group(1).expandtabs(2))
                lvl = min(2, indent // 2)
                items.append(ListItem(level=lvl, text=m.group(2).strip()))
                i += 1
            blocks.append(ListBlock(ordered=True, items=items))
            continue

        # Paragraph (collect contiguous lines until blank or next block starter)
        para_lines: list[str] = [stripped]
        i += 1
        while i < n:
            nxt = lines[i]
            ns = nxt.strip()
            if not ns:
                break
            if (
                re.match(r"^(#{1,4})\s+", ns)
                or re.match(r"^\s*(`{3,}|~{3,})", nxt)
                or re.match(r"^(?:---+|\*\*\*+|___+)\s*$", ns)
                or ns.startswith(">")
                or IMAGE_LINE_RE.match(ns)
                or re.match(r"^(\s*)[-*+]\s+", nxt)
                or re.match(r"^(\s*)\d+[.)]\s+", nxt)
                or ("|" in ns and i + 1 < n and is_table_separator(lines[i + 1]))
            ):
                break
            para_lines.append(ns)
            i += 1
        blocks.append(ParagraphBlock(text=" ".join(para_lines)))

    return blocks


def load_all_chapters() -> tuple[list[ChapterData], list[TocItem], list[FigureEntry], bool, bool]:
    """Load all 6 chapters, parse AST, collect TOC and Figures, and detect back-matter."""
    chapter_paths = sorted(CHAPTERS_DIR.glob("0[1-6]_*.md"))
    if len(chapter_paths) != 6:
        raise FileNotFoundError(
            f"Expected 6 chapter files in {CHAPTERS_DIR}, found {len(chapter_paths)}: "
            f"{[p.name for p in chapter_paths]}"
        )

    chapters: list[ChapterData] = []
    toc: list[TocItem] = []
    figures: list[FigureEntry] = []
    fig_counter = [0]
    has_references = False
    has_signoff = False

    for ch_idx, path in enumerate(chapter_paths, start=1):
        raw_md = path.read_text(encoding="utf-8")
        blocks = parse_markdown_blocks(raw_md, path.parent, fig_counter)

        chapter_title = f"Chapter {ch_idx}"
        for blk in blocks:
            if isinstance(blk, HeadingBlock) and blk.level == 1:
                chapter_title = strip_md_inline(blk.text)
                break

        # Detect embedded References / Sign-Off sections in Chapter 6
        for blk in blocks:
            if isinstance(blk, HeadingBlock):
                low = strip_md_inline(blk.text).lower()
                if "references" in low and blk.level <= 2:
                    has_references = True
                if ("sign-off" in low or "sign off" in low) and blk.level <= 2:
                    has_signoff = True

        # Collect TOC entries (levels 1 and 2) and Figures
        for blk in blocks:
            if isinstance(blk, HeadingBlock) and blk.level in (1, 2):
                clean_title = strip_md_inline(blk.text)
                low = clean_title.lower()
                toc_lvl = 1 if (blk.level == 1 or low == "references" or "sign-off" in low) else 2
                toc.append(TocItem(level=toc_lvl, title=clean_title, anchor=make_anchor(clean_title)))
            elif isinstance(blk, FigureBlock):
                short_title = strip_md_inline(blk.alt) or blk.caption
                if not re.match(r"^Figure\s+\d+\s*:", short_title, re.IGNORECASE):
                    short_title = f"Figure {blk.fig_num}: {short_title}"
                figures.append(
                    FigureEntry(
                        fig_num=blk.fig_num,
                        title=short_title,
                        chapter_label=f"Chapter {ch_idx}",
                        image_path=blk.image_path,
                        mmd_rel=blk.mmd_rel,
                    )
                )

        chapters.append(ChapterData(path=path, title=chapter_title, raw_md=raw_md, blocks=blocks))

    if not has_references:
        toc.append(TocItem(level=1, title="References", anchor="references"))
    if not has_signoff:
        toc.append(TocItem(level=1, title="Document Sign-Off Summary", anchor="document-sign-off-summary"))

    figures.sort(key=lambda f: f.fig_num)
    return chapters, toc, figures, has_references, has_signoff


# ---------------------------------------------------------------------------
# Unified Formal Markdown Book Builder (docs/SAD_Book.md)
# ---------------------------------------------------------------------------


def rewrite_chapter_links_for_book_md(raw_md: str) -> str:
    """Rewrite relative ../diagrams/ links to ../../diagrams/ for docs/books/md/SAD_Book.md."""
    text = raw_md.replace("../diagrams/png/", "../../diagrams/png/")
    text = text.replace("../diagrams/mmd/", "../../diagrams/mmd/")
    return text.strip()


def build_sad_book_md(
    chapters: list[ChapterData],
    toc: list[TocItem],
    figures: list[FigureEntry],
    has_references: bool,
    has_signoff: bool,
) -> str:
    """Assemble the complete unified Markdown book (docs/SAD_Book.md)."""
    parts: list[str] = []

    # Cover Header Block
    parts.append(f"# {BOOK_HEADER}\n")
    parts.append(f"## {BOOK_TITLE}\n")
    parts.append(f"*{BOOK_SUBTITLE}*\n")
    parts.append("---\n")

    # Executive Abstract
    parts.append("## Executive Abstract\n")
    parts.append(f"{EXECUTIVE_ABSTRACT}\n")

    # Formal Project Metadata Table
    parts.append("## Project Metadata\n")
    parts.append("| Attribute | Specification |")
    parts.append("| :--- | :--- |")
    for key, val in METADATA_ROWS:
        parts.append(f"| **{key}** | {val} |")
    parts.append("\n---\n")

    # Formal Table of Contents
    parts.append("## Table of Contents\n")
    for item in toc:
        if item.level == 1:
            parts.append(f"- **[{item.title}](#{item.anchor})**")
        else:
            parts.append(f"  - [{item.title}](#{item.anchor})")
    parts.append("\n---\n")

    # List of Figures (Figures 1-18)
    parts.append("## List of Figures\n")
    parts.append("| Figure | Title | Chapter | Image Asset | Mermaid Source |")
    parts.append("| :---: | :--- | :---: | :--- | :--- |")
    for fig in figures:
        img_rel = f"../../diagrams/png/{fig.image_path.name}"
        clean_title = re.sub(r"^Figure\s+\d+\s*:\s*", "", fig.title, flags=re.IGNORECASE)
        parts.append(
            f"| **Figure {fig.fig_num}** | {clean_title} | {fig.chapter_label} | "
            f"[{fig.image_path.name}]({img_rel}) | [{Path(fig.mmd_rel).name}]({fig.mmd_rel}) |"
        )
    parts.append("\n---\n")

    # All 6 Formal Chapters
    for ch in chapters:
        parts.append(rewrite_chapter_links_for_book_md(ch.raw_md))
        parts.append("\n---\n")

    # Append References if not already present in Chapter 6
    if not has_references:
        parts.append("# References\n")
        for ref in CANONICAL_REFERENCES:
            parts.append(f"{ref}\n")
        parts.append("\n---\n")

    # Append End-of-Document Sign-Off Summary Table if not already present
    if not has_signoff:
        parts.append("# Document Sign-Off Summary\n")
        parts.append("| Field | Details |")
        parts.append("| :--- | :--- |")
        for k, v in SIGN_OFF_ROWS:
            parts.append(f"| **{k}** | {v} |")
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Inline Markdown -> OOXML Runs Converter
# ---------------------------------------------------------------------------

INLINE_TOKEN_RE = re.compile(
    r"(`[^`]+`)"                       # inline code
    r"|(\*\*\*[^*]+\*\*\*)"            # bold italic
    r"|(\*\*[^*]+\*\*)"                # bold
    r"|(__[^_]+__)"                    # bold alt
    r"|(\[[^\]]+\]\([^)]+\))"          # markdown link
    r"|((?<!\*)\*[^*\n]+\*(?!\*))"     # italic
)


def make_run_xml(
    text: str,
    *,
    bold: bool = False,
    italic: bool = False,
    code: bool = False,
    color: str | None = None,
    size_half_pt: int | None = None,
    font_name: str | None = None,
) -> str:
    clean = sanitize_xml_text(text)
    if not clean:
        return ""
    rpr_parts: list[str] = []
    if code:
        rpr_parts.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>')
        rpr_parts.append(f'<w:sz w:val="{size_half_pt or 19}"/><w:szCs w:val="{size_half_pt or 19}"/>')
        rpr_parts.append(f'<w:color w:val="{color or "0F172A"}"/>')
        rpr_parts.append('<w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/>')
    else:
        if font_name:
            rpr_parts.append(
                f'<w:rFonts w:ascii="{font_name}" w:hAnsi="{font_name}" w:cs="{font_name}"/>'
            )
        if size_half_pt:
            rpr_parts.append(f'<w:sz w:val="{size_half_pt}"/><w:szCs w:val="{size_half_pt}"/>')
        if color:
            rpr_parts.append(f'<w:color w:val="{color}"/>')
    if bold:
        rpr_parts.append("<w:b/><w:bCs/>")
    if italic:
        rpr_parts.append("<w:i/><w:iCs/>")

    rpr = f"<w:rPr>{''.join(rpr_parts)}</w:rPr>" if rpr_parts else ""
    escaped = xml_escape(clean)
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escaped}</w:t></w:r>'


def inline_md_to_ooxml_runs(
    text: str,
    *,
    base_bold: bool = False,
    base_italic: bool = False,
    color: str | None = None,
    size_half_pt: int | None = None,
) -> str:
    """Convert inline Markdown formatting into a sequence of OOXML <w:r> elements."""
    out: list[str] = []
    pos = 0
    for m in INLINE_TOKEN_RE.finditer(text):
        if m.start() > pos:
            out.append(
                make_run_xml(
                    text[pos : m.start()],
                    bold=base_bold,
                    italic=base_italic,
                    color=color,
                    size_half_pt=size_half_pt,
                )
            )
        tok = m.group(0)
        if tok.startswith("`") and tok.endswith("`"):
            out.append(
                make_run_xml(
                    tok[1:-1],
                    bold=base_bold,
                    italic=base_italic,
                    code=True,
                    color=color,
                    size_half_pt=(size_half_pt - 2) if size_half_pt and size_half_pt > 16 else 18,
                )
            )
        elif tok.startswith("***") and tok.endswith("***"):
            out.append(
                make_run_xml(
                    tok[3:-3],
                    bold=True,
                    italic=True,
                    color=color,
                    size_half_pt=size_half_pt,
                )
            )
        elif (tok.startswith("**") and tok.endswith("**")) or (tok.startswith("__") and tok.endswith("__")):
            inner = tok[2:-2]
            # Handle inline code nested inside bold like **`POST /api/scans`**
            if "`" in inner:
                out.append(
                    inline_md_to_ooxml_runs(
                        inner,
                        base_bold=True,
                        base_italic=base_italic,
                        color=color,
                        size_half_pt=size_half_pt,
                    )
                )
            else:
                out.append(
                    make_run_xml(
                        inner,
                        bold=True,
                        italic=base_italic,
                        color=color,
                        size_half_pt=size_half_pt,
                    )
                )
        elif tok.startswith("[") and "](" in tok:
            lm = re.match(r"^\[([^\]]+)\]\(([^)]+)\)$", tok)
            label = lm.group(1) if lm else tok
            out.append(
                make_run_xml(
                    strip_md_inline(label),
                    bold=base_bold,
                    italic=base_italic,
                    color=color or "0F766E",
                    size_half_pt=size_half_pt,
                )
            )
        elif tok.startswith("*") and tok.endswith("*"):
            out.append(
                make_run_xml(
                    tok[1:-1],
                    bold=base_bold,
                    italic=True,
                    color=color,
                    size_half_pt=size_half_pt,
                )
            )
        pos = m.end()

    if pos < len(text):
        out.append(
            make_run_xml(
                text[pos:],
                bold=base_bold,
                italic=base_italic,
                color=color,
                size_half_pt=size_half_pt,
            )
        )
    return "".join(out)


# ---------------------------------------------------------------------------
# Pure-Python OOXML .docx Generator
# ---------------------------------------------------------------------------


class DocxBookBuilder:
    """Constructs a 100% valid ECMA-376 OOXML Word document with embedded PNGs."""

    def __init__(self) -> None:
        self.body_parts: list[str] = []
        self.media_files: list[tuple[str, str, bytes]] = []  # (rId, media_name, png_bytes)
        self._next_rid = 10  # rId1..rId4 reserved for styles, numbering, header, footer
        self._next_docpr = 1

    def _register_png(self, image_path: Path, fig_num: int) -> tuple[str, int, int]:
        """Embed a PNG file and return (rId, width_emu, height_emu)."""
        if not image_path.exists():
            raise FileNotFoundError(f"Required figure PNG not found: {image_path}")
        png_bytes = image_path.read_bytes()
        if not png_bytes:
            raise ValueError(f"Figure PNG is empty: {image_path}")

        with Image.open(image_path) as im:
            px_w, px_h = im.size
        if px_w <= 0 or px_h <= 0:
            raise ValueError(f"Invalid PNG dimensions for {image_path}: {px_w}x{px_h}")

        # Scale preserving aspect ratio to max 6.2 in wide and max 7.6 in tall
        # Assume 96 DPI base, then clamp to fit comfortably inside margins.
        emu_w = int((px_w / 96.0) * EMU_PER_INCH)
        emu_h = int((px_h / 96.0) * EMU_PER_INCH)

        # Always scale to full readable width (6.2 in) if larger, or proportionally if wide
        scale_w = MAX_IMG_WIDTH_EMU / emu_w
        scale_h = MAX_IMG_HEIGHT_EMU / emu_h
        # For high-DPI 2x PNGs (1600-2200px), scale down to fit max width/height cleanly
        scale = min(scale_w, scale_h, 1.0)
        # If an image is small, keep it crisp without upscaling past 6.2in
        final_w = max(int(emu_w * scale), int(2.5 * EMU_PER_INCH))
        final_h = int(final_w * (px_h / px_w))
        if final_h > MAX_IMG_HEIGHT_EMU:
            final_h = MAX_IMG_HEIGHT_EMU
            final_w = int(final_h * (px_w / px_h))
        if final_w > MAX_IMG_WIDTH_EMU:
            final_w = MAX_IMG_WIDTH_EMU
            final_h = int(final_w * (px_h / px_w))

        rid = f"rId{self._next_rid}"
        self._next_rid += 1
        media_name = f"fig{fig_num:02d}.png"
        # Ensure unique media name even if duplicate fig_num occurs
        existing_names = {m[1] for m in self.media_files}
        if media_name in existing_names:
            media_name = f"fig{fig_num:02d}_{self._next_rid}.png"
        self.media_files.append((rid, media_name, png_bytes))
        return rid, final_w, final_h

    def add_page_break(self) -> None:
        self.body_parts.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def add_heading(self, level: int, text: str, *, page_break_before: bool | None = None) -> None:
        style_map = {1: "Heading1", 2: "Heading2", 3: "Heading3", 4: "Heading4"}
        style = style_map.get(level, "Heading4")
        ppr_extra = ""
        if page_break_before is False:
            ppr_extra = '<w:pageBreakBefore w:val="0"/>'
        elif page_break_before is True:
            ppr_extra = "<w:pageBreakBefore/>"
        runs = inline_md_to_ooxml_runs(text)
        self.body_parts.append(
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{ppr_extra}</w:pPr>{runs}</w:p>'
        )

    def add_paragraph(
        self,
        text: str,
        *,
        style: str = "Normal",
        align: str | None = None,
        space_before: int | None = None,
        space_after: int | None = None,
        keep_next: bool = False,
        base_bold: bool = False,
        base_italic: bool = False,
        color: str | None = None,
        size_half_pt: int | None = None,
    ) -> None:
        ppr: list[str] = [f'<w:pStyle w:val="{style}"/>']
        if keep_next:
            ppr.append("<w:keepNext/>")
        if space_before is not None or space_after is not None:
            attrs = []
            if space_before is not None:
                attrs.append(f'w:before="{space_before}"')
            if space_after is not None:
                attrs.append(f'w:after="{space_after}"')
            ppr.append(f"<w:spacing {' '.join(attrs)}/>")
        if align:
            ppr.append(f'<w:jc w:val="{align}"/>')
        runs = inline_md_to_ooxml_runs(
            text,
            base_bold=base_bold,
            base_italic=base_italic,
            color=color,
            size_half_pt=size_half_pt,
        )
        self.body_parts.append(f"<w:p><w:pPr>{''.join(ppr)}</w:pPr>{runs}</w:p>")

    def add_list(self, lst: ListBlock) -> None:
        num_id = 2 if lst.ordered else 1
        for item in lst.items:
            ilvl = max(0, min(2, item.level))
            runs = inline_md_to_ooxml_runs(item.text)
            self.body_parts.append(
                "<w:p><w:pPr>"
                '<w:pStyle w:val="ListParagraph"/>'
                f'<w:numPr><w:ilvl w:val="{ilvl}"/><w:numId w:val="{num_id}"/></w:numPr>'
                '<w:spacing w:before="20" w:after="60" w:line="264" w:lineRule="auto"/>'
                f"</w:pPr>{runs}</w:p>"
            )

    def add_blockquote(self, bq: BlockQuoteBlock) -> None:
        border_color = {
            "WARNING": "D97706",
            "CAUTION": "DC2626",
            "IMPORTANT": "0F766E",
            "TIP": "059669",
            "NOTE": "0D9488",
        }.get(bq.alert_kind, "0D9488")
        fill_color = {
            "WARNING": "FFFBEB",
            "CAUTION": "FEF2F2",
            "IMPORTANT": "F0FDFA",
            "TIP": "ECFDF5",
            "NOTE": "F8FAFC",
        }.get(bq.alert_kind, "F8FAFC")

        paras: list[str] = []
        if bq.alert_kind:
            label = make_run_xml(
                f"{bq.alert_kind}: ",
                bold=True,
                color=border_color,
                size_half_pt=20,
            )
            first_text = inline_md_to_ooxml_runs(
                bq.lines[0] if bq.lines else "",
                color="334155",
                size_half_pt=20,
            )
            paras.append(
                '<w:p><w:pPr><w:spacing w:before="40" w:after="60" w:line="260" w:lineRule="auto"/></w:pPr>'
                f"{label}{first_text}</w:p>"
            )
            for extra in bq.lines[1:]:
                paras.append(
                    '<w:p><w:pPr><w:spacing w:before="20" w:after="60" w:line="260" w:lineRule="auto"/></w:pPr>'
                    f'{inline_md_to_ooxml_runs(extra, color="334155", size_half_pt=20)}</w:p>'
                )
        else:
            for line in bq.lines:
                paras.append(
                    '<w:p><w:pPr><w:spacing w:before="20" w:after="60" w:line="260" w:lineRule="auto"/></w:pPr>'
                    f'{inline_md_to_ooxml_runs(line, base_italic=True, color="334155", size_half_pt=20)}</w:p>'
                )

        tbl_xml = (
            "<w:tbl>"
            "<w:tblPr>"
            f'<w:tblW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:tblLayout w:type="fixed"/>'
            "<w:tblBorders>"
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
            f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
            "</w:tblBorders>"
            "</w:tblPr>"
            f'<w:tblGrid><w:gridCol w:w="{CONTENT_WIDTH_TWIPS}"/></w:tblGrid>'
            "<w:tr><w:trPr><w:cantSplit/></w:trPr>"
            "<w:tc><w:tcPr>"
            f'<w:tcW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            f'<w:shd w:val="clear" w:color="auto" w:fill="{fill_color}"/>'
            '<w:tcMar><w:top w:w="100" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/>'
            '<w:left w:w="160" w:type="dxa"/><w:right w:w="140" w:type="dxa"/></w:tcMar>'
            "</w:tcPr>"
            f"{''.join(paras)}</w:tc></w:tr>"
            "</w:tbl>"
            '<w:p><w:pPr><w:spacing w:before="0" w:after="80"/></w:pPr></w:p>'
        )
        self.body_parts.append(tbl_xml)

    def add_code_block(self, code_blk: CodeBlock) -> None:
        lines = sanitize_xml_text(code_blk.code).split("\n")
        if not lines:
            lines = [""]
        paras: list[str] = []
        if code_blk.lang:
            lang_run = make_run_xml(
                code_blk.lang.upper(),
                bold=True,
                color="0F766E",
                size_half_pt=15,
                font_name="Consolas",
            )
            paras.append(
                '<w:p><w:pPr><w:spacing w:before="0" w:after="60" w:line="220" w:lineRule="auto"/></w:pPr>'
                f"{lang_run}</w:p>"
            )
        for ln in lines:
            run = make_run_xml(
                ln if ln else " ",
                color="0F172A",
                size_half_pt=17,
                font_name="Consolas",
            )
            paras.append(
                '<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="220" w:lineRule="auto"/></w:pPr>'
                f"{run}</w:p>"
            )

        tbl_xml = (
            "<w:tbl>"
            "<w:tblPr>"
            f'<w:tblW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:tblLayout w:type="fixed"/>'
            "<w:tblBorders>"
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:left w:val="single" w:sz="18" w:space="0" w:color="0F172A"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            "</w:tblBorders>"
            "</w:tblPr>"
            f'<w:tblGrid><w:gridCol w:w="{CONTENT_WIDTH_TWIPS}"/></w:tblGrid>'
            "<w:tr>"
            "<w:tc><w:tcPr>"
            f'<w:tcW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/>'
            '<w:tcMar><w:top w:w="100" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/>'
            '<w:left w:w="140" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tcMar>'
            "</w:tcPr>"
            f"{''.join(paras)}</w:tc></w:tr>"
            "</w:tbl>"
            '<w:p><w:pPr><w:spacing w:before="0" w:after="100"/></w:pPr></w:p>'
        )
        self.body_parts.append(tbl_xml)

    def add_table(
        self,
        headers: list[str],
        rows: list[list[str]],
        *,
        col_weights: list[float] | None = None,
    ) -> None:
        ncols = len(headers)
        if ncols == 0:
            return

        # Compute intelligent proportional column widths summing to CONTENT_WIDTH_TWIPS
        if col_weights and len(col_weights) == ncols:
            weights = col_weights
        else:
            weights = []
            for c in range(ncols):
                h_len = len(strip_md_inline(headers[c]))
                cell_lens = [len(strip_md_inline(r[c])) for r in rows[:25] if c < len(r)]
                avg_len = (sum(cell_lens) / len(cell_lens)) if cell_lens else h_len
                p80 = sorted(cell_lens)[int(len(cell_lens) * 0.8)] if cell_lens else h_len
                score = max(h_len * 0.9, avg_len * 0.8 + p80 * 0.2, 6.0)
                weights.append(min(score, 65.0))

        total_w = sum(weights) or 1.0
        min_col = max(720, CONTENT_WIDTH_TWIPS // max(ncols * 2, 4))
        col_widths = [max(min_col, int(CONTENT_WIDTH_TWIPS * (w / total_w))) for w in weights]
        # Rescale to exact CONTENT_WIDTH_TWIPS
        scale = CONTENT_WIDTH_TWIPS / sum(col_widths)
        col_widths = [int(w * scale) for w in col_widths]
        col_widths[-1] += CONTENT_WIDTH_TWIPS - sum(col_widths)

        font_sz = 18 if ncols >= 5 else 19  # 9pt for wide tables, 9.5pt otherwise

        grid_xml = "".join(f'<w:gridCol w:w="{w}"/>' for w in col_widths)

        def build_row(cells: list[str], *, is_header: bool, zebra: bool) -> str:
            tr_pr = "<w:trPr><w:cantSplit/>" + ("<w:tblHeader/>" if is_header else "") + "</w:trPr>"
            fill = "0F172A" if is_header else ("F8FAFC" if zebra else "FFFFFF")
            txt_color = "FFFFFF" if is_header else "1E293B"
            tcs: list[str] = []
            for idx in range(ncols):
                val = cells[idx] if idx < len(cells) else ""
                runs = inline_md_to_ooxml_runs(
                    val,
                    base_bold=is_header,
                    color=txt_color,
                    size_half_pt=font_sz,
                )
                tcs.append(
                    "<w:tc><w:tcPr>"
                    f'<w:tcW w:w="{col_widths[idx]}" w:type="dxa"/>'
                    f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>'
                    '<w:vAlign w:val="center"/>'
                    '<w:tcMar><w:top w:w="75" w:type="dxa"/><w:bottom w:w="75" w:type="dxa"/>'
                    '<w:left w:w="100" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
                    "</w:tcPr>"
                    '<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/></w:pPr>'
                    f"{runs}</w:p></w:tc>"
                )
            return f"<w:tr>{tr_pr}{''.join(tcs)}</w:tr>"

        row_xmls = [build_row(headers, is_header=True, zebra=False)]
        for r_idx, row in enumerate(rows):
            row_xmls.append(build_row(row, is_header=False, zebra=(r_idx % 2 == 1)))

        tbl_xml = (
            "<w:tbl>"
            "<w:tblPr>"
            f'<w:tblW w:w="{CONTENT_WIDTH_TWIPS}" w:type="dxa"/>'
            '<w:tblLayout w:type="fixed"/>'
            "<w:tblBorders>"
            '<w:top w:val="single" w:sz="6" w:space="0" w:color="0F172A"/>'
            '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:bottom w:val="single" w:sz="8" w:space="0" w:color="0F172A"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
            "</w:tblBorders>"
            "</w:tblPr>"
            f"<w:tblGrid>{grid_xml}</w:tblGrid>"
            f"{''.join(row_xmls)}"
            "</w:tbl>"
            '<w:p><w:pPr><w:spacing w:before="0" w:after="100"/></w:pPr></w:p>'
        )
        self.body_parts.append(tbl_xml)

    def add_figure(self, fig: FigureBlock) -> None:
        rid, cx, cy = self._register_png(fig.image_path, fig.fig_num)
        docpr_id = self._next_docpr
        self._next_docpr += 1
        safe_name = xml_escape(f"Figure {fig.fig_num}")
        safe_descr = xml_escape(sanitize_xml_text(fig.caption))

        drawing_xml = (
            '<w:p><w:pPr><w:keepNext/><w:jc w:val="center"/>'
            '<w:spacing w:before="140" w:after="60"/></w:pPr>'
            "<w:r><w:drawing>"
            '<wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{cx}" cy="{cy}"/>'
            '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
            f'<wp:docPr id="{docpr_id}" name="{safe_name}" descr="{safe_descr}"/>'
            "<wp:cNvGraphicFramePr>"
            '<a:graphicFrameLocks noChangeAspect="1"/>'
            "</wp:cNvGraphicFramePr>"
            "<a:graphic>"
            '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            "<pic:pic>"
            "<pic:nvPicPr>"
            f'<pic:cNvPr id="{docpr_id}" name="{safe_name}" descr="{safe_descr}"/>'
            "<pic:cNvPicPr/>"
            "</pic:nvPicPr>"
            "<pic:blipFill>"
            f'<a:blip r:embed="{rid}"/>'
            "<a:stretch><a:fillRect/></a:stretch>"
            "</pic:blipFill>"
            "<pic:spPr>"
            "<a:xfrm>"
            '<a:off x="0" y="0"/>'
            f'<a:ext cx="{cx}" cy="{cy}"/>'
            "</a:xfrm>"
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
            '<a:ln w="9525"><a:solidFill><a:srgbClr val="E2E8F0"/></a:solidFill></a:ln>'
            "</pic:spPr>"
            "</pic:pic>"
            "</a:graphicData>"
            "</a:graphic>"
            "</wp:inline>"
            "</w:drawing></w:r></w:p>"
        )
        self.body_parts.append(drawing_xml)
        self.add_paragraph(
            fig.caption,
            style="Caption",
            align="center",
            space_before=40,
            space_after=180,
            base_italic=True,
            color="475569",
            size_half_pt=19,
        )

    def add_cover_page(self) -> None:
        # Navy accent banner table
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
            f'{make_run_xml(BOOK_HEADER, bold=True, color="5EEAD4", size_half_pt=22)}'
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

        # Executive Abstract block
        self.add_paragraph(
            "EXECUTIVE ABSTRACT",
            space_before=80,
            space_after=60,
            base_bold=True,
            color="0F766E",
            size_half_pt=22,
        )
        self.add_blockquote(BlockQuoteBlock(alert_kind="", lines=[EXECUTIVE_ABSTRACT]))

        # Formal Project Metadata Table
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
            rows=[[k, v] for k, v in METADATA_ROWS],
            col_weights=[28.0, 72.0],
        )
        self.add_page_break()

    def add_front_matter(self, toc: list[TocItem], figures: list[FigureEntry]) -> None:
        # Table of Contents
        self.add_heading(1, "Table of Contents", page_break_before=False)
        toc_rows: list[list[str]] = []
        for item in toc:
            if item.level == 1:
                toc_rows.append([f"**{item.title}**", "Chapter / Major Section"])
            else:
                toc_rows.append([f"    {item.title}", "Section"])
        self.add_table(
            headers=["Section Title", "Level"],
            rows=toc_rows,
            col_weights=[78.0, 22.0],
        )

        # List of Figures (starts cleanly on next page)
        self.add_heading(1, "List of Figures", page_break_before=True)
        fig_rows: list[list[str]] = []
        for fig in figures:
            clean_title = re.sub(r"^Figure\s+\d+\s*:\s*", "", fig.title, flags=re.IGNORECASE)
            fig_rows.append([f"**Figure {fig.fig_num}**", clean_title, fig.chapter_label])
        self.add_table(
            headers=["Figure", "Diagram Title", "Host Chapter"],
            rows=fig_rows,
            col_weights=[15.0, 68.0, 17.0],
        )

    def render_blocks(self, blocks: list[Block]) -> None:
        for blk in blocks:
            if isinstance(blk, HeadingBlock):
                # Start References or Sign-Off on a new page if they appear as H2 in Ch 6
                low = strip_md_inline(blk.text).lower()
                if blk.level == 2 and (low == "references" or "references" in low[:15]):
                    self.add_heading(1, blk.text, page_break_before=True)
                elif blk.level == 2 and ("sign-off" in low or "sign off" in low):
                    self.add_heading(1, blk.text, page_break_before=True)
                else:
                    self.add_heading(blk.level, blk.text)
            elif isinstance(blk, ParagraphBlock):
                self.add_paragraph(blk.text)
            elif isinstance(blk, FigureBlock):
                self.add_figure(blk)
            elif isinstance(blk, TableBlock):
                self.add_table(blk.headers, blk.rows)
            elif isinstance(blk, CodeBlock):
                self.add_code_block(blk)
            elif isinstance(blk, ListBlock):
                self.add_list(blk)
            elif isinstance(blk, BlockQuoteBlock):
                self.add_blockquote(blk)
            elif isinstance(blk, HorizontalRuleBlock):
                self.body_parts.append(
                    '<w:p><w:pPr><w:pBdr>'
                    '<w:bottom w:val="single" w:sz="6" w:space="1" w:color="CBD5E1"/>'
                    '</w:pBdr><w:spacing w:before="80" w:after="120"/></w:pPr></w:p>'
                )

    def add_back_matter(self, *, need_references: bool, need_signoff: bool) -> None:
        if need_references:
            self.add_heading(1, "References", page_break_before=True)
            for ref in CANONICAL_REFERENCES:
                self.body_parts.append(
                    '<w:p><w:pPr>'
                    '<w:ind w:left="420" w:hanging="420"/>'
                    '<w:spacing w:before="20" w:after="90" w:line="260" w:lineRule="auto"/>'
                    f"</w:pPr>{inline_md_to_ooxml_runs(ref, size_half_pt=20)}</w:p>"
                )
        if need_signoff:
            self.add_heading(1, "Document Sign-Off Summary", page_break_before=not need_references)
            self.add_paragraph(
                "This document has been prepared and submitted for formal first-semester "
                "academic review and sign-off prior to Phase 2 technical implementation."
            )
            self.add_table(
                headers=["Sign-Off Field", "Details"],
                rows=[[k, v] for k, v in SIGN_OFF_ROWS],
                col_weights=[30.0, 70.0],
            )

    # -- OOXML Package Parts --

    def _content_types_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
            '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
            '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
            '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            "</Types>"
        )

    def _root_rels_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>"
        )

    def _document_rels_xml(self) -> str:
        rels = [
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>',
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>',
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>',
            '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>',
        ]
        for rid, media_name, _ in self.media_files:
            rels.append(
                f'<Relationship Id="{rid}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                f'Target="media/{media_name}"/>'
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{''.join(rels)}"
            "</Relationships>"
        )

    def _styles_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:styles xmlns:w="{W_NS}">'
            "<w:docDefaults>"
            "<w:rPrDefault><w:rPr>"
            '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
            '<w:sz w:val="22"/><w:szCs w:val="22"/>'
            '<w:color w:val="1E293B"/>'
            '<w:lang w:val="en-US"/>'
            "</w:rPr></w:rPrDefault>"
            "<w:pPrDefault><w:pPr>"
            '<w:spacing w:before="0" w:after="110" w:line="276" w:lineRule="auto"/>'
            "</w:pPr></w:pPrDefault>"
            "</w:docDefaults>"
            '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
            '<w:name w:val="Normal"/><w:qFormat/>'
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="Heading1">'
            '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
            "<w:pPr>"
            "<w:pageBreakBefore/><w:keepNext/><w:keepLines/>"
            '<w:pBdr><w:bottom w:val="single" w:sz="12" w:space="6" w:color="0D9488"/></w:pBdr>'
            '<w:spacing w:before="160" w:after="180" w:line="260" w:lineRule="auto"/>'
            '<w:outlineLvl w:val="0"/>'
            "</w:pPr>"
            "<w:rPr>"
            '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
            '<w:b/><w:bCs/><w:color w:val="0F172A"/><w:sz w:val="34"/><w:szCs w:val="34"/>'
            "</w:rPr>"
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="Heading2">'
            '<w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
            "<w:pPr>"
            "<w:keepNext/><w:keepLines/>"
            '<w:spacing w:before="220" w:after="100" w:line="260" w:lineRule="auto"/>'
            '<w:outlineLvl w:val="1"/>'
            "</w:pPr>"
            "<w:rPr>"
            '<w:b/><w:bCs/><w:color w:val="0F766E"/><w:sz w:val="28"/><w:szCs w:val="28"/>'
            "</w:rPr>"
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="Heading3">'
            '<w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
            "<w:pPr>"
            "<w:keepNext/><w:keepLines/>"
            '<w:spacing w:before="180" w:after="80" w:line="260" w:lineRule="auto"/>'
            '<w:outlineLvl w:val="2"/>'
            "</w:pPr>"
            "<w:rPr>"
            '<w:b/><w:bCs/><w:color w:val="1E293B"/><w:sz w:val="24"/><w:szCs w:val="24"/>'
            "</w:rPr>"
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="Heading4">'
            '<w:name w:val="heading 4"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
            "<w:pPr>"
            "<w:keepNext/><w:keepLines/>"
            '<w:spacing w:before="140" w:after="60" w:line="260" w:lineRule="auto"/>'
            '<w:outlineLvl w:val="3"/>'
            "</w:pPr>"
            "<w:rPr>"
            '<w:b/><w:bCs/><w:i/><w:iCs/><w:color w:val="334155"/><w:sz w:val="22"/><w:szCs w:val="22"/>'
            "</w:rPr>"
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="ListParagraph">'
            '<w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:qFormat/>'
            '<w:pPr><w:ind w:left="420" w:hanging="240"/></w:pPr>'
            "</w:style>"
            '<w:style w:type="paragraph" w:styleId="Caption">'
            '<w:name w:val="caption"/><w:basedOn w:val="Normal"/><w:qFormat/>'
            '<w:pPr><w:jc w:val="center"/><w:spacing w:before="40" w:after="160"/></w:pPr>'
            '<w:rPr><w:i/><w:iCs/><w:color w:val="475569"/><w:sz w:val="19"/><w:szCs w:val="19"/></w:rPr>'
            "</w:style>"
            "</w:styles>"
        )

    def _numbering_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:numbering xmlns:w="{W_NS}">'
            '<w:abstractNum w:abstractNumId="0">'
            '<w:multiLevelType w:val="hybridMultilevel"/>'
            '<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#x2022;"/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="480" w:hanging="240"/></w:pPr>'
            '<w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:hint="default"/></w:rPr></w:lvl>'
            '<w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#x25E6;"/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="900" w:hanging="240"/></w:pPr>'
            '<w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:hint="default"/></w:rPr></w:lvl>'
            '<w:lvl w:ilvl="2"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#x25AA;"/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="1320" w:hanging="240"/></w:pPr>'
            '<w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:hint="default"/></w:rPr></w:lvl>'
            "</w:abstractNum>"
            '<w:abstractNum w:abstractNumId="1">'
            '<w:multiLevelType w:val="hybridMultilevel"/>'
            '<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="480" w:hanging="280"/></w:pPr></w:lvl>'
            '<w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="lowerLetter"/><w:lvlText w:val="%2."/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="900" w:hanging="280"/></w:pPr></w:lvl>'
            '<w:lvl w:ilvl="2"><w:start w:val="1"/><w:numFmt w:val="lowerRoman"/><w:lvlText w:val="%3."/>'
            '<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="1320" w:hanging="280"/></w:pPr></w:lvl>'
            "</w:abstractNum>"
            '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>'
            '<w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>'
            "</w:numbering>"
        )

    def _header_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:hdr xmlns:w="{W_NS}">'
            "<w:p><w:pPr>"
            '<w:jc w:val="right"/>'
            '<w:pBdr><w:bottom w:val="single" w:sz="4" w:space="4" w:color="CBD5E1"/></w:pBdr>'
            '<w:spacing w:before="0" w:after="60"/>'
            "</w:pPr>"
            f'{make_run_xml("GRADUATION PROJECT BOOK — OWASP Top 10 Vulnerability Scanner (SAD v1.1)", italic=True, color="64748B", size_half_pt=17)}'
            "</w:p>"
            "</w:hdr>"
        )

    def _footer_xml(self) -> str:
        page_field = (
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:t>1</w:t></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="end"/></w:r>'
        )
        numpages_field = (
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:t>1</w:t></w:r>'
            '<w:r><w:rPr><w:color w:val="475569"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr>'
            '<w:fldChar w:fldCharType="end"/></w:r>'
        )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:ftr xmlns:w="{W_NS}">'
            "<w:p><w:pPr>"
            '<w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="CBD5E1"/></w:pBdr>'
            f'<w:tabs><w:tab w:val="right" w:pos="{CONTENT_WIDTH_TWIPS}"/></w:tabs>'
            '<w:spacing w:before="60" w:after="0"/>'
            "</w:pPr>"
            f'{make_run_xml("Department of Cyber Security  |  Academic Year 2026–2027", color="64748B", size_half_pt=17)}'
            "<w:r><w:tab/></w:r>"
            f'{make_run_xml("Page ", color="475569", size_half_pt=17)}'
            f"{page_field}"
            f'{make_run_xml(" of ", color="475569", size_half_pt=17)}'
            f"{numpages_field}"
            "</w:p>"
            "</w:ftr>"
        )

    def _core_props_xml(self) -> str:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{xml_escape(BOOK_TITLE)}</dc:title>"
            f"<dc:subject>{xml_escape(BOOK_HEADER)}</dc:subject>"
            "<dc:creator>Graduation Project Team (Supervised by Dr. Samar)</dc:creator>"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>'
            "</cp:coreProperties>"
        )

    def _app_props_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            "<Application>Graduation Project SAD Book Builder</Application>"
            "</Properties>"
        )

    def _document_xml(self) -> str:
        sect_pr = (
            "<w:sectPr>"
            '<w:headerReference w:type="default" r:id="rId3"/>'
            '<w:footerReference w:type="default" r:id="rId4"/>'
            f'<w:pgSz w:w="{PAGE_WIDTH_TWIPS}" w:h="{PAGE_HEIGHT_TWIPS}"/>'
            f'<w:pgMar w:top="{MARGIN_TWIPS}" w:right="{MARGIN_TWIPS}" '
            f'w:bottom="{MARGIN_TWIPS}" w:left="{MARGIN_TWIPS}" '
            'w:header="720" w:footer="720" w:gutter="0"/>'
            "<w:titlePg/>"
            "</w:sectPr>"
        )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}" '
            f'xmlns:wp="{WP_NS}" xmlns:a="{A_NS}" xmlns:pic="{PIC_NS}" '
            f'xmlns:mc="{MC_NS}">'
            "<w:body>"
            f"{''.join(self.body_parts)}"
            f"{sect_pr}"
            "</w:body>"
            "</w:document>"
        )

    def write(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", self._content_types_xml().encode("utf-8"))
            zf.writestr("_rels/.rels", self._root_rels_xml().encode("utf-8"))
            zf.writestr("docProps/core.xml", self._core_props_xml().encode("utf-8"))
            zf.writestr("docProps/app.xml", self._app_props_xml().encode("utf-8"))
            zf.writestr("word/document.xml", self._document_xml().encode("utf-8"))
            zf.writestr("word/_rels/document.xml.rels", self._document_rels_xml().encode("utf-8"))
            zf.writestr("word/styles.xml", self._styles_xml().encode("utf-8"))
            zf.writestr("word/numbering.xml", self._numbering_xml().encode("utf-8"))
            zf.writestr("word/header1.xml", self._header_xml().encode("utf-8"))
            zf.writestr("word/footer1.xml", self._footer_xml().encode("utf-8"))
            for _, media_name, png_bytes in self.media_files:
                zf.writestr(f"word/media/{media_name}", png_bytes)


# ---------------------------------------------------------------------------
# Strict OOXML Validation
# ---------------------------------------------------------------------------


def validate_docx(docx_path: Path, expected_figures: int = 19) -> dict[str, int]:
    """
    Open the generated .docx archive, XML-parse every .xml and .rels entry,
    and verify every embedded PNG figure and drawing relationship.
    """
    if not docx_path.exists():
        raise FileNotFoundError(f"DOCX output missing: {docx_path}")

    xml_count = 0
    with zipfile.ZipFile(docx_path, "r") as zf:
        names = set(zf.namelist())
        required_parts = {
            "[Content_Types].xml",
            "_rels/.rels",
            "word/document.xml",
            "word/_rels/document.xml.rels",
            "word/styles.xml",
            "word/numbering.xml",
            "word/header1.xml",
            "word/footer1.xml",
        }
        missing = required_parts - names
        if missing:
            raise ValueError(f"Missing required OOXML parts: {sorted(missing)}")

        for name in sorted(names):
            if name.endswith(".xml") or name.endswith(".rels"):
                data = zf.read(name)
                try:
                    ET.fromstring(data)
                except ET.ParseError as exc:
                    raise ValueError(f"XML parse error in {name}: {exc}") from exc
                xml_count += 1

        # Verify image relationships & media bytes
        rels_root = ET.fromstring(zf.read("word/_rels/document.xml.rels"))
        rel_ns = {"pr": "http://schemas.openxmlformats.org/package/2006/relationships"}
        img_rels: dict[str, str] = {}
        for rel in rels_root.findall("pr:Relationship", rel_ns):
            if rel.attrib.get("Type", "").endswith("/image"):
                img_rels[rel.attrib["Id"]] = f"word/{rel.attrib['Target']}"

        media_entries = sorted(n for n in names if n.startswith("word/media/") and n.endswith(".png"))
        if len(media_entries) < expected_figures:
            raise ValueError(
                f"Expected at least {expected_figures} embedded PNGs in word/media/, found {len(media_entries)}"
            )
        for m in media_entries:
            if zf.getinfo(m).file_size <= 0:
                raise ValueError(f"Zero-byte image entry in DOCX: {m}")

        doc_root = ET.fromstring(zf.read("word/document.xml"))
        blips = doc_root.findall(f".//{{{A_NS}}}blip")
        embed_ids = [b.attrib.get(f"{{{R_NS}}}embed", "") for b in blips]
        if len(embed_ids) < expected_figures:
            raise ValueError(
                f"Expected at least {expected_figures} <a:blip r:embed> drawings, found {len(embed_ids)}"
            )
        for rid in embed_ids:
            if rid not in img_rels:
                raise ValueError(f"Broken r:embed reference in document.xml: {rid}")
            if img_rels[rid] not in names:
                raise ValueError(f"Relationship {rid} targets missing media file {img_rels[rid]}")

        docprs = doc_root.findall(f".//{{{WP_NS}}}docPr")
        docpr_ids = [d.attrib.get("id") for d in docprs]
        if len(docpr_ids) != len(set(docpr_ids)):
            raise ValueError("Duplicate wp:docPr IDs detected in word/document.xml")

    return {
        "xml_parts_validated": xml_count,
        "media_pngs": len(media_entries),
        "drawing_embeds": len(embed_ids),
        "file_size_bytes": docx_path.stat().st_size,
    }


def main() -> int:
    chapters, toc, figures, has_references, has_signoff = load_all_chapters()
    if len(figures) < 19:
        print(
            f"[WARN] Expected 19 figures across Chapters 1-6, found {len(figures)}.",
            file=sys.stderr,
        )

    # 1. Build unified Markdown book (docs/SAD_Book.md)
    book_md = build_sad_book_md(chapters, toc, figures, has_references, has_signoff)
    OUTPUT_MD_PATH.write_text(book_md, encoding="utf-8")
    print(f"[OK] Wrote {OUTPUT_MD_PATH} ({OUTPUT_MD_PATH.stat().st_size:,} bytes)")

    # 2. Build formal OOXML Word book (docs/SAD_Book.docx)
    builder = DocxBookBuilder()
    builder.add_cover_page()
    builder.add_front_matter(toc, figures)
    for ch in chapters:
        builder.render_blocks(ch.blocks)
    builder.add_back_matter(
        need_references=not has_references,
        need_signoff=not has_signoff,
    )
    builder.write(OUTPUT_DOCX_PATH)

    # 3. Validate every XML/rels part and every embedded PNG
    stats = validate_docx(OUTPUT_DOCX_PATH, expected_figures=len(figures) if figures else 18)
    print(
        f"[OK] Wrote & validated {OUTPUT_DOCX_PATH} "
        f"({stats['file_size_bytes']:,} bytes, {stats['xml_parts_validated']} XML/rels parts valid, "
        f"{stats['media_pngs']} PNGs embedded, {stats['drawing_embeds']} drawings verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
