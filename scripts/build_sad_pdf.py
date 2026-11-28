#!/usr/bin/env python3
"""
Build the unified Formal Graduation Project Book in PDF format (docs/SAD_Book.pdf).

Generates a 100% offline, print-styled standalone HTML book (embedding all 18
rendered PNG diagrams as base64 data URIs with zero CDN/network dependencies)
and renders it cleanly to A4 PDF via local headless Google Chrome or Microsoft Edge.

Reads:
    - docs/sad_chapters/01_*.md through 06_*.md (sorted)
    - docs/diagrams/images/01_*.png through 18_*.png

Writes:
    - docs/SAD_Book.pdf
"""

from __future__ import annotations

import base64
import html
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure sibling import works regardless of working directory
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_sad_docx import (  # noqa: E402
    BOOK_HEADER,
    BOOK_SUBTITLE,
    BOOK_TITLE,
    CANONICAL_REFERENCES,
    DOCS_DIR,
    EXECUTIVE_ABSTRACT,
    METADATA_ROWS,
    SIGN_OFF_ROWS,
    Block,
    BlockQuoteBlock,
    ChapterData,
    CodeBlock,
    FigureBlock,
    FigureEntry,
    HeadingBlock,
    HorizontalRuleBlock,
    ListBlock,
    ParagraphBlock,
    TableBlock,
    TocItem,
    load_all_chapters,
    make_anchor,
    strip_md_inline,
)

OUTPUT_PDF_PATH = DOCS_DIR / "books" / "pdf" / "SAD_Book.pdf"

BROWSER_CANDIDATES: list[Path] = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]

INLINE_HTML_RE = re.compile(
    r"(`[^`]+`)"
    r"|(\*\*\*[^*]+\*\*\*)"
    r"|(\*\*[^*]+\*\*)"
    r"|(__[^_]+__)"
    r"|(\[[^\]]+\]\([^)]+\))"
    r"|((?<!\*)\*[^*\n]+\*(?!\*))"
)


def inline_md_to_html(text: str) -> str:
    """Convert inline Markdown formatting into clean, escaped HTML."""
    out: list[str] = []
    pos = 0
    for m in INLINE_HTML_RE.finditer(text):
        if m.start() > pos:
            out.append(html.escape(text[pos : m.start()]))
        tok = m.group(0)
        if tok.startswith("`") and tok.endswith("`"):
            out.append(f"<code>{html.escape(tok[1:-1])}</code>")
        elif tok.startswith("***") and tok.endswith("***"):
            out.append(f"<strong><em>{html.escape(tok[3:-3])}</em></strong>")
        elif (tok.startswith("**") and tok.endswith("**")) or (
            tok.startswith("__") and tok.endswith("__")
        ):
            inner = tok[2:-2]
            if "`" in inner:
                out.append(f"<strong>{inline_md_to_html(inner)}</strong>")
            else:
                out.append(f"<strong>{html.escape(inner)}</strong>")
        elif tok.startswith("[") and "](" in tok:
            lm = re.match(r"^\[([^\]]+)\]\(([^)]+)\)$", tok)
            if lm:
                label = html.escape(strip_md_inline(lm.group(1)))
                href = html.escape(lm.group(2), quote=True)
                if href.startswith("#") or href.startswith("http://") or href.startswith("https://"):
                    out.append(f'<a href="{href}">{label}</a>')
                else:
                    out.append(f'<span class="ref-link">{label}</span>')
            else:
                out.append(html.escape(tok))
        elif tok.startswith("*") and tok.endswith("*"):
            out.append(f"<em>{html.escape(tok[1:-1])}</em>")
        pos = m.end()

    if pos < len(text):
        out.append(html.escape(text[pos:]))
    return "".join(out)


def encode_png_data_uri(image_path: Path) -> str:
    if not image_path.exists():
        raise FileNotFoundError(f"Required figure PNG not found: {image_path}")
    raw = image_path.read_bytes()
    if not raw:
        raise ValueError(f"Figure PNG is empty: {image_path}")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:image/png;base64,{b64}"


def render_list_html(lst: ListBlock) -> str:
    tag = "ol" if lst.ordered else "ul"
    items_html: list[str] = []
    for item in lst.items:
        cls = f' class="indent-{item.level}"' if item.level > 0 else ""
        items_html.append(f"<li{cls}>{inline_md_to_html(item.text)}</li>")
    return f"<{tag}>{''.join(items_html)}</{tag}>"


def render_table_html(headers: list[str], rows: list[list[str]], extra_cls: str = "") -> str:
    cls_attr = f' class="{extra_cls}"' if extra_cls else ""
    ths = "".join(f"<th>{inline_md_to_html(h)}</th>" for h in headers)
    trs: list[str] = []
    for row in rows:
        tds = "".join(f"<td>{inline_md_to_html(c)}</td>" for c in row)
        trs.append(f"<tr>{tds}</tr>")
    return (
        f"<table{cls_attr}>"
        f"<thead><tr>{ths}</tr></thead>"
        f"<tbody>{''.join(trs)}</tbody>"
        "</table>"
    )


def render_blocks_html(blocks: list[Block]) -> tuple[str, int]:
    parts: list[str] = []
    img_count = 0

    for blk in blocks:
        if isinstance(blk, HeadingBlock):
            clean_txt = strip_md_inline(blk.text)
            low = clean_txt.lower()
            anchor = make_anchor(clean_txt)
            if blk.level == 1:
                parts.append(
                    f'<h1 id="{anchor}" class="chapter-heading">{inline_md_to_html(blk.text)}</h1>'
                )
            elif blk.level == 2 and (low == "references" or "sign-off" in low):
                parts.append(
                    f'<h1 id="{anchor}" class="chapter-heading">{inline_md_to_html(blk.text)}</h1>'
                )
            else:
                tag = f"h{min(blk.level, 4)}"
                parts.append(f'<{tag} id="{anchor}">{inline_md_to_html(blk.text)}</{tag}>')
        elif isinstance(blk, ParagraphBlock):
            # Style IEEE reference lines with hanging indent
            if re.match(r"^\[\d+\]\s+", blk.text):
                parts.append(f'<p class="reference-item">{inline_md_to_html(blk.text)}</p>')
            else:
                parts.append(f"<p>{inline_md_to_html(blk.text)}</p>")
        elif isinstance(blk, FigureBlock):
            uri = encode_png_data_uri(blk.image_path)
            img_count += 1
            parts.append(
                '<figure class="diagram-figure">'
                f'<img src="{uri}" alt="{html.escape(blk.alt, quote=True)}" />'
                f"<figcaption>{html.escape(blk.caption)}</figcaption>"
                "</figure>"
            )
        elif isinstance(blk, TableBlock):
            extra = "dense-table" if len(blk.headers) >= 5 else ""
            parts.append(render_table_html(blk.headers, blk.rows, extra_cls=extra))
        elif isinstance(blk, CodeBlock):
            lang_badge = (
                f'<div class="code-lang">{html.escape(blk.lang.upper())}</div>'
                if blk.lang
                else ""
            )
            parts.append(
                f'<div class="code-block">{lang_badge}'
                f"<pre><code>{html.escape(blk.code)}</code></pre></div>"
            )
        elif isinstance(blk, ListBlock):
            parts.append(render_list_html(blk))
        elif isinstance(blk, BlockQuoteBlock):
            kind = blk.alert_kind.lower() if blk.alert_kind else "note"
            title_html = (
                f'<div class="callout-title">{html.escape(blk.alert_kind)}</div>'
                if blk.alert_kind
                else ""
            )
            body_html = "".join(f"<p>{inline_md_to_html(ln)}</p>" for ln in blk.lines)
            parts.append(f'<blockquote class="callout callout-{kind}">{title_html}{body_html}</blockquote>')
        elif isinstance(blk, HorizontalRuleBlock):
            parts.append("<hr />")

    return "\n".join(parts), img_count


CSS_STYLES = """
@page {
  size: A4 portrait;
  margin: 20mm 16mm 20mm 16mm;
  @top-right {
    content: "GRADUATION PROJECT BOOK — OWASP Top 10 Vulnerability Scanner (SAD v1.1)";
    font-family: "Segoe UI", Calibri, Arial, sans-serif;
    font-size: 7.5pt;
    font-style: italic;
    color: #64748B;
  }
  @bottom-left {
    content: "Department of Cyber Security  |  Academic Year 2026–2027";
    font-family: "Segoe UI", Calibri, Arial, sans-serif;
    font-size: 7.5pt;
    color: #64748B;
  }
  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: "Segoe UI", Calibri, Arial, sans-serif;
    font-size: 7.5pt;
    font-weight: 600;
    color: #334155;
  }
}

@page :first {
  margin: 14mm 16mm 14mm 16mm;
  @top-right { content: none; }
  @bottom-left { content: none; }
  @bottom-right { content: none; }
}

* {
  box-sizing: border-box;
}

body {
  font-family: "Segoe UI", Calibri, Arial, sans-serif;
  font-size: 10pt;
  line-height: 1.5;
  color: #1E293B;
  margin: 0;
  padding: 0;
  background: #FFFFFF;
}

/* Cover Page */
.cover-page {
  break-after: page;
  page-break-after: always;
}

.cover-banner {
  background: #0F172A;
  color: #FFFFFF;
  padding: 24px 26px 22px 26px;
  border-bottom: 6px solid #0D9488;
  border-radius: 4px;
  text-align: center;
  margin-bottom: 18px;
}

.cover-kicker {
  font-size: 9.5pt;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: #5EEAD4;
  text-transform: uppercase;
  margin-bottom: 8px;
}

.cover-title {
  font-size: 20pt;
  font-weight: 700;
  line-height: 1.25;
  margin: 0 0 8px 0;
  color: #FFFFFF;
}

.cover-subtitle {
  font-size: 11.5pt;
  font-style: italic;
  color: #E2E8F0;
  margin: 0;
}

.section-label {
  font-size: 9.5pt;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: #0F766E;
  text-transform: uppercase;
  margin: 14px 0 6px 0;
}

.abstract-box {
  background: #F8FAFC;
  border: 1px solid #E2E8F0;
  border-left: 4px solid #0D9488;
  padding: 12px 14px;
  font-size: 9.3pt;
  line-height: 1.48;
  color: #334155;
  text-align: justify;
  border-radius: 0 4px 4px 0;
  margin-bottom: 14px;
}

/* Headings */
h1.chapter-heading, h1.front-heading {
  font-size: 16.5pt;
  font-weight: 700;
  color: #0F172A;
  border-bottom: 2.5px solid #0D9488;
  padding-bottom: 5px;
  margin: 0 0 14px 0;
  break-after: avoid;
  page-break-after: avoid;
}

h1.chapter-heading {
  break-before: page;
  page-break-before: always;
}

h1.page-break {
  break-before: page;
  page-break-before: always;
}

h2 {
  font-size: 12.8pt;
  font-weight: 700;
  color: #0F766E;
  margin: 18px 0 8px 0;
  break-after: avoid;
  page-break-after: avoid;
}

h3 {
  font-size: 11pt;
  font-weight: 700;
  color: #1E293B;
  margin: 14px 0 6px 0;
  break-after: avoid;
  page-break-after: avoid;
}

h4 {
  font-size: 10pt;
  font-weight: 700;
  font-style: italic;
  color: #334155;
  margin: 10px 0 4px 0;
  break-after: avoid;
  page-break-after: avoid;
}

p {
  margin: 0 0 8px 0;
  text-align: justify;
  orphans: 3;
  widows: 3;
}

p.reference-item {
  padding-left: 24px;
  text-indent: -24px;
  text-align: left;
  font-size: 9.2pt;
  line-height: 1.45;
  margin-bottom: 7px;
  overflow-wrap: anywhere;
}

a {
  color: #0F766E;
  text-decoration: none;
}

.ref-link {
  color: #0F766E;
  font-weight: 500;
}

code {
  font-family: Consolas, "Courier New", monospace;
  font-size: 8.6pt;
  background: #F1F5F9;
  color: #0F172A;
  padding: 1px 4px;
  border-radius: 3px;
  overflow-wrap: anywhere;
}

/* Lists */
ul, ol {
  margin: 4px 0 10px 0;
  padding-left: 22px;
}

li {
  margin-bottom: 4px;
}

li.indent-1 {
  margin-left: 18px;
}

li.indent-2 {
  margin-left: 36px;
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  margin: 10px 0 14px 0;
  font-size: 8.8pt;
  line-height: 1.38;
  table-layout: auto;
}

table.dense-table {
  font-size: 8.0pt;
  line-height: 1.32;
}

table.meta-table td:first-child,
table.meta-table th:first-child {
  width: 28%;
  font-weight: 600;
}

table.toc-table td.toc-l1 {
  font-weight: 700;
  color: #0F172A;
}

table.toc-table td.toc-l2 {
  padding-left: 22px;
  color: #334155;
}

thead {
  display: table-header-group;
}

tr {
  break-inside: avoid;
  page-break-inside: avoid;
}

th {
  background: #0F172A;
  color: #FFFFFF;
  font-weight: 700;
  text-align: left;
  padding: 6px 8px;
  border: 1px solid #0F172A;
}

td {
  padding: 5.5px 8px;
  border: 1px solid #CBD5E1;
  vertical-align: top;
  overflow-wrap: break-word;
  word-break: break-word;
}

tbody tr:nth-child(even) td {
  background: #F8FAFC;
}

/* Code Blocks */
.code-block {
  background: #F1F5F9;
  border: 1px solid #CBD5E1;
  border-left: 4px solid #0F172A;
  border-radius: 0 4px 4px 0;
  padding: 8px 10px;
  margin: 10px 0 12px 0;
  break-inside: avoid;
  page-break-inside: avoid;
}

.code-lang {
  font-family: Consolas, "Courier New", monospace;
  font-size: 7.5pt;
  font-weight: 700;
  color: #0F766E;
  letter-spacing: 0.05em;
  margin-bottom: 4px;
}

.code-block pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.code-block pre code {
  background: transparent;
  padding: 0;
  font-size: 8.1pt;
  line-height: 1.38;
}

/* Callouts / Blockquotes */
blockquote.callout {
  margin: 10px 0 12px 0;
  padding: 9px 12px;
  background: #F8FAFC;
  border: 1px solid #E2E8F0;
  border-left: 4px solid #0D9488;
  border-radius: 0 4px 4px 0;
  break-inside: avoid;
  page-break-inside: avoid;
}

blockquote.callout-warning {
  background: #FFFBEB;
  border-left-color: #D97706;
}

blockquote.callout-caution {
  background: #FEF2F2;
  border-left-color: #DC2626;
}

.callout-title {
  font-size: 8.5pt;
  font-weight: 700;
  color: #0F766E;
  margin-bottom: 4px;
}

/* Figures */
figure.diagram-figure {
  margin: 12px 0 16px 0;
  padding: 6px;
  text-align: center;
  break-inside: avoid;
  page-break-inside: avoid;
}

figure.diagram-figure img {
  display: block;
  margin: 0 auto;
  max-width: 100%;
  max-height: 205mm;
  width: auto;
  height: auto;
  object-fit: contain;
  border: 1px solid #E2E8F0;
  border-radius: 4px;
  background: #FFFFFF;
  padding: 4px;
}

figure.diagram-figure figcaption {
  margin-top: 7px;
  font-size: 8.8pt;
  font-style: italic;
  color: #475569;
  line-height: 1.4;
  text-align: center;
}

hr {
  border: 0;
  border-top: 1px solid #CBD5E1;
  margin: 14px 0;
}
"""


def build_offline_print_html(
    chapters: list[ChapterData],
    toc: list[TocItem],
    figures: list[FigureEntry],
    has_references: bool,
    has_signoff: bool,
) -> tuple[str, int]:
    """Build complete standalone offline HTML document for PDF rendering."""
    sections: list[str] = []

    # 1. Cover Page
    meta_html = render_table_html(
        headers=["Attribute", "Project Specification"],
        rows=[[k, v] for k, v in METADATA_ROWS],
        extra_cls="meta-table",
    )
    sections.append(
        '<section class="cover-page">'
        '<div class="cover-banner">'
        f'<div class="cover-kicker">{html.escape(BOOK_HEADER)}</div>'
        f'<div class="cover-title">{html.escape(BOOK_TITLE)}</div>'
        f'<div class="cover-subtitle">{html.escape(BOOK_SUBTITLE)}</div>'
        "</div>"
        '<div class="section-label">Executive Abstract</div>'
        f'<div class="abstract-box">{html.escape(EXECUTIVE_ABSTRACT)}</div>'
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

    # 3. List of Figures (Figures 1-18)
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

    # 4. Chapters 1-6
    total_images = 0
    for ch in chapters:
        ch_html, count = render_blocks_html(ch.blocks)
        total_images += count
        sections.append(f'<section class="chapter">{ch_html}</section>')

    # 5. Back Matter fallbacks if not already present in Chapter 6
    if not has_references:
        ref_html = "\n".join(
            f'<p class="reference-item">{inline_md_to_html(r)}</p>' for r in CANONICAL_REFERENCES
        )
        sections.append(
            '<section class="chapter">'
            '<h1 id="references" class="chapter-heading">References</h1>'
            f"{ref_html}"
            "</section>"
        )

    if not has_signoff:
        signoff_tbl = render_table_html(
            headers=["Sign-Off Field", "Details"],
            rows=[[k, v] for k, v in SIGN_OFF_ROWS],
            extra_cls="meta-table",
        )
        sections.append(
            '<section class="chapter">'
            '<h1 id="document-sign-off-summary" class="chapter-heading">Document Sign-Off Summary</h1>'
            "<p>This document has been prepared and submitted for formal first-semester academic "
            "review and sign-off prior to Phase 2 technical implementation.</p>"
            f"{signoff_tbl}"
            "</section>"
        )

    full_html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8" />\n'
        f"<title>{html.escape(BOOK_TITLE)} — Graduation Project Book</title>\n"
        f"<style>{CSS_STYLES}</style>\n"
        "</head>\n"
        "<body>\n"
        f"{''.join(sections)}\n"
        "</body>\n"
        "</html>\n"
    )
    return full_html, total_images


def find_browser() -> Path:
    for candidate in BROWSER_CANDIDATES:
        if candidate.exists():
            return candidate
    for cmd in ("chrome", "google-chrome", "msedge", "chromium"):
        found = shutil.which(cmd)
        if found:
            return Path(found)
    raise FileNotFoundError(
        "No supported headless Chromium browser (Chrome/Edge) found for PDF rendering."
    )


def render_html_to_pdf(html_content: str, output_pdf: Path) -> Path:
    browser = find_browser()
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="sad_pdf_"))
    try:
        html_path = tmp_dir / "sad_book_print.html"
        profile_dir = tmp_dir / "browser_profile"
        html_path.write_text(html_content, encoding="utf-8")

        cmd = [
            str(browser),
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-crash-reporter",
            "--disable-extensions",
            "--disable-background-networking",
            f"--user-data-dir={profile_dir}",
            "--no-pdf-header-footer",
            f"--print-to-pdf={output_pdf}",
            html_path.as_uri(),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 or not output_pdf.exists():
            raise RuntimeError(
                f"Browser PDF export failed (rc={result.returncode}): {result.stderr[:500]}"
            )
        return browser
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def validate_pdf(pdf_path: Path, min_bytes: int = 200_000, min_images: int = 19) -> dict[str, int]:
    """Validate PDF magic header, size, multi-page count, and embedded images."""
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF output missing: {pdf_path}")
    raw = pdf_path.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError(f"Invalid PDF header in {pdf_path}: {raw[:16]!r}")
    if len(raw) < min_bytes:
        raise ValueError(f"PDF unexpectedly small ({len(raw):,} bytes < {min_bytes:,} bytes)")

    # Count /Type /Page objects (not /Type /Pages) and /Subtype /Image XObjects
    page_count = len(re.findall(rb"/Type\s*/Page\b(?!s)", raw))
    image_count = len(re.findall(rb"/Subtype\s*/Image\b", raw))

    if page_count < 10:
        raise ValueError(f"Expected multi-page PDF (>=10 pages), detected {page_count} pages")
    if image_count < min_images:
        raise ValueError(
            f"Expected at least {min_images} embedded images in PDF, detected {image_count}"
        )

    return {
        "file_size_bytes": len(raw),
        "page_count": page_count,
        "embedded_images": image_count,
    }


def main() -> int:
    chapters, toc, figures, has_references, has_signoff = load_all_chapters()
    if len(figures) < 19:
        print(
            f"[WARN] Expected 19 figures across Chapters 1-6, found {len(figures)}.",
            file=sys.stderr,
        )

    html_doc, img_count = build_offline_print_html(
        chapters, toc, figures, has_references, has_signoff
    )
    browser = render_html_to_pdf(html_doc, OUTPUT_PDF_PATH)
    stats = validate_pdf(OUTPUT_PDF_PATH, min_bytes=200_000, min_images=img_count)
    print(
        f"[OK] Rendered & validated {OUTPUT_PDF_PATH} via {browser.name} "
        f"({stats['file_size_bytes']:,} bytes, {stats['page_count']} pages, "
        f"{stats['embedded_images']} embedded images)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
