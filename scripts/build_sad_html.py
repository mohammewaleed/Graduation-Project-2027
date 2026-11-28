#!/usr/bin/env python3
"""
Build the formal, self-contained, 100% offline printable HTML edition of the
Graduation Project Book (Software Architecture Document).

Reads:
    - docs/SAD.md
    - docs/sad_chapters/01_*.md through 06_*.md (sorted)
    - Local diagram PNG/SVG images referenced via Markdown image syntax ![alt](path)

Writes:
    - docs/SAD_Printable.html

Uses Python standard library ONLY (zero third-party pip dependencies).
All referenced local diagram images are embedded as inline base64 data URIs so
the generated HTML renders all 18 figures cleanly offline with zero broken links.
"""

from __future__ import annotations

import base64
import html
import mimetypes
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
MASTER_SAD_PATH = DOCS_DIR / "SAD.md"
CHAPTERS_DIR = DOCS_DIR / "sad_chapters"
OUTPUT_HTML_PATH = DOCS_DIR / "books" / "html" / "SAD_Printable.html"

DOCUMENT_META = {
    "kicker": "GRADUATION PROJECT BOOK – SYSTEM ANALYSIS AND DESIGN",
    "title": "Developing a Lightweight OWASP Top 10 Vulnerability Scanner",
    "subtitle": "Tailored for Web Developers and Student Projects (Developer-Experience Focus)",
    "doc_type": "Software Architecture Document (Formal Edition v1.1)",
    "department": "Department of Cyber Security",
    "methodology": "OWASP Top 10 (2021) & NIST SSDF (SP 800-218)",
    "audience": "Junior Web Developers, University Students, and Small Development Teams",
    "supervisor": "Dr. Samar",
    "team": (
        "Seven Members: Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), "
        "Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), "
        "Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), "
        "Ali Ibrahim Elsayed (235332)"
    ),
    "academic_year": "2026–2027",
    "status": "Proposed System Analysis and Design (Formal Edition v1.1)",
    "current_phase": "First Semester – Requirements Analysis and System Architecture Design",
    "next_phase": "Second Semester – Technical Implementation, Integration, and Testbench Validation",
    "doc_id": "SAD-OWASP-DEVSCAN-2026-V1.1",
}

COVER_ABSTRACT = (
    "This Graduation Project Book presents the formal System Analysis and Design for a "
    "lightweight, self-contained OWASP Top 10 (2021) vulnerability scanner engineered "
    "specifically for student teams and early-stage web developers. Aligned with the NIST "
    "Secure Software Development Framework (SP 800-218), the proposed architecture launches "
    "through a single Docker Compose command, crawls authorized local web applications, "
    "executes 17 curated non-destructive security checks, and maps findings to exact "
    "endpoints and parameters with plain-language explanations and copy-ready multi-stack "
    "remediation snippets."
)


@dataclass
class TocEntry:
    level: int
    text: str
    slug: str
    section_kind: str  # "frontmatter" | "chapter"


@dataclass
class FigureEntry:
    number: int
    title: str
    anchor: str
    source_rel: str


class SlugRegistry:
    """Generates unique, HTML-safe anchor IDs across the entire document."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def make(self, text: str, prefix: str = "") -> str:
        plain = re.sub(r"`([^`]*)`", r"\1", text)
        plain = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", plain)
        plain = re.sub(r"[*_~]", "", plain)
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", plain.strip().lower()).strip("-")
        if not slug:
            slug = "section"
        if prefix:
            slug = f"{prefix}-{slug}"
        count = self._counts.get(slug, 0) + 1
        self._counts[slug] = count
        return slug if count == 1 else f"{slug}-{count}"


def escape_mermaid_html(code: str) -> str:
    """Prepare Mermaid source safely without double-escaping arrows or quotes."""
    cleaned = code.replace("\r\n", "\n").strip("\n")
    return re.sub(r"<(?=[A-Za-z/!?])", "&lt;", cleaned)


def encode_image_data_uri(image_path: Path) -> str | None:
    """Read a local image file and return a base64 data URI for 100% offline HTML."""
    if not image_path.is_file():
        return None
    mime, _ = mimetypes.guess_type(str(image_path))
    if not mime:
        ext = image_path.suffix.lower()
        mime = {
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
        }.get(ext, "application/octet-stream")
    raw = image_path.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:{mime};base64,{b64}"


class MarkdownConverter:
    """Stdlib-only GFM-to-HTML converter with offline image embedding and figure tracking."""

    ALERT_TYPES = {
        "NOTE": ("callout-note", "Note"),
        "TIP": ("callout-tip", "Tip"),
        "IMPORTANT": ("callout-important", "Important"),
        "WARNING": ("callout-warning", "Warning"),
        "CAUTION": ("callout-caution", "Caution"),
    }

    STANDALONE_IMG_RE = re.compile(r"^!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)\s*$")

    def __init__(
        self,
        slugs: SlugRegistry,
        chapter_anchor_map: dict[str, str],
    ) -> None:
        self.slugs = slugs
        self.chapter_anchor_map = chapter_anchor_map
        self.figure_anchor_map: dict[str, str] = {}
        self.toc: list[TocEntry] = []
        self.figures: list[FigureEntry] = []
        self.mermaid_count: int = 0
        self.embedded_image_count: int = 0
        self.missing_images: list[str] = []
        self._current_base_dir: Path = DOCS_DIR

    def convert(
        self,
        markdown_text: str,
        *,
        base_dir: Path,
        section_kind: str,
        slug_prefix: str = "",
        collect_toc: bool = True,
    ) -> str:
        self._current_base_dir = base_dir
        lines = markdown_text.replace("\r\n", "\n").split("\n")
        return self._parse_blocks(
            lines,
            section_kind=section_kind,
            slug_prefix=slug_prefix,
            collect_toc=collect_toc,
        )

    def _resolve_local_image(self, raw_src: str) -> Path | None:
        if raw_src.startswith(("http://", "https://", "data:")):
            return None
        clean = raw_src.split("#", 1)[0].split("?", 1)[0]
        candidate = (self._current_base_dir / clean).resolve()
        if candidate.is_file():
            return candidate
        fallback = (DOCS_DIR / clean.lstrip("./").replace("../", "")).resolve()
        if fallback.is_file():
            return fallback
        return None

    def _render_figure_block(self, alt_text: str, raw_src: str, caption_md: str | None) -> str:
        resolved = self._resolve_local_image(raw_src)
        fig_num_match = re.match(r"^Figure\s+(\d+)\s*[:\-–—]?\s*(.*)$", alt_text.strip(), re.I)
        if fig_num_match:
            fig_num = int(fig_num_match.group(1))
            fig_title = alt_text.strip()
        else:
            fig_num = len(self.figures) + 1
            fig_title = alt_text.strip() or f"Figure {fig_num}"

        anchor = f"figure-{fig_num:02d}"
        data_uri = encode_image_data_uri(resolved) if resolved else None

        if data_uri is not None:
            self.embedded_image_count += 1
            img_src_attr = data_uri
            try:
                rel_key = resolved.relative_to(DOCS_DIR).as_posix()
            except ValueError:
                rel_key = raw_src
            self.figure_anchor_map[rel_key] = anchor
            self.figure_anchor_map[resolved.name] = anchor
        else:
            self.missing_images.append(raw_src)
            img_src_attr = html.escape(raw_src, quote=True)
            rel_key = raw_src

        self.figures.append(
            FigureEntry(
                number=fig_num,
                title=fig_title,
                anchor=anchor,
                source_rel=rel_key,
            )
        )

        if caption_md:
            caption_html = self._render_inline(caption_md.strip())
        else:
            caption_html = f"<em>{html.escape(fig_title)}</em>"

        return (
            f'<figure class="diagram-figure" id="{anchor}">\n'
            f'  <img class="diagram-img" src="{img_src_attr}" alt="{html.escape(fig_title, quote=True)}" />\n'
            f'  <figcaption class="diagram-caption">{caption_html}</figcaption>\n'
            f"</figure>"
        )

    def _parse_blocks(
        self,
        lines: list[str],
        *,
        section_kind: str,
        slug_prefix: str,
        collect_toc: bool,
    ) -> str:
        out: list[str] = []
        i = 0
        n = len(lines)

        while i < n:
            line = lines[i]
            stripped = line.strip()

            # Blank line
            if not stripped:
                i += 1
                continue

            # Fenced code block (``` or ~~~)
            fence_match = re.match(r"^\s*(`{3,}|~{3,})\s*([^\s`~]*)\s*$", line)
            if fence_match:
                fence_chars = fence_match.group(1)
                fence_char = fence_chars[0]
                fence_len = len(fence_chars)
                lang = fence_match.group(2).strip().lower()
                i += 1
                code_lines: list[str] = []
                close_re = re.compile(rf"^\s*{re.escape(fence_char)}{{{fence_len},}}\s*$")
                while i < n and not close_re.match(lines[i]):
                    code_lines.append(lines[i])
                    i += 1
                if i < n:
                    i += 1
                code_body = "\n".join(code_lines)
                if lang == "mermaid":
                    self.mermaid_count += 1
                    safe_mermaid = escape_mermaid_html(code_body)
                    out.append(
                        f'<figure class="diagram-figure" data-diagram-index="{self.mermaid_count}">\n'
                        f'  <div class="mermaid">\n{safe_mermaid}\n  </div>\n'
                        f'  <figcaption class="diagram-caption">Diagram {self.mermaid_count}</figcaption>\n'
                        f"</figure>"
                    )
                else:
                    display_lang = html.escape(lang.upper() if lang else "TEXT")
                    css_lang = html.escape(lang if lang else "plaintext")
                    escaped_code = html.escape(code_body)
                    out.append(
                        f'<div class="code-block">\n'
                        f'  <div class="code-header"><span>{display_lang}</span></div>\n'
                        f'  <pre><code class="language-{css_lang}">{escaped_code}</code></pre>\n'
                        f"</div>"
                    )
                continue

            # Standalone Markdown Figure Image: ![Figure N: ...](../diagrams/images/NN_*.png)
            img_match = self.STANDALONE_IMG_RE.match(stripped)
            if img_match:
                alt_text = img_match.group(1)
                raw_src = img_match.group(2)
                caption_md: str | None = None
                # Look ahead for an adjacent italic caption line (*Figure N: ...* or _Figure N: ..._)
                j = i + 1
                while j < n and not lines[j].strip():
                    j += 1
                if j < n:
                    nxt = lines[j].strip()
                    if (
                        (nxt.startswith("*") and nxt.endswith("*") and not nxt.startswith("**"))
                        or (nxt.startswith("_") and nxt.endswith("_") and not nxt.startswith("__"))
                    ) and re.search(r"(figure\s+\d+|source|diagram)", nxt, re.I):
                        caption_md = nxt
                        i = j + 1
                    else:
                        i += 1
                else:
                    i += 1
                out.append(self._render_figure_block(alt_text, raw_src, caption_md))
                continue

            # Horizontal rule
            if re.match(r"^\s*(?:[-*_]\s*){3,}$", line):
                out.append("<hr />")
                i += 1
                continue

            # ATX Heading (# through ######)
            heading_match = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
            if heading_match:
                level = len(heading_match.group(1))
                raw_text = heading_match.group(2).strip()
                slug = self.slugs.make(raw_text, prefix=slug_prefix)
                rendered_text = self._render_inline(raw_text)
                if collect_toc and (
                    (section_kind == "chapter" and level in (1, 2))
                    or (section_kind == "frontmatter" and level == 2)
                ):
                    plain_label = self._strip_markdown_inline(raw_text)
                    self.toc.append(
                        TocEntry(
                            level=level,
                            text=plain_label,
                            slug=slug,
                            section_kind=section_kind,
                        )
                    )
                out.append(f'<h{level} id="{slug}">{rendered_text}</h{level}>')
                i += 1
                continue

            # Blockquote or GitHub Alert (> ...)
            if re.match(r"^\s*>\s?", line):
                bq_lines: list[str] = []
                while i < n and (
                    re.match(r"^\s*>\s?", lines[i])
                    or (lines[i].strip() != "" and bq_lines and not self._is_block_starter(lines[i]))
                ):
                    bq_lines.append(re.sub(r"^\s*>\s?", "", lines[i]))
                    i += 1
                alert_match = (
                    re.match(r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*)$", bq_lines[0].strip(), re.I)
                    if bq_lines
                    else None
                )
                if alert_match:
                    alert_key = alert_match.group(1).upper()
                    css_class, label = self.ALERT_TYPES[alert_key]
                    rest_first = alert_match.group(2).strip()
                    inner_lines = ([rest_first] if rest_first else []) + bq_lines[1:]
                    inner_html = self._parse_blocks(
                        inner_lines,
                        section_kind=section_kind,
                        slug_prefix=slug_prefix,
                        collect_toc=False,
                    )
                    out.append(
                        f'<div class="callout {css_class}">\n'
                        f'  <div class="callout-title">{label}</div>\n'
                        f'  <div class="callout-body">{inner_html}</div>\n'
                        f"</div>"
                    )
                else:
                    inner_html = self._parse_blocks(
                        bq_lines,
                        section_kind=section_kind,
                        slug_prefix=slug_prefix,
                        collect_toc=False,
                    )
                    out.append(f"<blockquote>\n{inner_html}\n</blockquote>")
                continue

            # GFM Table (header row + separator row)
            if i + 1 < n and self._is_table_header(line, lines[i + 1]):
                header_cells = self._split_table_row(line)
                alignments = self._parse_table_alignments(lines[i + 1], len(header_cells))
                i += 2
                body_rows: list[list[str]] = []
                while i < n and lines[i].strip() and "|" in lines[i]:
                    if re.match(r"^\s*(`{3,}|~{3,})", lines[i]):
                        break
                    body_rows.append(self._split_table_row(lines[i]))
                    i += 1
                out.append(self._render_table(header_cells, alignments, body_rows))
                continue

            # Ordered or unordered list
            if self._is_list_item(line):
                list_html, i = self._parse_list(lines, i)
                out.append(list_html)
                continue

            # Paragraph
            para_lines: list[str] = []
            while i < n and lines[i].strip():
                if para_lines and self._is_block_starter(lines[i]):
                    break
                if para_lines and i + 1 < n and self._is_table_header(lines[i], lines[i + 1]):
                    break
                if para_lines and self.STANDALONE_IMG_RE.match(lines[i].strip()):
                    break
                para_lines.append(lines[i])
                i += 1
            para_html = self._render_paragraph(para_lines)
            out.append(f"<p>{para_html}</p>")

        return "\n".join(out)

    @classmethod
    def _is_block_starter(cls, line: str) -> bool:
        if re.match(r"^\s*(`{3,}|~{3,})", line):
            return True
        if re.match(r"^#{1,6}\s+", line):
            return True
        if re.match(r"^\s*>\s?", line):
            return True
        if re.match(r"^\s*(?:[-*_]\s*){3,}$", line):
            return True
        if cls._is_list_item(line):
            return True
        if cls.STANDALONE_IMG_RE.match(line.strip()):
            return True
        return False

    @staticmethod
    def _is_list_item(line: str) -> bool:
        return bool(re.match(r"^(\s*)(?:[-*+]|\d+[.)])\s+\S", line))

    @staticmethod
    def _list_item_info(line: str) -> tuple[int, str, str] | None:
        m = re.match(r"^(\s*)(?:([-*+])|(\d+)[.)])\s+(.*)$", line)
        if not m:
            return None
        indent = len(m.group(1).replace("\t", "    "))
        list_type = "ul" if m.group(2) else "ol"
        content = m.group(4)
        return indent, list_type, content

    def _parse_list(self, lines: list[str], start: int) -> tuple[str, int]:
        n = len(lines)
        first = self._list_item_info(lines[start])
        assert first is not None
        base_indent, list_type, _ = first
        items: list[str] = []
        i = start

        while i < n:
            if not lines[i].strip():
                j = i + 1
                while j < n and not lines[j].strip():
                    j += 1
                if j < n:
                    nxt = self._list_item_info(lines[j])
                    if nxt and nxt[0] >= base_indent and (nxt[0] > base_indent or nxt[1] == list_type):
                        i = j
                        continue
                break

            info = self._list_item_info(lines[i])
            if not info:
                break
            indent, item_type, content = info
            if indent < base_indent or (indent == base_indent and item_type != list_type):
                break
            if indent > base_indent:
                nested_html, i = self._parse_list(lines, i)
                if items:
                    items[-1] = f"{items[-1]}\n{nested_html}"
                else:
                    items.append(nested_html)
                continue

            item_parts = [content.strip()]
            i += 1
            while i < n:
                if not lines[i].strip():
                    break
                next_info = self._list_item_info(lines[i])
                if next_info:
                    if next_info[0] > base_indent:
                        nested_html, i = self._parse_list(lines, i)
                        item_parts.append(f"\n{nested_html}")
                        continue
                    break
                if self._is_block_starter(lines[i]):
                    break
                item_parts.append(" " + lines[i].strip())
                i += 1

            rendered_chunks: list[str] = []
            text_buf: list[str] = []
            for part in item_parts:
                if part.startswith("\n<ul") or part.startswith("\n<ol"):
                    if text_buf:
                        rendered_chunks.append(self._render_inline("".join(text_buf).strip()))
                        text_buf = []
                    rendered_chunks.append(part)
                else:
                    text_buf.append(part)
            if text_buf:
                rendered_chunks.append(self._render_inline("".join(text_buf).strip()))
            items.append("".join(rendered_chunks))

        li_html = "\n".join(f"  <li>{item}</li>" for item in items)
        return f"<{list_type}>\n{li_html}\n</{list_type}>", i

    @staticmethod
    def _is_table_header(header_line: str, sep_line: str) -> bool:
        if "|" not in header_line or "|" not in sep_line:
            return False
        sep = sep_line.strip()
        if sep.startswith("|"):
            sep = sep[1:]
        if sep.endswith("|"):
            sep = sep[:-1]
        cells = [c.strip() for c in sep.split("|")]
        if not cells:
            return False
        return all(bool(re.match(r"^:?-{2,}:?$", c)) for c in cells)

    @staticmethod
    def _split_table_row(row_line: str) -> list[str]:
        s = row_line.strip()
        if s.startswith("|"):
            s = s[1:]
        if s.endswith("|") and not s.endswith(r"\|"):
            s = s[:-1]
        parts = re.split(r"(?<!\\)\|", s)
        return [p.replace(r"\|", "|").strip() for p in parts]

    @staticmethod
    def _parse_table_alignments(sep_line: str, col_count: int) -> list[str]:
        raw = MarkdownConverter._split_table_row(sep_line)
        aligns: list[str] = []
        for idx in range(col_count):
            token = raw[idx].strip() if idx < len(raw) else "---"
            left = token.startswith(":")
            right = token.endswith(":")
            if left and right:
                aligns.append("center")
            elif right:
                aligns.append("right")
            else:
                aligns.append("left")
        return aligns

    def _render_table(
        self,
        headers: list[str],
        alignments: list[str],
        rows: list[list[str]],
    ) -> str:
        col_count = len(headers)
        ths = []
        for idx, h in enumerate(headers):
            align = alignments[idx] if idx < len(alignments) else "left"
            ths.append(f'<th style="text-align:{align}">{self._render_inline(h)}</th>')
        thead = "<thead><tr>" + "".join(ths) + "</tr></thead>"

        body_trs = []
        for row in rows:
            tds = []
            for idx in range(col_count):
                cell = row[idx] if idx < len(row) else ""
                align = alignments[idx] if idx < len(alignments) else "left"
                tds.append(f'<td style="text-align:{align}">{self._render_inline(cell)}</td>')
            body_trs.append("<tr>" + "".join(tds) + "</tr>")
        tbody = "<tbody>\n" + "\n".join(body_trs) + "\n</tbody>"
        return f'<div class="table-wrap">\n<table>\n{thead}\n{tbody}\n</table>\n</div>'

    def _render_paragraph(self, lines: list[str]) -> str:
        parts: list[str] = []
        for idx, line in enumerate(lines):
            hard_break = line.endswith("  ")
            rendered = self._render_inline(line.strip())
            if idx < len(lines) - 1:
                parts.append(rendered + ("<br />" if hard_break else " "))
            else:
                parts.append(rendered)
        return "".join(parts)

    def _render_inline(self, text: str) -> str:
        # 1. Extract inline code spans first
        code_tokens: dict[str, str] = {}

        def _replace_code(match: re.Match[str]) -> str:
            key = f"\x00CODE{len(code_tokens)}\x00"
            code_tokens[key] = f"<code>{html.escape(match.group(1))}</code>"
            return key

        text = re.sub(r"`([^`\n]+)`", _replace_code, text)

        # 2. Extract inline images ![alt](url)
        img_tokens: dict[str, str] = {}

        def _replace_img(match: re.Match[str]) -> str:
            alt = match.group(1)
            src = match.group(2).strip()
            resolved = self._resolve_local_image(src)
            data_uri = encode_image_data_uri(resolved) if resolved else None
            if data_uri is not None:
                self.embedded_image_count += 1
                final_src = data_uri
            else:
                final_src = html.escape(src, quote=True)
            key = f"\x00IMG{len(img_tokens)}\x00"
            img_tokens[key] = (
                f'<img class="inline-img" src="{final_src}" '
                f'alt="{html.escape(alt, quote=True)}" />'
            )
            return key

        text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", _replace_img, text)

        # 3. Extract markdown links [label](url)
        link_tokens: dict[str, str] = {}

        def _replace_link(match: re.Match[str]) -> str:
            label = match.group(1)
            href = match.group(2).strip()
            rewritten_href = self._rewrite_href(href)
            rendered_label = self._format_emphasis(html.escape(label))
            for k, v in code_tokens.items():
                rendered_label = rendered_label.replace(k, v)
            target_attr = (
                ' target="_blank" rel="noopener noreferrer"'
                if rewritten_href.startswith(("http://", "https://"))
                else ""
            )
            key = f"\x00LINK{len(link_tokens)}\x00"
            link_tokens[key] = (
                f'<a href="{html.escape(rewritten_href, quote=True)}"{target_attr}>'
                f"{rendered_label}</a>"
            )
            return key

        text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _replace_link, text)

        # 4. Escape remaining HTML safely
        escaped = html.escape(text)

        # 5. Bold, italic, strikethrough
        escaped = self._format_emphasis(escaped)

        # 6. Restore protected tokens
        for key, val in link_tokens.items():
            escaped = escaped.replace(key, val)
        for key, val in img_tokens.items():
            escaped = escaped.replace(key, val)
        for key, val in code_tokens.items():
            escaped = escaped.replace(key, val)

        return escaped

    def _rewrite_href(self, href: str) -> str:
        normalized = href.replace("\\", "/").lstrip("./")
        if normalized in self.chapter_anchor_map:
            return f"#{self.chapter_anchor_map[normalized]}"
        base = normalized.split("/")[-1]
        if base in self.chapter_anchor_map:
            return f"#{self.chapter_anchor_map[base]}"
        if normalized in self.figure_anchor_map:
            return f"#{self.figure_anchor_map[normalized]}"
        if base in self.figure_anchor_map:
            return f"#{self.figure_anchor_map[base]}"
        return href

    @staticmethod
    def _format_emphasis(text: str) -> str:
        text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<!\w)__(.+?)__(?!\w)", r"<strong>\1</strong>", text)
        text = re.sub(r"~~(.+?)~~", r"<del>\1</del>", text)
        text = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<em>\1</em>", text)
        text = re.sub(r"(?<!\w)_(?!\s)(.+?)(?<!\s)_(?!\w)", r"<em>\1</em>", text)
        return text

    @staticmethod
    def _strip_markdown_inline(text: str) -> str:
        s = re.sub(r"`([^`]*)`", r"\1", text)
        s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
        s = re.sub(r"[*_~]", "", s)
        return s.strip()


def build_toc_html(entries: list[TocEntry]) -> str:
    items: list[str] = []
    for entry in entries:
        if entry.section_kind == "frontmatter":
            css = "toc-item toc-frontmatter"
        elif entry.level == 1:
            css = "toc-item toc-chapter"
        else:
            css = "toc-item toc-section"
        items.append(
            f'  <li class="{css}"><a href="#{html.escape(entry.slug, quote=True)}">'
            f"{html.escape(entry.text)}</a></li>"
        )
    return '<ul class="toc-list">\n' + "\n".join(items) + "\n</ul>"


def build_lof_html(figures: list[FigureEntry]) -> str:
    if not figures:
        return "<p>No figures indexed.</p>"
    items: list[str] = []
    for fig in sorted(figures, key=lambda f: f.number):
        items.append(
            f'  <li class="lof-item"><a href="#{html.escape(fig.anchor, quote=True)}">'
            f"{html.escape(fig.title)}</a></li>"
        )
    return '<ul class="lof-list">\n' + "\n".join(items) + "\n</ul>"


def build_html_document(
    *,
    frontmatter_html: str,
    chapters_html: list[tuple[str, str, str]],
    toc_html: str,
    lof_html: str,
    figure_count: int,
    mermaid_count: int,
    chapter_count: int,
) -> str:
    chapter_sections = []
    for anchor_id, filename, body in chapters_html:
        chapter_sections.append(
            f'<section class="sad-chapter" id="{html.escape(anchor_id, quote=True)}" '
            f'data-source="{html.escape(filename, quote=True)}">\n{body}\n</section>'
        )
    chapters_joined = "\n\n".join(chapter_sections)

    mermaid_scripts = ""
    if mermaid_count > 0:
        mermaid_scripts = """
  <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
  <script>
    if (typeof mermaid !== "undefined") {
      mermaid.initialize({ startOnLoad: true, theme: "neutral", securityLevel: "loose" });
    }
  </script>"""

    status_badge_text = (
        f"All {figure_count} figures embedded offline"
        if figure_count > 0
        else f"{mermaid_count} Mermaid diagrams"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(DOCUMENT_META["kicker"])} — {html.escape(DOCUMENT_META["title"])}</title>
  <style>
    :root {{
      --navy: #0f172a;
      --slate: #1e293b;
      --muted: #475569;
      --subtle: #64748b;
      --teal: #0f766e;
      --teal-soft: #f0fdfa;
      --teal-border: #99f6e4;
      --bg: #eef2f6;
      --paper: #ffffff;
      --border: #cbd5e1;
      --border-soft: #e2e8f0;
      --code-bg: #f8fafc;
      --code-header: #e2e8f0;
      --font-sans: "Segoe UI", Calibri, -apple-system, BlinkMacSystemFont, "Inter", Roboto, Arial, sans-serif;
      --font-serif: Georgia, Cambria, "Times New Roman", serif;
      --font-mono: "Cascadia Code", Consolas, "Courier New", monospace;
    }}

    * {{
      box-sizing: border-box;
    }}

    html {{
      scroll-behavior: smooth;
    }}

    body {{
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--navy);
      font-family: var(--font-sans);
      font-size: 10.5pt;
      line-height: 1.65;
      -webkit-font-smoothing: antialiased;
    }}

    /* Interactive Toolbar (hidden in print) */
    .toolbar {{
      position: sticky;
      top: 0;
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.75rem 1.5rem;
      background: var(--navy);
      color: #f8fafc;
      border-bottom: 3px solid var(--teal);
      box-shadow: 0 2px 10px rgba(15, 23, 42, 0.25);
    }}

    .toolbar-brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 600;
      font-size: 0.92rem;
    }}

    .toolbar-badge {{
      display: inline-block;
      padding: 0.16rem 0.6rem;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.35);
      color: #5eead4;
      font-size: 0.74rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}

    .toolbar-actions {{
      display: flex;
      align-items: center;
      gap: 0.65rem;
      flex-wrap: wrap;
    }}

    .status-pill {{
      font-size: 0.79rem;
      padding: 0.28rem 0.68rem;
      border-radius: 6px;
      background: rgba(16, 185, 129, 0.2);
      color: #6ee7b7;
      font-weight: 600;
    }}

    .btn-nav {{
      color: #cbd5e1;
      text-decoration: none;
      font-size: 0.82rem;
      padding: 0.36rem 0.68rem;
      border: 1px solid rgba(148, 163, 184, 0.35);
      border-radius: 6px;
    }}

    .btn-nav:hover {{
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
    }}

    .btn-print {{
      appearance: none;
      border: 0;
      border-radius: 6px;
      padding: 0.44rem 1rem;
      background: var(--teal);
      color: #ffffff;
      font-family: var(--font-sans);
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
    }}

    .btn-print:hover {{
      background: #115e59;
    }}

    /* Main Academic Book Sheet */
    .document-sheet {{
      max-width: 980px;
      margin: 2rem auto 4rem auto;
      background: var(--paper);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 10px 32px rgba(15, 23, 42, 0.08);
      padding: 3.25rem 3.75rem;
    }}

    /* Formal Cover Page */
    .cover-page {{
      min-height: 82vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 0.5rem 0 2rem 0;
      border-bottom: 2px solid var(--border-soft);
      margin-bottom: 2.5rem;
    }}

    .cover-banner {{
      background: var(--navy);
      color: #ffffff;
      padding: 1.75rem 2rem;
      border-radius: 6px;
      border-bottom: 5px solid var(--teal);
    }}

    .cover-kicker {{
      font-size: 0.82rem;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: #5eead4;
      margin-bottom: 0.65rem;
    }}

    .cover-title {{
      font-family: var(--font-serif);
      font-size: 2.15rem;
      line-height: 1.24;
      font-weight: 700;
      color: #ffffff;
      margin: 0 0 0.65rem 0;
      border: 0;
      padding: 0;
    }}

    .cover-subtitle {{
      font-size: 1.12rem;
      font-style: italic;
      color: #cbd5e1;
      margin: 0;
    }}

    .cover-abstract {{
      margin: 1.65rem 0;
      padding: 1.1rem 1.3rem;
      background: var(--teal-soft);
      border-left: 4px solid var(--teal);
      border-radius: 0 6px 6px 0;
      font-size: 0.96rem;
      color: var(--slate);
    }}

    .cover-abstract-label {{
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--teal);
      margin-bottom: 0.35rem;
    }}

    .cover-summary-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.9rem;
      margin: 1.25rem 0 1.5rem 0;
    }}

    .cover-stat {{
      background: #f8fafc;
      border: 1px solid var(--border-soft);
      border-top: 3px solid var(--teal);
      border-radius: 6px;
      padding: 0.85rem 1rem;
    }}

    .cover-stat-value {{
      font-size: 1.35rem;
      font-weight: 700;
      color: var(--navy);
      line-height: 1.2;
    }}

    .cover-stat-label {{
      font-size: 0.8rem;
      color: var(--subtle);
      margin-top: 0.18rem;
    }}

    .cover-meta-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.89rem;
    }}

    .cover-meta-table th,
    .cover-meta-table td {{
      padding: 0.55rem 0.85rem;
      border: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}

    .cover-meta-table th {{
      width: 27%;
      background: #f1f5f9;
      color: var(--navy);
      font-weight: 700;
    }}

    /* Table of Contents & List of Figures */
    .toc-section,
    .lof-section {{
      padding: 0.75rem 0 1.75rem 0;
      border-bottom: 2px solid var(--border-soft);
      margin-bottom: 2.25rem;
    }}

    .nav-heading {{
      font-family: var(--font-serif);
      font-size: 1.55rem;
      color: var(--navy);
      border-bottom: 2.5px solid var(--teal);
      padding-bottom: 0.38rem;
      margin: 0 0 1.15rem 0;
    }}

    .toc-list,
    .lof-list {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}

    .toc-item,
    .lof-item {{
      margin: 0.24rem 0;
    }}

    .toc-item a,
    .lof-item a {{
      color: var(--slate);
      text-decoration: none;
      display: inline-block;
      padding: 0.1rem 0;
    }}

    .toc-item a:hover,
    .lof-item a:hover {{
      color: var(--teal);
      text-decoration: underline;
    }}

    .toc-frontmatter {{
      font-weight: 600;
      color: var(--muted);
      padding-left: 0.25rem;
    }}

    .toc-chapter {{
      margin-top: 0.68rem;
      font-weight: 700;
      font-size: 0.99rem;
      border-bottom: 1px dotted var(--border);
      padding-bottom: 0.16rem;
    }}

    .toc-chapter a {{
      color: var(--navy);
    }}

    .toc-section {{
      border-bottom: 2px solid var(--border-soft);
    }}

    .toc-item.toc-section {{
      padding-left: 1.45rem;
      font-size: 0.91rem;
      border-bottom: 0;
      margin-bottom: 0.2rem;
    }}

    .lof-item {{
      padding: 0.22rem 0;
      border-bottom: 1px dotted var(--border-soft);
      font-size: 0.92rem;
    }}

    /* Body Typography */
    .sad-frontmatter,
    .sad-chapter {{
      margin-bottom: 2.75rem;
    }}

    h1 {{
      font-family: var(--font-serif);
      font-size: 1.8rem;
      line-height: 1.25;
      color: var(--navy);
      border-bottom: 2.5px solid var(--teal);
      padding-bottom: 0.42rem;
      margin: 0 0 1.2rem 0;
    }}

    h2 {{
      font-family: var(--font-serif);
      font-size: 1.32rem;
      line-height: 1.3;
      color: var(--teal);
      border-bottom: 1px solid var(--border-soft);
      padding-bottom: 0.25rem;
      margin: 1.9rem 0 0.85rem 0;
    }}

    h3 {{
      font-size: 1.08rem;
      line-height: 1.35;
      color: var(--slate);
      margin: 1.45rem 0 0.55rem 0;
    }}

    h4 {{
      font-size: 0.98rem;
      line-height: 1.35;
      color: var(--muted);
      margin: 1.1rem 0 0.4rem 0;
    }}

    p {{
      margin: 0 0 0.88rem 0;
      text-align: justify;
    }}

    a {{
      color: var(--teal);
    }}

    ul, ol {{
      margin: 0 0 1rem 0;
      padding-left: 1.6rem;
    }}

    li {{
      margin-bottom: 0.3rem;
    }}

    hr {{
      border: 0;
      border-top: 1px solid var(--border-soft);
      margin: 1.65rem 0;
    }}

    code {{
      font-family: var(--font-mono);
      font-size: 0.86em;
      background: #f1f5f9;
      color: var(--navy);
      padding: 0.1rem 0.34rem;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
    }}

    /* Code Blocks */
    .code-block {{
      margin: 1.1rem 0 1.3rem 0;
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      background: var(--code-bg);
    }}

    .code-header {{
      background: var(--code-header);
      color: #334155;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      padding: 0.28rem 0.85rem;
      border-bottom: 1px solid var(--border);
    }}

    .code-block pre {{
      margin: 0;
      padding: 0.85rem 1rem;
      overflow-x: auto;
      line-height: 1.45;
      font-size: 0.83rem;
    }}

    .code-block code {{
      background: transparent;
      border: 0;
      padding: 0;
      font-size: inherit;
      white-space: pre;
    }}

    /* Tables */
    .table-wrap {{
      width: 100%;
      overflow-x: auto;
      margin: 1.05rem 0 1.35rem 0;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
      line-height: 1.45;
    }}

    thead th {{
      background: var(--navy);
      color: #ffffff;
      font-weight: 600;
      padding: 0.56rem 0.72rem;
      border: 1px solid var(--navy);
    }}

    tbody td {{
      padding: 0.52rem 0.72rem;
      border: 1px solid var(--border);
      vertical-align: top;
    }}

    tbody tr:nth-child(even) {{
      background: #f8fafc;
    }}

    /* Blockquotes & Callouts */
    blockquote {{
      margin: 1.05rem 0 1.25rem 0;
      padding: 0.72rem 1.05rem;
      border-left: 4px solid var(--teal);
      background: #f8fafc;
      color: var(--muted);
      border-radius: 0 6px 6px 0;
    }}

    blockquote p:last-child {{
      margin-bottom: 0;
    }}

    .callout {{
      margin: 1.1rem 0 1.3rem 0;
      padding: 0.82rem 1.05rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      border-left-width: 5px;
    }}

    .callout-title {{
      font-weight: 700;
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 0.3rem;
    }}

    .callout-body p:last-child {{
      margin-bottom: 0;
    }}

    .callout-note {{ background: #eff6ff; border-color: #bfdbfe; border-left-color: #2563eb; }}
    .callout-note .callout-title {{ color: #1d4ed8; }}
    .callout-tip {{ background: #f0fdfa; border-color: #99f6e4; border-left-color: #0f766e; }}
    .callout-tip .callout-title {{ color: #0f766e; }}
    .callout-important {{ background: #f5f3ff; border-color: #ddd6fe; border-left-color: #7c3aed; }}
    .callout-important .callout-title {{ color: #6d28d9; }}
    .callout-warning {{ background: #fffbeb; border-color: #fde68a; border-left-color: #d97706; }}
    .callout-warning .callout-title {{ color: #b45309; }}
    .callout-caution {{ background: #fef2f2; border-color: #fecaca; border-left-color: #dc2626; }}
    .callout-caution .callout-title {{ color: #b91c1c; }}

    /* Figures & Embedded High-DPI Diagram Images */
    .diagram-figure {{
      margin: 1.4rem 0 1.75rem 0;
      padding: 1rem 1rem 0.8rem 1rem;
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 6px;
      text-align: center;
    }}

    .diagram-img {{
      display: block;
      margin: 0 auto;
      max-width: 100%;
      height: auto;
      border-radius: 3px;
    }}

    .inline-img {{
      max-width: 100%;
      height: auto;
      vertical-align: middle;
    }}

    .diagram-caption {{
      margin-top: 0.72rem;
      font-size: 0.84rem;
      color: var(--muted);
      text-align: center;
      line-height: 1.45;
    }}

    /* Footer */
    .doc-footer {{
      margin-top: 3rem;
      padding-top: 1.1rem;
      border-top: 1px solid var(--border);
      font-size: 0.8rem;
      color: var(--subtle);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    /* A4 Print & PDF Export Rules */
    @page {{
      size: A4;
      margin: 16mm 14mm 18mm 14mm;
    }}

    @media print {{
      body {{
        background: #ffffff !important;
        color: #0f172a !important;
        font-size: 9.8pt;
        line-height: 1.5;
      }}

      .no-print {{
        display: none !important;
      }}

      .document-sheet {{
        max-width: 100%;
        margin: 0;
        padding: 0;
        border: 0;
        border-radius: 0;
        box-shadow: none;
      }}

      .cover-page {{
        min-height: 92vh;
        border-bottom: 0;
        margin-bottom: 0;
        page-break-after: always;
        break-after: page;
      }}

      .cover-banner {{
        background: #0f172a !important;
        color: #ffffff !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}

      .toc-section {{
        border-bottom: 0;
        page-break-after: always;
        break-after: page;
      }}

      .lof-section {{
        border-bottom: 0;
        page-break-after: always;
        break-after: page;
      }}

      .sad-frontmatter {{
        page-break-after: always;
        break-after: page;
      }}

      .sad-chapter {{
        page-break-before: always;
        break-before: page;
      }}

      h1, h2, h3, h4 {{
        page-break-after: avoid;
        break-after: avoid;
      }}

      .diagram-figure,
      .callout,
      blockquote,
      .code-block,
      .cover-stat,
      tr {{
        page-break-inside: avoid;
        break-inside: avoid;
      }}

      .table-wrap {{
        overflow: visible;
      }}

      table {{
        font-size: 8.5pt;
      }}

      thead {{
        display: table-header-group;
      }}

      thead th {{
        background: #0f172a !important;
        color: #ffffff !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}

      tbody tr:nth-child(even) {{
        background: #f8fafc !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}

      .code-block pre {{
        white-space: pre-wrap;
        word-break: break-word;
        font-size: 7.8pt;
      }}

      .diagram-img {{
        max-width: 100% !important;
        max-height: 215mm;
        width: auto;
        height: auto;
      }}

      a {{
        color: #0f172a;
        text-decoration: none;
      }}
    }}
  </style>
</head>
<body>
  <header class="toolbar no-print">
    <div class="toolbar-brand">
      <span class="toolbar-badge">FORMAL EDITION v1.1</span>
      <span>Graduation Project Book — Offline Printable HTML Edition</span>
    </div>
    <div class="toolbar-actions">
      <span class="status-pill">{html.escape(status_badge_text)}</span>
      <a class="btn-nav" href="#table-of-contents">Contents</a>
      <a class="btn-nav" href="#list-of-figures">Figures</a>
      <button type="button" class="btn-print" onclick="window.print()">Print / Save as PDF</button>
    </div>
  </header>

  <main class="document-sheet">
    <!-- Formal Academic Cover Page -->
    <section class="cover-page" id="cover">
      <div>
        <div class="cover-banner">
          <div class="cover-kicker">{html.escape(DOCUMENT_META["kicker"])}</div>
          <h1 class="cover-title">{html.escape(DOCUMENT_META["title"])}</h1>
          <p class="cover-subtitle">{html.escape(DOCUMENT_META["subtitle"])}</p>
        </div>

        <div class="cover-abstract">
          <div class="cover-abstract-label">Executive Abstract</div>
          <p style="margin:0;">{html.escape(COVER_ABSTRACT)}</p>
        </div>

        <div class="cover-summary-grid">
          <div class="cover-stat">
            <div class="cover-stat-value">{chapter_count} Chapters</div>
            <div class="cover-stat-label">Requirements, Architecture, Data/API, Security &amp; Validation</div>
          </div>
          <div class="cover-stat">
            <div class="cover-stat-value">{figure_count} Figures</div>
            <div class="cover-stat-label">High-DPI Embedded Diagrams (100% Offline)</div>
          </div>
          <div class="cover-stat">
            <div class="cover-stat-value">17 Checks</div>
            <div class="cover-stat-label">Curated OWASP Top 10 (2021) + NIST SSDF Alignment</div>
          </div>
        </div>
      </div>

      <table class="cover-meta-table">
        <tbody>
          <tr>
            <th>Project Title</th>
            <td>{html.escape(DOCUMENT_META["title"])} ({html.escape(DOCUMENT_META["subtitle"])})</td>
          </tr>
          <tr>
            <th>Methodological Reference</th>
            <td>{html.escape(DOCUMENT_META["methodology"])}</td>
          </tr>
          <tr>
            <th>Target Audience</th>
            <td>{html.escape(DOCUMENT_META["audience"])}</td>
          </tr>
          <tr>
            <th>Department</th>
            <td>{html.escape(DOCUMENT_META["department"])}</td>
          </tr>
          <tr>
            <th>Project Supervisor</th>
            <td><strong>{html.escape(DOCUMENT_META["supervisor"])}</strong></td>
          </tr>
          <tr>
            <th>Project Team</th>
            <td>{html.escape(DOCUMENT_META["team"])}</td>
          </tr>
          <tr>
            <th>Academic Year</th>
            <td>{html.escape(DOCUMENT_META["academic_year"])}</td>
          </tr>
          <tr>
            <th>Document Status</th>
            <td>{html.escape(DOCUMENT_META["status"])}</td>
          </tr>
          <tr>
            <th>Current Project Phase</th>
            <td>{html.escape(DOCUMENT_META["current_phase"])}</td>
          </tr>
          <tr>
            <th>Next Project Phase</th>
            <td>{html.escape(DOCUMENT_META["next_phase"])}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- Auto-Generated Clickable Table of Contents -->
    <nav class="toc-section" id="table-of-contents" aria-label="Table of Contents">
      <h2 class="nav-heading">Table of Contents</h2>
      {toc_html}
    </nav>

    <!-- Auto-Generated Clickable List of Figures -->
    <nav class="lof-section" id="list-of-figures" aria-label="List of Figures">
      <h2 class="nav-heading">List of Figures</h2>
      {lof_html}
    </nav>

    <!-- Master SAD Overview (from docs/SAD.md) -->
    <section class="sad-frontmatter" id="executive-overview" data-source="SAD.md">
      {frontmatter_html}
    </section>

    <!-- Chapters 1 through 6 -->
    {chapters_joined}

    <footer class="doc-footer">
      <span>{html.escape(DOCUMENT_META["doc_id"])} · {html.escape(DOCUMENT_META["academic_year"])}</span>
      <span>Prepared for {html.escape(DOCUMENT_META["supervisor"])} · {html.escape(DOCUMENT_META["department"])}</span>
    </footer>
  </main>{mermaid_scripts}
</body>
</html>
"""


def main() -> int:
    if not MASTER_SAD_PATH.is_file():
        print(f"ERROR: Master SAD file not found: {MASTER_SAD_PATH}", file=sys.stderr)
        return 1

    if not CHAPTERS_DIR.is_dir():
        print(f"ERROR: Chapters directory not found: {CHAPTERS_DIR}", file=sys.stderr)
        return 1

    chapter_files = sorted(CHAPTERS_DIR.glob("[0-9][0-9]_*.md"))
    if not chapter_files:
        print(f"ERROR: No chapter markdown files (01_*.md..06_*.md) found in {CHAPTERS_DIR}", file=sys.stderr)
        return 1

    # Map chapter filenames -> internal HTML section anchors
    chapter_anchor_map: dict[str, str] = {}
    for ch_path in chapter_files:
        ch_num = ch_path.name[:2]
        anchor = f"chapter-{ch_num}"
        chapter_anchor_map[ch_path.name] = anchor
        chapter_anchor_map[f"sad_chapters/{ch_path.name}"] = anchor

    slugs = SlugRegistry()
    converter = MarkdownConverter(slugs=slugs, chapter_anchor_map=chapter_anchor_map)

    # Convert chapters first so figure_anchor_map is populated for SAD.md List of Figures links,
    # then reorder TOC entries cleanly (frontmatter first, then chapters 1..6).
    chapters_html: list[tuple[str, str, str]] = []
    for ch_path in chapter_files:
        ch_num = ch_path.name[:2]
        anchor = f"chapter-{ch_num}"
        ch_md = ch_path.read_text(encoding="utf-8")
        ch_body = converter.convert(
            ch_md,
            base_dir=ch_path.parent,
            section_kind="chapter",
            slug_prefix=f"ch{ch_num}",
            collect_toc=True,
        )
        chapters_html.append((anchor, ch_path.name, ch_body))

    chapter_toc = list(converter.toc)
    converter.toc.clear()

    master_md = MASTER_SAD_PATH.read_text(encoding="utf-8")
    frontmatter_html = converter.convert(
        master_md,
        base_dir=MASTER_SAD_PATH.parent,
        section_kind="frontmatter",
        slug_prefix="overview",
        collect_toc=True,
    )
    frontmatter_toc = list(converter.toc)
    combined_toc = frontmatter_toc + chapter_toc

    if converter.missing_images:
        print(
            f"ERROR: {len(converter.missing_images)} referenced image(s) not found: "
            f"{', '.join(converter.missing_images)}",
            file=sys.stderr,
        )
        return 2

    toc_html = build_toc_html(combined_toc)
    lof_html = build_lof_html(converter.figures)
    final_html = build_html_document(
        frontmatter_html=frontmatter_html,
        chapters_html=chapters_html,
        toc_html=toc_html,
        lof_html=lof_html,
        figure_count=len(converter.figures),
        mermaid_count=converter.mermaid_count,
        chapter_count=len(chapter_files),
    )

    OUTPUT_HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_HTML_PATH.write_text(final_html, encoding="utf-8")

    print(
        f"Built {OUTPUT_HTML_PATH.relative_to(REPO_ROOT)} successfully: "
        f"{len(chapter_files)} chapters, {len(converter.figures)} embedded offline figures "
        f"({converter.embedded_image_count} base64 images), "
        f"{converter.mermaid_count} inline Mermaid blocks, {len(final_html):,} bytes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
