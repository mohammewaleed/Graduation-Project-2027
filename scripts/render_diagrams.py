#!/usr/bin/env python3
"""
Publication-grade SVG + 2x High-DPI PNG renderer for all 19 SAD diagrams.

Reads/mirrors the exact specifications of docs/diagrams/01_*.mmd .. 19_*.mmd,
produces crisp academic vector SVGs in docs/diagrams/images/*.svg, and renders
every SVG to high-DPI (1600px-2200px wide) auto-cropped PNGs via local headless
Chrome/Edge + Pillow.

Usage:
    py -3.12 scripts/render_diagrams.py
    py -3.12 scripts/render_diagrams.py 19_master_system_flowchart
"""

from __future__ import annotations

import html
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Iterable, List, Optional, Sequence, Tuple

from PIL import Image, ImageChops, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Paths & Palette Constants
# ---------------------------------------------------------------------------
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
DIAGRAMS_DIR = ROOT_DIR / "docs" / "diagrams"
IMAGES_DIR = DIAGRAMS_DIR / "images"

FONT_SANS = "Segoe UI, Arial, Helvetica, sans-serif"
FONT_MONO = "Consolas, 'Courier New', monospace"

# Consistent Light / Print-Friendly Academic Palette
WHITE = "#FFFFFF"
NAVY = "#0F172A"
NAVY_MID = "#1E293B"
SLATE_TEXT = "#1E293B"
MUTED_TEXT = "#475569"
LIGHT_MUTED = "#64748B"

TEAL = "#0D9488"
TEAL_DARK = "#0F766E"
TEAL_FILL = "#CCFBF1"
TEAL_SOFT = "#F0FDFA"
TEAL_BORDER = "#14B8A6"

BOX_BG = "#FFFFFF"
CONTAINER_BG = "#F1F5F9"
CONTAINER_LIGHT = "#F8FAFC"
BORDER_SLATE = "#CBD5E1"
BORDER_DARK = "#94A3B8"

BLUE = "#1D4ED8"
BLUE_FILL = "#DBEAFE"
BLUE_SOFT = "#EFF6FF"
BLUE_BORDER = "#60A5FA"

RED = "#DC2626"
RED_DARK = "#991B1B"
RED_FILL = "#FEE2E2"
RED_SOFT = "#FEF2F2"
RED_BORDER = "#F87171"

AMBER = "#B45309"
AMBER_FILL = "#FEF3C7"
AMBER_SOFT = "#FFFBEB"
AMBER_BORDER = "#F59E0B"

GREEN = "#047857"
GREEN_FILL = "#D1FAE5"
GREEN_SOFT = "#ECFDF5"
GREEN_BORDER = "#34D399"

PURPLE = "#6D28D9"
PURPLE_FILL = "#EDE9FE"
PURPLE_SOFT = "#F5F3FF"
PURPLE_BORDER = "#A78BFA"


# ---------------------------------------------------------------------------
# Exact Font Metrics & Text Wrapping
# ---------------------------------------------------------------------------
_FONT_CACHE: dict[Tuple[str, int], Optional[ImageFont.FreeTypeFont]] = {}


def _load_ttf(bold: bool = False, mono: bool = False, size: int = 13) -> Optional[ImageFont.FreeTypeFont]:
    key = (f"{'m' if mono else 's'}{'b' if bold else 'r'}", size)
    if key in _FONT_CACHE:
        return _FONT_CACHE[key]
    candidates: List[str] = []
    if mono:
        candidates = [
            r"C:\Windows\Fonts\consolab.ttf" if bold else r"C:\Windows\Fonts\consola.ttf",
            r"C:\Windows\Fonts\courbd.ttf" if bold else r"C:\Windows\Fonts\cour.ttf",
        ]
    else:
        candidates = [
            r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
            r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
        ]
    font_obj = None
    for path in candidates:
        if os.path.exists(path):
            try:
                font_obj = ImageFont.truetype(path, size=size)
                break
            except Exception:
                pass
    _FONT_CACHE[key] = font_obj
    return font_obj


def measure_text(text: str, size: int = 13, bold: bool = False, mono: bool = False) -> float:
    """Return pixel width estimate for text rendered in Segoe UI / Consolas."""
    if not text:
        return 0.0
    font = _load_ttf(bold=bold, mono=mono, size=size)
    if font is not None:
        bbox = font.getbbox(text)
        # Add 6% safety margin for SVG browser font-hinting differences
        return (bbox[2] - bbox[0]) * 1.06
    factor = 0.62 if mono else (0.59 if bold else 0.54)
    return len(text) * size * factor


def wrap_text(
    text: str,
    max_width: float,
    size: int = 13,
    bold: bool = False,
    mono: bool = False,
) -> List[str]:
    """Wrap text into lines that strictly fit inside max_width."""
    lines: List[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split(" ")
        cur = ""
        for w in words:
            trial = w if not cur else f"{cur} {w}"
            if measure_text(trial, size=size, bold=bold, mono=mono) <= max_width:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                # If a single token is wider than max_width, split on '/' or '-' if possible
                if measure_text(w, size=size, bold=bold, mono=mono) > max_width and ("/" in w or "_" in w):
                    parts = re.split(r"([/_-])", w)
                    sub = ""
                    for p in parts:
                        t2 = sub + p
                        if measure_text(t2, size=size, bold=bold, mono=mono) <= max_width or not sub:
                            sub = t2
                        else:
                            lines.append(sub)
                            sub = p
                    cur = sub
                else:
                    cur = w
        if cur:
            lines.append(cur)
    return lines or [""]


def esc(text: str) -> str:
    return html.escape(text, quote=True)


# ---------------------------------------------------------------------------
# SVG Canvas Builder
# ---------------------------------------------------------------------------
class SvgCanvas:
    def __init__(self, width: float, height: float, title: str = "") -> None:
        self.width = float(width)
        self.height = float(height)
        self.title = title
        self.parts: List[str] = []
        self.top_parts: List[str] = []  # rendered last (labels/badges on top of arrows)

    def raw(self, s: str, top: bool = False) -> None:
        (self.top_parts if top else self.parts).append(s)

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: str = WHITE,
        stroke: str = NAVY,
        stroke_width: float = 1.5,
        rx: float = 8,
        dash: str = "",
        shadow: bool = False,
        opacity: float = 1.0,
        top: bool = False,
    ) -> None:
        attrs = [
            f'x="{x:.1f}"',
            f'y="{y:.1f}"',
            f'width="{w:.1f}"',
            f'height="{h:.1f}"',
            f'rx="{rx:.1f}"',
            f'ry="{rx:.1f}"',
            f'fill="{fill}"',
            f'stroke="{stroke}"',
            f'stroke-width="{stroke_width}"',
        ]
        if dash:
            attrs.append(f'stroke-dasharray="{dash}"')
        if shadow:
            attrs.append('filter="url(#shadow)"')
        if opacity < 1.0:
            attrs.append(f'opacity="{opacity}"')
        self.raw(f'<rect {" ".join(attrs)}/>', top=top)

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        dash: str = "",
        marker_end: str = "",
        marker_start: str = "",
        top: bool = False,
    ) -> None:
        attrs = [
            f'x1="{x1:.1f}"',
            f'y1="{y1:.1f}"',
            f'x2="{x2:.1f}"',
            f'y2="{y2:.1f}"',
            f'stroke="{stroke}"',
            f'stroke-width="{stroke_width}"',
        ]
        if dash:
            attrs.append(f'stroke-dasharray="{dash}"')
        if marker_end:
            attrs.append(f'marker-end="url(#{marker_end})"')
        if marker_start:
            attrs.append(f'marker-start="url(#{marker_start})"')
        self.raw(f'<line {" ".join(attrs)}/>', top=top)

    def path(
        self,
        d: str,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        fill: str = "none",
        dash: str = "",
        marker_end: str = "",
        marker_start: str = "",
        top: bool = False,
    ) -> None:
        attrs = [
            f'd="{d}"',
            f'fill="{fill}"',
            f'stroke="{stroke}"',
            f'stroke-width="{stroke_width}"',
            'stroke-linejoin="round"',
            'stroke-linecap="round"',
        ]
        if dash:
            attrs.append(f'stroke-dasharray="{dash}"')
        if marker_end:
            attrs.append(f'marker-end="url(#{marker_end})"')
        if marker_start:
            attrs.append(f'marker-start="url(#{marker_start})"')
        self.raw(f'<path {" ".join(attrs)}/>', top=top)

    def polyline_arrow(
        self,
        points: Sequence[Tuple[float, float]],
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        dash: str = "",
        marker_end: str = "arrow-navy",
        marker_start: str = "",
        radius: float = 7.0,
        top: bool = False,
    ) -> None:
        """Draw a rounded orthogonal/polyline path through points."""
        if len(points) < 2:
            return
        if len(points) == 2 or radius <= 0:
            d = f"M {points[0][0]:.1f} {points[0][1]:.1f} " + " ".join(
                f"L {x:.1f} {y:.1f}" for x, y in points[1:]
            )
            self.path(d, stroke=stroke, stroke_width=stroke_width, dash=dash,
                      marker_end=marker_end, marker_start=marker_start, top=top)
            return
        cmds = [f"M {points[0][0]:.1f} {points[0][1]:.1f}"]
        for i in range(1, len(points) - 1):
            p0 = points[i - 1]
            p1 = points[i]
            p2 = points[i + 1]
            dx1, dy1 = p1[0] - p0[0], p1[1] - p0[1]
            dx2, dy2 = p2[0] - p1[0], p2[1] - p1[1]
            l1 = math.hypot(dx1, dy1)
            l2 = math.hypot(dx2, dy2)
            r = min(radius, l1 / 2.2, l2 / 2.2)
            if r < 1.0 or l1 == 0 or l2 == 0:
                cmds.append(f"L {p1[0]:.1f} {p1[1]:.1f}")
            else:
                ax = p1[0] - (dx1 / l1) * r
                ay = p1[1] - (dy1 / l1) * r
                bx = p1[0] + (dx2 / l2) * r
                by = p1[1] + (dy2 / l2) * r
                cmds.append(f"L {ax:.1f} {ay:.1f}")
                cmds.append(f"Q {p1[0]:.1f} {p1[1]:.1f} {bx:.1f} {by:.1f}")
        cmds.append(f"L {points[-1][0]:.1f} {points[-1][1]:.1f}")
        self.path(
            " ".join(cmds),
            stroke=stroke,
            stroke_width=stroke_width,
            dash=dash,
            marker_end=marker_end,
            marker_start=marker_start,
            top=top,
        )

    def circle(
        self,
        cx: float,
        cy: float,
        r: float,
        fill: str = WHITE,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        shadow: bool = False,
        top: bool = False,
    ) -> None:
        filt = ' filter="url(#shadow)"' if shadow else ""
        self.raw(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{stroke_width}"{filt}/>',
            top=top,
        )

    def ellipse(
        self,
        cx: float,
        cy: float,
        rx: float,
        ry: float,
        fill: str = WHITE,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        shadow: bool = False,
        top: bool = False,
    ) -> None:
        filt = ' filter="url(#shadow)"' if shadow else ""
        self.raw(
            f'<ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{rx:.1f}" ry="{ry:.1f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}"{filt}/>',
            top=top,
        )

    def polygon(
        self,
        points: Sequence[Tuple[float, float]],
        fill: str = WHITE,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        shadow: bool = False,
        top: bool = False,
    ) -> None:
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        filt = ' filter="url(#shadow)"' if shadow else ""
        self.raw(
            f'<polygon points="{pts}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{stroke_width}" stroke-linejoin="round"{filt}/>',
            top=top,
        )

    def text(
        self,
        x: float,
        y: float,
        content: str,
        size: int = 13,
        fill: str = SLATE_TEXT,
        bold: bool = False,
        italic: bool = False,
        mono: bool = False,
        anchor: str = "middle",
        top: bool = False,
    ) -> None:
        ff = FONT_MONO if mono else FONT_SANS
        fw = "700" if bold else "400"
        fs = ' font-style="italic"' if italic else ""
        self.raw(
            f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
            f'font-family="{ff}" font-size="{size}" font-weight="{fw}"{fs} '
            f'fill="{fill}">{esc(content)}</text>',
            top=top,
        )

    def text_block(
        self,
        cx: float,
        cy: float,
        lines: Sequence[str],
        size: int = 12,
        line_height: float = 1.32,
        fill: str = SLATE_TEXT,
        bold: bool = False,
        italic: bool = False,
        mono: bool = False,
        anchor: str = "middle",
        bold_first: bool = False,
        first_fill: Optional[str] = None,
        top: bool = False,
    ) -> None:
        lh = size * line_height
        total_h = len(lines) * lh
        start_y = cy - total_h / 2.0 + size * 0.85
        for idx, ln in enumerate(lines):
            is_b = bold or (bold_first and idx == 0)
            col = first_fill if (bold_first and idx == 0 and first_fill) else fill
            self.text(
                cx,
                start_y + idx * lh,
                ln,
                size=size,
                fill=col,
                bold=is_b,
                italic=italic,
                mono=mono,
                anchor=anchor,
                top=top,
            )

    def title_bar(self, title: str, subtitle: str = "", y: float = 26) -> None:
        self.text(self.width / 2, y, title, size=18, fill=NAVY, bold=True)
        if subtitle:
            self.text(self.width / 2, y + 20, subtitle, size=12, fill=MUTED_TEXT)
        line_y = y + (30 if subtitle else 14)
        self.line(36, line_y, self.width - 36, line_y, stroke=BORDER_SLATE, stroke_width=1.2)

    def box(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        subtitle: str = "",
        fill: str = WHITE,
        stroke: str = NAVY,
        stroke_width: float = 1.6,
        title_color: str = NAVY,
        sub_color: str = MUTED_TEXT,
        rx: float = 8,
        title_size: int = 12,
        sub_size: int = 11,
        accent_bar: Optional[str] = None,
        dash: str = "",
        shadow: bool = True,
    ) -> None:
        self.rect(x, y, w, h, fill=fill, stroke=stroke, stroke_width=stroke_width, rx=rx, dash=dash, shadow=shadow)
        pad_x = 12
        if accent_bar:
            self.rect(x + 1, y + 1, 6, h - 2, fill=accent_bar, stroke="none", stroke_width=0, rx=3)
            pad_x = 16
        avail = w - pad_x * 2
        t_lines = wrap_text(title, avail, size=title_size, bold=True)
        if subtitle:
            s_lines = wrap_text(subtitle, avail, size=sub_size, bold=False)
            t_lh = title_size * 1.28
            s_lh = sub_size * 1.28
            gap = 4
            tot = len(t_lines) * t_lh + gap + len(s_lines) * s_lh
            cur_y = y + (h - tot) / 2.0 + title_size * 0.85
            cx = x + w / 2.0 + (2 if accent_bar else 0)
            for ln in t_lines:
                self.text(cx, cur_y, ln, size=title_size, fill=title_color, bold=True)
                cur_y += t_lh
            cur_y += gap - (t_lh - title_size) * 0.2
            for ln in s_lines:
                self.text(cx, cur_y, ln, size=sub_size, fill=sub_color, bold=False)
                cur_y += s_lh
        else:
            cx = x + w / 2.0 + (2 if accent_bar else 0)
            self.text_block(cx, y + h / 2.0, t_lines, size=title_size, fill=title_color, bold=True)

    def subgraph(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        label: str,
        fill: str = CONTAINER_BG,
        stroke: str = BORDER_DARK,
        header_bg: str = NAVY,
        header_fg: str = WHITE,
        dash: str = "",
        rx: float = 10,
        header_x_offset: float = 12,
    ) -> None:
        self.rect(x, y, w, h, fill=fill, stroke=stroke, stroke_width=1.6, rx=rx, dash=dash)
        fsize = 12
        if measure_text(label, size=12, bold=True) + 28 > w - 16:
            fsize = 11
        pill_w = min(w - 16, measure_text(label, size=fsize, bold=True) + 26)
        px = x + header_x_offset
        if px + pill_w > x + w - 8:
            px = x + w - 8 - pill_w
        self.rect(px, y - 13, pill_w, 26, fill=header_bg, stroke=header_bg, stroke_width=1, rx=6)
        self.text(px + pill_w / 2.0, y + 4.2, label, size=fsize, fill=header_fg, bold=True)

    def cylinder(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        subtitle: str = "",
        fill: str = TEAL_SOFT,
        stroke: str = TEAL_DARK,
        dash: str = "",
        title_size: int = 12,
        sub_size: int = 10,
    ) -> None:
        ry = 11.0
        cx = x + w / 2.0
        body_d = (
            f"M {x:.1f} {y + ry:.1f} "
            f"L {x:.1f} {y + h - ry:.1f} "
            f"A {w/2:.1f} {ry:.1f} 0 0 0 {x + w:.1f} {y + h - ry:.1f} "
            f"L {x + w:.1f} {y + ry:.1f} Z"
        )
        self.path(body_d, stroke=stroke, stroke_width=1.6, fill=fill, dash=dash)
        # Top ellipse
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        self.raw(
            f'<ellipse cx="{cx:.1f}" cy="{y + ry:.1f}" rx="{w/2:.1f}" ry="{ry:.1f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"{dash_attr}/>'
        )
        # Text inside cylinder body
        avail = w - 18
        cy_text = y + ry + (h - ry) / 2.0
        t_lines = wrap_text(title, avail, size=title_size, bold=True)
        if subtitle:
            s_lines = wrap_text(subtitle, avail, size=sub_size)
            tot = len(t_lines) * title_size * 1.26 + 3 + len(s_lines) * sub_size * 1.25
            cur = cy_text - tot / 2.0 + title_size * 0.85
            for ln in t_lines:
                self.text(cx, cur, ln, size=title_size, fill=NAVY, bold=True)
                cur += title_size * 1.26
            cur += 2
            for ln in s_lines:
                self.text(cx, cur, ln, size=sub_size, fill=MUTED_TEXT)
                cur += sub_size * 1.25
        else:
            self.text_block(cx, cy_text, t_lines, size=title_size, fill=NAVY, bold=True)

    def diamond(
        self,
        cx: float,
        cy: float,
        w: float,
        h: float,
        label: str,
        fill: str = AMBER_SOFT,
        stroke: str = AMBER,
        size: int = 11,
        text_color: str = NAVY,
    ) -> None:
        pts = [(cx, cy - h / 2), (cx + w / 2, cy), (cx, cy + h / 2), (cx - w / 2, cy)]
        self.polygon(pts, fill=fill, stroke=stroke, stroke_width=1.7, shadow=True)
        lines = wrap_text(label, w * 0.64, size=size, bold=True)
        self.text_block(cx, cy, lines, size=size, fill=text_color, bold=True)

    def parallelogram(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        label: str,
        slant: float = 20.0,
        fill: str = BLUE_SOFT,
        stroke: str = BLUE,
        size: int = 12,
        text_color: str = NAVY,
    ) -> None:
        """Classic ISO 5807 slanted Input/Output parallelogram."""
        pts = [
            (x + slant, y),
            (x + w, y),
            (x + w - slant, y + h),
            (x, y + h),
        ]
        self.polygon(pts, fill=fill, stroke=stroke, stroke_width=1.8, shadow=True)
        safe_w = w - 2.0 * slant - 24.0
        lines = wrap_text(label, safe_w, size=size, bold=True)
        self.text_block(x + w / 2.0, y + h / 2.0, lines, size=size, fill=text_color, bold=True)

    def terminator(
        self,
        cx: float,
        cy: float,
        w: float,
        h: float,
        label: str,
        fill: str = NAVY,
        stroke: str = NAVY,
        text_color: str = WHITE,
        size: int = 13,
    ) -> None:
        """Classic ISO 5807 rounded pill/oval START/END terminator."""
        self.rect(
            cx - w / 2.0,
            cy - h / 2.0,
            w,
            h,
            fill=fill,
            stroke=stroke,
            stroke_width=2.0,
            rx=h / 2.0,
            shadow=True,
        )
        self.text(cx, cy + size * 0.36, label, size=size, fill=text_color, bold=True)

    def edge_label(
        self,
        cx: float,
        cy: float,
        text: str,
        max_w: float = 210,
        size: int = 10,
        bg: str = WHITE,
        border: str = BORDER_SLATE,
        fg: str = SLATE_TEXT,
        bold: bool = False,
        italic: bool = False,
    ) -> None:
        lines = wrap_text(text, max_w, size=size, bold=bold)
        w = max(measure_text(ln, size=size, bold=bold) for ln in lines) + 14
        lh = size * 1.28
        h = len(lines) * lh + 8
        self.rect(cx - w / 2, cy - h / 2, w, h, fill=bg, stroke=border, stroke_width=1.0, rx=5, top=True)
        self.text_block(cx, cy, lines, size=size, line_height=1.28, fill=fg, bold=bold, italic=italic, top=True)

    def actor(self, cx: float, cy: float, label: str, color: str = NAVY) -> None:
        # Crisp UML stick figure centered at (cx, cy - 18)
        head_y = cy - 32
        self.circle(cx, head_y, 11, fill=TEAL_SOFT, stroke=color, stroke_width=2.0)
        self.line(cx, head_y + 11, cx, head_y + 38, stroke=color, stroke_width=2.0)
        self.line(cx - 18, head_y + 20, cx + 18, head_y + 20, stroke=color, stroke_width=2.0)
        self.line(cx, head_y + 38, cx - 14, head_y + 56, stroke=color, stroke_width=2.0)
        self.line(cx, head_y + 38, cx + 14, head_y + 56, stroke=color, stroke_width=2.0)
        lines = wrap_text(label, 140, size=12, bold=True)
        self.text_block(cx, head_y + 76, lines, size=12, fill=color, bold=True)

    def dfd_store(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        code: str,
        label: str,
        fill: str = TEAL_SOFT,
        stroke: str = TEAL_DARK,
    ) -> None:
        """Open-right Yourdon/Gane-Sarson DFD Data Store."""
        self.rect(x, y, w, h, fill=fill, stroke="none", stroke_width=0, rx=2)
        self.line(x, y, x + w, y, stroke=stroke, stroke_width=1.8)
        self.line(x, y + h, x + w, y + h, stroke=stroke, stroke_width=1.8)
        self.line(x, y, x, y + h, stroke=stroke, stroke_width=1.8)
        self.line(x + 34, y, x + 34, y + h, stroke=stroke, stroke_width=1.4)
        self.text(x + 17, y + h / 2 + 4.5, code, size=11, fill=TEAL_DARK, bold=True)
        lines = wrap_text(label, w - 46, size=11, bold=True)
        self.text_block(x + 34 + (w - 34) / 2, y + h / 2, lines, size=11, fill=NAVY, bold=True)

    def render(self) -> str:
        defs = f"""
  <defs>
    <filter id="shadow" x="-6%" y="-6%" width="114%" height="118%">
      <feDropShadow dx="0" dy="2" stdDeviation="2.4" flood-color="#0F172A" flood-opacity="0.08"/>
    </filter>
    <marker id="arrow-navy" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{NAVY}"/>
    </marker>
    <marker id="arrow-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{TEAL_DARK}"/>
    </marker>
    <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{RED}"/>
    </marker>
    <marker id="arrow-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{BLUE}"/>
    </marker>
    <marker id="arrow-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{AMBER}"/>
    </marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{GREEN}"/>
    </marker>
    <marker id="arrow-slate" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1.2 L 9.2 5 L 0 8.8 z" fill="{MUTED_TEXT}"/>
    </marker>
    <marker id="arrow-open-navy" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 1 1.5 L 8.8 5 L 1 8.5" fill="none" stroke="{NAVY}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
    <marker id="arrow-open-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 1 1.5 L 8.8 5 L 1 8.5" fill="none" stroke="{TEAL_DARK}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
    <marker id="uml-inherit" viewBox="0 0 12 12" refX="11" refY="6" markerWidth="10" markerHeight="10" orient="auto-start-reverse">
      <path d="M 1 1.2 L 10.8 6 L 1 10.8 Z" fill="{WHITE}" stroke="{NAVY}" stroke-width="1.5"/>
    </marker>
    <marker id="uml-agg" viewBox="0 0 16 10" refX="1" refY="5" markerWidth="13" markerHeight="9" orient="auto">
      <path d="M 1 5 L 7.5 1 L 14 5 L 7.5 9 Z" fill="{WHITE}" stroke="{NAVY}" stroke-width="1.4"/>
    </marker>
    <marker id="uml-comp" viewBox="0 0 16 10" refX="1" refY="5" markerWidth="13" markerHeight="9" orient="auto">
      <path d="M 1 5 L 7.5 1 L 14 5 L 7.5 9 Z" fill="{NAVY}" stroke="{NAVY}" stroke-width="1.4"/>
    </marker>
    <marker id="arrow-x-red" viewBox="0 0 12 12" refX="6" refY="6" markerWidth="10" markerHeight="10" orient="auto">
      <path d="M 2 2 L 10 10 M 10 2 L 2 10" fill="none" stroke="{RED}" stroke-width="2.2" stroke-linecap="round"/>
    </marker>
  </defs>"""
        body = "\n  ".join(self.parts + self.top_parts)
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(self.width)}" height="{int(self.height)}" '
            f'viewBox="0 0 {int(self.width)} {int(self.height)}">\n'
            f'{defs}\n'
            f'  <rect width="{int(self.width)}" height="{int(self.height)}" fill="{WHITE}"/>\n'
            f'  {body}\n'
            f'</svg>\n'
        )


# ===========================================================================
# DIAGRAM 01: As-Is vs To-Be Workflow
# ===========================================================================
def render_01() -> Tuple[str, float, float]:
    W, H = 1080, 500
    c = SvgCanvas(W, H)
    c.title_bar(
        "As-Is vs. To-Be Security Testing Workflow",
        "Shift-Left Developer-First Workflow Eliminating Pre-Release Enterprise DAST Bottlenecks",
    )

    # Top Subgraph: As-Is
    c.subgraph(
        30, 88, 1020, 152,
        "As-Is: Traditional Enterprise DAST Workflow",
        fill=RED_SOFT, stroke=RED_BORDER, header_bg=RED, header_fg=WHITE,
    )
    asis = [
        ("Active Coding", "(Weeks 1-10)"),
        ("Pre-Release Handoff", "(Late Stage)"),
        ("Enterprise Suite Setup", "(Proxy Certs & Policy Tuning)"),
        ("Raw HTTP Dumps", "& CWE Jargon"),
        ("Costly Late Fixes", "or Ignored Findings"),
    ]
    bw, bh, gap = 172, 88, 25
    start_x = 58
    ay = 122
    for i, (t, s) in enumerate(asis):
        bx = start_x + i * (bw + gap)
        c.box(bx, ay, bw, bh, t, s, fill=WHITE, stroke=RED_BORDER, title_color=RED_DARK, accent_bar=RED)
        if i < len(asis) - 1:
            c.line(bx + bw, ay + bh / 2, bx + bw + gap - 2, ay + bh / 2, stroke=RED, stroke_width=2.0, marker_end="arrow-red")

    # Bottom Subgraph: To-Be
    c.subgraph(
        30, 278, 1020, 196,
        "To-Be: Developer-First Local Scanner Workflow",
        fill=TEAL_SOFT, stroke=TEAL_BORDER, header_bg=TEAL_DARK, header_fg=WHITE,
    )
    tobe = [
        ("Active Local Coding", "(localhost Target App)"),
        ("Step 1: One-Command Launch", "(docker compose up)"),
        ("Step 2: Automated Crawl", "& 17 OWASP Checks"),
        ("Step 3: Exact Endpoint Map", "& Copy-Ready Fixes"),
        ("Immediate Code Fix", "& Diff Re-Verification"),
    ]
    by = 312
    for i, (t, s) in enumerate(tobe):
        bx = start_x + i * (bw + gap)
        c.box(bx, by, bw, bh, t, s, fill=WHITE, stroke=TEAL_DARK, title_color=NAVY, accent_bar=TEAL)
        if i < len(tobe) - 1:
            c.line(bx + bw, by + bh / 2, bx + bw + gap - 2, by + bh / 2, stroke=TEAL_DARK, stroke_width=2.0, marker_end="arrow-teal")

    # Continuous feedback loop dashed arrow B5 -> B1
    x_b5 = start_x + 4 * (bw + gap) + bw / 2
    x_b1 = start_x + bw / 2
    loop_y = by + bh + 38
    c.polyline_arrow(
        [(x_b5, by + bh), (x_b5, loop_y), (x_b1, loop_y), (x_b1, by + bh + 2)],
        stroke=TEAL_DARK, stroke_width=2.0, dash="6,4", marker_end="arrow-teal",
    )
    c.edge_label(
        (x_b1 + x_b5) / 2, loop_y,
        "Continuous Local Feedback Loop",
        max_w=260, size=11, bg=TEAL_FILL, border=TEAL_DARK, fg=TEAL_DARK, bold=True,
    )
    return c.render(), W, H


# ===========================================================================
# DIAGRAM 02: Master Scanner Pipeline
# ===========================================================================
def render_02() -> Tuple[str, float, float]:
    W, H = 1168, 500
    c = SvgCanvas(W, H)
    c.title_bar(
        "Master Vulnerability Scanning Pipeline",
        "Four-Stage Architecture from Safe Target Intake to Developer-Experience Remediation Output",
    )

    col_w = 250
    gap = 36
    x0 = 30
    top_y = 92
    col_h = 376

    stages = [
        ("Stage 1: Intake & Safety Guardrail", BLUE_SOFT, BLUE_BORDER, BLUE),
        ("Stage 2: Bounded Discovery", CONTAINER_BG, BORDER_DARK, NAVY),
        ("Stage 3: Curated OWASP Top 10 Engine", TEAL_SOFT, TEAL_BORDER, TEAL_DARK),
        ("Stage 4: Developer-Experience Output", GREEN_SOFT, GREEN_BORDER, GREEN),
    ]
    xs = [x0 + i * (col_w + gap) for i in range(4)]
    for i, (lbl, bg, st, hdr) in enumerate(stages):
        c.subgraph(xs[i], top_y, col_w, col_h, lbl, fill=bg, stroke=st, header_bg=hdr)

    bw = col_w - 28
    # Stage 1 nodes
    s1 = (xs[0] + 14, 152, bw, 92)
    s2 = (xs[0] + 14, 294, bw, 92)
    c.box(*s1, "Target URL & Scan Profile", "(Quick / Standard / Deep)", stroke=BLUE, accent_bar=BLUE)
    c.box(*s2, "Ownership Confirmation &", "Allow-List Guardrail", stroke=BLUE, accent_bar=BLUE)
    c.line(s1[0] + bw / 2, s1[1] + s1[3], s2[0] + bw / 2, s2[1] - 2, stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue")

    # Stage 2 nodes
    s3 = (xs[1] + 14, 152, bw, 92)
    s4 = (xs[1] + 14, 294, bw, 92)
    c.box(*s3, "Rate-Limited HTTP Client &", "Soft-404 Calibration", stroke=NAVY, accent_bar=NAVY)
    c.box(*s4, "Bounded BFS Crawler", "(Links, Forms & Parameters)", stroke=NAVY, accent_bar=NAVY)
    c.line(s3[0] + bw / 2, s3[1] + s3[3], s4[0] + bw / 2, s4[1] - 2, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # Stage 3 nodes (17 Checks badge + 3 parallel groups)
    c.text(xs[2] + col_w / 2, 126, "17 Curated Non-Destructive Checks", size=11, fill=TEAL_DARK, bold=True)
    s5 = (xs[2] + 14, 140, bw, 88)
    s6 = (xs[2] + 14, 248, bw, 88)
    s7 = (xs[2] + 14, 356, bw, 88)
    c.box(*s5, "Passive Checks (8)", "Headers, CSP, Cookies, Errors, JS", stroke=TEAL_DARK, accent_bar=TEAL)
    c.box(*s6, "Active Safe Probes (5)", "CORS, SQLi, XSS, Open Redirect", stroke=TEAL_DARK, accent_bar=AMBER)
    c.box(*s7, "Discovery & Auth Checks (4)", "Files, Dir Listing, Admin, IDOR", stroke=TEAL_DARK, accent_bar=BLUE)

    # Stage 4 nodes
    s8 = (xs[3] + 14, 134, bw, 86)
    s9 = (xs[3] + 14, 246, bw, 90)
    s10 = (xs[3] + 14, 360, bw, 88)
    c.box(*s8, "Deduplication, SHA-1", "Fingerprint & Risk Scoring", stroke=GREEN, accent_bar=GREEN)
    c.box(*s9, "Remediation KB Enrichment", "(FastAPI, Flask, Express, PHP, HTML)", stroke=GREEN, accent_bar=GREEN)
    c.box(*s10, "SQLite / PostgreSQL, Live SSE", "Dashboard & JSON / HTML Reports", stroke=GREEN, accent_bar=GREEN)
    c.line(s8[0] + bw / 2, s8[1] + s8[3], s9[0] + bw / 2, s9[1] - 2, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.line(s9[0] + bw / 2, s9[1] + s9[3], s10[0] + bw / 2, s10[1] - 2, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")

    # Inter-stage connectors
    # S2 -> S3 (routed cleanly through gap between Stage 1 and Stage 2)
    gx12 = xs[0] + col_w + gap / 2
    c.polyline_arrow(
        [(s2[0] + bw, s2[1] + s2[3] / 2), (gx12, s2[1] + s2[3] / 2), (gx12, s3[1] + s3[3] / 2), (s3[0] - 2, s3[1] + s3[3] / 2)],
        stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy",
    )

    # S4 -> S5, S6, S7 (vertical fan-out bus in gap 2-3)
    gx23 = xs[1] + col_w + gap / 2
    s4_mid_y = s4[1] + s4[3] / 2
    c.line(s4[0] + bw, s4_mid_y, gx23, s4_mid_y, stroke=TEAL_DARK, stroke_width=1.8)
    for target in (s5, s6, s7):
        ty = target[1] + target[3] / 2
        c.polyline_arrow([(gx23, s4_mid_y), (gx23, ty), (target[0] - 2, ty)], stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")

    # S5, S6, S7 -> S8 (vertical fan-in bus in gap 3-4)
    gx34 = xs[2] + col_w + gap / 2
    s8_mid_y = s8[1] + s8[3] / 2
    for src in (s5, s6, s7):
        sy = src[1] + src[3] / 2
        c.polyline_arrow([(src[0] + bw, sy), (gx34, sy), (gx34, s8_mid_y)], stroke=GREEN, stroke_width=1.8, marker_end="")
    c.line(gx34, s8_mid_y, s8[0] - 2, s8_mid_y, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 03: UML Use Case Diagram
# ===========================================================================
def render_03() -> Tuple[str, float, float]:
    W, H = 1080, 650
    c = SvgCanvas(W, H)
    c.title_bar(
        "UML Use Case Diagram",
        "Primary Actors, Core Functional Use Cases, and «include» / «extend» System Relationships",
    )

    # Actors on the left
    c.actor(88, 224, "Actor: Student /\nWeb Developer", color=NAVY)
    c.actor(88, 485, "Actor: Team Lead /\nCapstone Instructor", color=BLUE)

    # System Boundary
    c.subgraph(
        212, 92, 838, 530,
        "Lightweight OWASP Top 10 Vulnerability Scanner",
        fill=CONTAINER_LIGHT, stroke=NAVY, header_bg=NAVY, header_fg=WHITE,
    )

    # Primary Use Cases (Left Column inside system boundary)
    uc_x = 408
    uc_rx, uc_ry = 148, 31
    ucs = {
        "UC01": (uc_x, 152, "UC-01: Create & Authorize Project"),
        "UC02": (uc_x, 236, "UC-02: Launch & Monitor Live Scan"),
        "UC03": (uc_x, 320, "UC-03: Cancel Running Scan"),
        "UC04": (uc_x, 404, "UC-04: Inspect Finding & Apply Code Fix"),
        "UC05": (uc_x, 488, "UC-05: Triage & Compare Scans"),
        "UC06": (uc_x, 572, "UC-06: Export Developer Report"),
    }
    for key, (cx, cy, lbl) in ucs.items():
        c.ellipse(cx, cy, uc_rx, uc_ry, fill=WHITE, stroke=NAVY, stroke_width=1.7, shadow=True)
        lines = wrap_text(lbl, uc_rx * 1.65, size=11, bold=True)
        c.text_block(cx, cy, lines, size=11, fill=NAVY, bold=True)

    # Secondary Included/Extended Use Cases (Right Column inside system boundary)
    sub_x = 858
    sub_rx, sub_ry = 148, 33
    subs = {
        "UC_GUARD": (sub_x, 165, "Validate Allow-List &\nScope Guardrail"),
        "UC_SSE": (sub_x, 265, "Stream Live Progress\nvia SSE"),
        "UC_AUTH": (sub_x, 365, "Configure Optional\nAuth Session"),
        "UC_KB": (sub_x, 465, "Retrieve Multi-Stack\nRemediation Guidance"),
    }
    for key, (cx, cy, lbl) in subs.items():
        c.ellipse(cx, cy, sub_rx, sub_ry, fill=TEAL_SOFT, stroke=TEAL_DARK, stroke_width=1.6, shadow=True)
        lines = wrap_text(lbl, sub_rx * 1.62, size=11, bold=True)
        c.text_block(cx, cy, lines, size=11, fill=TEAL_DARK, bold=True)

    # Actor associations (DEV -> UC01..UC06)
    dev_pt = (118, 212)
    for k in ("UC01", "UC02", "UC03", "UC04", "UC05", "UC06"):
        ux, uy, _ = ucs[k]
        c.line(dev_pt[0], dev_pt[1], ux - uc_rx - 2, uy, stroke=NAVY, stroke_width=1.4)

    # Actor associations (INST -> UC04..UC06)
    inst_pt = (118, 474)
    for k in ("UC04", "UC05", "UC06"):
        ux, uy, _ = ucs[k]
        c.line(inst_pt[0], inst_pt[1], ux - uc_rx - 2, uy, stroke=BLUE, stroke_width=1.5)

    # <<include>> and <<extend>> relationships
    def dashed_rel(p1: Tuple[float, float], p2: Tuple[float, float], label: str, color: str, marker: str, lx: float, ly: float) -> None:
        c.line(p1[0], p1[1], p2[0], p2[1], stroke=color, stroke_width=1.5, dash="5,4", marker_end=marker)
        c.edge_label(lx, ly, label, size=10, bg=WHITE, border=color, fg=color, italic=True, bold=True)

    # UC01 -> UC_GUARD (include)
    dashed_rel(
        (uc_x + uc_rx, 148), (sub_x - sub_rx - 2, 158),
        "«include»", TEAL_DARK, "arrow-open-teal", 632, 142,
    )
    # UC02 -> UC_GUARD (include)
    dashed_rel(
        (uc_x + uc_rx, 224), (sub_x - sub_rx - 2, 178),
        "«include»", TEAL_DARK, "arrow-open-teal", 634, 200,
    )
    # UC02 -> UC_SSE (include)
    dashed_rel(
        (uc_x + uc_rx, 240), (sub_x - sub_rx - 2, 260),
        "«include»", TEAL_DARK, "arrow-open-teal", 634, 255,
    )
    # UC_AUTH -> UC02 (extend)
    dashed_rel(
        (sub_x - sub_rx, 354), (uc_x + uc_rx + 2, 252),
        "«extend»", AMBER, "arrow-amber", 636, 320,
    )
    # UC04 -> UC_KB (include)
    dashed_rel(
        (uc_x + uc_rx, 412), (sub_x - sub_rx - 2, 462),
        "«include»", TEAL_DARK, "arrow-open-teal", 634, 444,
    )
    # UC03 -> UC02 (extend, routed neatly vertically between UC03 and UC02)
    c.line(uc_x, 320 - uc_ry, uc_x, 236 + uc_ry + 2, stroke=AMBER, stroke_width=1.6, dash="5,4", marker_end="arrow-amber")
    c.edge_label(uc_x, 278, "«extend»", size=10, bg=AMBER_SOFT, border=AMBER, fg=AMBER, italic=True, bold=True)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 04: C4 Level 1 System Context
# ===========================================================================
def render_04() -> Tuple[str, float, float]:
    W, H = 1080, 690
    c = SvgCanvas(W, H)
    c.title_bar(
        "C4 Level 1: System Context Diagram",
        "External Actors, Local Target Applications, Validation Testbenches, and Exported Reports",
    )

    # Top row: 2 Actors
    dev_box = (110, 92, 340, 94)
    inst_box = (630, 92, 340, 94)
    c.box(*dev_box, "Web Developer / Student", "Person — Primary User (Browser)", fill=BLUE_SOFT, stroke=BLUE, title_color=NAVY, accent_bar=BLUE, title_size=13)
    c.box(*inst_box, "Team Lead / Capstone Instructor", "Person — Academic Reviewer", fill=BLUE_SOFT, stroke=BLUE, title_color=NAVY, accent_bar=BLUE, title_size=13)

    # Center Hero System
    sys_box = (260, 294, 560, 114)
    c.box(
        *sys_box,
        "Lightweight OWASP Top 10 Vulnerability Scanner",
        "Software System — Local FastAPI Web App & Decoupled Engine (Docker / Python venv)",
        fill=NAVY, stroke=TEAL, stroke_width=2.5, title_color=WHITE, sub_color=TEAL_FILL, title_size=15, sub_size=12,
    )

    # Bottom row: 3 External Systems
    local_box = (36, 548, 310, 102)
    bench_box = (385, 548, 310, 102)
    rep_box = (734, 548, 310, 102)
    c.box(*local_box, "Developer Local Web App", "External Target (localhost / host.docker.internal)", fill=CONTAINER_BG, stroke=BORDER_DARK, accent_bar=NAVY_MID)
    c.box(*bench_box, "Validation Testbench Targets", "DVWA, OWASP Juice Shop, Local VulnBench", fill=CONTAINER_BG, stroke=BORDER_DARK, accent_bar=TEAL_DARK)
    c.box(*rep_box, "Local Filesystem Exports", "JSON & Standalone HTML Developer Reports", fill=GREEN_SOFT, stroke=GREEN, accent_bar=GREEN)

    # Dev -> Scanner
    c.polyline_arrow([(280, 186), (280, 240), (420, 240), (420, 292)], stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue")
    c.edge_label(280, 238, "Manages projects, launches scans,\nviews SSE progress & code fixes (HTTP/SSE :8000)", max_w=270, size=10, border=BLUE_BORDER)

    # Instructor -> Scanner
    c.polyline_arrow([(800, 186), (800, 240), (660, 240), (660, 292)], stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue")
    c.edge_label(800, 238, "Reviews vulnerability trends,\ntriage states & exported reports", max_w=240, size=10, border=BLUE_BORDER)

    # Scanner <-> LocalApp (offset pair)
    c.polyline_arrow([(340, 408), (340, 444), (132, 444), (132, 546)], stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(142, 470, "Sends allow-listed, rate-limited\nnon-destructive HTTP probes", max_w=190, size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    c.polyline_arrow([(248, 548), (248, 496), (390, 496), (390, 410)], stroke=MUTED_TEXT, stroke_width=1.6, dash="5,3", marker_end="arrow-slate")
    c.edge_label(278, 514, "Returns HTTP responses,\nheaders, cookies & HTML forms", max_w=195, size=10, bg=WHITE, border=BORDER_DARK)

    # Scanner <-> Testbench (offset pair)
    c.line(500, 408, 500, 546, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(460, 466, "Executes automated\nbenchmark scans on\nisolated Docker network", max_w=155, size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    c.line(580, 548, 580, 410, stroke=MUTED_TEXT, stroke_width=1.6, dash="5,3", marker_end="arrow-slate")
    c.edge_label(626, 494, "Returns HTTP responses\nfor Precision/Recall\nevaluation", max_w=150, size=10, bg=WHITE, border=BORDER_DARK)

    # Scanner -> Reports
    c.polyline_arrow([(720, 408), (720, 456), (889, 456), (889, 546)], stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.edge_label(885, 480, "Exports downloadable\ndeveloper reports", max_w=175, size=10, bg=GREEN_SOFT, border=GREEN_BORDER)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 05: C4 Level 2 Container Diagram
# ===========================================================================
def render_05() -> Tuple[str, float, float]:
    W, H = 1120, 760
    c = SvgCanvas(W, H)
    c.title_bar(
        "C4 Level 2: Container Architecture Diagram",
        "Browser Tier, Single-Container FastAPI + Decoupled Scanner Engine, SQLAlchemy Persistence, and Target",
    )

    # Tier 1: Developer Browser Tier
    c.subgraph(220, 86, 680, 102, "Developer Browser Tier", fill=BLUE_SOFT, stroke=BLUE_BORDER, header_bg=BLUE)
    webui = (260, 110, 600, 62)
    c.box(*webui, "Developer Dashboard UI", "HTML5, Tailwind CSS, Modular Vanilla JS, Chart.js — 6 Views", stroke=BLUE, accent_bar=BLUE)

    # Tier 2: Scanner Application Container
    c.subgraph(34, 240, 1052, 268, "Scanner Application Container (Python 3.12 + Uvicorn :8000)", fill=CONTAINER_LIGHT, stroke=NAVY, header_bg=NAVY)

    fastapi = (62, 272, 430, 84)
    reporter = (628, 272, 430, 84)
    worker = (62, 402, 306, 86)
    engine = (408, 402, 324, 86)
    remkb = (772, 402, 286, 86)

    c.box(*fastapi, "FastAPI REST & SSE Server", "Pydantic v2, pydantic-settings, Security Headers MW", stroke=NAVY, accent_bar=NAVY)
    c.box(*reporter, "Report Exporter", "Jinja2 Standalone HTML & Structured JSON", stroke=GREEN, accent_bar=GREEN)
    c.box(*worker, "In-Process Scan Worker", "Bounded ThreadPoolExecutor + threading.Event Cancel Registry", stroke=TEAL_DARK, accent_bar=TEAL)
    c.box(*engine, "Pure Decoupled Scanner Engine", "backend/scanner — Requests, BS4/lxml, 17 OWASP Checks", fill=TEAL_SOFT, stroke=TEAL_DARK, accent_bar=TEAL_DARK)
    c.box(*remkb, "Multi-Stack Remediation KB", "backend/scanner/remediation/kb.json", fill=AMBER_SOFT, stroke=AMBER, accent_bar=AMBER)

    # Tier 3 Left: Persistence Layer (header pill placed cleanly right of all 3 downward arrows at x=140, 268, 400)
    c.subgraph(34, 578, 666, 152, "Persistence Layer (SQLAlchemy 2.0 ORM)", fill=CONTAINER_BG, stroke=BORDER_DARK, header_bg=NAVY_MID, header_x_offset=388)
    sqlite = (58, 608, 294, 104)
    postgres = (382, 608, 294, 104)
    c.cylinder(*sqlite, "SQLite Default Database", "data/scanner.db — WAL Mode", fill=WHITE, stroke=TEAL_DARK)
    c.cylinder(*postgres, "Optional PostgreSQL 16", "--profile postgres via DATABASE_URL", fill=WHITE, stroke=MUTED_TEXT, dash="6,4")

    # Tier 3 Right: Authorized Target Web App
    target = (746, 602, 340, 114)
    c.box(*target, "Authorized Target Web App", "localhost / host.docker.internal / Testbench\n(DVWA, Juice Shop, VulnBench)", fill=RED_SOFT, stroke=RED, accent_bar=RED)

    # Edges
    # WebUI -> FastAPI (drops cleanly at x=456 to the right of AppTier header pill)
    c.polyline_arrow([(560, 172), (560, 214), (456, 214), (456, 270)], stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue")
    c.edge_label(606, 214, "REST JSON (/api/*) & Live SSE (/api/scans/{id}/stream)", max_w=340, size=10, border=BLUE_BORDER)

    # FastAPI -> Reporter
    c.line(492, 314, 626, 314, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.edge_label(560, 296, "Generates\ndownloadable reports", max_w=135, size=10, bg=GREEN_SOFT, border=GREEN_BORDER)

    # FastAPI -> Worker
    c.line(215, 356, 215, 400, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")
    c.edge_label(284, 378, "Submits scan jobs & signals cancel_event", max_w=240, size=10)

    # Worker -> Engine
    c.line(368, 445, 406, 445, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(388, 378, "", size=10) if False else None
    c.edge_label(540, 376, "Invokes ScanOrchestrator & receives progress events", max_w=285, size=10, bg=TEAL_SOFT, border=TEAL_BORDER)
    # Small indicator line from label to Worker->Engine connector
    c.line(387, 445, 387, 390, stroke=TEAL_BORDER, stroke_width=1.0, dash="3,2")

    # Engine -> RemKB
    c.line(732, 445, 770, 445, stroke=AMBER, stroke_width=1.8, marker_end="arrow-amber")
    c.edge_label(885, 378, "Loads plain-language root causes & Before/After fixes", max_w=275, size=10, bg=AMBER_SOFT, border=AMBER_BORDER)
    c.line(751, 445, 751, 390, stroke=AMBER_BORDER, stroke_width=1.0, dash="3,2")

    # FastAPI -> SQLite (routed cleanly down far-left gutter inside/alongside container)
    c.polyline_arrow([(62, 330), (46, 330), (46, 540), (140, 540), (140, 606)], stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.edge_label(138, 540, "CRUD Projects, Scans,\nFindings & Triage", max_w=155, size=10)

    # Worker -> SQLite
    c.polyline_arrow([(235, 488), (235, 558), (268, 558), (268, 606)], stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")
    c.edge_label(318, 540, "Persists Endpoints,\nEnriched Findings & Risk Score", max_w=175, size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    # FastAPI & Worker -.-> Postgres (optional dashed via shared bus, drops at x=400 left of header pill)
    c.polyline_arrow([(320, 488), (320, 520), (400, 520), (400, 606)], stroke=MUTED_TEXT, stroke_width=1.5, dash="5,4", marker_end="arrow-slate")
    c.edge_label(506, 540, "Optional drop-in dialect\nvia DATABASE_URL", max_w=170, size=10, bg=CONTAINER_LIGHT, border=BORDER_DARK, italic=True)

    # Engine -> Target
    c.polyline_arrow([(620, 488), (620, 540), (916, 540), (916, 600)], stroke=RED, stroke_width=1.9, marker_end="arrow-red")
    c.edge_label(860, 540, "Allow-listed, rate-limited\nHTTP/HTTPS requests", max_w=185, size=10, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 06: C4 Level 3 Scanner Engine Components
# ===========================================================================
def render_06() -> Tuple[str, float, float]:
    W, H = 1220, 710
    c = SvgCanvas(W, H)
    c.title_bar(
        "C4 Level 3: Scanner Engine Component Architecture",
        "Orchestration, Safety Controls, Attack Surface Discovery, 17-Check Plugin Registry, and Enrichment Pipeline",
    )

    dy = 36
    # 4 Column Subgraphs
    c.subgraph(24, 88 + dy, 280, 496, "Orchestration & Safety Controls", fill=BLUE_SOFT, stroke=BLUE_BORDER, header_bg=BLUE)
    c.subgraph(332, 88 + dy, 240, 496, "Attack Surface Discovery", fill=CONTAINER_BG, stroke=BORDER_DARK, header_bg=NAVY)
    c.subgraph(600, 88 + dy, 304, 496, "17-Check Plugin Registry (BaseCheck)", fill=TEAL_SOFT, stroke=TEAL_BORDER, header_bg=TEAL_DARK)
    c.subgraph(932, 88 + dy, 264, 496, "Enrichment & Scoring Pipeline", fill=GREEN_SOFT, stroke=GREEN_BORDER, header_bg=GREEN)

    # Col 1: Control
    orch = (40, 120 + dy, 248, 86)
    guard = (40, 238 + dy, 248, 84)
    soft404 = (40, 354 + dy, 248, 82)
    httpclient = (40, 470 + dy, 248, 94)
    c.box(*orch, "ScanOrchestrator", "Lifecycle, Progress Emitter, Error Isolation", stroke=BLUE, accent_bar=BLUE)
    c.box(*guard, "ScopeGuardrail", "Allow-List, DNS Check, Origin & Denylist", stroke=RED, accent_bar=RED)
    c.box(*soft404, "Soft404Calibrator", "Baseline Length & Similarity Fingerprint", stroke=BLUE, accent_bar=BLUE)
    c.box(*httpclient, "SafeHttpClient", "requests.Session, Rate Limiter, Cap 2000, Auth/DVWA Login", stroke=NAVY, accent_bar=NAVY)

    # Col 2: Surface
    crawler = (348, 178 + dy, 208, 108)
    inventory = (348, 368 + dy, 208, 108)
    c.box(*crawler, "BFSCrawler", "BeautifulSoup4 + lxml, Forms, Links, Params", stroke=NAVY, accent_bar=NAVY)
    c.box(*inventory, "EndpointInventory", "Normalized Method, Path, Query & Form Fields", stroke=NAVY, accent_bar=TEAL)

    # Col 3: Plugins
    reg = (616, 114 + dy, 272, 74)
    passive = (616, 206 + dy, 272, 82)
    active = (616, 302 + dy, 272, 84)
    disc = (616, 400 + dy, 272, 78)
    deep = (616, 492 + dy, 272, 74)
    c.box(*reg, "CheckRegistry", "Auto-Discovery & Quick/Standard/Deep Filter", stroke=TEAL_DARK, accent_bar=NAVY)
    c.box(*passive, "Passive Checks — 8", "Headers, CSP, Banner, Errors, Cookies, TLS, CSRF, JS", stroke=TEAL_DARK, accent_bar=TEAL)
    c.box(*active, "Active Safe Checks — 5", "CORS, SQLi Error, SQLi Boolean, Reflected XSS, Open Redirect", stroke=AMBER, accent_bar=AMBER)
    c.box(*disc, "Discovery Checks — 3", "Sensitive Files, Dir Listing, Forced Browsing Admin", stroke=BLUE, accent_bar=BLUE)
    c.box(*deep, "Deep Auth Check — 1", "IDOR Heuristic — Tentative", stroke=PURPLE, accent_bar=PURPLE)

    # Col 4: Enrichment
    dedup = (948, 152 + dy, 232, 92)
    kbenrich = (948, 294 + dy, 232, 98)
    scorer = (948, 442 + dy, 232, 96)
    c.box(*dedup, "FindingDeduplicator", "SHA-1 Fingerprint & Confidence", stroke=GREEN, accent_bar=GREEN)
    c.box(*kbenrich, "RemediationEnricher", "kb.json: FastAPI, Flask, Express, PHP, HTML", stroke=GREEN, accent_bar=GREEN)
    c.box(*scorer, "RiskScoreCalculator", "Weighted 0-100 Score Excl. False Positives", stroke=GREEN, accent_bar=GREEN)

    # Intra-Col 1 edges
    c.line(164, 206 + dy, 164, 236 + dy, stroke=BLUE, stroke_width=1.6, marker_end="arrow-blue")
    c.edge_label(164, 222 + dy, "1. Validate target", size=9, bg=BLUE_SOFT, border=BLUE_BORDER)

    # Guardrail -> HttpClient (routed left gutter inside Col 1)
    c.polyline_arrow([(40, 280 + dy), (30, 280 + dy), (30, 517 + dy), (38, 517 + dy)], stroke=RED, stroke_width=1.5, marker_end="arrow-red")
    # Orchestrator -> Soft404 (routed right inside Col 1)
    c.polyline_arrow([(288, 182 + dy), (298, 182 + dy), (298, 395 + dy), (290, 395 + dy)], stroke=BLUE, stroke_width=1.5, marker_end="arrow-blue")
    c.edge_label(258, 338 + dy, "2. Establish 404 baseline", size=9, bg=BLUE_SOFT, border=BLUE_BORDER)
    c.line(164, 436 + dy, 164, 468 + dy, stroke=NAVY, stroke_width=1.5, marker_end="arrow-navy")

    # Orchestrator -> Crawler (3. Run BFS crawl)
    c.polyline_arrow([(288, 150 + dy), (318, 150 + dy), (318, 224 + dy), (346, 224 + dy)], stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.edge_label(346, 148 + dy, "3. Run BFS crawl", size=10, bg=WHITE, border=NAVY)

    # Orchestrator -> Registry (4. Select profile checks) cleanly in white corridor above subgraphs
    c.polyline_arrow([(262, 120 + dy), (262, 82), (874, 82), (874, 112 + dy)], stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")
    c.edge_label(570, 82, "4. Select profile checks", size=10, bg=TEAL_SOFT, border=TEAL_DARK, fg=TEAL_DARK, bold=True)

    # Crawler -> HttpClient
    c.polyline_arrow([(348, 260 + dy), (318, 260 + dy), (318, 505 + dy), (290, 505 + dy)], stroke=MUTED_TEXT, stroke_width=1.5, dash="4,3", marker_end="arrow-slate")

    # Crawler -> Inventory
    c.line(452, 286 + dy, 452, 366 + dy, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")
    c.edge_label(452, 326 + dy, "Normalized endpoints", size=10)

    # Registry -> 4 check groups (left internal rail inside Col 3)
    rail_reg = 608
    c.line(616, 150 + dy, rail_reg, 150 + dy, stroke=TEAL_DARK, stroke_width=1.4)
    for box in (passive, active, disc, deep):
        by = box[1] + box[3] / 2 - 12
        c.polyline_arrow([(rail_reg, 150 + dy), (rail_reg, by), (614, by)], stroke=TEAL_DARK, stroke_width=1.4, marker_end="arrow-teal")

    # Inventory -> 4 check groups (CheckContext fan-out in gap 2-3)
    gap23 = 584
    c.line(556, 422 + dy, gap23, 422 + dy, stroke=NAVY, stroke_width=1.7)
    for box in (passive, active, disc, deep):
        by = box[1] + box[3] / 2 + 8
        c.polyline_arrow([(gap23, 422 + dy), (gap23, by), (614, by)], stroke=NAVY, stroke_width=1.6, marker_end="arrow-navy")
    c.edge_label(584, 344 + dy, "CheckContext", size=10, bg=WHITE, border=NAVY, bold=True)

    # 4 check groups -> Dedup (RawFinding fan-in in gap 3-4)
    gap34 = 918
    for box in (passive, active, disc, deep):
        by = box[1] + box[3] / 2
        c.polyline_arrow([(888, by), (gap34, by), (gap34, 198 + dy)], stroke=GREEN, stroke_width=1.6, marker_end="")
    c.line(gap34, 198 + dy, 946, 198 + dy, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(918, 250 + dy, "RawFinding", size=10, bg=GREEN_SOFT, border=GREEN, fg=GREEN, bold=True)

    # Dedup -> KBEnrich -> Scorer
    c.line(1064, 244 + dy, 1064, 292 + dy, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.line(1064, 392 + dy, 1064, 440 + dy, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")

    # Active, Discovery, DeepAuth -> SafeHttpClient via clean bottom return bus
    bus_y = 626 + dy
    for idx, box in enumerate((active, disc, deep)):
        bx_out = 888
        by_out = box[1] + box[3] - 12
        rail_x = 896 + idx * 5
        c.polyline_arrow([(bx_out, by_out), (rail_x, by_out), (rail_x, bus_y)], stroke=AMBER, stroke_width=1.4, dash="5,3", marker_end="")
    c.polyline_arrow([(906, bus_y), (164, bus_y), (164, 566 + dy)], stroke=AMBER, stroke_width=1.6, dash="5,3", marker_end="arrow-amber")
    c.edge_label(520, bus_y, "Active / Discovery / Deep Auth Probes -> SafeHttpClient (Allow-List & Rate-Limited)", max_w=480, size=10, bg=AMBER_SOFT, border=AMBER, fg=AMBER, bold=True)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 07: DFD Level 0 Context Diagram
# ===========================================================================
def render_07() -> Tuple[str, float, float]:
    W, H = 1080, 420
    c = SvgCanvas(W, H)
    c.title_bar(
        "Data Flow Diagram — Level 0 (Context Diagram)",
        "External Entities and High-Level Data Flows Crossing the Scanner System Boundary",
    )

    # Left External Entity
    dev = (34, 178, 210, 106)
    c.box(*dev, "Developer / Student", "External Entity", fill=BLUE_SOFT, stroke=BLUE, stroke_width=2.0, title_size=14, accent_bar=BLUE)

    # Center System Process (double circle)
    cx, cy, r = 540, 231, 102
    c.circle(cx, cy, r, fill=TEAL_SOFT, stroke=NAVY, stroke_width=2.2, shadow=True)
    c.circle(cx, cy, r - 6, fill=WHITE, stroke=TEAL_DARK, stroke_width=1.4)
    c.text(cx, cy - 36, "0.0", size=16, fill=TEAL_DARK, bold=True)
    c.line(cx - 56, cy - 22, cx + 56, cy - 22, stroke=BORDER_SLATE, stroke_width=1.2)
    c.text_block(cx, cy + 16, ["Lightweight OWASP", "Top 10 Scanner", "System"], size=13, fill=NAVY, bold=True)

    # Right External Entity
    tgt = (836, 178, 210, 106)
    c.box(*tgt, "Authorized Target Web App", "/ Testbench (External Entity)", fill=RED_SOFT, stroke=RED, stroke_width=2.0, title_size=13, accent_bar=RED)

    # Top-left flow: Dev -> System
    c.path(f"M 190 178 Q 315 110 {cx - r + 10} 182", stroke=BLUE, stroke_width=2.0, marker_end="arrow-blue")
    c.edge_label(322, 128, "Project Target URL, Ownership Ack,\nScan Profile, Auth & Triage Decisions", max_w=240, size=10, bg=BLUE_SOFT, border=BLUE_BORDER)

    # Bottom-left flow: System -> Dev
    c.path(f"M {cx - r + 10} 280 Q 315 352 190 286", stroke=TEAL_DARK, stroke_width=2.0, marker_end="arrow-teal")
    c.edge_label(322, 342, "Live SSE Progress, Ranked Findings,\nCode Fixes & JSON/HTML Reports", max_w=240, size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    # Top-right flow: System -> Target
    c.path(f"M {cx + r - 10} 182 Q 765 110 890 176", stroke=RED, stroke_width=2.0, marker_end="arrow-red")
    c.edge_label(758, 128, "Scoped, Rate-Limited HTTP/HTTPS\nCrawl & Safe OWASP Probes", max_w=230, size=10, bg=RED_SOFT, border=RED_BORDER)

    # Bottom-right flow: Target -> System
    c.path(f"M 890 286 Q 765 352 {cx + r - 10} 280", stroke=NAVY, stroke_width=2.0, marker_end="arrow-navy")
    c.edge_label(758, 342, "HTTP Status Codes, Response\nHeaders, Cookies & HTML Bodies", max_w=230, size=10, bg=WHITE, border=BORDER_DARK)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 08: DFD Level 1 with Trust Boundaries
# ===========================================================================
def render_08() -> Tuple[str, float, float]:
    W, H = 1140, 860
    c = SvgCanvas(W, H)
    c.title_bar(
        "Data Flow Diagram — Level 1 with Trust Boundaries",
        "Six Core Scanner Processes, Three Data Stores, and Guardrail-Enforced Network Perimeter",
    )

    # Trust Boundary 1: Developer Browser
    c.subgraph(
        36, 84, 1068, 92,
        "Trust Boundary 1: Developer Browser (Client Presentation)",
        fill=BLUE_SOFT, stroke=RED, header_bg=RED, dash="8,5",
    )
    devui = (340, 106, 460, 54)
    c.box(*devui, "Developer Web UI", "6 Modular JS Views (HTML5 + Tailwind + Chart.js)", stroke=BLUE, accent_bar=BLUE)

    # Trust Boundary 2: Scanner Process (header pill sits in 556..920 gap between x=544 and x=940)
    c.subgraph(
        36, 224, 1068, 434,
        "Trust Boundary 2: Scanner Process (Trusted Application Plane)",
        fill=CONTAINER_LIGHT, stroke=RED, header_bg=RED, dash="8,5",
        header_x_offset=520,
    )

    # 6 Processes (rounded pills / DFD process nodes)
    def proc(x: float, y: float, w: float, h: float, num: str, name: str) -> Tuple[float, float, float, float]:
        c.rect(x, y, w, h, fill=WHITE, stroke=NAVY, stroke_width=1.8, rx=22, shadow=True)
        c.rect(x + 8, y + 8, 36, h - 16, fill=NAVY, stroke=NAVY, stroke_width=1, rx=14)
        c.text(x + 26, y + h / 2 + 4, num, size=11, fill=WHITE, bold=True)
        lines = wrap_text(name, w - 58, size=11, bold=True)
        c.text_block(x + 48 + (w - 54) / 2, y + h / 2, lines, size=11, fill=NAVY, bold=True)
        return (x, y, w, h)

    p1 = proc(64, 260, 240, 58, "1.0", "Validate Input & Auth Config")
    p2 = proc(424, 260, 240, 58, "2.0", "Schedule Scan & Stream SSE")
    p6 = proc(806, 260, 268, 58, "6.0", "Compare Scans & Export Reports")

    p3 = proc(424, 496, 240, 60, "3.0", "Crawl & Normalize Endpoints")
    p4 = proc(76, 496, 240, 60, "4.0", "Run 17 Curated OWASP Checks")
    p5 = proc(806, 496, 268, 60, "5.0", "Deduplicate, Enrich & Score")

    # 3 Data Stores in middle band of TB2
    ds1 = (64, 376, 264, 52)
    ds2 = (424, 376, 264, 52)
    ds3 = (806, 376, 268, 52)
    c.dfd_store(*ds1, "D1", "Projects & Scans Store")
    c.dfd_store(*ds2, "D2", "Endpoints & Findings Store")
    c.dfd_store(*ds3, "D3", "Remediation KB (kb.json)", fill=AMBER_SOFT, stroke=AMBER)

    # Trust Boundary 3: Target Network Perimeter (header pill placed cleanly right of Guardrail arrows)
    c.subgraph(
        36, 712, 1068, 122,
        "Trust Boundary 3: Target Network Perimeter (Guardrail Enforced)",
        fill=RED_SOFT, stroke=RED, header_bg=RED, dash="8,5",
        header_x_offset=584,
    )
    guard = (110, 742, 360, 72)
    target = (660, 742, 370, 72)
    c.box(*guard, "Scope Guardrail, DNS Verifier & Rate Limiter", "Allow-List + RFC1918 + 10 req/s + Cap 2000", fill=WHITE, stroke=RED, accent_bar=RED)
    c.box(*target, "Authorized Target App", "Localhost / host.docker.internal / Testbench", fill=WHITE, stroke=NAVY, accent_bar=NAVY)

    # Data flows TB1 <-> TB2
    # DevUI -> P1
    c.polyline_arrow([(420, 160), (420, 198), (184, 198), (184, 258)], stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.edge_label(268, 198, "REST Requests (JSON)", size=10, border=BLUE_BORDER)

    # P2 -> DevUI
    c.line(544, 260, 544, 162, stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")
    c.edge_label(544, 198, "SSE Progress & Finding Events", size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    # P6 -> DevUI
    c.polyline_arrow([(940, 260), (940, 198), (720, 198), (720, 162)], stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(850, 198, "Diff Results, JSON & HTML Reports", size=10, bg=GREEN_SOFT, border=GREEN_BORDER)

    # Intra-TB2 flows
    # P1 -> DS1
    c.line(184, 318, 184, 374, stroke=NAVY, stroke_width=1.5, marker_end="arrow-navy")
    c.edge_label(184, 346, "Validated Project/Scan DTO", size=9)

    # P1 -> P2
    c.line(304, 289, 422, 289, stroke=NAVY, stroke_width=1.6, marker_end="arrow-navy")
    c.edge_label(363, 273, "Authorized Scan Job", size=9)

    # P2 -> P3 (routed cleanly right of DS2)
    c.polyline_arrow([(664, 300), (724, 300), (724, 514), (666, 514)], stroke=NAVY, stroke_width=1.6, marker_end="arrow-navy")
    c.edge_label(724, 434, "Start Crawl\nContext", size=9)

    # P3 -> DS2
    c.line(544, 496, 544, 430, stroke=TEAL_DARK, stroke_width=1.6, marker_end="arrow-teal")
    c.edge_label(544, 462, "Endpoint Inventory", size=9, bg=TEAL_SOFT, border=TEAL_BORDER)

    # P3 -> P4
    c.line(424, 526, 318, 526, stroke=NAVY, stroke_width=1.6, marker_end="arrow-navy")
    c.edge_label(371, 510, "Attack Surface Context", size=9)

    # P4 -> P5 (routed along y=586 cleanly below P3)
    c.polyline_arrow([(260, 556), (260, 594), (940, 594), (940, 558)], stroke=TEAL_DARK, stroke_width=1.6, marker_end="arrow-teal")
    c.edge_label(600, 594, "RawFinding Stream", size=10, bg=TEAL_SOFT, border=TEAL_BORDER)

    # DS3 -> P5
    c.line(940, 428, 940, 494, stroke=AMBER, stroke_width=1.6, marker_end="arrow-amber")
    c.edge_label(940, 460, "Multi-Stack Fixes & Plain Causes", size=9, bg=AMBER_SOFT, border=AMBER_BORDER)

    # P5 -> DS2
    c.polyline_arrow([(806, 536), (766, 536), (766, 402), (690, 402)], stroke=TEAL_DARK, stroke_width=1.5, marker_end="arrow-teal")
    c.edge_label(766, 492, "Enriched Findings\n& Risk Score", size=9, bg=TEAL_SOFT, border=TEAL_BORDER)

    # P5 -> DS1 (Scan Completion Metrics routed neatly along y=628 then left rail x=52 to DS1)
    c.polyline_arrow([(996, 556), (996, 636), (48, 636), (48, 402), (62, 402)], stroke=NAVY, stroke_width=1.4, dash="4,3", marker_end="arrow-navy")
    c.edge_label(540, 636, "Scan Completion Metrics (P5 -> D1)", size=9, bg=WHITE, border=BORDER_DARK)

    # DS1 -> P6 (Scan History routed cleanly via y=346 corridor to P6)
    c.polyline_arrow([(328, 392), (382, 392), (382, 344), (868, 344), (868, 320)], stroke=MUTED_TEXT, stroke_width=1.4, marker_end="arrow-slate")
    c.edge_label(638, 344, "Scan History (D1 -> 6.0)", size=9)

    # DS2 -> P6 (Findings & Fingerprints)
    c.polyline_arrow([(688, 386), (754, 386), (754, 289), (804, 289)], stroke=MUTED_TEXT, stroke_width=1.5, marker_end="arrow-slate")
    c.edge_label(754, 320, "Findings &\nFingerprints", size=9)

    # TB2 <-> TB3 flows
    # P3 <-> Guard
    c.polyline_arrow([(500, 556), (500, 686), (360, 686), (360, 740)], stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.edge_label(510, 686, "HTTP GET Crawl Requests / Filtered Responses", size=9, bg=RED_SOFT, border=RED_BORDER)
    c.polyline_arrow([(404, 742), (404, 670), (540, 670), (540, 558)], stroke=MUTED_TEXT, stroke_width=1.4, dash="4,3", marker_end="arrow-slate")

    # P4 <-> Guard
    c.line(156, 556, 156, 740, stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.line(226, 742, 226, 558, stroke=MUTED_TEXT, stroke_width=1.4, dash="4,3", marker_end="arrow-slate")
    c.edge_label(190, 686, "Safe OWASP Probes /\nProbe Responses", size=9, bg=RED_SOFT, border=RED_BORDER)

    # Guard <-> TargetApp
    c.line(470, 766, 658, 766, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label(564, 750, "Verified In-Scope Requests", size=9, bg=RED_SOFT, border=RED_BORDER)
    c.line(660, 796, 472, 796, stroke=NAVY, stroke_width=1.6, dash="4,3", marker_end="arrow-navy")
    c.edge_label(564, 812, "HTML & Headers", size=9)

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 09: Docker & Testbench Deployment Architecture
# ===========================================================================
def render_09() -> Tuple[str, float, float]:
    W, H = 1120, 670
    c = SvgCanvas(W, H)
    c.title_bar(
        "Docker & Local Testbench Deployment Architecture",
        "Single-Command Scanner Stack, Optional PostgreSQL Profile, and Isolated Vulnerable Testbenches",
    )

    # Outer Host Frame
    c.subgraph(24, 86, 1072, 558, "Developer Workstation (Windows / macOS / Linux)", fill=CONTAINER_LIGHT, stroke=NAVY, header_bg=NAVY)

    # Top row inside Host
    browser = (58, 120, 356, 76)
    local_app = (646, 120, 412, 76)
    c.box(*browser, "Developer Browser", "http://localhost:8000", fill=BLUE_SOFT, stroke=BLUE, accent_bar=BLUE)
    c.box(*local_app, "Developer Local Web App", "e.g., localhost:5000 or :8081 (Host Process)", fill=GREEN_SOFT, stroke=GREEN, accent_bar=GREEN)

    # Core Compose Frame (Left)
    c.subgraph(52, 250, 486, 370, "docker-compose.yml (Network: scanner_net)", fill=TEAL_SOFT, stroke=TEAL_DARK, header_bg=TEAL_DARK)
    scanner = (78, 286, 434, 86)
    datavol = (78, 482, 200, 106)
    pgdb = (302, 418, 210, 76)
    pgvol = (312, 520, 190, 82)
    c.box(*scanner, "scanner Container", "Python 3.12-slim, Non-Root User, Uvicorn :8000", fill=WHITE, stroke=NAVY, accent_bar=NAVY)
    c.cylinder(*datavol, "Named Volume:\nscanner_data", "/app/data/scanner.db", fill=WHITE, stroke=TEAL_DARK)
    c.box(*pgdb, "postgres Container", "Optional --profile postgres (PostgreSQL 16 :5432)", fill=WHITE, stroke=MUTED_TEXT, dash="5,4", accent_bar=BORDER_DARK, title_size=11, sub_size=10)
    c.cylinder(*pgvol, "Named Volume:\npostgres_data", "", fill=WHITE, stroke=MUTED_TEXT, dash="5,4", title_size=11)

    # Testbench Compose Frame (Right)
    c.subgraph(614, 250, 456, 370, "docker-compose.testbench.yml (Network: testbench_net)", fill=RED_SOFT, stroke=RED_BORDER, header_bg=RED)
    dvwa = (646, 286, 396, 86)
    juice = (646, 400, 396, 86)
    vulnbench = (646, 514, 396, 86)
    c.box(*dvwa, "dvwa Container", "vulnerables/web-dvwa — 127.0.0.1:8080:80", fill=WHITE, stroke=RED, accent_bar=RED)
    c.box(*juice, "juice-shop Container", "bkimminich/juice-shop — 127.0.0.1:3000:3000", fill=WHITE, stroke=RED, accent_bar=AMBER)
    c.box(*vulnbench, "vulnbench Container", "Local Flask + SQLite — 127.0.0.1:5050:5050", fill=WHITE, stroke=RED, accent_bar=TEAL_DARK)

    # Connections
    # Browser -> Scanner (drops at x=392 cleanly to the right of docker-compose header pill)
    c.polyline_arrow([(236, 196), (236, 224), (392, 224), (392, 284)], stroke=BLUE, stroke_width=1.9, marker_end="arrow-blue")
    c.edge_label(280, 224, "HTTP / SSE (127.0.0.1:8000)", size=10, bg=BLUE_SOFT, border=BLUE_BORDER)

    # Scanner -> LocalApp
    c.polyline_arrow([(450, 286), (450, 224), (852, 224), (852, 198)], stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.edge_label(650, 224, "extra_hosts: host.docker.internal:host-gateway", max_w=310, size=10, bg=GREEN_SOFT, border=GREEN_BORDER, bold=True)

    # Scanner -> DataVol
    c.line(178, 372, 178, 480, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(178, 424, "SQLite WAL\nDefault", size=10, bg=WHITE, border=TEAL_BORDER)

    # Scanner -.-> PgDB -.-> PgVol
    c.line(407, 372, 407, 416, stroke=MUTED_TEXT, stroke_width=1.5, dash="5,4", marker_end="arrow-slate")
    c.edge_label(400, 394, "Optional DATABASE_URL", size=9, bg=WHITE, border=BORDER_DARK, italic=True)
    c.line(407, 494, 407, 518, stroke=MUTED_TEXT, stroke_width=1.4, dash="5,4", marker_end="arrow-slate")

    # Scanner -> Testbench containers via clean bus in center gutter (x=576)
    bus_x = 576
    c.line(512, 329, bus_x, 329, stroke=RED, stroke_width=1.8)
    c.line(bus_x, 329, 644, 329, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label(576, 304, "http://dvwa", size=9, bg=WHITE, border=RED_BORDER, fg=RED_DARK)

    c.polyline_arrow([(bus_x, 329), (bus_x, 443), (644, 443)], stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label(576, 418, "http://juice-shop:3000", size=9, bg=WHITE, border=RED_BORDER, fg=RED_DARK)

    c.polyline_arrow([(bus_x, 443), (bus_x, 557), (644, 557)], stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label(576, 532, "http://vulnbench:5050", size=9, bg=WHITE, border=RED_BORDER, fg=RED_DARK)

    return c.render(), W, H


# ===========================================================================
# Shared UML Sequence Diagram Builder (Used by Diagrams 10 & 11)
# ===========================================================================
def _draw_sequence(
    title: str,
    subtitle: str,
    participants: Sequence[Tuple[str, str, str]],  # (id, label, accent_color)
    events: Sequence[dict],
    width: float = 1140,
    row_h: float = 34,
) -> Tuple[str, float, float]:
    n = len(participants)
    margin_x = 84
    col_step = (width - 2 * margin_x) / max(1, n - 1)
    xs = {pid: margin_x + i * col_step for i, (pid, _, _) in enumerate(participants)}

    top_box_y = 74
    box_h = 46
    box_w = min(142, col_step - 14)

    # First pass: compute vertical positions of all events
    cur_y = top_box_y + box_h + 26
    positioned: List[Tuple[dict, float, float]] = []  # (event, y_start, y_end)
    active_loops: List[Tuple[str, float]] = []
    loop_boxes: List[Tuple[str, float, float]] = []

    for ev in events:
        kind = ev["kind"]
        if kind == "loop_start":
            cur_y += 10
            active_loops.append((ev["label"], cur_y))
            cur_y += 30
        elif kind == "loop_end":
            lbl, sy = active_loops.pop()
            loop_boxes.append((lbl, sy, cur_y + 8))
            cur_y += 22
        elif kind == "note":
            y0 = cur_y
            y1 = y0 + 28
            positioned.append((ev, y0, y1))
            cur_y = y1 + 14
        elif kind == "msg":
            if ev["src"] == ev["dst"]:
                y0 = cur_y + 4
                y1 = y0 + 28
                positioned.append((ev, y0, y1))
                cur_y = y1 + 16
            else:
                y0 = cur_y + 10
                positioned.append((ev, y0, y0))
                cur_y = y0 + row_h

    bottom_box_y = cur_y + 14
    H = bottom_box_y + box_h + 26

    c = SvgCanvas(width, H)
    c.title_bar(title, subtitle)

    # Loop frames (behind lifelines & arrows)
    for lbl, y0, y1 in loop_boxes:
        lx = 26
        lw = width - 52
        c.rect(lx, y0, lw, y1 - y0, fill=TEAL_SOFT, stroke=TEAL_DARK, stroke_width=1.5, rx=6, opacity=0.65)
        tag_w = 50
        c.polygon([(lx, y0), (lx + tag_w, y0), (lx + tag_w, y0 + 16), (lx + tag_w - 8, y0 + 22), (lx, y0 + 22)],
                  fill=TEAL_DARK, stroke=TEAL_DARK, stroke_width=1.0)
        c.text(lx + 22, y0 + 15, "loop", size=11, fill=WHITE, bold=True)
        c.text(lx + tag_w + 10, y0 + 15, f"[{lbl}]", size=11, fill=TEAL_DARK, bold=True, anchor="start")

    # Lifelines
    for pid, _, _ in participants:
        px = xs[pid]
        c.line(px, top_box_y + box_h, px, bottom_box_y, stroke=BORDER_DARK, stroke_width=1.4, dash="6,5")

    # Top and bottom participant boxes
    for pid, label, accent in participants:
        px = xs[pid]
        for by in (top_box_y, bottom_box_y):
            c.box(px - box_w / 2, by, box_w, box_h, label, fill=WHITE, stroke=NAVY, stroke_width=1.6,
                  title_size=11, accent_bar=accent, rx=6)

    # Draw notes and messages
    step_num = 0
    for ev, y0, y1 in positioned:
        if ev["kind"] == "note":
            x_left = min(xs[ev["p1"]], xs[ev["p2"]]) - 62
            x_right = max(xs[ev["p1"]], xs[ev["p2"]]) + 62
            c.rect(x_left, y0, x_right - x_left, 28, fill=AMBER_SOFT, stroke=AMBER, stroke_width=1.4, rx=5)
            c.text((x_left + x_right) / 2, y0 + 18, ev["text"], size=11, fill=AMBER, bold=True)
        elif ev["kind"] == "msg":
            step_num += 1
            x1 = xs[ev["src"]]
            x2 = xs[ev["dst"]]
            style = ev.get("style", "solid")  # solid | dashed | fail
            txt = ev["text"]
            stroke = RED if style == "fail" else (TEAL_DARK if style == "dashed" else NAVY)
            dash = "5,4" if style in ("dashed", "fail") else ""
            marker = "arrow-x-red" if style == "fail" else ("arrow-open-teal" if style == "dashed" else "arrow-navy")

            if ev["src"] == ev["dst"]:
                # Self-call loop on right
                loop_w = 42
                c.polyline_arrow(
                    [(x1, y0), (x1 + loop_w, y0), (x1 + loop_w, y1), (x1 + 3, y1)],
                    stroke=stroke, stroke_width=1.6, dash=dash, marker_end=marker, radius=5,
                )
                # Number badge + text cleanly placed to the right of self-call (or left if last column)
                is_rightmost = x1 > width - 220
                if not is_rightmost:
                    bx = x1 + loop_w + 14
                    c.circle(bx, (y0 + y1) / 2, 9.5, fill=NAVY, stroke=NAVY, stroke_width=1, top=True)
                    c.text(bx, (y0 + y1) / 2 + 3.5, str(step_num), size=9, fill=WHITE, bold=True, top=True)
                    tw = measure_text(txt, size=10) + 12
                    c.rect(bx + 13, (y0 + y1) / 2 - 10, tw, 20, fill=WHITE, stroke=BORDER_SLATE, stroke_width=0.9, rx=4, top=True)
                    c.text(bx + 19, (y0 + y1) / 2 + 3.5, txt, size=10, fill=SLATE_TEXT, anchor="start", top=True)
                else:
                    bx = x1 - 14
                    c.circle(bx, (y0 + y1) / 2, 9.5, fill=NAVY, stroke=NAVY, stroke_width=1, top=True)
                    c.text(bx, (y0 + y1) / 2 + 3.5, str(step_num), size=9, fill=WHITE, bold=True, top=True)
                    c.text(bx - 14, (y0 + y1) / 2 + 3.5, txt, size=10, fill=SLATE_TEXT, anchor="end", top=True)
            else:
                # Horizontal arrow
                dx_sign = 1 if x2 > x1 else -1
                c.line(x1, y0, x2 - dx_sign * 3, y0, stroke=stroke, stroke_width=1.6, dash=dash, marker_end=marker)
                mid_x = (x1 + x2) / 2
                # Label pill positioned just above the arrow line
                badge_r = 9.0
                tw = measure_text(txt, size=10)
                pill_w = tw + 30
                pill_h = 19
                pill_x = mid_x - pill_w / 2
                # Keep inside canvas horizontally
                pill_x = max(32, min(width - 32 - pill_w, pill_x))
                pill_y = y0 - pill_h - 3
                bg = RED_SOFT if style == "fail" else (TEAL_SOFT if style == "dashed" else WHITE)
                bd = RED_BORDER if style == "fail" else (TEAL_BORDER if style == "dashed" else BORDER_SLATE)
                c.rect(pill_x, pill_y, pill_w, pill_h, fill=bg, stroke=bd, stroke_width=0.9, rx=4, top=True)
                c.circle(pill_x + 11, pill_y + pill_h / 2, badge_r - 1, fill=RED if style == "fail" else NAVY, stroke="none", stroke_width=0, top=True)
                c.text(pill_x + 11, pill_y + pill_h / 2 + 3.2, str(step_num), size=9, fill=WHITE, bold=True, top=True)
                c.text(pill_x + 23, pill_y + pill_h / 2 + 3.4, txt, size=10, fill=RED_DARK if style == "fail" else SLATE_TEXT, anchor="start", top=True)

    return c.render(), width, H


# ===========================================================================
# DIAGRAM 10: End-to-End Scan Lifecycle Sequence Diagram
# ===========================================================================
def render_10() -> Tuple[str, float, float]:
    participants = [
        ("Dev", "Developer\nBrowser", BLUE),
        ("API", "FastAPI\nServer", NAVY),
        ("DB", "SQLAlchemy\nDB", TEAL_DARK),
        ("Pool", "ThreadPool\nExecutor", NAVY_MID),
        ("Orch", "Scan\nOrchestrator", TEAL),
        ("Target", "Authorized\nTarget App", RED),
        ("KB", "Remediation\nKB", AMBER),
    ]
    events = [
        {"kind": "msg", "src": "Dev", "dst": "API", "text": "POST /api/projects/{id}/scans (profile, auth, ownership_confirmed)"},
        {"kind": "msg", "src": "API", "dst": "API", "text": "Validate Pydantic v2 schema and ScopeGuardrail allow-list"},
        {"kind": "msg", "src": "API", "dst": "DB", "text": "INSERT scans (status=queued, config_snapshot)"},
        {"kind": "msg", "src": "API", "dst": "Pool", "text": "Submit run_scan(scan_id, cancel_event)"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "202 Accepted (scan_id, status=queued)"},
        {"kind": "msg", "src": "Dev", "dst": "API", "text": "GET /api/scans/{id}/stream (EventSource SSE)"},
        {"kind": "msg", "src": "Pool", "dst": "Orch", "text": "Start execution in worker thread"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "UPDATE scans SET status=crawling, started_at=now"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE phase_change (crawling)"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data phase=crawling, progress=5%"},
        {"kind": "msg", "src": "Orch", "dst": "Target", "text": "GET random non-existent path (Soft-404 calibration)"},
        {"kind": "msg", "src": "Target", "dst": "Orch", "style": "dashed", "text": "404 or Soft-404 baseline signature"},
        {"kind": "loop_start", "label": "BFS Crawl within depth, page and request caps"},
        {"kind": "msg", "src": "Orch", "dst": "Target", "text": "Scoped rate-limited GET (respecting denylist)"},
        {"kind": "msg", "src": "Target", "dst": "Orch", "style": "dashed", "text": "HTML body, headers, cookies, status"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Parse links, forms and params via BeautifulSoup4 + lxml"},
        {"kind": "loop_end"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "Bulk INSERT endpoints"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "UPDATE scans SET status=scanning, endpoints_found=N"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE phase_change (scanning)"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data phase=scanning, endpoints_found=N"},
        {"kind": "loop_start", "label": "For each profile-selected Check in CheckRegistry"},
        {"kind": "msg", "src": "Orch", "dst": "Target", "text": "Execute passive analysis or safe active probe"},
        {"kind": "msg", "src": "Target", "dst": "Orch", "style": "dashed", "text": "HTTP response and timing"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Deduplicate RawFinding via SHA-1 fingerprint"},
        {"kind": "msg", "src": "Orch", "dst": "KB", "text": "Lookup plain explanation and multi-stack Before/After fix"},
        {"kind": "msg", "src": "KB", "dst": "Orch", "style": "dashed", "text": "EnrichedFinding payload"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "INSERT findings"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE finding_discovered and progress"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data finding summary and progress_pct"},
        {"kind": "loop_end"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Compute risk_score (0-100) excluding false_positive"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "UPDATE scans SET status=completed, risk_score, finished_at"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE scan_completed"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data status=completed, risk_score"},
        {"kind": "msg", "src": "Dev", "dst": "API", "text": "GET /api/scans/{id}/findings"},
        {"kind": "msg", "src": "API", "dst": "DB", "text": "SELECT findings JOIN endpoints"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "200 OK (Ranked findings + code fixes)"},
    ]
    return _draw_sequence(
        "End-to-End Scan Lifecycle Sequence Diagram",
        "Asynchronous Scan Enqueue, SSE Streaming, Soft-404 Calibration, BFS Crawl, 17-Check Execution, and Enrichment",
        participants,
        events,
        width=1160,
        row_h=34,
    )


# ===========================================================================
# DIAGRAM 11: Cancellation & Per-Check Error Isolation Sequence Diagram
# ===========================================================================
def render_11() -> Tuple[str, float, float]:
    participants = [
        ("Dev", "Developer\nBrowser", BLUE),
        ("API", "FastAPI\nServer", NAVY),
        ("Reg", "Cancel\nRegistry", AMBER),
        ("Orch", "Scan\nOrchestrator", TEAL_DARK),
        ("ChkA", "Plugin\nCheck A", RED),
        ("ChkB", "Plugin\nCheck B", GREEN),
        ("DB", "SQLAlchemy\nDB", NAVY_MID),
    ]
    events = [
        {"kind": "note", "p1": "Orch", "p2": "ChkB", "text": "Scenario 1 — Per-Check Error Isolation"},
        {"kind": "msg", "src": "Orch", "dst": "ChkA", "text": "run(check_context) inside try/except boundary"},
        {"kind": "msg", "src": "ChkA", "dst": "Orch", "style": "fail", "text": "Raises ReadTimeout or Unexpected Exception"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Catch exception, log structured error, record warning"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE event check_warning (check_id, error_type)"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data non-fatal warning badge (scan continues)"},
        {"kind": "msg", "src": "Orch", "dst": "ChkB", "text": "run(check_context)"},
        {"kind": "msg", "src": "ChkB", "dst": "Orch", "style": "dashed", "text": "Returns List of RawFinding"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "Commit enriched findings from Check B"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE event finding_discovered"},
        {"kind": "note", "p1": "Dev", "p2": "DB", "text": "Scenario 2 — Cooperative User Cancellation"},
        {"kind": "msg", "src": "Dev", "dst": "API", "text": "POST /api/scans/{id}/cancel"},
        {"kind": "msg", "src": "API", "dst": "Reg", "text": "Lookup threading.Event for scan_id and call cancel_event.set()"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "202 Accepted (cancellation_requested=true)"},
        {"kind": "msg", "src": "Orch", "dst": "Reg", "text": "Poll cancel_event.is_set() before next probe or check"},
        {"kind": "msg", "src": "Reg", "dst": "Orch", "style": "dashed", "text": "True (stop signal active)"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Halt active probing and preserve committed findings"},
        {"kind": "msg", "src": "Orch", "dst": "Orch", "text": "Recompute partial risk_score from committed findings"},
        {"kind": "msg", "src": "Orch", "dst": "DB", "text": "UPDATE scans SET status=cancelled, finished_at=now"},
        {"kind": "msg", "src": "Orch", "dst": "Reg", "text": "Unregister cancel_event(scan_id)"},
        {"kind": "msg", "src": "Orch", "dst": "API", "style": "dashed", "text": "Emit SSE event scan_cancelled"},
        {"kind": "msg", "src": "API", "dst": "Dev", "style": "dashed", "text": "SSE data status=cancelled, partial_findings_preserved=true"},
    ]
    return _draw_sequence(
        "Scan Cancellation & Per-Check Error Isolation Sequence",
        "Fault-Tolerant Plugin Execution and Cooperative threading.Event Cancellation Preserving Partial Results",
        participants,
        events,
        width=1160,
        row_h=36,
    )


# ===========================================================================
# DIAGRAM 12: Scan Job Lifecycle State Machine
# ===========================================================================
def render_12() -> Tuple[str, float, float]:
    W, H = 1120, 620
    c = SvgCanvas(W, H)
    c.title_bar(
        "Scan Job Lifecycle State Machine (UML State Diagram)",
        "Deterministic State Transitions Across Queued, Crawling, Scanning, Completed, Cancelled, and Failed States",
    )

    def state_box(x: float, y: float, w: float, h: float, name: str, sub: str, fill: str, stroke: str, badge_col: str) -> None:
        c.rect(x, y, w, h, fill=fill, stroke=stroke, stroke_width=2.0, rx=16, shadow=True)
        c.line(x, y + 32, x + w, y + 32, stroke=stroke, stroke_width=1.2)
        c.text(x + w / 2, y + 21, name, size=14, fill=badge_col, bold=True)
        lines = wrap_text(sub, w - 18, size=10)
        c.text_block(x + w / 2, y + 32 + (h - 32) / 2, lines, size=10, fill=MUTED_TEXT)

    # Initial pseudostate
    init_x, init_y = 66, 200
    c.circle(init_x, init_y, 12, fill=NAVY, stroke=NAVY, stroke_width=2)

    # Active spine states (row y=160)
    q = (160, 160, 156, 80)
    cr = (420, 160, 156, 80)
    sc = (680, 160, 156, 80)
    co = (918, 160, 148, 80)

    state_box(*q, "queued", "Persisted in DB;\nwaiting for worker", BLUE_SOFT, BLUE, BLUE)
    state_box(*cr, "crawling", "Soft-404 baseline &\nbounded BFS crawl", TEAL_SOFT, TEAL_DARK, TEAL_DARK)
    state_box(*sc, "scanning", "Executing profile-\nselected OWASP checks", TEAL_FILL, TEAL_DARK, NAVY)
    state_box(*co, "completed", "All checks finished &\nrisk_score saved", GREEN_SOFT, GREEN, GREEN)

    # Terminal abnormal states below
    ca = (340, 444, 174, 80)
    fa = (660, 444, 174, 80)
    state_box(*ca, "cancelled", "Cooperative stop;\npartial findings kept", AMBER_SOFT, AMBER, AMBER)
    state_box(*fa, "failed", "Pre-flight guardrail or\nfatal runtime error", RED_SOFT, RED, RED_DARK)

    # Final bullseye states
    def final_node(cx: float, cy: float) -> None:
        c.circle(cx, cy, 14, fill=WHITE, stroke=NAVY, stroke_width=2.0)
        c.circle(cx, cy, 8.5, fill=NAVY, stroke=NAVY, stroke_width=1.0)

    final_node(992, 326)  # from completed
    final_node(427, 578)  # from cancelled
    final_node(747, 578)  # from failed

    # Main Spine Transitions
    c.line(init_x + 12, init_y, q[0] - 2, init_y, stroke=NAVY, stroke_width=1.9, marker_end="arrow-navy")
    c.edge_label(112, 124, "POST /api/projects/{id}/scans\n(202 Accepted)", max_w=175, size=9, bg=BLUE_SOFT, border=BLUE_BORDER)
    c.line(112, 144, 112, 198, stroke=BLUE_BORDER, stroke_width=1.0, dash="3,2")

    c.line(q[0] + q[2], 200, cr[0] - 2, 200, stroke=NAVY, stroke_width=1.9, marker_end="arrow-navy")
    c.edge_label(368, 126, "Worker acquires\nThreadPoolExecutor slot", max_w=155, size=9)
    c.line(368, 146, 368, 198, stroke=BORDER_DARK, stroke_width=1.0, dash="3,2")

    c.line(cr[0] + cr[2], 200, sc[0] - 2, 200, stroke=TEAL_DARK, stroke_width=1.9, marker_end="arrow-teal")
    c.edge_label(628, 126, "Soft-404 calibrated &\nBFS endpoints persisted", max_w=160, size=9, bg=TEAL_SOFT, border=TEAL_BORDER)
    c.line(628, 146, 628, 198, stroke=TEAL_BORDER, stroke_width=1.0, dash="3,2")

    c.line(sc[0] + sc[2], 200, co[0] - 2, 200, stroke=GREEN, stroke_width=1.9, marker_end="arrow-green")
    c.edge_label(878, 126, "All selected checks\nfinished & risk_score saved", max_w=165, size=9, bg=GREEN_SOFT, border=GREEN_BORDER)
    c.line(878, 146, 878, 198, stroke=GREEN_BORDER, stroke_width=1.0, dash="3,2")

    # completed -> final
    c.line(992, 240, 992, 310, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    # cancelled -> final & failed -> final
    c.line(427, 524, 427, 562, stroke=AMBER, stroke_width=1.8, marker_end="arrow-amber")
    c.line(747, 524, 747, 562, stroke=RED, stroke_width=1.8, marker_end="arrow-red")

    # Transitions to cancelled (amber)
    # queued -> cancelled
    c.polyline_arrow([(204, 240), (204, 484), (338, 484)], stroke=AMBER, stroke_width=1.6, marker_end="arrow-amber")
    c.edge_label(184, 376, "User calls POST\n/api/scans/{id}/cancel\nbefore start", max_w=145, size=9, bg=AMBER_SOFT, border=AMBER_BORDER)

    # crawling -> cancelled
    c.polyline_arrow([(464, 240), (464, 442)], stroke=AMBER, stroke_width=1.6, marker_end="arrow-amber")
    c.edge_label(450, 326, "cancel_event.is_set()\nduring crawl loop", max_w=135, size=9, bg=AMBER_SOFT, border=AMBER_BORDER)

    # scanning -> cancelled
    c.polyline_arrow([(718, 240), (718, 372), (492, 372), (492, 442)], stroke=AMBER, stroke_width=1.6, marker_end="arrow-amber")
    c.edge_label(612, 372, "cancel_event.is_set()\nbetween checks or requests", max_w=160, size=9, bg=AMBER_SOFT, border=AMBER_BORDER)

    # Transitions to failed (red)
    # queued -> failed
    c.polyline_arrow([(268, 240), (268, 412), (694, 412), (694, 442)], stroke=RED, stroke_width=1.5, dash="5,3", marker_end="arrow-red")
    c.edge_label(354, 412, "Pre-flight guardrail failure\nor unreachable target", max_w=165, size=9, bg=RED_SOFT, border=RED_BORDER)

    # crawling -> failed
    c.polyline_arrow([(538, 240), (538, 296), (748, 296), (748, 442)], stroke=RED, stroke_width=1.5, dash="5,3", marker_end="arrow-red")
    c.edge_label(624, 296, "Fatal network loss or\ndatabase write failure", max_w=148, size=9, bg=RED_SOFT, border=RED_BORDER)

    # scanning -> failed
    c.polyline_arrow([(796, 240), (796, 442)], stroke=RED, stroke_width=1.5, dash="5,3", marker_end="arrow-red")
    c.edge_label(854, 344, "Unhandled orchestrator\nruntime error", max_w=140, size=9, bg=RED_SOFT, border=RED_BORDER)

    # Note right of scanning (placed cleanly bottom-right)
    nx, ny, nw, nh = 860, 424, 232, 114
    c.rect(nx, ny, nw, nh, fill="#FFFBEB", stroke=AMBER, stroke_width=1.5, rx=6, shadow=True)
    c.text(nx + 12, ny + 22, "Note (scanning state):", size=11, fill=AMBER, bold=True, anchor="start")
    n_lines = wrap_text(
        "Per-check exceptions are isolated inside try/except and emit check_warning events without transitioning the scan to failed.",
        nw - 24, size=10,
    )
    c.text_block(nx + nw / 2, ny + 70, n_lines, size=10, fill=SLATE_TEXT)
    c.line(836, 224, nx + 24, ny, stroke=AMBER, stroke_width=1.2, dash="4,3")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 13: Cross-Functional Swimlane Activity Diagram
# ===========================================================================
def render_13() -> Tuple[str, float, float]:
    W, H = 1140, 820
    c = SvgCanvas(W, H)
    c.title_bar(
        "Cross-Functional Swimlane Activity Diagram",
        "End-to-End Developer, FastAPI API, Scanner Engine, and Persistence Coordination Flow",
    )

    lanes = [
        ("Developer", BLUE_SOFT, BLUE),
        ("FastAPI API", CONTAINER_LIGHT, NAVY),
        ("Scanner Engine", TEAL_SOFT, TEAL_DARK),
        ("Database & Remediation KB", GREEN_SOFT, GREEN),
    ]
    lx0 = 28
    lw = 271
    top_y = 84
    lh = 712
    for i, (name, bg, hdr) in enumerate(lanes):
        lx = lx0 + i * lw
        c.rect(lx, top_y, lw, lh, fill=bg, stroke=BORDER_DARK, stroke_width=1.4, rx=0)
        c.rect(lx, top_y, lw, 38, fill=hdr, stroke=hdr, stroke_width=1.0, rx=0)
        c.text(lx + lw / 2, top_y + 24, name, size=13, fill=WHITE, bold=True)

    def cx(lane_idx: int) -> float:
        return lx0 + lane_idx * lw + lw / 2

    bw = 232
    bh = 62

    def node(lane: int, y: float, title: str, stroke: str, accent: str) -> Tuple[float, float, float, float]:
        x = cx(lane) - bw / 2
        c.box(x, y, bw, bh, title, fill=WHITE, stroke=stroke, accent_bar=accent, title_size=11)
        return (x, y, bw, bh)

    # Row-aligned chronological placement
    a1 = node(0, 140, "Create Project & Confirm Ownership Checkbox", BLUE, BLUE)
    b1 = node(1, 140, "Validate Input (Pydantic v2) & Enforce Allow-List", NAVY, NAVY)
    d1 = node(3, 140, "Persist Project & Scan Row (status=queued)", GREEN, GREEN)

    a2 = node(0, 246, "Select Profile (Quick / Standard / Deep) & Launch Scan", BLUE, BLUE)
    b2 = node(1, 246, "Enqueue Job on ThreadPoolExecutor & Return 202", NAVY, NAVY)
    c1 = node(2, 246, "Calibrate Soft-404 & Run BFS Crawler (BS4/lxml)", TEAL_DARK, TEAL)

    d2 = node(3, 352, "Store Normalized Endpoints Inventory", GREEN, GREEN)
    c2 = node(2, 352, "Execute Curated OWASP Checks with Error Isolation", TEAL_DARK, TEAL)
    b3 = node(1, 352, "Stream SSE Events via /api/scans/{id}/stream", NAVY, TEAL)
    a3 = node(0, 352, "Monitor Live SSE Progress & Findings Feed", BLUE, BLUE)

    # Decision diamond C3 in Lane 2
    c3_cx, c3_cy = cx(2) - 10, 492
    c.diamond(c3_cx, c3_cy, 152, 76, "Cancel Event Set?", fill=AMBER_SOFT, stroke=AMBER, size=11)

    d3 = node(3, 462, "Lookup kb.json Multi-Stack Fixes & Save Findings", GREEN, AMBER)
    c4 = node(2, 594, "Deduplicate (SHA-1) & Compute Risk Score (0-100)", TEAL_DARK, TEAL)
    d4 = node(3, 594, "Commit Final Scan Status (completed or cancelled)", GREEN, GREEN)

    a4 = node(0, 594, "Open Fix Modal, Copy Stack Code Fix & Triage Finding", BLUE, BLUE)
    b4 = node(1, 704, "Serve Filtered Findings, Triage PATCH, Diff & Exports", NAVY, NAVY)
    a5 = node(0, 704, "Re-Scan, Compare Diff (New/Fixed) & Export Report", BLUE, GREEN)

    # Arrows
    # A1 -> B1 -> D1
    c.line(a1[0] + bw, a1[1] + bh / 2, b1[0] - 2, b1[1] + bh / 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.line(b1[0] + bw, b1[1] + bh / 2, d1[0] - 2, d1[1] + bh / 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")

    # D1 -> A2 (routed cleanly via horizontal channel y=222)
    c.polyline_arrow([(cx(3), d1[1] + bh), (cx(3), 222), (cx(0), 222), (cx(0), a2[1] - 2)], stroke=GREEN, stroke_width=1.6, marker_end="arrow-green")

    # A2 -> B2 -> C1
    c.line(a2[0] + bw, a2[1] + bh / 2, b2[0] - 2, b2[1] + bh / 2, stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.line(b2[0] + bw, b2[1] + bh / 2, c1[0] - 2, c1[1] + bh / 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")

    # B2 -> B3 -> A3
    c.line(cx(1), b2[1] + bh, cx(1), b3[1] - 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.line(b3[0], b3[1] + bh / 2, a3[0] + bw + 2, a3[1] + bh / 2, stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")

    # C1 -> D2 -> C2 -> C3
    c.polyline_arrow([(c1[0] + bw, c1[1] + bh / 2), (cx(3), c1[1] + bh / 2), (cx(3), d2[1] - 2)], stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")
    c.line(d2[0], d2[1] + bh / 2, c2[0] + bw + 2, c2[1] + bh / 2, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.line(c3_cx, c2[1] + bh, c3_cx, c3_cy - 38, stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")

    # C3 -- No - Continue Checks --> D3
    c.line(c3_cx + 76, c3_cy, d3[0] - 2, d3[1] + bh / 2, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label((c3_cx + 76 + d3[0]) / 2 - 4, c3_cy - 20, "No — Continue", size=9, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)

    # D3 -> C4
    c.polyline_arrow([(cx(3) - 40, d3[1] + bh), (cx(3) - 40, 560), (cx(2) + 40, 560), (cx(2) + 40, c4[1] - 2)], stroke=TEAL_DARK, stroke_width=1.6, marker_end="arrow-teal")

    # C4 -> D4
    c.line(c4[0] + bw, c4[1] + bh / 2, d4[0] - 2, d4[1] + bh / 2, stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")

    # C3 -- Yes - Stop Gracefully --> D4
    c.polyline_arrow([(c3_cx, c3_cy + 39), (c3_cx, 544), (cx(3) + 56, 544), (cx(3) + 56, d4[1] - 2)], stroke=AMBER, stroke_width=1.7, dash="5,3", marker_end="arrow-amber")
    c.edge_label(cx(2) + 56, 544, "Yes — Stop Gracefully", size=9, bg=AMBER_SOFT, border=AMBER_BORDER, fg=AMBER, bold=True)

    # D4 -> B3 (SSE final completion push routed cleanly at bottom-center up to B3)
    c.polyline_arrow([(cx(3), d4[1] + bh), (cx(3), 680), (cx(1), 680), (cx(1), b3[1] + bh + 2)], stroke=TEAL_DARK, stroke_width=1.6, dash="5,3", marker_end="arrow-teal")
    c.edge_label(cx(2), 680, "SSE scan_completed / scan_cancelled", size=9, bg=TEAL_SOFT, border=TEAL_BORDER)

    # A3 -> A4 -> B4 -> A5
    c.line(cx(0), a3[1] + bh, cx(0), a4[1] - 2, stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.polyline_arrow([(a4[0] + bw, a4[1] + bh / 2), (cx(1) - 44, a4[1] + bh / 2), (cx(1) - 44, b4[1] - 2)], stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.line(b4[0], b4[1] + bh / 2, a5[0] + bw + 2, a5[1] + bh / 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 14: UML Class Diagram (Scanner Plugin Architecture)
# ===========================================================================
def render_14() -> Tuple[str, float, float]:
    W, H = 1480, 1220
    c = SvgCanvas(W, H)
    c.title_bar(
        "Scanner Plugin Architecture — UML Class Diagram",
        "Orchestration, Auto-Discovered CheckRegistry, Abstract BaseCheck Hierarchy, Context, and Remediation Models",
    )

    def uml_class(
        x: float,
        y: float,
        w: float,
        name: str,
        attrs: Sequence[str],
        methods: Sequence[str],
        stereotype: str = "",
        header_bg: str = NAVY,
        border: str = NAVY,
    ) -> Tuple[float, float, float, float]:
        hdr_h = 44 if stereotype else 30
        lh = 15.5
        attr_h = max(12, len(attrs) * lh + 10) if attrs else 8
        meth_h = max(12, len(methods) * lh + 10) if methods else 8
        total_h = hdr_h + attr_h + meth_h

        c.rect(x, y, w, total_h, fill=WHITE, stroke=border, stroke_width=1.6, rx=5, shadow=True)
        # Header background
        c.rect(x, y, w, hdr_h, fill=header_bg, stroke=border, stroke_width=1.6, rx=5)
        # Square off bottom of header
        c.rect(x + 1, y + hdr_h - 6, w - 2, 6, fill=header_bg, stroke="none", stroke_width=0, rx=0)
        if stereotype:
            c.text(x + w / 2, y + 16, f"«{stereotype}»", size=10, fill=TEAL_FILL, italic=True)
            c.text(x + w / 2, y + 34, name, size=12, fill=WHITE, bold=True, italic=(stereotype == "abstract"))
        else:
            c.text(x + w / 2, y + 20, name, size=12, fill=WHITE, bold=True)

        # Attributes
        cur_y = y + hdr_h + 15
        for a in attrs:
            c.text(x + 9, cur_y, a, size=10, fill=SLATE_TEXT, mono=True, anchor="start")
            cur_y += lh

        # Divider
        div_y = y + hdr_h + attr_h
        c.line(x, div_y, x + w, div_y, stroke=BORDER_DARK, stroke_width=1.1)

        # Methods
        cur_y = div_y + 15
        for m in methods:
            is_abs = m.endswith("*")
            c.text(x + 9, cur_y, m, size=10, fill=NAVY, mono=True, italic=is_abs, anchor="start")
            cur_y += lh

        return (x, y, w, total_h)

    # Row 1: Orchestrator, CheckRegistry, CheckContext, RawFinding
    orch = uml_class(
        28, 86, 360, "ScanOrchestrator",
        [
            "-CheckRegistry registry",
            "-SafeHttpClient http_client",
            "-BFSCrawler crawler",
            "-RemediationEnricher enricher",
            "-Event cancel_event",
        ],
        [
            "+run_scan(scan_id, target_url, profile) ScanSummary",
            "+emit_event(event_type, payload) void",
            "+compute_risk_score(findings) int",
            "-execute_check_isolated(check, ctx) List<RawFinding>",
        ],
        header_bg=NAVY,
    )

    reg = uml_class(
        430, 86, 330, "CheckRegistry",
        ["-Dict<str, BaseCheck> checks"],
        [
            "+register(check_cls) void",
            "+discover_plugins() void",
            "+get_checks_for_profile(profile) List<BaseCheck>",
            "+list_catalog() List<Dict>",
        ],
        header_bg=TEAL_DARK, border=TEAL_DARK,
    )

    ctx = uml_class(
        800, 86, 290, "CheckContext",
        [
            "+str scan_id",
            "+str target_url",
            "+str profile",
            "+SafeHttpClient http_client",
            "+List<EndpointRecord> endpoints",
            "+Soft404Baseline soft404",
            "+Event cancel_event",
            "+bool auth_enabled",
        ],
        ["+check_cancelled() bool"],
        header_bg=BLUE, border=BLUE,
    )

    rawf = uml_class(
        1134, 86, 316, "RawFinding",
        [
            "+str check_id",
            "+str title",
            "+str severity",
            "+str confidence",
            "+str http_method",
            "+str affected_url",
            "+str parameter_name",
            "+str evidence_snippet",
            "+str endpoint_id",
        ],
        ["+compute_fingerprint() str"],
        header_bg=NAVY_MID, border=NAVY_MID,
    )

    # Row 2: BaseCheck (center-left), EnrichedFinding & RemediationFix (right)
    base = uml_class(
        420, 386, 350, "BaseCheck",
        [
            "+str check_id",
            "+str name",
            "+str category",
            "+str owasp_category",
            "+str cwe_id",
            "+str default_severity",
            "+List<str> profiles",
        ],
        [
            "+run(ctx) List<RawFinding>*",
            "+is_applicable(ctx) bool",
        ],
        stereotype="abstract", header_bg=TEAL_DARK, border=TEAL_DARK,
    )

    enrf = uml_class(
        1134, 386, 316, "EnrichedFinding",
        [
            "+str id",
            "+str fingerprint",
            "+str owasp_category",
            "+str cwe_id",
            "+str status",
            "+str plain_explanation",
            "+RemediationFix remediation",
        ],
        [],
        header_bg=GREEN, border=GREEN,
    )

    remf = uml_class(
        1134, 622, 316, "RemediationFix",
        [
            "+str summary",
            "+str root_cause",
            "+List<str> verification_steps",
            "+Dict<str, CodeSnippet> stacks",
        ],
        [],
        header_bg=AMBER, border=AMBER,
    )

    # Row 3: 4 Abstract Subclasses of BaseCheck (placed cleanly below RemediationFix)
    passive = uml_class(
        28, 804, 344, "PassiveCheck",
        ["+str category"],
        ["+analyze_response(endpoint, headers, body)", "    -> List<RawFinding>"],
        stereotype="abstract", header_bg=TEAL, border=TEAL_DARK,
    )
    active = uml_class(
        394, 804, 348, "ActiveSafeCheck",
        ["+str category"],
        ["+send_non_destructive_probe(ctx, endpoint,", "    payload) -> Response"],
        stereotype="abstract", header_bg=AMBER, border=AMBER,
    )
    disc = uml_class(
        764, 804, 336, "DiscoveryCheck",
        ["+str category"],
        ["+probe_wordlist_paths(ctx, paths)", "    -> List<RawFinding>"],
        stereotype="abstract", header_bg=BLUE, border=BLUE,
    )
    deep = uml_class(
        1122, 804, 328, "DeepAuthCheck",
        ["+str category"],
        ["+compare_object_ids(ctx, endpoint)", "    -> List<RawFinding>"],
        stereotype="abstract", header_bg=PURPLE, border=PURPLE,
    )

    # Row 4: 4 Concrete Example Checks
    c_hdr = uml_class(
        56, 1050, 288, "MissingSecurityHeadersCheck",
        ["+str check_id"],
        ["+run(ctx) List<RawFinding>"],
        header_bg=NAVY_MID, border=TEAL_DARK,
    )
    c_sql = uml_class(
        424, 1050, 288, "SqliErrorBasedCheck",
        ["+str check_id"],
        ["+run(ctx) List<RawFinding>"],
        header_bg=NAVY_MID, border=AMBER,
    )
    c_file = uml_class(
        788, 1050, 288, "SensitiveFilesCheck",
        ["+str check_id"],
        ["+run(ctx) List<RawFinding>"],
        header_bg=NAVY_MID, border=BLUE,
    )
    c_idor = uml_class(
        1142, 1050, 288, "IdorHeuristicCheck",
        ["+str check_id"],
        ["+run(ctx) List<RawFinding>"],
        header_bg=NAVY_MID, border=PURPLE,
    )

    # Relationships
    # ScanOrchestrator --> CheckRegistry : queries plugins
    c.line(orch[0] + orch[2], 150, reg[0] - 2, 150, stroke=NAVY, stroke_width=1.6, marker_end="arrow-open-navy")
    c.edge_label(409, 122, "queries\nplugins", size=9)

    # ScanOrchestrator --> CheckContext : builds and passes (routed via y=316 below Reg)
    c.polyline_arrow([(208, orch[1] + orch[3]), (208, 316), (860, 316), (860, ctx[1] + ctx[3] + 2)], stroke=BLUE, stroke_width=1.6, marker_end="arrow-blue")
    c.edge_label(340, 316, "builds and passes", size=9, bg=BLUE_SOFT, border=BLUE_BORDER)

    # ScanOrchestrator ..> EnrichedFinding : enriches and persists (routed via y=348)
    c.polyline_arrow([(120, orch[1] + orch[3]), (120, 348), (1082, 348), (1082, 468), (enrf[0] - 2, 468)], stroke=GREEN, stroke_width=1.5, dash="5,4", marker_end="arrow-green")
    c.edge_label(280, 348, "enriches and persists", size=9, bg=GREEN_SOFT, border=GREEN_BORDER)

    # CheckRegistry o-- BaseCheck : manages 17 checks
    c.line(595, reg[1] + reg[3], 595, base[1] - 2, stroke=NAVY, stroke_width=1.6, marker_start="uml-agg")
    c.edge_label(595, 290, "manages 17 checks", size=10, bg=TEAL_SOFT, border=TEAL_DARK, fg=TEAL_DARK, bold=True)

    # BaseCheck ..> CheckContext : reads
    c.polyline_arrow([(base[0] + base[2], 446), (945, 446), (945, ctx[1] + ctx[3] + 2)], stroke=BLUE, stroke_width=1.5, dash="5,4", marker_end="arrow-open-navy")
    c.edge_label(945, 366, "reads", size=9, bg=BLUE_SOFT, border=BLUE_BORDER)

    # BaseCheck ..> RawFinding : yields
    c.polyline_arrow([(base[0] + base[2], 494), (1034, 494), (1034, 248), (rawf[0] - 2, 248)], stroke=NAVY, stroke_width=1.5, dash="5,4", marker_end="arrow-open-navy")
    c.edge_label(1034, 316, "yields", size=9)

    # EnrichedFinding --|> RawFinding : extends with KB
    c.line(1292, enrf[1], 1292, rawf[1] + rawf[3] + 2, stroke=NAVY, stroke_width=1.7, marker_end="uml-inherit")
    c.edge_label(1292, 346, "extends with KB", size=9, bg=GREEN_SOFT, border=GREEN_BORDER)

    # EnrichedFinding *-- RemediationFix : embeds
    c.line(1292, enrf[1] + enrf[3], 1292, remf[1] - 2, stroke=NAVY, stroke_width=1.7, marker_start="uml-comp")
    c.edge_label(1292, 594, "embeds", size=9, bg=AMBER_SOFT, border=AMBER_BORDER)

    # Inheritance tree bus: 4 Abstract Subclasses --|> BaseCheck (cleanly below RemediationFix)
    bus_y = 762
    base_mid_x = base[0] + base[2] / 2
    base_bot_y = base[1] + base[3]
    c.line(base_mid_x, bus_y, base_mid_x, base_bot_y + 2, stroke=NAVY, stroke_width=1.8, marker_end="uml-inherit")
    child_xs = [
        passive[0] + passive[2] / 2,
        active[0] + active[2] / 2,
        disc[0] + disc[2] / 2,
        deep[0] + deep[2] / 2,
    ]
    c.line(child_xs[0], bus_y, child_xs[-1], bus_y, stroke=NAVY, stroke_width=1.8)
    for chx in child_xs:
        c.line(chx, 804, chx, bus_y, stroke=NAVY, stroke_width=1.8)

    # Concrete checks --|> Abstract checks
    for concrete, parent in ((c_hdr, passive), (c_sql, active), (c_file, disc), (c_idor, deep)):
        mx = concrete[0] + concrete[2] / 2
        c.line(mx, concrete[1], mx, parent[1] + parent[3] + 2, stroke=NAVY, stroke_width=1.7, marker_end="uml-inherit")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 15: 3NF Entity-Relationship Diagram (Crow's Foot)
# ===========================================================================
def render_15() -> Tuple[str, float, float]:
    W, H = 1320, 1126
    c = SvgCanvas(W, H)
    c.title_bar(
        "Third Normal Form (3NF) Entity-Relationship Diagram",
        "Relational Schema for PROJECTS, SCANS, ENDPOINTS, and FINDINGS (SQLite WAL & PostgreSQL 16 Compatible)",
    )

    def erd_table(
        x: float,
        y: float,
        w: float,
        name: str,
        rows: Sequence[Tuple[str, str, str, str]],  # (key, dtype, col, desc)
        header_bg: str = NAVY,
    ) -> Tuple[float, float, float, float]:
        hdr_h = 34
        row_h = 22.5
        h = hdr_h + len(rows) * row_h + 6
        c.rect(x, y, w, h, fill=WHITE, stroke=header_bg, stroke_width=1.8, rx=7, shadow=True)
        c.rect(x, y, w, hdr_h, fill=header_bg, stroke=header_bg, stroke_width=1.5, rx=7)
        c.rect(x + 1, y + hdr_h - 6, w - 2, 6, fill=header_bg, stroke="none", stroke_width=0, rx=0)
        c.text(x + 14, y + 22, name, size=13, fill=WHITE, bold=True, anchor="start")
        c.text(x + w - 12, y + 21, f"{len(rows)} columns", size=10, fill=TEAL_FILL, anchor="end")

        for i, (key, dtype, col, desc) in enumerate(rows):
            ry = y + hdr_h + i * row_h
            if i % 2 == 1:
                c.rect(x + 1.5, ry, w - 3, row_h, fill=CONTAINER_LIGHT, stroke="none", stroke_width=0, rx=0)
            mid_y = ry + row_h / 2 + 3.5
            # PK / FK badge
            if key == "PK":
                c.rect(x + 8, ry + 3.5, 26, 15, fill=AMBER_FILL, stroke=AMBER, stroke_width=1.0, rx=3)
                c.text(x + 21, mid_y - 0.5, "PK", size=9, fill=AMBER, bold=True)
            elif key == "FK":
                c.rect(x + 8, ry + 3.5, 26, 15, fill=BLUE_FILL, stroke=BLUE, stroke_width=1.0, rx=3)
                c.text(x + 21, mid_y - 0.5, "FK", size=9, fill=BLUE, bold=True)

            c.text(x + 42, mid_y, col, size=10, fill=NAVY, bold=(key in ("PK", "FK")), mono=True, anchor="start")
            c.text(x + 178, mid_y, dtype, size=9.5, fill=TEAL_DARK, mono=True, anchor="start")
            # Truncate desc safely if needed (never clips)
            max_dw = w - 246
            d_txt = desc
            while measure_text(d_txt, size=9) > max_dw and len(d_txt) > 8:
                d_txt = d_txt[:-2] + "…"
            c.text(x + 240, mid_y, d_txt, size=9, fill=MUTED_TEXT, anchor="start")

        return (x, y, w, h)

    projects_rows = [
        ("PK", "varchar", "id", "UUID v4 primary key"),
        ("", "varchar", "name", "Project display name"),
        ("", "varchar", "target_url", "Allow-listed base URL"),
        ("", "varchar", "framework_hint", "fastapi|flask|express|php|html|auto"),
        ("", "boolean", "ownership_confirmed", "Mandatory explicit authorization flag"),
        ("", "text", "description", "Optional developer notes"),
        ("", "datetime", "created_at", "UTC creation timestamp"),
        ("", "datetime", "updated_at", "UTC update timestamp"),
    ]

    scans_rows = [
        ("PK", "varchar", "id", "UUID v4 primary key"),
        ("FK", "varchar", "project_id", "References PROJECTS.id"),
        ("", "varchar", "profile", "quick|standard|deep"),
        ("", "varchar", "status", "queued|crawling|scanning|completed|failed|cancelled"),
        ("", "integer", "progress_pct", "0 to 100 completion percentage"),
        ("", "varchar", "current_phase", "Active execution phase label"),
        ("", "integer", "endpoints_found", "Count of normalized endpoints"),
        ("", "integer", "requests_sent", "Total HTTP requests dispatched"),
        ("", "integer", "risk_score", "Weighted score 0-100 excl. false_positive"),
        ("", "integer", "critical_count", "Open/active critical finding count"),
        ("", "integer", "high_count", "Open/active high finding count"),
        ("", "integer", "medium_count", "Open/active medium finding count"),
        ("", "integer", "low_count", "Open/active low finding count"),
        ("", "integer", "info_count", "Open/active info finding count"),
        ("", "json", "config_snapshot", "Rate limit, max requests, auth mode (redacted)"),
        ("", "text", "error_message", "Fatal scan error if status=failed"),
        ("", "datetime", "started_at", "Worker execution start UTC"),
        ("", "datetime", "finished_at", "Worker completion/cancel UTC"),
        ("", "datetime", "created_at", "Enqueue timestamp UTC"),
    ]

    endpoints_rows = [
        ("PK", "varchar", "id", "UUID v4 primary key"),
        ("FK", "varchar", "scan_id", "References SCANS.id"),
        ("", "varchar", "method", "HTTP method GET|POST|PUT|DELETE"),
        ("", "text", "url", "Full normalized endpoint URL"),
        ("", "varchar", "normalized_path", "Canonical path without query string"),
        ("", "integer", "status_code", "Observed HTTP response status"),
        ("", "varchar", "content_type", "Response MIME media type"),
        ("", "integer", "depth", "BFS crawl depth from base URL"),
        ("", "json", "query_params", "Discovered URL query parameter names"),
        ("", "json", "form_fields", "Extracted HTML form input descriptors"),
        ("", "datetime", "discovered_at", "Discovery timestamp UTC"),
    ]

    findings_rows = [
        ("PK", "varchar", "id", "UUID v4 primary key"),
        ("FK", "varchar", "scan_id", "References SCANS.id"),
        ("FK", "varchar", "endpoint_id", "Nullable FK to ENDPOINTS.id"),
        ("", "varchar", "check_id", "One of 17 curated check identifiers"),
        ("", "varchar", "owasp_category", "OWASP Top 10 2021 code e.g. A03:2021"),
        ("", "varchar", "cwe_id", "CWE identifier e.g. CWE-89"),
        ("", "varchar", "title", "Developer-friendly finding title"),
        ("", "varchar", "severity", "critical|high|medium|low|info"),
        ("", "varchar", "confidence", "high|medium|low|tentative"),
        ("", "varchar", "status", "open|fixed|false_positive|accepted"),
        ("", "varchar", "fingerprint", "SHA-1 deduplication & diff digest"),
        ("", "varchar", "http_method", "Exact vulnerable HTTP method"),
        ("", "text", "affected_url", "Exact vulnerable endpoint URL"),
        ("", "varchar", "parameter_name", "Exact parameter or header name"),
        ("", "text", "evidence_snippet", "Sanitized non-destructive proof snippet"),
        ("", "text", "plain_explanation", "Plain-language root cause description"),
        ("", "json", "remediation_json", "Multi-stack Before/After fix payload"),
        ("", "text", "triage_note", "Optional developer triage rationale"),
        ("", "datetime", "created_at", "Finding creation UTC"),
        ("", "datetime", "updated_at", "Last triage update UTC"),
    ]

    t_proj = erd_table(34, 86, 540, "PROJECTS", projects_rows, header_bg=NAVY)
    t_scan = erd_table(696, 86, 590, "SCANS", scans_rows, header_bg=TEAL_DARK)
    t_endp = erd_table(34, 654, 540, "ENDPOINTS", endpoints_rows, header_bg=BLUE)
    t_find = erd_table(696, 622, 590, "FINDINGS", findings_rows, header_bg=RED_DARK)

    # Crow's Foot notation helpers
    def draw_one_mandatory(x: float, y: float, orient: str) -> None:
        if orient == "h":
            c.line(x, y - 8, x, y + 8, stroke=NAVY, stroke_width=1.8)
            c.line(x + 6, y - 8, x + 6, y + 8, stroke=NAVY, stroke_width=1.8)
        else:
            c.line(x - 8, y, x + 8, y, stroke=NAVY, stroke_width=1.8)
            c.line(x - 8, y + 6, x + 8, y + 6, stroke=NAVY, stroke_width=1.8)

    def draw_zero_or_one(x: float, y: float) -> None:
        c.line(x, y - 8, x, y + 8, stroke=NAVY, stroke_width=1.8)
        c.circle(x + 11, y, 5, fill=WHITE, stroke=NAVY, stroke_width=1.8)

    def draw_zero_or_many(x: float, y: float, direction: str) -> None:
        # direction: "right" (crow opens to right onto table left edge), "down" (opens downward onto table top edge)
        if direction == "right":
            c.circle(x - 18, y, 5, fill=WHITE, stroke=NAVY, stroke_width=1.8)
            c.line(x - 12, y, x, y - 9, stroke=NAVY, stroke_width=1.8)
            c.line(x - 12, y, x, y, stroke=NAVY, stroke_width=1.8)
            c.line(x - 12, y, x, y + 9, stroke=NAVY, stroke_width=1.8)
        elif direction == "left":
            c.circle(x + 18, y, 5, fill=WHITE, stroke=NAVY, stroke_width=1.8)
            c.line(x + 12, y, x, y - 9, stroke=NAVY, stroke_width=1.8)
            c.line(x + 12, y, x, y, stroke=NAVY, stroke_width=1.8)
            c.line(x + 12, y, x, y + 9, stroke=NAVY, stroke_width=1.8)
        elif direction == "down":
            c.circle(x, y - 18, 5, fill=WHITE, stroke=NAVY, stroke_width=1.8)
            c.line(x, y - 12, x - 9, y, stroke=NAVY, stroke_width=1.8)
            c.line(x, y - 12, x, y, stroke=NAVY, stroke_width=1.8)
            c.line(x, y - 12, x + 9, y, stroke=NAVY, stroke_width=1.8)

    # 1) PROJECTS ||--o{ SCANS : "triggers"
    y_ps = 196
    c.line(t_proj[0] + t_proj[2], y_ps, t_scan[0], y_ps, stroke=NAVY, stroke_width=1.8)
    draw_one_mandatory(t_proj[0] + t_proj[2] + 8, y_ps, "h")
    draw_zero_or_many(t_scan[0], y_ps, "right")
    c.edge_label((t_proj[0] + t_proj[2] + t_scan[0]) / 2, y_ps - 18, "triggers (1 : 0..N)", size=10, bg=WHITE, border=NAVY, bold=True)

    # 2) SCANS ||--o{ ENDPOINTS : "discovers" (routed from left side of SCANS down to top of ENDPOINTS)
    c.polyline_arrow(
        [(t_scan[0], 456), (620, 456), (620, 560), (304, 560), (304, t_endp[1])],
        stroke=BLUE, stroke_width=1.8, marker_end="",
    )
    draw_one_mandatory(t_scan[0] - 14, 456, "h")
    draw_zero_or_many(304, t_endp[1], "down")
    c.edge_label(460, 560, "discovers (1 : 0..N)", size=10, bg=BLUE_SOFT, border=BLUE, fg=BLUE, bold=True)

    # 3) SCANS ||--o{ FINDINGS : "produces" (vertical line between SCANS bottom and FINDINGS top)
    x_sf = 990
    c.line(x_sf, t_scan[1] + t_scan[3], x_sf, t_find[1], stroke=RED_DARK, stroke_width=1.8)
    draw_one_mandatory(x_sf, t_scan[1] + t_scan[3] + 8, "v")
    draw_zero_or_many(x_sf, t_find[1], "down")
    c.edge_label(x_sf + 86, (t_scan[1] + t_scan[3] + t_find[1]) / 2, "produces (1 : 0..N)", size=10, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    # 4) ENDPOINTS |o--o{ FINDINGS : "maps_to" (horizontal between ENDPOINTS right and FINDINGS left)
    y_ef = 798
    c.line(t_endp[0] + t_endp[2], y_ef, t_find[0], y_ef, stroke=TEAL_DARK, stroke_width=1.8)
    draw_zero_or_one(t_endp[0] + t_endp[2] + 8, y_ef)
    draw_zero_or_many(t_find[0], y_ef, "right")
    c.edge_label((t_endp[0] + t_endp[2] + t_find[0]) / 2, y_ef - 18, "maps_to (0..1 : 0..N)", size=10, bg=TEAL_SOFT, border=TEAL_DARK, fg=TEAL_DARK, bold=True)

    # Legend strip bottom-left under ENDPOINTS
    ly = 988
    c.rect(34, ly, 540, 88, fill=CONTAINER_LIGHT, stroke=BORDER_DARK, stroke_width=1.3, rx=8)
    c.text(50, ly + 22, "Notation & Normalization Guarantees:", size=11, fill=NAVY, bold=True, anchor="start")
    c.text(50, ly + 42, "•  || = Exactly One (Mandatory)   •  |o = Zero or One (Nullable FK)", size=10, fill=SLATE_TEXT, anchor="start")
    c.text(50, ly + 60, "•  o{ = Zero or Many (0..N)       •  3NF: Zero transitive dependencies; snapshots immutable", size=10, fill=SLATE_TEXT, anchor="start")
    c.text(50, ly + 78, "•  SQLAlchemy 2.0 portable dialect: SQLite (WAL) default + optional PostgreSQL 16", size=10, fill=TEAL_DARK, bold=True, anchor="start")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 16: 9-Gate Scope Guardrail Decision Flowchart
# ===========================================================================
def render_16() -> Tuple[str, float, float]:
    W, H = 1120, 1340
    c = SvgCanvas(W, H)
    c.title_bar(
        "9-Gate Scope Guardrail & Safe HTTP Request Pipeline",
        "Mandatory Pre-Request Ownership, URL Validation, Denylist, RFC1918 DNS Rebinding Defense, and Redirect Verification",
    )

    spine_x = 396
    right_x = 768
    rb_w = 312
    rb_h = 58

    # Start stadium
    c.rect(spine_x - 210, 82, 420, 44, fill=NAVY, stroke=NAVY, stroke_width=1.6, rx=22, shadow=True)
    c.text(spine_x, 108, "Outbound HTTP Request Candidate (method, target_url, scan_ctx)", size=11, fill=WHITE, bold=True)

    # Gate 1
    g1_y = 190
    c.diamond(spine_x, g1_y, 260, 72, "Gate 1: UI Ownership Confirmed?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, 126, spine_x, g1_y - 36, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.box(right_x, g1_y - rb_h / 2, rb_w, rb_h, "Block Request — 403", "OwnershipNotConfirmedError", fill=RED_SOFT, stroke=RED, title_color=RED_DARK, accent_bar=RED)
    c.line(spine_x + 130, g1_y, right_x - 2, g1_y, stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.edge_label(638, g1_y - 14, "No", size=10, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    # Gate 2
    g2_y = 306
    c.diamond(spine_x, g2_y, 310, 78, "Gate 2: Valid HTTP/HTTPS Scheme & No Embedded Creds?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g1_y + 36, spine_x, g2_y - 39, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g1_y + 36 + g2_y - 39) / 2, "Yes", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)
    c.box(right_x, g2_y - rb_h / 2, rb_w, rb_h, "Block Request — 400", "InvalidTargetURLError", fill=RED_SOFT, stroke=RED, title_color=RED_DARK, accent_bar=RED)
    c.line(spine_x + 155, g2_y, right_x - 2, g2_y, stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.edge_label(650, g2_y - 14, "No", size=10, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    # Gate 3
    g3_y = 426
    c.diamond(spine_x, g3_y, 300, 78, "Gate 3: Matches Destructive / Logout Route Denylist?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g2_y + 39, spine_x, g3_y - 39, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g2_y + 39 + g3_y - 39) / 2, "Yes", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)
    c.box(right_x, g3_y - rb_h / 2, rb_w, rb_h, "Skip Route Safely", "Log GuardrailSkip Event", fill=AMBER_SOFT, stroke=AMBER, title_color=AMBER, accent_bar=AMBER)
    c.line(spine_x + 150, g3_y, right_x - 2, g3_y, stroke=AMBER, stroke_width=1.7, marker_end="arrow-amber")
    c.edge_label(652, g3_y - 16, "Yes (/logout, /signout,\n/delete, /remove, /reset)", max_w=175, size=9, bg=AMBER_SOFT, border=AMBER_BORDER, fg=AMBER, bold=True)

    # Gate 4
    g4_y = 546
    c.diamond(spine_x, g4_y, 300, 78, "Gate 4: Hostname in Hardcoded Allow-List or RFC1918?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g3_y + 39, spine_x, g4_y - 39, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g3_y + 39 + g4_y - 39) / 2, "No", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)
    c.box(right_x, g4_y - rb_h / 2, rb_w, rb_h, "Block Request — 403", "OutOfScopeHostError", fill=RED_SOFT, stroke=RED, title_color=RED_DARK, accent_bar=RED)
    c.line(spine_x + 150, g4_y, right_x - 2, g4_y, stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.edge_label(652, g4_y - 16, "No (External Domain /\nPublic Host)", max_w=165, size=9, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    # Gate 5 (Process) -> Gate 5B (Diamond)
    g5_y = 632
    c.box(spine_x - 166, g5_y, 332, 46, "Gate 5: Pre-Request DNS Resolve (socket.getaddrinfo)", fill=BLUE_SOFT, stroke=BLUE, accent_bar=BLUE, title_size=11)
    c.line(spine_x, g4_y + 39, spine_x, g5_y - 2, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g4_y + 39 + g5_y) / 2, "Yes", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)

    g5b_y = 740
    c.diamond(spine_x, g5b_y, 314, 78, "Every Resolved IP Loopback or RFC1918 Private?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g5_y + 46, spine_x, g5b_y - 39, stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.box(right_x, g5b_y - rb_h / 2, rb_w, rb_h, "Block Request — 403", "DNSRebindingBlockedError", fill=RED_SOFT, stroke=RED, title_color=RED_DARK, accent_bar=RED)
    c.line(spine_x + 157, g5b_y, right_x - 2, g5b_y, stroke=RED, stroke_width=1.7, marker_end="arrow-red")
    c.edge_label(654, g5b_y - 18, "No (Public IP or Link-Local\n169.254.169.254)", max_w=172, size=9, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True)

    # Gate 6
    g6_y = 858
    c.diamond(spine_x, g6_y, 310, 76, "Gate 6: Request Count < 2000 and Not Cancelled?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g5b_y + 39, spine_x, g6_y - 38, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g5b_y + 39 + g6_y - 38) / 2, "Yes", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)
    c.box(right_x, g6_y - rb_h / 2, rb_w, rb_h, "Halt Scan Cleanly", "(BudgetExceeded / Cancelled)", fill=AMBER_SOFT, stroke=AMBER, title_color=AMBER, accent_bar=AMBER)
    c.line(spine_x + 155, g6_y, right_x - 2, g6_y, stroke=AMBER, stroke_width=1.7, marker_end="arrow-amber")
    c.edge_label(654, g6_y - 16, "No (Cap Reached or\nCancel Event Set)", max_w=160, size=9, bg=AMBER_SOFT, border=AMBER_BORDER, fg=AMBER, bold=True)

    # Gate 7 (Process) -> Dispatch (Process)
    g7_y = 936
    c.box(spine_x - 166, g7_y, 332, 44, "Gate 7: Token-Bucket Rate Limiter (Default 10 req/s)", fill=TEAL_SOFT, stroke=TEAL_DARK, accent_bar=TEAL, title_size=11)
    c.line(spine_x, g6_y + 38, spine_x, g7_y - 2, stroke=GREEN, stroke_width=1.7, marker_end="arrow-green")
    c.edge_label(spine_x + 24, (g6_y + 38 + g7_y) / 2, "Yes", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)

    disp_y = 1004
    c.box(spine_x - 196, disp_y, 392, 48, "Dispatch Non-Destructive Request", "(allow_redirects=False, timeout=10s)", fill=NAVY, stroke=NAVY, title_color=WHITE, sub_color=TEAL_FILL, title_size=11, sub_size=10)
    c.line(spine_x, g7_y + 44, spine_x, disp_y - 2, stroke=TEAL_DARK, stroke_width=1.7, marker_end="arrow-teal")

    # Gate 8
    g8_y = 1118
    c.diamond(spine_x, g8_y, 300, 76, "Gate 8: Redirect Status (301/302/303/307/308)?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, disp_y + 48, spine_x, g8_y - 38, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    # Gate 8 -- No --> Ok
    c.rect(right_x, g8_y - 28, rb_w, 56, fill=GREEN, stroke=GREEN, stroke_width=1.6, rx=28, shadow=True)
    c.text_block(right_x + rb_w / 2, g8_y, ["Return HttpResponse to", "Crawler / Check Plugin"], size=11, fill=WHITE, bold=True)
    c.line(spine_x + 150, g8_y, right_x - 2, g8_y, stroke=GREEN, stroke_width=1.8, marker_end="arrow-green")
    c.edge_label(650, g8_y - 14, "No", size=10, bg=GREEN_SOFT, border=GREEN_BORDER, fg=GREEN, bold=True)

    # Gate 9
    g9_y = 1248
    c.diamond(spine_x, g9_y, 310, 80, "Gate 9: Same-Origin Location & Redirect Hops <= 5?", fill=AMBER_SOFT, stroke=AMBER)
    c.line(spine_x, g8_y + 38, spine_x, g9_y - 40, stroke=AMBER, stroke_width=1.7, marker_end="arrow-amber")
    c.edge_label(spine_x + 24, (g8_y + 38 + g9_y - 40) / 2, "Yes", size=10, bg=AMBER_SOFT, border=AMBER_BORDER, fg=AMBER, bold=True)

    # Gate 9 -- No --> B5
    c.box(right_x, g9_y - 31, rb_w, 62, "Do Not Follow Redirect", "Return 3xx for open_redirect Analysis", fill=BLUE_SOFT, stroke=BLUE, title_color=NAVY, accent_bar=BLUE)
    c.line(spine_x + 155, g9_y, right_x - 2, g9_y, stroke=BLUE, stroke_width=1.7, marker_end="arrow-blue")
    c.edge_label(654, g9_y - 18, "No (Cross-Origin\nor Hop Limit)", max_w=148, size=9, bg=BLUE_SOFT, border=BLUE_BORDER, fg=BLUE, bold=True)

    # Gate 9 -- Yes (Resolve Relative Location) --> Gate 2 (routed cleanly up far-left margin x=88)
    loop_x = 84
    c.polyline_arrow(
        [(spine_x - 155, g9_y), (loop_x, g9_y), (loop_x, g2_y), (spine_x - 157, g2_y)],
        stroke=TEAL_DARK, stroke_width=2.0, dash="6,4", marker_end="arrow-teal",
    )
    c.edge_label(loop_x + 62, 780, "Yes (Resolve Relative\nLocation -> Re-validate\nfrom Gate 2)", max_w=145, size=10, bg=TEAL_SOFT, border=TEAL_DARK, fg=TEAL_DARK, bold=True)

    return c.render(), W, H


# ===========================================================================
# Shared Publication Chart Builder (Diagrams 17 & 18)
# ===========================================================================
def _draw_bar_line_chart(
    title: str,
    subtitle: str,
    categories: Sequence[str],
    y_label: str,
    y_max: int,
    y_step: int,
    bar_values: Sequence[float],
    line_values: Sequence[float],
    bar_legend: str,
    line_legend: str,
    bar_unit: str,
    line_unit: str,
    bar_color: str = TEAL,
    line_color: str = NAVY,
) -> Tuple[str, float, float]:
    W, H = 1040, 560
    c = SvgCanvas(W, H)
    c.title_bar(title, subtitle)

    # Plot margins (with 30px internal headroom above y_max so high data badges never clip or flip onto bars)
    px0, py0 = 104, 118
    px1, py1 = 986, 466
    pw = px1 - px0
    ph = py1 - py0
    headroom = 30.0
    eff_ph = ph - headroom

    # Subtle chart area card
    c.rect(px0, py0, pw, ph, fill=CONTAINER_LIGHT, stroke=BORDER_SLATE, stroke_width=1.2, rx=4)

    # Horizontal gridlines & Y ticks
    for val in range(0, y_max + 1, y_step):
        gy = py1 - (val / y_max) * eff_ph
        c.line(px0, gy, px1, gy, stroke=BORDER_SLATE if val > 0 else NAVY, stroke_width=1.0 if val > 0 else 1.6, dash="4,4" if val > 0 else "")
        c.text(px0 - 12, gy + 4, str(val), size=11, fill=MUTED_TEXT, anchor="end")

    # Left axis line
    c.line(px0, py0, px0, py1, stroke=NAVY, stroke_width=1.6)

    # Y-axis rotated label
    ymid = (py0 + py1) / 2
    c.raw(
        f'<text x="38" y="{ymid:.1f}" text-anchor="middle" font-family="{FONT_SANS}" '
        f'font-size="13" font-weight="700" fill="{NAVY}" transform="rotate(-90 38 {ymid:.1f})">'
        f'{esc(y_label)}</text>'
    )

    n = len(categories)
    slot_w = pw / n
    bar_w = min(76, slot_w * 0.46)

    line_pts: List[Tuple[float, float]] = []
    for i, cat in enumerate(categories):
        cx = px0 + (i + 0.5) * slot_w
        bv = bar_values[i]
        lv = line_values[i]

        bh = (bv / y_max) * eff_ph
        by = py1 - bh
        # Bar with rounded top
        c.rect(cx - bar_w / 2, by, bar_w, bh, fill=bar_color, stroke=TEAL_DARK, stroke_width=1.2, rx=4)
        # Square off bottom of bar
        if bh > 6:
            c.rect(cx - bar_w / 2 + 0.6, py1 - 5, bar_w - 1.2, 5, fill=bar_color, stroke="none", stroke_width=0, rx=0)

        # Bar value label inside top of bar (white bold) if tall enough, else above
        if bh >= 34:
            c.text(cx, by + 22, f"{int(bv)}{bar_unit}", size=11, fill=WHITE, bold=True)
        else:
            c.text(cx, by - 8, f"{int(bv)}{bar_unit}", size=11, fill=TEAL_DARK, bold=True)

        # Category label on X axis
        cat_lines = wrap_text(cat, slot_w - 14, size=12, bold=True)
        c.text_block(cx, py1 + 26, cat_lines, size=12, fill=NAVY, bold=True)

        ly = py1 - (lv / y_max) * eff_ph
        line_pts.append((cx, ly))

    # Draw connecting line
    d_line = f"M {line_pts[0][0]:.1f} {line_pts[0][1]:.1f} " + " ".join(f"L {x:.1f} {y:.1f}" for x, y in line_pts[1:])
    c.path(d_line, stroke=line_color, stroke_width=2.8, fill="none")

    # Draw line points & non-overlapping value badges (always cleanly above the marker!)
    for i, (cx, ly) in enumerate(line_pts):
        lv = line_values[i]
        c.circle(cx, ly, 6.2, fill=WHITE, stroke=line_color, stroke_width=2.6, top=True)
        badge_y = ly - 20
        c.edge_label(cx, badge_y, f"{int(lv)}{line_unit}", size=10, bg=WHITE, border=line_color, fg=line_color, bold=True)

    # Legend box at top right above plot
    leg_w = 430
    leg_x = px1 - leg_w
    leg_y = 76
    c.rect(leg_x, leg_y, leg_w, 30, fill=WHITE, stroke=BORDER_SLATE, stroke_width=1.2, rx=6)
    # Bar swatch
    c.rect(leg_x + 14, leg_y + 8, 16, 14, fill=bar_color, stroke=TEAL_DARK, stroke_width=1.0, rx=2)
    c.text(leg_x + 38, leg_y + 19, bar_legend, size=11, fill=NAVY, bold=True, anchor="start")
    # Line swatch
    lx_s = leg_x + 215
    c.line(lx_s, leg_y + 15, lx_s + 26, leg_y + 15, stroke=line_color, stroke_width=2.8)
    c.circle(lx_s + 13, leg_y + 15, 4.5, fill=WHITE, stroke=line_color, stroke_width=2.2)
    c.text(lx_s + 34, leg_y + 19, line_legend, size=11, fill=NAVY, bold=True, anchor="start")

    return c.render(), W, H


# ===========================================================================
# DIAGRAM 17: Target Accuracy Baseline on VulnBench
# ===========================================================================
def render_17() -> Tuple[str, float, float]:
    return _draw_bar_line_chart(
        title="Target Accuracy Baseline on VulnBench (Bars = Recall %, Line = Precision %)",
        subtitle="Expected Detection Recall and Precision Targets Across OWASP Top 10 (2021) Vulnerability Categories",
        categories=["A01 Access", "A02 Crypto", "A03 Injection", "A05 Misconfig", "A06 Outdated", "A07 Auth"],
        y_label="Target Score (%)",
        y_max=100,
        y_step=20,
        bar_values=[85, 95, 85, 92, 90, 88],
        line_values=[88, 98, 90, 95, 95, 90],
        bar_legend="Recall Target (%)",
        line_legend="Precision Target (%)",
        bar_unit="%",
        line_unit="%",
        bar_color=TEAL,
        line_color=NAVY,
    )


# ===========================================================================
# DIAGRAM 18: Target Coverage and Latency SLA Profile
# ===========================================================================
def render_18() -> Tuple[str, float, float]:
    return _draw_bar_line_chart(
        title="Target Coverage and Latency SLA Profile (Bars = Coverage %, Line = Duration s)",
        subtitle="Expected Vulnerability Coverage Percentage vs. End-to-End Scan Duration Across Benchmark Profiles",
        categories=["Quick VulnBench", "Standard VulnBench", "Deep VulnBench", "Standard DVWA", "Standard JuiceShop"],
        y_label="Coverage (%) / Duration (s)",
        y_max=120,
        y_step=20,
        bar_values=[55, 95, 100, 88, 35],
        line_values=[8, 28, 65, 42, 55],
        bar_legend="Coverage Target (%)",
        line_legend="Latency SLA (seconds)",
        bar_unit="%",
        line_unit="s",
        bar_color=TEAL,
        line_color=RED,
    )


# ===========================================================================
# DIAGRAM 19: Classic Top-Down Master System Flowchart
# ===========================================================================
def render_19() -> Tuple[str, float, float]:
    W, H = 1080, 1620
    c = SvgCanvas(W, H)
    c.title_bar(
        "Classic Top-Down Master System Flowchart",
        "End-to-End Decision Flow: Target Authorization, Bounded BFS Crawl, Profile Checks, Cancellation & Report Delivery",
    )

    cx = 400.0        # Main vertical execution spine
    loop_x = 112.0    # Left return bus for bounded crawl & check loops
    err_x = 665.0     # Right column for early-termination process boxes
    err_w = 278.0
    bus_x = 1015.0    # Right vertical END collector bus

    # Helper for crisp flowchart decision diamonds with slightly tighter wrap
    def flow_diamond(dcx: float, dcy: float, dw: float, dh: float, label: str, size: int = 11) -> None:
        pts = [(dcx, dcy - dh / 2), (dcx + dw / 2, dcy), (dcx, dcy + dh / 2), (dcx - dw / 2, dcy)]
        c.polygon(pts, fill=AMBER_SOFT, stroke=AMBER, stroke_width=1.8, shadow=True)
        lines = wrap_text(label, dw * 0.56, size=size, bold=True)
        c.text_block(dcx, dcy, lines, size=size, fill=NAVY, bold=True)

    # 1. START (Terminator pill)
    c.terminator(cx, 92, 152, 40, "START", fill=TEAL_DARK, stroke=TEAL_DARK, text_color=WHITE, size=13)
    c.line(cx, 112, cx, 134, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 2. Input Parallelogram
    c.parallelogram(
        cx - 218, 136, 436, 54,
        "Input Target URL, Stack, Profile & Ownership Confirmation",
        slant=20, fill=BLUE_SOFT, stroke=BLUE, size=12, text_color=NAVY,
    )
    c.line(cx, 190, cx, 214, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 3. Decision 1: Target Authorized & In Allow-List?
    d1_y, d1_w, d1_h = 258.0, 276.0, 84.0
    flow_diamond(cx, d1_y, d1_w, d1_h, "Target Authorized & In Allow-List?", size=11)

    # 3a. No -> Reject Scan (403 TARGET_NOT_ALLOWED) -> END bus
    c.line(cx + d1_w / 2, d1_y, err_x - 2, d1_y, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label((cx + d1_w / 2 + err_x) / 2, d1_y, "No", max_w=60, size=10, bg=RED_FILL, border=RED, fg=RED_DARK, bold=True)
    c.box(
        err_x, d1_y - 26, err_w, 52,
        "Reject Scan", "(403 TARGET_NOT_ALLOWED)",
        fill=RED_SOFT, stroke=RED, title_color=RED_DARK, sub_color=RED_DARK,
        rx=4, title_size=12, sub_size=10, accent_bar=RED,
    )
    c.polyline_arrow(
        [(err_x + err_w, d1_y), (bus_x, d1_y)],
        stroke=RED, stroke_width=1.8, marker_end="", radius=0,
    )

    # 3b. Yes -> Create Scan
    c.line(cx, d1_y + d1_h / 2, cx, 342, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(cx, 320, "Yes", max_w=60, size=10, bg=GREEN_FILL, border=GREEN, fg=GREEN, bold=True)

    # 4. Process: Create Scan (Queued), Open SSE Stream & Calibrate Soft-404
    p1_y, p1_h = 344.0, 52.0
    c.box(
        cx - 210, p1_y, 420, p1_h,
        "Create Scan (Queued), Open SSE Stream & Calibrate Soft-404",
        fill=WHITE, stroke=NAVY, title_color=NAVY, rx=4, title_size=11, accent_bar=TEAL,
    )
    c.line(cx, p1_y + p1_h, cx, 420, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 5. Decision 2: Target Reachable?
    d2_y, d2_w, d2_h = 456.0, 232.0, 68.0
    flow_diamond(cx, d2_y, d2_w, d2_h, "Target Reachable?", size=11)

    # 5a. No -> Mark Scan Failed & Log Error -> END bus
    c.line(cx + d2_w / 2, d2_y, err_x - 2, d2_y, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label((cx + d2_w / 2 + err_x) / 2, d2_y, "No", max_w=60, size=10, bg=RED_FILL, border=RED, fg=RED_DARK, bold=True)
    c.box(
        err_x, d2_y - 26, err_w, 52,
        "Mark Scan Failed & Log Error",
        fill=RED_SOFT, stroke=RED, title_color=RED_DARK,
        rx=4, title_size=12, accent_bar=RED,
    )
    c.polyline_arrow(
        [(err_x + err_w, d2_y), (bus_x, d2_y)],
        stroke=RED, stroke_width=1.8, marker_end="", radius=0,
    )
    c.circle(bus_x, d2_y, 4.0, fill=RED, stroke=WHITE, stroke_width=1.2, top=True)

    # 5b. Yes -> Bounded BFS Crawl
    c.line(cx, d2_y + d2_h / 2, cx, 532, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(cx, 510, "Yes", max_w=60, size=10, bg=GREEN_FILL, border=GREEN, fg=GREEN, bold=True)

    # 6. Process: Bounded BFS Crawl (Links, Forms, Params) & Persist Endpoints
    p2_y, p2_h = 534.0, 54.0
    c.box(
        cx - 210, p2_y, 420, p2_h,
        "Bounded BFS Crawl (Links, Forms, Params) & Persist Endpoints",
        fill=WHITE, stroke=NAVY, title_color=NAVY, rx=4, title_size=11, accent_bar=TEAL,
    )
    c.line(cx, p2_y + p2_h, cx, 612, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 7. Decision 3: Crawl Limit Reached or Cancelled?
    d3_y, d3_w, d3_h = 656.0, 276.0, 84.0
    flow_diamond(cx, d3_y, d3_w, d3_h, "Crawl Limit Reached or Cancelled?", size=11)

    # 7a. No -> Loop back to Bounded BFS Crawl
    c.polyline_arrow(
        [(cx - d3_w / 2, d3_y), (loop_x, d3_y), (loop_x, p2_y + p2_h / 2), (cx - 210 - 2, p2_y + p2_h / 2)],
        stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue", radius=8.0,
    )
    c.edge_label((loop_x + cx - d3_w / 2) / 2, d3_y, "No", max_w=60, size=10, bg=BLUE_FILL, border=BLUE, fg=BLUE, bold=True)

    # 7b. Yes -> Select Scan Profile
    c.line(cx, d3_y + d3_h / 2, cx, 738, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(cx, 716, "Yes", max_w=60, size=10, bg=GREEN_FILL, border=GREEN, fg=GREEN, bold=True)

    # 8. Decision 4: Select Scan Profile
    d4_y, d4_w, d4_h = 774.0, 232.0, 68.0
    flow_diamond(cx, d4_y, d4_w, d4_h, "Select Scan Profile", size=11)

    # 9. Three Profile Process Boxes
    prof_y, prof_h, prof_w = 848.0, 56.0, 184.0
    p_quick_cx = 184.0
    p_std_cx = cx
    p_deep_cx = 616.0

    # Branch arrows from Select Scan Profile
    c.polyline_arrow(
        [(cx - d4_w / 2, d4_y), (p_quick_cx, d4_y), (p_quick_cx, prof_y - 2)],
        stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy", radius=7.0,
    )
    c.edge_label((p_quick_cx + cx - d4_w / 2) / 2, d4_y, "Quick", max_w=80, size=10, bg=TEAL_FILL, border=TEAL_DARK, fg=TEAL_DARK, bold=True)

    c.line(cx, d4_y + d4_h / 2, cx, prof_y - 2, stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy")
    c.edge_label(cx, (d4_y + d4_h / 2 + prof_y) / 2 - 1, "Standard", max_w=84, size=10, bg=BLUE_FILL, border=BLUE, fg=BLUE, bold=True)

    c.polyline_arrow(
        [(cx + d4_w / 2, d4_y), (p_deep_cx, d4_y), (p_deep_cx, prof_y - 2)],
        stroke=NAVY, stroke_width=1.7, marker_end="arrow-navy", radius=7.0,
    )
    c.edge_label((p_deep_cx + cx + d4_w / 2) / 2, d4_y, "Deep", max_w=80, size=10, bg=PURPLE_FILL, border=PURPLE, fg=PURPLE, bold=True)

    c.box(
        p_quick_cx - prof_w / 2, prof_y, prof_w, prof_h,
        "Run 8 Passive Checks", "(Headers, CSP, Cookies, JS)",
        fill=TEAL_SOFT, stroke=TEAL_DARK, title_color=NAVY, sub_color=MUTED_TEXT,
        rx=4, title_size=11, sub_size=9, accent_bar=TEAL,
    )
    c.box(
        p_std_cx - prof_w / 2, prof_y, prof_w, prof_h,
        "+ 5 Active Safe Probes", "(CORS, SQLi, XSS, Redirect)",
        fill=BLUE_SOFT, stroke=BLUE, title_color=NAVY, sub_color=MUTED_TEXT,
        rx=4, title_size=11, sub_size=9, accent_bar=BLUE,
    )
    c.box(
        p_deep_cx - prof_w / 2, prof_y, prof_w, prof_h,
        "+ 3 Discovery & IDOR Checks", "(Files, Dir, Admin, IDOR)",
        fill=PURPLE_SOFT, stroke=PURPLE, title_color=NAVY, sub_color=MUTED_TEXT,
        rx=4, title_size=11, sub_size=9, accent_bar=PURPLE,
    )

    # Merge bar from all 3 profiles into Execute Next Check Plugin
    merge_y = prof_y + prof_h + 18.0
    c.line(p_quick_cx, prof_y + prof_h, p_quick_cx, merge_y, stroke=NAVY, stroke_width=1.7)
    c.line(p_std_cx, prof_y + prof_h, p_std_cx, merge_y, stroke=NAVY, stroke_width=1.7)
    c.line(p_deep_cx, prof_y + prof_h, p_deep_cx, merge_y, stroke=NAVY, stroke_width=1.7)
    c.line(p_quick_cx, merge_y, p_deep_cx, merge_y, stroke=NAVY, stroke_width=1.7)
    c.line(cx, merge_y, cx, 946, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 10. Process: Execute Next Check Plugin (Per-Check Error Isolation)
    p3_y, p3_h = 948.0, 52.0
    c.box(
        cx - 210, p3_y, 420, p3_h,
        "Execute Next Check Plugin (Per-Check Error Isolation)",
        fill=WHITE, stroke=NAVY, title_color=NAVY, rx=4, title_size=11, accent_bar=TEAL,
    )
    c.line(cx, p3_y + p3_h, cx, 1024, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 11. Decision 5: User Cancelled Scan?
    d5_y, d5_w, d5_h = 1060.0, 240.0, 68.0
    flow_diamond(cx, d5_y, d5_w, d5_h, "User Cancelled Scan?", size=11)

    # 11a. Yes -> Mark Cancelled & Save Partial Findings -> END bus
    c.line(cx + d5_w / 2, d5_y, err_x - 2, d5_y, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.edge_label((cx + d5_w / 2 + err_x) / 2, d5_y, "Yes", max_w=60, size=10, bg=AMBER_FILL, border=AMBER, fg=AMBER, bold=True)
    c.box(
        err_x, d5_y - 26, err_w, 52,
        "Mark Cancelled &", "Save Partial Findings",
        fill=AMBER_SOFT, stroke=AMBER, title_color=NAVY, sub_color=AMBER,
        rx=4, title_size=11, sub_size=10, accent_bar=AMBER,
    )
    c.polyline_arrow(
        [(err_x + err_w, d5_y), (bus_x, d5_y)],
        stroke=RED, stroke_width=1.8, marker_end="", radius=0,
    )
    c.circle(bus_x, d5_y, 4.0, fill=RED, stroke=WHITE, stroke_width=1.2, top=True)

    # 11b. No -> More Checks Remaining?
    c.line(cx, d5_y + d5_h / 2, cx, 1136, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(cx, 1114, "No", max_w=60, size=10, bg=GREEN_FILL, border=GREEN, fg=GREEN, bold=True)

    # 12. Decision 6: More Checks Remaining?
    d6_y, d6_w, d6_h = 1172.0, 250.0, 68.0
    flow_diamond(cx, d6_y, d6_w, d6_h, "More Checks Remaining?", size=11)

    # 12a. Yes -> Loop back to Execute Next Check Plugin
    c.polyline_arrow(
        [(cx - d6_w / 2, d6_y), (loop_x, d6_y), (loop_x, p3_y + p3_h / 2), (cx - 210 - 2, p3_y + p3_h / 2)],
        stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue", radius=8.0,
    )
    c.edge_label((loop_x + cx - d6_w / 2) / 2, d6_y, "Yes", max_w=60, size=10, bg=BLUE_FILL, border=BLUE, fg=BLUE, bold=True)

    # 12b. No -> Deduplicate & Score Risk
    c.line(cx, d6_y + d6_h / 2, cx, 1248, stroke=TEAL_DARK, stroke_width=1.8, marker_end="arrow-teal")
    c.edge_label(cx, 1226, "No", max_w=60, size=10, bg=GREEN_FILL, border=GREEN, fg=GREEN, bold=True)

    # 13. Process: Deduplicate (SHA-1), Score Risk (0-100) & Attach Multi-Stack Fixes
    p4_y, p4_h = 1250.0, 52.0
    c.box(
        cx - 218, p4_y, 436, p4_h,
        "Deduplicate (SHA-1), Score Risk (0-100) & Attach Multi-Stack Fixes",
        fill=WHITE, stroke=NAVY, title_color=NAVY, rx=4, title_size=11, accent_bar=TEAL,
    )
    c.line(cx, p4_y + p4_h, cx, 1324, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 14. Process: Persist Findings to SQLite / PostgreSQL & Mark Completed
    p5_y, p5_h = 1326.0, 52.0
    c.box(
        cx - 218, p5_y, 436, p5_h,
        "Persist Findings to SQLite / PostgreSQL & Mark Completed",
        fill=WHITE, stroke=NAVY, title_color=NAVY, rx=4, title_size=11, accent_bar=TEAL,
    )
    c.line(cx, p5_y + p5_h, cx, 1400, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 15. Output Parallelogram
    c.parallelogram(
        cx - 228, 1402, 456, 54,
        "Display Dashboard, Copy-Ready Fixes & Export JSON / HTML Report",
        slant=20, fill=BLUE_SOFT, stroke=BLUE, size=11, text_color=NAVY,
    )
    c.line(cx, 1456, cx, 1480, stroke=NAVY, stroke_width=1.8, marker_end="arrow-navy")

    # 16. END (Terminator pill)
    end_y = 1502.0
    c.terminator(cx, end_y, 152, 40, "END", fill=NAVY, stroke=NAVY, text_color=WHITE, size=13)

    # Complete right-hand END Collector Bus from Reject (d1_y) -> END pill right edge
    c.polyline_arrow(
        [(bus_x, d1_y), (bus_x, end_y), (cx + 76 + 2, end_y)],
        stroke=RED, stroke_width=1.8, marker_end="arrow-red", radius=10.0,
    )
    c.edge_label(
        740, end_y,
        "Early Exit / Abort Path",
        max_w=170, size=10, bg=RED_SOFT, border=RED_BORDER, fg=RED_DARK, bold=True,
    )

    # 17. Classic ISO 5807 Flowchart Symbol Legend Strip
    leg_y = 1554.0
    c.rect(72, leg_y, 936, 44, fill=CONTAINER_LIGHT, stroke=BORDER_SLATE, stroke_width=1.2, rx=8)
    # Terminator icon
    c.rect(92, leg_y + 12, 34, 20, fill=TEAL_DARK, stroke=TEAL_DARK, stroke_width=1.2, rx=10)
    c.text(134, leg_y + 26, "Terminator (START / END)", size=10, fill=NAVY, bold=True, anchor="start")
    # Parallelogram icon
    px0 = 286.0
    c.polygon(
        [(px0 + 7, leg_y + 12), (px0 + 36, leg_y + 12), (px0 + 29, leg_y + 32), (px0, leg_y + 32)],
        fill=BLUE_SOFT, stroke=BLUE, stroke_width=1.4,
    )
    c.text(px0 + 44, leg_y + 26, "Input / Output", size=10, fill=NAVY, bold=True, anchor="start")
    # Process rectangle icon
    rx0 = 434.0
    c.rect(rx0, leg_y + 12, 34, 20, fill=WHITE, stroke=NAVY, stroke_width=1.4, rx=3)
    c.text(rx0 + 42, leg_y + 26, "Process Step", size=10, fill=NAVY, bold=True, anchor="start")
    # Decision diamond icon
    dx0 = 574.0
    c.polygon(
        [(dx0 + 16, leg_y + 9), (dx0 + 32, leg_y + 22), (dx0 + 16, leg_y + 35), (dx0, leg_y + 22)],
        fill=AMBER_SOFT, stroke=AMBER, stroke_width=1.4,
    )
    c.text(dx0 + 40, leg_y + 26, "Decision Branch", size=10, fill=NAVY, bold=True, anchor="start")
    # Loop / Abort legend
    lx0 = 730.0
    c.line(lx0, leg_y + 22, lx0 + 28, leg_y + 22, stroke=BLUE, stroke_width=1.8, marker_end="arrow-blue")
    c.text(lx0 + 36, leg_y + 26, "Loop-Back", size=10, fill=BLUE, bold=True, anchor="start")
    ax0 = 848.0
    c.line(ax0, leg_y + 22, ax0 + 28, leg_y + 22, stroke=RED, stroke_width=1.8, marker_end="arrow-red")
    c.text(ax0 + 36, leg_y + 26, "Abort / Exit", size=10, fill=RED_DARK, bold=True, anchor="start")

    return c.render(), W, H


# ===========================================================================
# High-DPI PNG Rendering (Headless Chrome/Edge + Pillow Auto-Crop)
# ===========================================================================
DIAGRAM_SPECS = [
    ("01_as_is_vs_to_be", render_01),
    ("02_master_scanner_pipeline", render_02),
    ("03_use_case_diagram", render_03),
    ("04_c4_l1_context", render_04),
    ("05_c4_l2_containers", render_05),
    ("06_c4_l3_scanner_components", render_06),
    ("07_dfd_l0_context", render_07),
    ("08_dfd_l1_trust_boundaries", render_08),
    ("09_docker_deployment", render_09),
    ("10_scan_lifecycle_sequence", render_10),
    ("11_cancel_error_isolation_sequence", render_11),
    ("12_scan_state_machine", render_12),
    ("13_swimlane_activity", render_13),
    ("14_scanner_plugin_class_diagram", render_14),
    ("15_erd_3nf", render_15),
    ("16_scope_guardrail_flow", render_16),
    ("17_accuracy_benchmark_chart", render_17),
    ("18_coverage_latency_chart", render_18),
    ("19_master_system_flowchart", render_19),
]


def _find_browser() -> Optional[str]:
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for exe in candidates:
        if os.path.exists(exe):
            return exe
    return None


def _autocrop_with_margin(png_path: pathlib.Path, margin: int = 24) -> Tuple[int, int]:
    img = Image.open(png_path).convert("RGB")
    bg = Image.new("RGB", img.size, (255, 255, 255))
    diff = ImageChops.difference(img, bg)
    # Threshold faint noise > 3 so cropping is razor-clean
    gray = diff.convert("L").point(lambda p: 255 if p > 3 else 0)
    bbox = gray.getbbox()
    if bbox:
        cropped = img.crop(bbox)
    else:
        cropped = img
    out_w = cropped.width + margin * 2
    out_h = cropped.height + margin * 2
    canvas = Image.new("RGB", (out_w, out_h), (255, 255, 255))
    canvas.paste(cropped, (margin, margin))
    canvas.save(png_path, format="PNG", optimize=True)
    return out_w, out_h


def _render_svg_to_png_browser(
    browser_exe: str,
    svg_text: str,
    png_path: pathlib.Path,
    vb_w: float,
    vb_h: float,
    tmp_dir: pathlib.Path,
    stem: str,
) -> bool:
    # Target physical PNG width between ~1720px and 2160px at 2x DPI
    css_w = int(round(max(860.0, min(1080.0, vb_w))))
    css_h = int(round(css_w * vb_h / vb_w))

    # Strip XML prolog and inject responsive display width/height matching css_w x css_h
    svg_inline = re.sub(r"^<\?xml[^>]*\?>\s*", "", svg_text.strip())
    svg_inline = re.sub(
        r'<svg([^>]*)width="[^"]*"([^>]*)height="[^"]*"',
        f'<svg\\1width="{css_w}"\\2height="{css_h}"',
        svg_inline,
        count=1,
    )

    html_content = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>html,body{margin:0;padding:0;background:#ffffff;overflow:hidden;}"
        "svg{display:block;}</style></head>"
        f"<body><div style='padding:12px;display:inline-block;background:#ffffff;'>{svg_inline}</div></body></html>"
    )
    html_path = tmp_dir / f"{stem}.html"
    html_path.write_text(html_content, encoding="utf-8")

    win_w = css_w + 64
    win_h = css_h + 96
    cmd = [
        browser_exe,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        f"--window-size={win_w},{win_h}",
        "--force-device-scale-factor=2",
        f"--screenshot={png_path}",
        html_path.as_uri(),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and png_path.exists() and png_path.stat().st_size > 1000


def _render_fallback_pillow(stem: str, png_path: pathlib.Path, vb_w: float, vb_h: float) -> None:
    """Emergency Pillow fallback if headless browser is unavailable."""
    w = 1800
    h = max(700, int(round(w * vb_h / vb_w)))
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = _load_ttf(bold=True, size=28) or ImageFont.load_default()
    draw.rectangle([20, 20, w - 20, h - 20], outline=(15, 23, 42), width=3)
    draw.text((60, 60), f"Diagram: {stem} (Fallback Raster)", fill=(15, 23, 42), font=font)
    img.save(png_path, format="PNG")


def main() -> int:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    browser = _find_browser()
    if browser:
        print(f"[render_diagrams] Using headless browser: {browser}")
    else:
        print("[render_diagrams] WARNING: No headless Chrome/Edge found; using Pillow fallback.")

    requested = set(sys.argv[1:])
    specs = [
        (stem, fn) for stem, fn in DIAGRAM_SPECS
        if not requested or stem in requested or any(r in stem for r in requested)
    ]

    failures = []
    with tempfile.TemporaryDirectory(prefix="sad_diagrams_") as tmp_str:
        tmp_dir = pathlib.Path(tmp_str)
        for stem, renderer in specs:
            svg_text, vb_w, vb_h = renderer()
            svg_path = IMAGES_DIR / f"{stem}.svg"
            png_path = IMAGES_DIR / f"{stem}.png"
            svg_path.write_text(svg_text, encoding="utf-8")

            ok = False
            if browser:
                try:
                    ok = _render_svg_to_png_browser(browser, svg_text, png_path, vb_w, vb_h, tmp_dir, stem)
                except Exception as exc:
                    print(f"  [ERROR] {stem}: browser render failed: {exc}")
            if not ok:
                _render_fallback_pillow(stem, png_path, vb_w, vb_h)

            pw, ph = _autocrop_with_margin(png_path, margin=24)
            fsize = png_path.stat().st_size
            ratio = pw / max(1, ph)
            status = "OK" if fsize >= 15000 else "SMALL"
            if fsize < 15000:
                failures.append((stem, fsize))
            print(f"  [{status:5s}] {stem:36s}  SVG={len(svg_text):6d}B  PNG={fsize:7d}B  {pw:4d}x{ph:4d}px  AR={ratio:.2f}")

    if failures:
        print(f"[render_diagrams] WARNING: {len(failures)} PNGs below 15KB: {failures}")
        return 1
    print(f"[render_diagrams] Successfully generated all {len(DIAGRAM_SPECS)} SVG + PNG diagram pairs in {IMAGES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
