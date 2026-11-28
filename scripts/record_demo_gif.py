#!/usr/bin/env python3
"""
Record an authentic animated GIF walkthrough of the live OWASP-Lite Scanner UI
running against VulnBench, and save it to docs/media/gif/demo_walkthrough.gif.

Uses an isolated temporary SQLite database (never modifies data/scanner.db),
launches VulnBench + FastAPI locally, drives headless Chrome via CDP
(zero external driver downloads), and renders a smooth 960x540 animated GIF
with sleek step overlays and crossfade transitions.

Usage:
    py -3.12 scripts/record_demo_gif.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import requests
import websockets
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT_GIF = ROOT / "docs" / "media" / "gif" / "demo_walkthrough.gif"
CHROME_CANDIDATES = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]

VULNBENCH_PORT = 5053
API_PORT = 8013
CDP_PORT = 9233
API_BASE = f"http://127.0.0.1:{API_PORT}"
VULN_BASE = f"http://127.0.0.1:{VULNBENCH_PORT}"

VIEW_W = 1280
VIEW_H = 720
GIF_W = 960
GIF_H = 540


def find_chrome() -> Path:
    for p in CHROME_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError("Chrome/Edge executable not found.")


def wait_http(url: str, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2.0)
            if r.status_code < 500:
                return
        except Exception as e:
            last_err = e
        time.sleep(0.35)
    raise RuntimeError(f"Service at {url} did not become ready: {last_err}")


def wait_scan_done(scan_id: int, timeout: float = 90.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{API_BASE}/api/scans/{scan_id}", timeout=5.0)
        r.raise_for_status()
        data = r.json()
        if data.get("status") in ("completed", "failed", "cancelled"):
            return data
        time.sleep(0.5)
    raise RuntimeError(f"Scan {scan_id} timed out")


class CDPClient:
    def __init__(self, ws_url: str) -> None:
        self.ws_url = ws_url
        self.ws = None
        self._id = 0

    async def __aenter__(self) -> "CDPClient":
        self.ws = await websockets.connect(self.ws_url, max_size=32 * 1024 * 1024)
        await self.send("Page.enable")
        await self.send("Runtime.enable")
        await self.send(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": VIEW_W,
                "height": VIEW_H,
                "deviceScaleFactor": 1,
                "mobile": False,
            },
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self.ws is not None:
            await self.ws.close()

    async def send(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg_id = self._id
        payload = {"id": msg_id, "method": method, "params": params or {}}
        await self.ws.send(json.dumps(payload))
        while True:
            raw = await self.ws.recv()
            msg = json.loads(raw)
            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(f"CDP error {method}: {msg['error']}")
                return msg.get("result", {})

    async def navigate(self, url: str, wait_s: float = 1.6) -> None:
        await self.send("Page.navigate", {"url": url})
        await asyncio.sleep(wait_s)

    async def eval_js(self, expr: str):
        res = await self.send(
            "Runtime.evaluate",
            {
                "expression": expr,
                "awaitPromise": True,
                "returnByValue": True,
            },
        )
        return res.get("result", {}).get("value")

    async def screenshot(self) -> Image.Image:
        res = await self.send("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(res["data"])
        from io import BytesIO

        return Image.open(BytesIO(data)).convert("RGB")


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        [
            r"C:\Windows\Fonts\segoeuib.ttf",
            r"C:\Windows\Fonts\arialbd.ttf",
        ]
        if bold
        else [
            r"C:\Windows\Fonts\segoeui.ttf",
            r"C:\Windows\Fonts\arial.ttf",
        ]
    )
    for c in candidates:
        if os.path.exists(c):
            return ImageFont.truetype(c, size=size)
    return ImageFont.load_default()


def decorate_frame(
    img: Image.Image,
    step_num: int,
    total_steps: int,
    title: str,
    subtitle: str,
) -> Image.Image:
    """Downscale cleanly to 960x540 and add a sleek bottom glass caption strip."""
    base = img.resize((GIF_W, GIF_H), Image.Resampling.LANCZOS).convert("RGBA")
    bar_h = 46
    overlay = Image.new("RGBA", (GIF_W, GIF_H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    # Subtle bottom dark glass bar
    y0 = GIF_H - bar_h
    draw.rectangle([0, y0, GIF_W, GIF_H], fill=(9, 14, 26, 232))
    draw.line([(0, y0), (GIF_W, y0)], fill=(45, 212, 191, 140), width=1)

    # Progress bar along very bottom edge
    prog_w = int(GIF_W * (step_num / total_steps))
    draw.rectangle([0, GIF_H - 3, GIF_W, GIF_H], fill=(30, 41, 59, 255))
    draw.rectangle([0, GIF_H - 3, prog_w, GIF_H], fill=(20, 184, 166, 255))

    # Step badge pill
    f_badge = load_font(12, bold=True)
    f_title = load_font(15, bold=True)
    f_sub = load_font(13, bold=False)

    pill_text = f"{step_num:02d} / {total_steps:02d}"
    draw.rounded_rectangle([16, y0 + 10, 74, y0 + 34], radius=12, fill=(13, 148, 136, 255))
    draw.text((26, y0 + 14), pill_text, fill=(255, 255, 255, 255), font=f_badge)

    # Title + subtitle
    draw.text((88, y0 + 11), title, fill=(248, 250, 252, 255), font=f_title)
    title_bbox = draw.textbbox((88, y0 + 11), title, font=f_title)
    sep_x = title_bbox[2] + 12
    draw.text((sep_x, y0 + 12), "·", fill=(100, 116, 139, 255), font=f_title)
    draw.text((sep_x + 12, y0 + 13), subtitle, fill=(148, 163, 184, 255), font=f_sub)

    # Right-side step dots
    dot_r = 3
    dot_gap = 12
    dots_w = (total_steps - 1) * dot_gap
    start_x = GIF_W - 22 - dots_w
    cy = y0 + 22
    for idx in range(1, total_steps + 1):
        cx = start_x + (idx - 1) * dot_gap
        fill = (20, 184, 166, 255) if idx == step_num else (71, 85, 105, 220)
        r = dot_r + 1 if idx == step_num else dot_r
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)

    combined = Image.alpha_composite(base, overlay).convert("RGB")
    return combined


async def capture_all_scenes(
    ws_url: str,
    quick_scan_id: int,
    project_id: int,
    debug_dir: Path | None = None,
) -> list[tuple[Image.Image, int, str, str]]:
    """Capture 8 real interactive scenes; returns list of (image, hold_ms, title, subtitle)."""
    scenes: list[tuple[Image.Image, int, str, str]] = []

    async with CDPClient(ws_url) as cdp:
        # Start a REAL Deep scan right before viewing Live Scan so we catch it live!
        await cdp.navigate(API_BASE, wait_s=2.2)

        # Scene 1: Scan Launcher (select Deep 17/17 profile!)
        await cdp.eval_js("document.getElementById('nav-launcher').click()")
        await asyncio.sleep(0.8)
        await cdp.eval_js("""
            (() => {
                const btns = Array.from(document.querySelectorAll('#view-launcher button, #view-launcher [role="radio"], #view-launcher .profile-card'));
                const deepCard = btns.find(b => (b.textContent || '').includes('All 17 Checks') || (b.textContent || '').trim().startsWith('Deep'));
                if (deepCard) deepCard.click();
            })()
        """)
        await asyncio.sleep(0.5)
        img_launcher = await cdp.screenshot()

        # Trigger REAL Deep scan via UI Submit button (which opens Live SSE stream automatically!)
        await cdp.eval_js("""
            (() => {
                const btn = document.querySelector('#view-launcher button[type="submit"]');
                if (btn) btn.click();
            })()
        """)
        # Wait ~3.5s so Live Scan SSE progress bar & findings feed are visibly streaming
        await asyncio.sleep(3.5)
        # Hide ephemeral toast notifications so the Live Finding Feed is 100% crisp
        await cdp.eval_js("const tc = document.getElementById('toast-container'); if (tc) tc.style.display = 'none';")
        await asyncio.sleep(0.2)
        img_live = await cdp.screenshot()

        # Find the active Deep scan ID via API and wait for completion
        scans_list = requests.get(f"{API_BASE}/api/projects/{project_id}/scans", timeout=10.0).json()
        other_scans = [s for s in scans_list if s["id"] != quick_scan_id]
        if other_scans:
            deep_scan_id = other_scans[0]["id"]
        else:
            deep_resp = requests.post(
                f"{API_BASE}/api/projects/{project_id}/scans",
                json={"profile": "deep"},
                timeout=10.0,
            )
            deep_resp.raise_for_status()
            deep_scan_id = deep_resp.json()["id"]
            await cdp.eval_js("document.getElementById('nav-live').click()")
            await asyncio.sleep(3.2)
            img_live = await cdp.screenshot()

        # Wait for Deep scan to complete cleanly
        wait_scan_done(deep_scan_id, timeout=90.0)
        await asyncio.sleep(1.0)

        # Reload dashboard overview with both completed scans + full metrics!
        await cdp.navigate(API_BASE, wait_s=2.0)
        await cdp.eval_js("const tc = document.getElementById('toast-container'); if (tc) tc.style.display = 'none';")
        img_dashboard = await cdp.screenshot()

        # Findings Explorer (select the completed Deep scan)
        await cdp.eval_js("document.getElementById('nav-findings').click()")
        await asyncio.sleep(1.2)
        img_findings = await cdp.screenshot()

        # Open VS Code Dark+ Fix Modal on the first SQLi or XSS Critical/High finding
        await cdp.eval_js("""
            (() => {
                const rows = Array.from(document.querySelectorAll('tr, .finding-row, .finding-card'));
                let targetBtn = null;
                for (const row of rows) {
                    const txt = (row.textContent || '').toLowerCase();
                    if (txt.includes('sql') || txt.includes('xss') || txt.includes('injection')) {
                        const btn = Array.from(row.querySelectorAll('button')).find(
                            b => (b.textContent || '').includes('View Fix')
                        );
                        if (btn) { targetBtn = btn; break; }
                    }
                }
                if (!targetBtn) {
                    targetBtn = Array.from(document.querySelectorAll('button')).find(
                        b => (b.textContent || '').includes('View Fix')
                    );
                }
                if (targetBtn) targetBtn.click();
            })()
        """)
        await asyncio.sleep(1.1)
        # Scroll every scrollable container inside #fix-modal so the full VS Code Dark+ Before/After diff is centered!
        await cdp.eval_js("""
            (() => {
                const nodes = Array.from(document.querySelectorAll('#fix-modal, #fix-modal *'));
                for (const el of nodes) {
                    if (el.scrollHeight > el.clientHeight + 40) {
                        const st = window.getComputedStyle(el);
                        if (st.overflowY === 'auto' || st.overflowY === 'scroll') {
                            el.scrollTop = 260;
                        }
                    }
                }
            })()
        """)
        await asyncio.sleep(0.4)
        img_fix_fastapi = await cdp.screenshot()

        # Switch stack tab to Express (Node.js) inside Fix Modal!
        await cdp.eval_js("""
            (() => {
                const btns = Array.from(document.querySelectorAll('#fix-modal button'));
                const exp = btns.find(b => (b.textContent || '').toLowerCase().includes('express'));
                if (exp) exp.click();
            })()
        """)
        await asyncio.sleep(0.5)
        img_fix_express = await cdp.screenshot()

        # Close Fix Modal
        await cdp.eval_js("""
            (() => {
                const close = document.querySelector('#fix-modal .modal-close, #fix-modal button[aria-label*="Close"]');
                if (close) close.click();
            })()
        """)
        await asyncio.sleep(0.4)

        # Compare Scans (Quick baseline vs Deep scan — shows rich New + Unchanged cards!)
        await cdp.eval_js("document.getElementById('nav-compare').click()")
        await asyncio.sleep(1.2)
        await cdp.eval_js("""
            (() => {
                const btn = Array.from(document.querySelectorAll('#view-compare button')).find(
                    b => (b.textContent || '').toLowerCase().includes('compare')
                      && !(b.textContent || '').toLowerCase().includes('reset')
                );
                if (btn) btn.click();
            })()
        """)
        await asyncio.sleep(1.2)
        img_compare = await cdp.screenshot()

        # Standalone Offline HTML5 Report (open directly in browser!)
        await cdp.navigate(f"{API_BASE}/api/scans/{deep_scan_id}/report?format=html", wait_s=1.4)
        img_report = await cdp.screenshot()

        scenes = [
            (img_dashboard, 2600, "Dashboard Overview", "Risk Score, Severity Distribution & OWASP Top 10 Coverage"),
            (img_launcher, 2200, "Scan Launcher", "Quick / Standard / Deep (17/17 Checks) + Local Scope Guardrail"),
            (img_live, 2200, "Live SSE Scan Stream", "Real-Time Progress Telemetry & Streaming Findings"),
            (img_findings, 2500, "Findings Explorer", "Prioritized OWASP Findings, Triage & One-Click Export"),
            (img_fix_fastapi, 2800, "VS Code Dark+ Code Fix (FastAPI)", "Line-Level Before/After Diff & Where-to-Patch Guide"),
            (img_fix_express, 2400, "5-Stack Remediation KB (Express)", "Instant Switching: FastAPI · Flask · Express · PHP · HTML"),
            (img_compare, 2600, "Compare Scans Regression Diff", "SHA-1 Fingerprinting Tracks Fixed vs. New Findings"),
            (img_report, 2600, "Standalone Offline HTML5 Report", "Autoescaped Zero-JS Audit Report Ready for Submission"),
        ]

        if debug_dir is not None:
            debug_dir.mkdir(parents=True, exist_ok=True)
            for idx, (im, _ms, title, sub) in enumerate(scenes, start=1):
                dec = decorate_frame(im, idx, len(scenes), title, sub)
                dec.save(debug_dir / f"frame_{idx:02d}.png")

    return scenes


def build_animated_gif(scenes: list[tuple[Image.Image, int, str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = len(scenes)
    decorated = [
        (decorate_frame(im, idx, total, title, sub), hold_ms)
        for idx, (im, hold_ms, title, sub) in enumerate(scenes, start=1)
    ]

    frames: list[Image.Image] = []
    durations: list[int] = []

    for i, (frame_rgb, hold_ms) in enumerate(decorated):
        frames.append(frame_rgb)
        durations.append(hold_ms)
        # Smooth 3-step crossfade into the next scene (and loop smoothly back to scene 1)
        next_rgb = decorated[(i + 1) % total][0]
        for alpha in (0.28, 0.56, 0.82):
            blended = Image.blend(frame_rgb, next_rgb, alpha)
            frames.append(blended)
            durations.append(75)

    # Quantize each frame cleanly with adaptive 256-color palette (fast & sharp)
    pal_frames = [
        f.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG)
        for f in frames
    ]

    pal_frames[0].save(
        out_path,
        save_all=True,
        append_images=pal_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )


def main() -> int:
    chrome = find_chrome()
    debug_dir = Path(os.environ.get("DEMO_DEBUG_DIR", "")) if os.environ.get("DEMO_DEBUG_DIR") else None

    tmp_dir = Path(tempfile.mkdtemp(prefix="owasp_demo_rec_"))
    db_file = tmp_dir / "demo.db"
    chrome_profile = tmp_dir / "chrome_profile"
    chrome_profile.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_file.as_posix()}"

    procs: list[subprocess.Popen] = []
    try:
        print(f"[1/5] Starting VulnBench on {VULN_BASE} ...")
        p_vuln = subprocess.Popen(
            [sys.executable, str(ROOT / "testbench" / "vulnbench" / "app.py"), "--host", "127.0.0.1", "--port", str(VULNBENCH_PORT)],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p_vuln)

        print(f"[2/5] Starting OWASP-Lite Scanner API on {API_BASE} ...")
        p_api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(API_PORT), "--no-server-header"],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p_api)

        wait_http(f"{VULN_BASE}/")
        wait_http(f"{API_BASE}/api/health")
        print("[OK] Both servers healthy.")

        # Seed project + Quick baseline scan
        proj_resp = requests.post(
            f"{API_BASE}/api/projects",
            json={
                "name": "VulnBench Local Lab",
                "base_url": VULN_BASE,
                "target_stack": "fastapi",
                "authorized_confirmed": True,
            },
            timeout=10.0,
        )
        proj_resp.raise_for_status()
        project_id = proj_resp.json()["id"]

        quick_resp = requests.post(
            f"{API_BASE}/api/projects/{project_id}/scans",
            json={"profile": "quick"},
            timeout=10.0,
        )
        quick_resp.raise_for_status()
        quick_scan_id = quick_resp.json()["id"]
        wait_scan_done(quick_scan_id, timeout=45.0)
        print(f"[OK] Seeded project #{project_id} + baseline Quick scan #{quick_scan_id}.")

        print(f"[3/5] Launching headless Chrome CDP on port {CDP_PORT} ...")
        p_chrome = subprocess.Popen(
            [
                str(chrome),
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--hide-scrollbars",
                f"--window-size={VIEW_W},{VIEW_H}",
                f"--remote-debugging-port={CDP_PORT}",
                f"--user-data-dir={chrome_profile}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p_chrome)
        wait_http(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=15.0)

        with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=5) as resp:
            targets = json.loads(resp.read().decode("utf-8"))
        ws_url = next(t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page")

        print("[4/5] Capturing 8 real interactive UI scenes ...")
        scenes = asyncio.run(capture_all_scenes(ws_url, quick_scan_id, project_id, debug_dir=debug_dir))

        print(f"[5/5] Encoding animated GIF -> {OUT_GIF} ...")
        build_animated_gif(scenes, OUT_GIF)
        size_mb = OUT_GIF.stat().st_size / (1024 * 1024)
        print(f"[OK] Saved {OUT_GIF} ({OUT_GIF.stat().st_size:,} bytes / {size_mb:.2f} MB)")
        return 0
    finally:
        for p in reversed(procs):
            try:
                p.terminate()
                p.wait(timeout=4)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
