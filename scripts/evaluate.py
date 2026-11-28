#!/usr/bin/env python3
"""Empirical evaluation runner and benchmark report generator for OWASP Lite Scanner.

Runs the decoupled ``ScanOrchestrator`` against a target application (such as the
deterministic local ``VulnBench`` server started automatically via
``--auto-start-vulnbench`` or an externally hosted testbench target), compares
detected findings against a version-controlled ground-truth manifest
(``testbench/ground_truth.json``), computes SAD Chapter 6 accuracy and coverage
metrics, verifies ``NFR-08`` / ``NFR-02`` / ``NFR-07`` acceptance gates, and
optionally writes a formal academic Markdown benchmark report and raw JSON
metrics artifact.

Pure Python 3.12 CLI with zero FastAPI or SQLAlchemy dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Ensure repository root is importable when invoked directly as `python scripts/evaluate.py`.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.scanner import (  # noqa: E402
    EnrichedFinding,
    ScanConfig,
    ScanOrchestrator,
    ScanOutcome,
    ScanProfile,
    ScanProgress,
    ScanStatus,
    get_checks_for_profile,
    list_check_catalog,
)

DEFAULT_GROUND_TRUTH_PATH: Path = PROJECT_ROOT / "testbench" / "ground_truth.json"

# NFR-08 / SAD Chapter 6.2.2 acceptance thresholds.
NFR08_MIN_RECALL: float = 0.80
NFR08_MIN_PRECISION: float = 0.85
NFR08_MIN_F1: float = 0.82
NFR08_MAX_CLEAN_CONTROL_FP: int = 0
MIN_CRAWLER_COVERAGE: float = 0.80

# Profile duration SLAs from SAD Chapter 6.2.2 (NFR-02).
PROFILE_DURATION_SLAS_S: dict[str, float] = {
    ScanProfile.QUICK.value: 15.0,
    ScanProfile.STANDARD.value: 45.0,
    ScanProfile.DEEP.value: 90.0,
}

# Passive checks whose findings represent origin-level properties where the check
# attaches the first matching cached URL for that origin.
ORIGIN_LEVEL_PASSIVE_CHECKS: frozenset[str] = frozenset(
    {
        "missing_security_headers",
        "server_banner_leak",
        "insecure_cookies",
    }
)

# SAD Chapter 6.4.1 pre-execution target baselines by OWASP Top 10 (2021) code.
SAD_CATEGORY_TARGETS: dict[str, dict[str, float]] = {
    "A01": {"recall": 0.85, "precision": 0.88, "f1": 0.865},
    "A02": {"recall": 0.95, "precision": 0.98, "f1": 0.965},
    "A03": {"recall": 0.85, "precision": 0.90, "f1": 0.874},
    "A05": {"recall": 0.92, "precision": 0.95, "f1": 0.935},
    "A06": {"recall": 0.90, "precision": 0.95, "f1": 0.924},
    "A07": {"recall": 0.88, "precision": 0.90, "f1": 0.890},
}


def normalize_path(url_or_path: str) -> str:
    """Extract and normalize a URL path (strip query/fragment and trailing slash)."""
    raw = (url_or_path or "").strip()
    if not raw:
        return "/"
    parsed = urlsplit(raw)
    path = parsed.path or "/"
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def normalize_param(parameter: str | None) -> str:
    """Normalize a finding parameter / header / cookie / artifact name for matching."""
    if parameter is None:
        return ""
    cleaned = str(parameter).strip().lower()
    if len(cleaned) > 1 and cleaned.startswith("/") and cleaned.endswith("/"):
        cleaned = cleaned.rstrip("/")
    return cleaned


def canonical_match_key(
    check_id: str,
    method: str,
    url_or_path: str,
    parameter: str | None,
) -> tuple[str, str, str, str]:
    """Build the SAD Chapter 6.3.1 canonical 4-tuple ``(check_id, method, path, param)``."""
    return (
        (check_id or "").strip().lower(),
        (method or "GET").strip().upper() or "GET",
        normalize_path(url_or_path),
        normalize_param(parameter),
    )


def _safe_div(numerator: float, denominator: float) -> float:
    return (numerator / denominator) if denominator > 0 else 0.0


def _compute_f1(precision: float, recall: float) -> float:
    return (
        (2.0 * precision * recall) / (precision + recall)
        if (precision + recall) > 0.0
        else 0.0
    )


def _owasp_code(category_label: str) -> str:
    """Extract the leading OWASP code (e.g. 'A03') from a full category string."""
    raw = (category_label or "").strip()
    if ":" in raw:
        return raw.split(":", 1)[0].strip().upper()
    return raw.split(" ", 1)[0].strip().upper() or "OTHER"


def load_ground_truth(path: str | Path = DEFAULT_GROUND_TRUTH_PATH) -> dict[str, Any]:
    """Load and validate a ground-truth JSON manifest."""
    gt_path = Path(path)
    if not gt_path.is_absolute() and not gt_path.exists():
        candidate = PROJECT_ROOT / gt_path
        if candidate.exists():
            gt_path = candidate

    with gt_path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    if not isinstance(data.get("expected_findings"), list):
        raise ValueError(f"Ground-truth manifest {gt_path} must define 'expected_findings' list.")
    return data


@contextmanager
def running_vulnbench_server(
    host: str = "127.0.0.1",
    port: int = 0,
) -> Iterator[str]:
    """Context manager starting ``VulnBench`` in-process on a background daemon thread."""
    from testbench.vulnbench.app import create_vulnbench_server

    server = create_vulnbench_server(host=host, port=port)
    bound_host, bound_port = server.server_address[:2]
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        name="vulnbench-eval-server",
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://{bound_host}:{bound_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _serialize_expected(entry: dict[str, Any]) -> dict[str, Any]:
    path_val = entry.get("path") or entry.get("normalized_path") or "/"
    method_val = (entry.get("method") or "GET").strip().upper()
    param_val = entry.get("parameter")
    return {
        "check_id": str(entry["check_id"]).strip().lower(),
        "owasp_category": str(entry.get("owasp_category", "")),
        "method": method_val,
        "path": normalize_path(str(path_val)),
        "raw_path": str(path_val),
        "parameter": param_val,
        "normalized_parameter": normalize_param(param_val),
    }


def _serialize_detected(finding: EnrichedFinding) -> dict[str, Any]:
    return {
        "check_id": finding.check_id.strip().lower(),
        "title": finding.title,
        "owasp_category": str(finding.owasp_category),
        "cwe_id": finding.cwe_id,
        "severity": str(finding.severity),
        "confidence": str(finding.confidence),
        "method": (finding.method or "GET").strip().upper(),
        "url": finding.url,
        "path": normalize_path(finding.url),
        "parameter": finding.parameter,
        "normalized_parameter": normalize_param(finding.parameter),
        "fingerprint": finding.fingerprint,
        "evidence": dict(finding.evidence),
    }


def _finding_matches_expected(
    detected: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    """Return True if ``detected`` matches ``expected``.

    Applies exact 4-tuple matching ``(check_id, method, normalized_path, param)``
    with clean handling for:
    - Origin-level passive findings (``missing_security_headers``,
      ``server_banner_leak``, ``insecure_cookies``) when expected at ``"/"`` so
      origin-wide passive attributes reported on any cached URL of the same
      origin match accurately without false negatives or double-counting.
    - ``outdated_js_components`` when a finding's ``evidence["script_url"]``
      resolves to the expected static script path.
    """
    det_key = (
        detected["check_id"],
        detected["method"],
        detected["path"],
        detected["normalized_parameter"],
    )
    exp_key = (
        expected["check_id"],
        expected["method"],
        expected["path"],
        expected["normalized_parameter"],
    )
    if det_key == exp_key:
        return True

    if (
        detected["check_id"] == expected["check_id"]
        and detected["check_id"] in ORIGIN_LEVEL_PASSIVE_CHECKS
        and expected["path"] == "/"
        and detected["method"] == expected["method"]
        and detected["normalized_parameter"] == expected["normalized_parameter"]
    ):
        return True

    if (
        detected["check_id"] == "outdated_js_components"
        and expected["check_id"] == "outdated_js_components"
        and detected["normalized_parameter"] == expected["normalized_parameter"]
    ):
        script_url = str((detected.get("evidence") or {}).get("script_url") or "")
        if script_url and normalize_path(script_url) == expected["path"]:
            return True

    return False


def _match_findings(
    detected_items: list[dict[str, Any]],
    expected_items: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Perform deterministic 1-to-1 greedy matching (exact 4-tuple first, then origin-level)."""
    matched_exp_indices: set[int] = set()
    matched_det_indices: set[int] = set()
    tp_pairs: list[dict[str, Any]] = []

    # Pass 1: Strict exact 4-tuple matching.
    for det_idx, det in enumerate(detected_items):
        det_key = (
            det["check_id"],
            det["method"],
            det["path"],
            det["normalized_parameter"],
        )
        for exp_idx, exp in enumerate(expected_items):
            if exp_idx in matched_exp_indices:
                continue
            exp_key = (
                exp["check_id"],
                exp["method"],
                exp["path"],
                exp["normalized_parameter"],
            )
            if det_key == exp_key:
                matched_det_indices.add(det_idx)
                matched_exp_indices.add(exp_idx)
                tp_pairs.append({"expected": exp, "detected": det, "match_type": "exact"})
                break

    # Pass 2: Origin-level passive & script-evidence fallback matching.
    for det_idx, det in enumerate(detected_items):
        if det_idx in matched_det_indices:
            continue
        for exp_idx, exp in enumerate(expected_items):
            if exp_idx in matched_exp_indices:
                continue
            if _finding_matches_expected(det, exp):
                matched_det_indices.add(det_idx)
                matched_exp_indices.add(exp_idx)
                tp_pairs.append(
                    {"expected": exp, "detected": det, "match_type": "origin_or_script"}
                )
                break

    fp_items = [
        det for idx, det in enumerate(detected_items) if idx not in matched_det_indices
    ]
    fn_items = [
        exp for idx, exp in enumerate(expected_items) if idx not in matched_exp_indices
    ]
    return tp_pairs, fp_items, fn_items


def _collect_discovered_paths(outcome: ScanOutcome) -> set[str]:
    """Collect normalized paths discovered by the crawler across endpoints and forms."""
    paths: set[str] = set()
    for ep in outcome.endpoints:
        if ep.url:
            paths.add(normalize_path(ep.url))
    for form in outcome.forms:
        if form.source_url:
            paths.add(normalize_path(form.source_url))
        if form.action_url:
            paths.add(normalize_path(form.action_url))
    return paths


def _is_clean_control_path(path: str, clean_control_set: set[str]) -> bool:
    norm = normalize_path(path)
    if norm in clean_control_set:
        return True
    return norm.startswith("/safe/") or norm.startswith("/clean/")


def evaluate_target(
    target_url: str,
    *,
    ground_truth_path: str | Path = DEFAULT_GROUND_TRUTH_PATH,
    profile: ScanProfile | str = ScanProfile.DEEP,
    rate_limit_rps: float = 10.0,
    max_requests: int = 2000,
    timeout_s: float = 10.0,
    enabled_checks: list[str] | None = None,
) -> dict[str, Any]:
    """Run ``ScanOrchestrator`` against ``target_url`` and compute SAD Chapter 6 metrics."""
    scan_profile = (
        profile if isinstance(profile, ScanProfile) else ScanProfile(str(profile).lower())
    )
    gt = load_ground_truth(ground_truth_path)
    catalog = list_check_catalog()
    catalog_by_id: dict[str, dict[str, Any]] = {str(item["id"]): item for item in catalog}

    expected_all = [_serialize_expected(e) for e in gt.get("expected_findings", [])]
    known_endpoints = sorted(
        {
            normalize_path(p)
            for p in (gt.get("known_endpoints") or gt.get("expected_routes") or [])
        }
    )
    clean_control_routes = sorted(
        {
            normalize_path(p)
            for p in (
                gt.get("clean_control_routes") or gt.get("clean_control_paths") or []
            )
        }
    )
    clean_control_set = set(clean_control_routes)

    scheduled_checks = get_checks_for_profile(scan_profile, enabled_checks)
    scheduled_check_ids = [chk.id for chk in scheduled_checks]
    executed_checks_seen: list[str] = []

    def _on_progress(progress: ScanProgress) -> None:
        if progress.stage == "scanning" and progress.current_check:
            if progress.current_check not in executed_checks_seen:
                executed_checks_seen.append(progress.current_check)

    orchestrator = ScanOrchestrator()
    config = ScanConfig(
        target_url=target_url,
        profile=scan_profile,
        rate_limit_rps=rate_limit_rps,
        max_requests=max_requests,
        timeout_s=timeout_s,
        enabled_checks=enabled_checks,
    )

    wall_start = time.perf_counter()
    outcome = orchestrator.run_scan(
        config,
        progress_callback=_on_progress,
    )
    wall_duration = round(max(0.0, time.perf_counter() - wall_start), 3)

    detected_items = [_serialize_detected(f) for f in outcome.findings]

    # Full-catalog matching (all seeded ground-truth items).
    tp_pairs, fp_items, fn_items = _match_findings(detected_items, expected_all)
    tp_count = len(tp_pairs)
    fp_count = len(fp_items)
    fn_count = len(fn_items)

    precision = _safe_div(tp_count, tp_count + fp_count)
    recall = _safe_div(tp_count, tp_count + fn_count)
    f1_score = _compute_f1(precision, recall)

    # Profile-scoped matching (only ground-truth items belonging to checks enabled in this profile).
    scheduled_set = set(scheduled_check_ids)
    expected_in_profile = [e for e in expected_all if e["check_id"] in scheduled_set]
    prof_tp_pairs, prof_fp_items, prof_fn_items = _match_findings(
        detected_items, expected_in_profile
    )
    profile_precision = _safe_div(
        len(prof_tp_pairs), len(prof_tp_pairs) + len(prof_fp_items)
    )
    profile_recall = _safe_div(
        len(prof_tp_pairs), len(prof_tp_pairs) + len(prof_fn_items)
    )
    profile_f1 = _compute_f1(profile_precision, profile_recall)

    # Clean control route false-positive check (0 findings permitted on /safe/* routes).
    clean_control_fp_details = [
        det
        for det in detected_items
        if _is_clean_control_path(det["path"], clean_control_set)
    ]
    clean_control_fp = len(clean_control_fp_details)

    # Crawler route coverage.
    discovered_paths = _collect_discovered_paths(outcome)
    known_set = set(known_endpoints)
    discovered_known_paths = sorted(discovered_paths & known_set)
    missing_known_paths = sorted(known_set - discovered_paths)
    crawler_coverage = _safe_div(len(discovered_known_paths), len(known_set))

    # Per-check metrics across all 17 registered checks.
    per_check: list[dict[str, Any]] = []
    for entry in catalog:
        cid = str(entry["id"])
        chk_expected = [e for e in expected_all if e["check_id"] == cid]
        chk_detected = [d for d in detected_items if d["check_id"] == cid]
        chk_tp, chk_fp, chk_fn = _match_findings(chk_detected, chk_expected)
        c_tp = len(chk_tp)
        c_fp = len(chk_fp)
        c_fn = len(chk_fn)
        c_prec = _safe_div(c_tp, c_tp + c_fp) if (c_tp + c_fp) > 0 else (1.0 if not chk_expected else 0.0)
        c_rec = _safe_div(c_tp, c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
        c_f1 = _compute_f1(c_prec, c_rec)

        was_scheduled = cid in scheduled_set
        was_executed = cid in executed_checks_seen
        if not was_scheduled:
            chk_status = "SKIPPED_BY_PROFILE"
        elif c_fn == 0 and c_fp == 0:
            chk_status = "PASS"
        elif c_tp > 0 and c_fn == 0 and c_fp > 0:
            chk_status = "FP"
        elif c_tp > 0 and c_fn > 0:
            chk_status = "PARTIAL"
        else:
            chk_status = "MISS"

        per_check.append(
            {
                "check_id": cid,
                "name": str(entry["name"]),
                "kind": str(entry["kind"]),
                "owasp_category": str(entry["owasp_category"]),
                "owasp_code": _owasp_code(str(entry["owasp_category"])),
                "profiles": list(entry.get("profiles", [])),
                "scheduled": was_scheduled,
                "executed": was_executed,
                "expected": len(chk_expected),
                "detected": len(chk_detected),
                "tp": c_tp,
                "fp": c_fp,
                "fn": c_fn,
                "precision": round(c_prec, 4),
                "recall": round(c_rec, 4),
                "f1_score": round(c_f1, 4),
                "status": chk_status,
            }
        )

    # Per-OWASP-category aggregation (using check catalog OWASP categories for consistency).
    category_buckets: dict[str, dict[str, Any]] = {}
    for row in per_check:
        code = row["owasp_code"]
        bucket = category_buckets.setdefault(
            code,
            {
                "owasp_code": code,
                "owasp_category": row["owasp_category"],
                "check_ids": [],
                "expected": 0,
                "detected": 0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
            },
        )
        bucket["check_ids"].append(row["check_id"])
        bucket["expected"] += row["expected"]
        bucket["detected"] += row["detected"]
        bucket["tp"] += row["tp"]
        bucket["fp"] += row["fp"]
        bucket["fn"] += row["fn"]

    per_category: list[dict[str, Any]] = []
    for code in sorted(category_buckets.keys()):
        b = category_buckets[code]
        cat_prec = _safe_div(b["tp"], b["tp"] + b["fp"])
        cat_rec = _safe_div(b["tp"], b["tp"] + b["fn"])
        cat_f1 = _compute_f1(cat_prec, cat_rec)
        b["precision"] = round(cat_prec, 4)
        b["recall"] = round(cat_rec, 4)
        b["f1_score"] = round(cat_f1, 4)
        per_category.append(b)

    all_registered_ids = sorted(catalog_by_id.keys())
    all_17_checks_executed = (
        len(all_registered_ids) == 17
        and set(all_registered_ids).issubset(set(executed_checks_seen))
        and len(outcome.errors) == 0
    )

    duration_s = outcome.duration_seconds if outcome.duration_seconds > 0 else wall_duration
    duration_sla_s = PROFILE_DURATION_SLAS_S.get(scan_profile.value, 90.0)

    gates = {
        "recall_pass": recall >= NFR08_MIN_RECALL,
        "precision_pass": precision >= NFR08_MIN_PRECISION,
        "f1_pass": f1_score >= NFR08_MIN_F1,
        "clean_control_fp_pass": clean_control_fp <= NFR08_MAX_CLEAN_CONTROL_FP,
        "crawler_coverage_pass": crawler_coverage >= MIN_CRAWLER_COVERAGE,
        "duration_sla_pass": duration_s <= duration_sla_s,
        "zero_scanner_errors_pass": len(outcome.errors) == 0,
        "all_17_checks_executed": all_17_checks_executed,
    }
    gates["nfr08_passed"] = (
        gates["recall_pass"]
        and gates["precision_pass"]
        and gates["clean_control_fp_pass"]
    )
    gates["all_passed"] = (
        gates["nfr08_passed"]
        and gates["f1_pass"]
        and gates["crawler_coverage_pass"]
        and gates["duration_sla_pass"]
        and gates["zero_scanner_errors_pass"]
        and (all_17_checks_executed if scan_profile == ScanProfile.DEEP else True)
    )

    return {
        "target_name": str(gt.get("target_name", "Target")),
        "target_url": target_url,
        "ground_truth_path": str(ground_truth_path),
        "profile": scan_profile.value,
        "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": str(outcome.status),
        "risk_score": outcome.risk_score,
        "severity_summary": dict(outcome.summary),
        "duration_seconds": round(duration_s, 3),
        "duration_sla_seconds": duration_sla_s,
        "pages_crawled": outcome.pages_crawled,
        "requests_sent": outcome.requests_sent,
        "endpoints_discovered": len(outcome.endpoints),
        "forms_discovered": len(outcome.forms),
        "expected_total": len(expected_all),
        "expected_in_profile": len(expected_in_profile),
        "detected_total": len(detected_items),
        "tp": tp_count,
        "fp": fp_count,
        "fn": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "profile_scoped_metrics": {
            "expected": len(expected_in_profile),
            "tp": len(prof_tp_pairs),
            "fp": len(prof_fp_items),
            "fn": len(prof_fn_items),
            "precision": round(profile_precision, 4),
            "recall": round(profile_recall, 4),
            "f1_score": round(profile_f1, 4),
        },
        "clean_control_routes": clean_control_routes,
        "clean_control_fp": clean_control_fp,
        "clean_control_fp_details": clean_control_fp_details,
        "crawler_coverage": round(crawler_coverage, 4),
        "discovered_known_count": len(discovered_known_paths),
        "total_known_count": len(known_set),
        "discovered_known_endpoints": discovered_known_paths,
        "missing_known_endpoints": missing_known_paths,
        "scheduled_checks": scheduled_check_ids,
        "executed_checks": executed_checks_seen,
        "all_17_checks_executed": all_17_checks_executed,
        "scanner_errors": list(outcome.errors),
        "gates": gates,
        "per_check": per_check,
        "per_category": per_category,
        "fp_details": fp_items,
        "fn_details": fn_items,
        "detected_findings": detected_items,
    }


def benchmark_all_profiles(
    target_url: str,
    *,
    ground_truth_path: str | Path = DEFAULT_GROUND_TRUTH_PATH,
    rate_limit_rps: float = 10.0,
    max_requests: int = 2000,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """Evaluate ``Quick``, ``Standard``, and ``Deep`` profiles sequentially on ``target_url``."""
    profiles_order = (ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP)
    results_by_profile: dict[str, dict[str, Any]] = {}
    for prof in profiles_order:
        results_by_profile[prof.value] = evaluate_target(
            target_url,
            ground_truth_path=ground_truth_path,
            profile=prof,
            rate_limit_rps=rate_limit_rps,
            max_requests=max_requests,
            timeout_s=timeout_s,
        )

    return {
        "mode": "all_profiles",
        "primary_profile": ScanProfile.DEEP.value,
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_name": results_by_profile[ScanProfile.DEEP.value]["target_name"],
        "target_url": target_url,
        "ground_truth_path": str(ground_truth_path),
        "rate_limit_rps": rate_limit_rps,
        "profiles": results_by_profile,
        "primary": results_by_profile[ScanProfile.DEEP.value],
    }


def _pct(val: float) -> str:
    return f"{val * 100:.1f}%"


def format_terminal_summary(bundle: dict[str, Any]) -> str:
    """Format a crisp human-readable ASCII/Unicode terminal summary table."""
    profiles_map: dict[str, dict[str, Any]] = bundle["profiles"]
    primary: dict[str, Any] = bundle["primary"]

    lines: list[str] = []
    sep = "=" * 96
    lines.append(sep)
    lines.append(
        f"OWASP Lite Scanner — Empirical Evaluation Summary ({primary['target_name']})"
    )
    lines.append(f"Target: {primary['target_url']} | Ground Truth: {primary['ground_truth_path']}")
    lines.append(sep)
    header = (
        f"{'Profile':<10} {'Checks':>6} {'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'CleanFP':>8} {'Cov':>8} {'Reqs':>6} {'Time(s)':>8}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for prof_name in ("quick", "standard", "deep"):
        if prof_name not in profiles_map:
            continue
        r = profiles_map[prof_name]
        lines.append(
            f"{prof_name.capitalize():<10} {len(r['executed_checks']):>6} "
            f"{r['tp']:>4} {r['fp']:>4} {r['fn']:>4} "
            f"{_pct(r['precision']):>8} {_pct(r['recall']):>8} {_pct(r['f1_score']):>8} "
            f"{r['clean_control_fp']:>8} {_pct(r['crawler_coverage']):>8} "
            f"{r['requests_sent']:>6} {r['duration_seconds']:>8.2f}"
        )

    lines.append("-" * len(header))
    lines.append(f"\nPer-Check Breakdown ({primary['profile'].capitalize()} Profile):")
    chk_hdr = (
        f"{'Check ID':<26} {'Kind':<10} {'OWASP':<6} {'Exp':>4} {'Det':>4} "
        f"{'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>7} {'Rec':>7} {'F1':>7} {'Status':<10}"
    )
    lines.append(chk_hdr)
    lines.append("-" * len(chk_hdr))
    for row in primary["per_check"]:
        lines.append(
            f"{row['check_id']:<26} {row['kind']:<10} {row['owasp_code']:<6} "
            f"{row['expected']:>4} {row['detected']:>4} "
            f"{row['tp']:>3} {row['fp']:>3} {row['fn']:>3} "
            f"{_pct(row['precision']):>7} {_pct(row['recall']):>7} {_pct(row['f1_score']):>7} "
            f"{row['status']:<10}"
        )

    gates = primary["gates"]
    lines.append("-" * len(chk_hdr))
    lines.append(
        "NFR-08 Acceptance Gates "
        f"({primary['profile'].capitalize()}): "
        f"Recall {_pct(primary['recall'])} (>= 80.0%: {'PASS' if gates['recall_pass'] else 'FAIL'}) | "
        f"Precision {_pct(primary['precision'])} (>= 85.0%: {'PASS' if gates['precision_pass'] else 'FAIL'}) | "
        f"F1 {_pct(primary['f1_score'])} (>= 82.0%: {'PASS' if gates['f1_pass'] else 'FAIL'}) | "
        f"Clean-Route FPs: {primary['clean_control_fp']} (== 0: {'PASS' if gates['clean_control_fp_pass'] else 'FAIL'}) | "
        f"Errors: {len(primary['scanner_errors'])}"
    )
    lines.append(f"Overall NFR-08 Gate Status: {'PASS' if gates['nfr08_passed'] else 'FAIL'}")
    if primary["scanner_errors"]:
        lines.append("Scanner Errors:")
        for err in primary["scanner_errors"]:
            lines.append(f"  - {err}")
    lines.append(sep)
    return "\n".join(lines)


def render_markdown_report(bundle: dict[str, Any]) -> str:
    """Generate the formal academic ``docs/reports/TESTBENCH_RESULTS.md`` benchmark report."""
    profiles_map: dict[str, dict[str, Any]] = bundle["profiles"]
    primary: dict[str, Any] = bundle["primary"]
    gates: dict[str, Any] = primary["gates"]
    generated_at = bundle.get("generated_at_utc") or primary.get("timestamp_utc", "")

    md: list[str] = []
    md.append("# Phase 6 Empirical Validation & Testbench Benchmark Report")
    md.append("")
    md.append(
        "> **Automated Reproducibility Statement:** All quantitative VulnBench metrics in "
        "this report were generated directly by `scripts/evaluate.py` executing "
        "`backend.scanner.ScanOrchestrator` against the deterministic local `VulnBench` "
        "server (`testbench/vulnbench/app.py`) and verified against `testbench/ground_truth.json`."
    )
    md.append("")
    md.append("| Metadata Field | Value |")
    md.append("|---|---|")
    md.append(f"| **Generated (UTC)** | `{generated_at}` |")
    md.append(f"| **Primary Benchmark Target** | `{primary['target_name']}` (Python 3.12 stdlib `ThreadingHTTPServer` + in-memory `sqlite3`) |")
    md.append(f"| **Ground-Truth Manifest** | `testbench/ground_truth.json` (`{primary['expected_total']}` expected findings across all 17 OWASP checks; `{len(primary['clean_control_routes'])}` clean `/safe/*` control routes) |")
    md.append(f"| **Primary Evaluation Profile** | `{primary['profile'].capitalize()}` (`{len(primary['executed_checks'])} / 17` checks executed, `{len(primary['scanner_errors'])}` runtime errors) |")
    md.append(f"| **Rate Limit Configuration** | `{bundle.get('rate_limit_rps', 10.0)} req/s` (default non-destructive throttle, `max_requests=2000`) |")
    md.append(f"| **Overall NFR-08 Gate Verdict** | **{'PASS' if gates['nfr08_passed'] else 'FAIL'}** |")
    md.append("")

    # 1. Acceptance Gate Scorecard
    md.append("## 1. Quantitative Acceptance Gate Scorecard (`NFR-08`, `NFR-02`, `NFR-07`)")
    md.append("")
    md.append(
        "| Acceptance Gate | Governing Req. | Mandatory Threshold | Observed (`Deep`) | Status |"
    )
    md.append("|---|---|---:|---:|---|")
    md.append(
        f"| **Overall Recall (TPR)** | `NFR-08` | `>= 80.0%` | **{_pct(primary['recall'])}** (`{primary['tp']}/{primary['expected_total']}`) | {'PASS' if gates['recall_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Overall Precision** | `NFR-08` | `>= 85.0%` | **{_pct(primary['precision'])}** (`{primary['tp']}/{primary['tp'] + primary['fp']}`) | {'PASS' if gates['precision_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Overall F1-Score** | `NFR-08` | `>= 82.0%` | **{_pct(primary['f1_score'])}** | {'PASS' if gates['f1_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Clean-Control False Positives (`/safe/*`)** | `NFR-08` | `0` FPs (`0.0%` FPR) | **`{primary['clean_control_fp']}`** | {'PASS' if gates['clean_control_fp_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Crawler Route Coverage** | `FR-04` / Ch. 6 | `>= 80.0%` | **{_pct(primary['crawler_coverage'])}** (`{primary['discovered_known_count']}/{primary['total_known_count']}` routes) | {'PASS' if gates['crawler_coverage_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Deep Profile Scan Duration** | `NFR-02` | `<= {primary['duration_sla_seconds']:.0f} s` | **`{primary['duration_seconds']:.2f} s`** | {'PASS' if gates['duration_sla_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **Per-Check Error Isolation (Unhandled Crashes)** | `NFR-07` | `0` errors | **`{len(primary['scanner_errors'])}`** | {'PASS' if gates['zero_scanner_errors_pass'] else 'FAIL'} |"
    )
    md.append(
        f"| **All 17 OWASP Checks Executed** | `FR-05` | `17 / 17` | **`{len(primary['executed_checks'])} / 17`** | {'PASS' if gates['all_17_checks_executed'] else 'FAIL'} |"
    )
    md.append("")

    # 2. Scan Profile Comparison
    md.append("## 2. Empirical `VulnBench` Results Across Scan Profiles (`Quick`, `Standard`, `Deep`)")
    md.append("")
    md.append(
        "Table 2 compares all three scan profiles against the identical `VulnBench` instance. "
        "Note that `Quick` executes only the 8 passive checks (zero active injection probes), "
        "`Standard` adds 5 active checks plus `sensitive_files` (14 checks total), and `Deep` "
        "executes all 17 checks including `idor_heuristic`, `directory_listing`, and `forced_browsing_admin`."
    )
    md.append("")
    md.append(
        "| Profile | Checks Run | Seeded Total | Profile Expected | TP | FP | FN (All) | Precision | Recall (All) | Recall (Profile) | F1 (All) | Clean FPs | Route Coverage | Pages Crawled | Requests | Duration (s) | SLA (s) | Risk Score |"
    )
    md.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    for prof_name in ("quick", "standard", "deep"):
        if prof_name not in profiles_map:
            continue
        r = profiles_map[prof_name]
        ps = r["profile_scoped_metrics"]
        md.append(
            f"| **{prof_name.capitalize()}** | {len(r['executed_checks'])}/17 | "
            f"{r['expected_total']} | {r['expected_in_profile']} | "
            f"{r['tp']} | {r['fp']} | {r['fn']} | "
            f"{_pct(r['precision'])} | {_pct(r['recall'])} | {_pct(ps['recall'])} | "
            f"{_pct(r['f1_score'])} | {r['clean_control_fp']} | "
            f"{_pct(r['crawler_coverage'])} ({r['discovered_known_count']}/{r['total_known_count']}) | "
            f"{r['pages_crawled']} | {r['requests_sent']} | "
            f"{r['duration_seconds']:.2f} | <= {r['duration_sla_seconds']:.0f} | {r['risk_score']}/100 |"
        )
    md.append("")

    # 3. Per-Check Breakdown (17 Checks)
    md.append(f"## 3. Per-Check Empirical Breakdown ({primary['profile'].capitalize()} Profile — All 17 Checks)")
    md.append("")
    md.append(
        "| Check ID | Kind | OWASP 2021 | Expected | Detected | TP | FP | FN | Precision | Recall | F1-Score | Status |"
    )
    md.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for row in primary["per_check"]:
        md.append(
            f"| `{row['check_id']}` | {row['kind']} | `{row['owasp_code']}` | "
            f"{row['expected']} | {row['detected']} | {row['tp']} | {row['fp']} | {row['fn']} | "
            f"{_pct(row['precision'])} | {_pct(row['recall'])} | {_pct(row['f1_score'])} | **{row['status']}** |"
        )
    md.append("")

    # 4. Per-OWASP Category Accuracy vs SAD Chapter 6.4.1 Targets
    md.append("## 4. Per-OWASP Category Accuracy vs. SAD Chapter 6.4.1 Target Baselines")
    md.append("")
    md.append(
        "| OWASP Category | Assigned Checks | Seeded | TP | FP | FN | Observed Recall | SAD Target Recall | Observed Precision | SAD Target Precision | Observed F1 |"
    )
    md.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cat in primary["per_category"]:
        code = cat["owasp_code"]
        target = SAD_CATEGORY_TARGETS.get(code, {})
        tgt_rec = _pct(target["recall"]) if "recall" in target else "—"
        tgt_prec = _pct(target["precision"]) if "precision" in target else "—"
        checks_str = ", ".join(f"`{cid}`" for cid in cat["check_ids"])
        md.append(
            f"| **{cat['owasp_category']}** | {checks_str} | {cat['expected']} | "
            f"{cat['tp']} | {cat['fp']} | {cat['fn']} | "
            f"{_pct(cat['recall'])} | {tgt_rec} | {_pct(cat['precision'])} | {tgt_prec} | {_pct(cat['f1_score'])} |"
        )
    md.append("")

    # 5. Clean Control Route Verification
    md.append("## 5. Clean Control Route False-Positive Verification (`/safe/*`)")
    md.append("")
    md.append(
        "To confirm that active injection, redirect, CSRF, and header heuristics do not trigger "
        "false alarms on properly hardened endpoints, `VulnBench` exposes four clean control routes "
        "implementing strict security headers, HTML output encoding, parameterized SQLite queries, "
        "allow-listed redirects, and anti-CSRF tokens:"
    )
    md.append("")
    md.append("| Clean Control Route | Hardening Controls Tested | Discovered by Crawler | False Positives Observed | Verdict |")
    md.append("|---|---|---|---:|---|")
    clean_descriptions = {
        "/safe/search": "HTML-escaped output (`html.escape(..., quote=True)`) + strict headers (`xss_reflected` negative control)",
        "/safe/item": "Parameterized SQLite query (`?`) + non-enumerable ID check (`sqli_*` & `idor_heuristic` negative control)",
        "/safe/redirect": "Strict relative-path allowlist (`{/home, /about}`) (`open_redirect` negative control)",
        "/safe/form": "Hidden `csrf_token` field + non-password POST form (`csrf_missing_token` & `insecure_transport` negative control)",
    }
    discovered_set = set(primary["discovered_known_endpoints"])
    for route in primary["clean_control_routes"]:
        route_fps = [
            f for f in primary["clean_control_fp_details"] if f["path"] == route
        ]
        desc = clean_descriptions.get(route, "Hardened negative control endpoint")
        disc = "Yes" if route in discovered_set else "No"
        verdict = "PASS" if len(route_fps) == 0 else "FAIL"
        md.append(f"| `{route}` | {desc} | {disc} | `{len(route_fps)}` | **{verdict}** |")
    md.append("")

    # 6. Crawler Route Coverage Analysis
    md.append("## 6. Crawler Route Coverage Analysis")
    md.append("")
    md.append(
        f"- **Known Linked Routes in Manifest:** `{primary['total_known_count']}`"
    )
    md.append(
        f"- **Discovered Known Routes (`Deep`):** `{primary['discovered_known_count']}` "
        f"(**{_pct(primary['crawler_coverage'])}**)"
    )
    md.append(
        f"- **Total Attack Surface Recorded (`Deep`):** `{primary['endpoints_discovered']}` endpoints, "
        f"`{primary['forms_discovered']}` forms, `{primary['pages_crawled']}` pages crawled"
    )
    if primary["missing_known_endpoints"]:
        missing_str = ", ".join(f"`{p}`" for p in primary["missing_known_endpoints"])
        md.append(f"- **Undiscovered Known Routes:** {missing_str}")
    else:
        md.append("- **Undiscovered Known Routes:** None (100% of linked routes discovered).")
    md.append("")

    # 7. External Community Benchmark Procedure (DVWA & OWASP Juice Shop)
    md.append("## 7. External Community Target Benchmarking Procedure (Docker Testbench)")
    md.append("")
    md.append(
        "To mitigate construct-validity bias from evaluating solely against our own `VulnBench` target "
        "(SAD Section 6.7.2), `docker-compose.testbench.yml` provisions two independent community "
        "targets strictly bound to `127.0.0.1` on an isolated `testbench_net` bridge network."
    )
    md.append("")
    md.append("### 7.1 Provisioning All Three Testbench Containers")
    md.append("")
    md.append("```bash")
    md.append("# 1. Start VulnBench (127.0.0.1:5050), DVWA (127.0.0.1:8080), and OWASP Juice Shop (127.0.0.1:3000)")
    md.append("docker compose -f docker-compose.testbench.yml up -d")
    md.append("")
    md.append("# 2. Verify all local testbench services respond on loopback only")
    md.append("curl -fsS http://127.0.0.1:5050/ > /dev/null && echo 'VulnBench ready'")
    md.append("curl -fsS http://127.0.0.1:8080/login.php > /dev/null && echo 'DVWA ready'")
    md.append("curl -fsS http://127.0.0.1:3000/ > /dev/null && echo 'Juice Shop ready'")
    md.append("```")
    md.append("")
    md.append("### 7.2 Tier 2: DVWA (`http://127.0.0.1:8080`, Authenticated Server-Rendered Benchmark)")
    md.append("")
    md.append(
        "1. Initialize the DVWA database once at `http://127.0.0.1:8080/setup.php` (**Create / Reset Database**).\n"
        "2. In the OWASP Lite Scanner dashboard (`http://127.0.0.1:8000`), create a project for "
        "`http://127.0.0.1:8080` with ownership confirmed, select the **Standard** or **Deep** profile, "
        "and enable **DVWA Auto-Login** (`admin` / `password`, `security=low` or `security=medium`).\n"
        "3. Verify that:\n"
        "   - The crawler authenticates cleanly via `ScannerHttpClient.auto_login_dvwa()` and skips `/logout.php` via `ScopeGuardrail.is_destructive_path()`.\n"
        "   - `sqli_error_based` / `sqli_boolean_diff`, `xss_reflected`, `csrf_missing_token`, `missing_security_headers`, `insecure_cookies`, and `server_banner_leak` fire on the expected DVWA modules.\n"
        "   - Switching DVWA to `security=medium` demonstrates reduced findings and cross-scan diff classification (`Fixed` vs `Unchanged`)."
    )
    md.append("")
    md.append("### 7.3 Tier 3: OWASP Juice Shop (`http://127.0.0.1:3000`, Modern SPA Benchmark)")
    md.append("")
    md.append(
        "1. Create a project for `http://127.0.0.1:3000` (anonymous or with an optional Bearer JWT obtained from `/rest/user/login`) and run the **Standard** or **Deep** profile.\n"
        "2. Verify that:\n"
        "   - Pre-scan Soft-404 calibration (`calibrate_soft_404`) accurately fingerprints Angular's catch-all `index.html` HTTP `200 OK` fallback and prevents false-positive floods in `sensitive_files`, `directory_listing`, and `forced_browsing_admin`.\n"
        "   - Passive/active checks detect permissive CORS (`cors_misconfig`), missing/weak CSP headers, and outdated client-side libraries where exposed.\n"
        "   - Non-headless crawler route coverage aligns with the documented ~35% SPA ceiling (SAD Section 6.4.2 & 6.7.1)."
    )
    md.append("")
    md.append("### 7.4 Re-Running the Automated `VulnBench` Benchmark Anytime")
    md.append("")
    md.append("```bash")
    md.append("# Zero-external-server reproducible run across Quick, Standard, and Deep profiles:")
    md.append(
        "python scripts/evaluate.py --auto-start-vulnbench --benchmark-all-profiles "
        "--write-report docs/reports/TESTBENCH_RESULTS.md --json-out data/eval_results.json"
    )
    md.append("")
    md.append("# Or against a running Docker VulnBench container:")
    md.append(
        "python scripts/evaluate.py --target http://127.0.0.1:5050 --benchmark-all-profiles "
        "--ground-truth testbench/ground_truth.json"
    )
    md.append("```")
    md.append("")

    # 8. Qualitative DX Comparison Rubric vs OWASP ZAP
    md.append("## 8. Developer-Experience (DX) Comparison Rubric vs. OWASP ZAP Baseline")
    md.append("")
    md.append(
        "Aligned with SAD Section 6.6, the scanner's primary differentiation is **developer ergonomics "
        "and rapid remediation for student and local web projects** rather than enterprise scan breadth. "
        "Table 8 summarizes the structured 5-dimension comparison rubric against **OWASP ZAP** on the "
        "identical `VulnBench` target."
    )
    md.append("")
    md.append("| DX Dimension | Measurement Protocol | OWASP ZAP Baseline | OWASP Lite Scanner (This Project) | Key Engineering Advantage |")
    md.append("|---|---|---|---|---|")
    md.append(
        "| **1. Setup Time** | Clean host to first completed `VulnBench` scan | `10–20 min` (JVM/Desktop or CLI Docker flags, proxy CA cert, context config) | **`< 3 min`** (`docker compose up` or `uvicorn` + single-command `evaluate.py`) | Zero JVM overhead, SQLite default, zero proxy CA configuration |"
    )
    md.append(
        "| **2. Configuration Steps** | Manual steps before scan starts | `6–10+` steps (mode, spider policy, active scan policy, alert thresholds) | **`<= 3` steps** (create project + confirm ownership, choose profile, launch) | Opinionated `Quick` / `Standard` / `Deep` profiles + built-in loopback safety guardrail |"
    )
    md.append(
        "| **3. Finding Clarity** | Junior developer review of 5 seeded flaws | Raw HTTP traces, WASC/CWE jargon, analyst-oriented descriptions | Exact `METHOD /path · param`, severity/confidence badge, plain-language root cause | Eliminates security-analyst translation overhead (`FR-08`) |"
    )
    md.append(
        "| **4. Copy-Ready Fix Guidance** | Remediation inspection per finding | Conceptual paragraphs + external OWASP/CWE links | Multi-stack **Before / After** code tabs (**FastAPI, Flask, Express, PHP, HTML**) | Directly copy-pasteable remediation tailored to student web stacks (`FR-09`) |"
    )
    md.append(
        "| **5. Time-to-First-Fix (TTFF)** | Locate, patch, and re-verify 3 `VulnBench` flaws | Manual re-scan and alert diffing | One-click re-scan + deterministic SHA-1 cross-scan diff showing **`Fixed`** badges | Closed feedback loop accelerates developer remediation (`FR-11`) |"
    )
    md.append("")
    md.append(
        "> **Fair Trade-Off Disclosure:** OWASP ZAP and Burp Suite remain superior for enterprise "
        "penetration testing requiring an intercepting HTTPS proxy, headless AJAX spidering, custom "
        "active fuzzer scripts, and broad non-OWASP CVE coverage. OWASP Lite Scanner intentionally "
        "trades enterprise breadth for safe local defaults, sub-minute feedback, and actionable code fixes."
    )
    md.append("")

    # 9. Honest Limitations, Observed Misses & False Positives
    md.append("## 9. Honest Limitations, Observed Misses / False Positives & Threats to Validity")
    md.append("")
    md.append("### 9.1 Observed False Negatives & False Positives on `VulnBench` (`Deep` Profile)")
    md.append("")
    if not primary["fn_details"] and not primary["fp_details"]:
        md.append(
            f"- **False Negatives (`FN = 0`):** All `{primary['expected_total']}` seeded ground-truth "
            "findings across all 17 OWASP checks were detected cleanly."
        )
        md.append(
            "- **False Positives (`FP = 0`):** Zero unexpected findings were emitted across both "
            "vulnerable routes and all four `/safe/*` clean control routes."
        )
    else:
        if primary["fn_details"]:
            md.append(f"- **Observed False Negatives (`FN = {len(primary['fn_details'])}`):**")
            for miss in primary["fn_details"]:
                md.append(
                    f"  - `{miss['check_id']}` on `{miss['method']} {miss['path']}` "
                    f"(parameter: `{miss['parameter']}`)"
                )
        else:
            md.append("- **Observed False Negatives (`FN = 0`):** None.")

        if primary["fp_details"]:
            md.append(f"- **Observed False Positives (`FP = {len(primary['fp_details'])}`):**")
            for extra in primary["fp_details"]:
                md.append(
                    f"  - `{extra['check_id']}` on `{extra['method']} {extra['path']}` "
                    f"(parameter: `{extra['parameter']}`, severity: `{extra['severity']}`)"
                )
        else:
            md.append("- **Observed False Positives (`FP = 0`):** None.")
    md.append("")

    md.append("### 9.2 Architectural Boundaries & Threats to Validity")
    md.append("")
    md.append(
        "1. **Construct Validity (`VulnBench` Authorship):** Because `VulnBench` was authored alongside "
        "the 17 checks, 100% or near-100% deterministic metrics on `VulnBench` validate check contract "
        "correctness and regression safety rather than universal real-world recall. Cross-validation "
        "against **DVWA** and **OWASP Juice Shop** (Section 7) is essential for external generalization.\n"
        "2. **Non-Headless SPA Crawling Ceiling:** The lightweight `requests` + `BeautifulSoup4` crawler "
        "does not execute client-side JavaScript frameworks (React/Angular/Vue). SPAs that build routes "
        "dynamically at runtime exhibit lower automated discovery coverage than server-rendered apps.\n"
        "3. **Non-Destructive Scope Boundary:** Persistent state-mutating attacks (Stored XSS across "
        "sessions, Second-Order SQLi, Blind OOB SSRF, and destructive `DELETE`/`/logout` mutations) are "
        "deliberately excluded to uphold ethical non-destructive scanning guarantees (`NFR-03`).\n"
        "4. **Heuristic Tentative Confidence (`idor_heuristic`):** Numeric ID adjacency probing cannot "
        "prove broken authorization without multi-user session comparison; findings are intentionally "
        "labeled `confidence=low` so developers manually confirm object-level ownership checks.\n"
        "5. **Loopback & Private-Network Scope Guardrail:** Public internet scanning is hard-blocked by "
        "`ScopeGuardrail` (`127.0.0.1`, `localhost`, and RFC1918 allow-listed targets only)."
    )
    md.append("")
    return "\n".join(md)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run empirical OWASP Lite Scanner evaluation against VulnBench or an "
            "external local testbench target and verify SAD Chapter 6 / NFR-08 gates."
        )
    )
    parser.add_argument(
        "--target",
        default="",
        help=(
            "Target base URL (e.g. http://127.0.0.1:5050). Optional when "
            "--auto-start-vulnbench is specified."
        ),
    )
    parser.add_argument(
        "--auto-start-vulnbench",
        action="store_true",
        help=(
            "Start VulnBench in-process on 127.0.0.1:0 (ephemeral port) for "
            "zero-dependency, single-command reproducible evaluation."
        ),
    )
    parser.add_argument(
        "--ground-truth",
        default=str(DEFAULT_GROUND_TRUTH_PATH),
        help="Path to ground-truth JSON manifest (default: testbench/ground_truth.json).",
    )
    parser.add_argument(
        "--profile",
        choices=("quick", "standard", "deep"),
        default="deep",
        help="Scan profile to evaluate (default: deep).",
    )
    parser.add_argument(
        "--benchmark-all-profiles",
        action="store_true",
        help="Run Quick, Standard, and Deep profiles sequentially and compare results.",
    )
    parser.add_argument(
        "--rate-limit-rps",
        type=float,
        default=10.0,
        help="Maximum HTTP requests per second during evaluation (default: 10.0).",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=2000,
        help="Maximum HTTP request budget per scan profile (default: 2000).",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=10.0,
        help="Per-request HTTP timeout in seconds (default: 10.0).",
    )
    parser.add_argument(
        "--write-report",
        default="",
        help="Optional output path to write the Markdown benchmark report (e.g. docs/reports/TESTBENCH_RESULTS.md).",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional output path to write raw JSON evaluation metrics (e.g. data/eval_results.json).",
    )
    return parser


def _execute_evaluation(args: argparse.Namespace, target_url: str) -> dict[str, Any]:
    if args.benchmark_all_profiles:
        return benchmark_all_profiles(
            target_url,
            ground_truth_path=args.ground_truth,
            rate_limit_rps=args.rate_limit_rps,
            max_requests=args.max_requests,
            timeout_s=args.timeout_s,
        )

    single = evaluate_target(
        target_url,
        ground_truth_path=args.ground_truth,
        profile=args.profile,
        rate_limit_rps=args.rate_limit_rps,
        max_requests=args.max_requests,
        timeout_s=args.timeout_s,
    )
    return {
        "mode": "single_profile",
        "primary_profile": single["profile"],
        "generated_at_utc": single["timestamp_utc"],
        "target_name": single["target_name"],
        "target_url": target_url,
        "ground_truth_path": str(args.ground_truth),
        "rate_limit_rps": args.rate_limit_rps,
        "profiles": {single["profile"]: single},
        "primary": single,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.auto_start_vulnbench and not args.target.strip():
        parser.error("Provide --target <URL> or pass --auto-start-vulnbench.")

    if args.auto_start_vulnbench:
        with running_vulnbench_server("127.0.0.1", 0) as target_url:
            bundle = _execute_evaluation(args, target_url)
    else:
        bundle = _execute_evaluation(args, args.target.strip())

    print(format_terminal_summary(bundle))

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"Wrote JSON metrics to {json_path}")

    if args.write_report:
        if bundle["primary"]["status"] == ScanStatus.COMPLETED.value:
            report_path = Path(args.write_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(render_markdown_report(bundle), encoding="utf-8")
            print(f"Wrote Markdown benchmark report to {report_path}")
        else:
            print(
                f"Skipped writing report to {args.write_report} because scan status was "
                f"'{bundle['primary']['status']}' (target unreachable or cancelled).",
                file=sys.stderr,
            )

    primary_gates = bundle["primary"]["gates"]
    return 0 if primary_gates["nfr08_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
