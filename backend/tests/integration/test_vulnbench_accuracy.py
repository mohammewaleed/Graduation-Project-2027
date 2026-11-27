"""Phase 6 empirical accuracy integration tests against deterministic VulnBench.

Spins up ``create_vulnbench_server("127.0.0.1", 0)`` in-process on an ephemeral
loopback port, executes ``evaluate_target(...)`` from ``scripts/evaluate.py`` in
the ``DEEP`` profile, and verifies all SAD Chapter 6 / NFR-08 acceptance gates:
- ``recall >= 0.80`` (NFR-08)
- ``precision >= 0.85`` (NFR-08)
- ``clean_control_fp == 0`` (zero false positives on ``/safe/*`` control routes)
- ``crawler_coverage >= 0.80``
- ``all_17_checks_executed`` cleanly with ``0`` scanner errors (NFR-07)
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from backend.scanner import ScanProfile, ScanStatus
from scripts.evaluate import (
    DEFAULT_GROUND_TRUTH_PATH,
    evaluate_target,
    render_markdown_report,
)
from testbench.vulnbench.app import create_vulnbench_server


@pytest.fixture(scope="module")
def vulnbench_url() -> Iterator[str]:
    """Start an ephemeral local VulnBench HTTP server on ``127.0.0.1:0``."""
    server = create_vulnbench_server("127.0.0.1", 0)
    host, port = server.server_address[:2]
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        name="pytest-vulnbench-server",
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@pytest.fixture(scope="module")
def deep_eval_result(vulnbench_url: str) -> dict[str, Any]:
    """Run ``evaluate_target`` once in DEEP profile across the module tests."""
    return evaluate_target(
        vulnbench_url,
        ground_truth_path=DEFAULT_GROUND_TRUTH_PATH,
        profile=ScanProfile.DEEP,
        rate_limit_rps=50.0,
    )


def test_vulnbench_deep_nfr08_accuracy_gates(deep_eval_result: dict[str, Any]) -> None:
    """Verify NFR-08 Recall >= 0.80, Precision >= 0.85, F1 >= 0.82, and 0 clean FPs."""
    assert deep_eval_result["status"] == ScanStatus.COMPLETED.value
    assert deep_eval_result["recall"] >= 0.80, (
        f"Recall {deep_eval_result['recall']:.3f} < 0.80; "
        f"missed={deep_eval_result['fn_details']}"
    )
    assert deep_eval_result["precision"] >= 0.85, (
        f"Precision {deep_eval_result['precision']:.3f} < 0.85; "
        f"false_positives={deep_eval_result['fp_details']}"
    )
    assert deep_eval_result["f1_score"] >= 0.82
    assert deep_eval_result["clean_control_fp"] == 0, (
        f"Expected 0 clean-control FPs, got {deep_eval_result['clean_control_fp_details']}"
    )
    assert deep_eval_result["gates"]["nfr08_passed"] is True


def test_vulnbench_crawler_coverage_and_17_checks_isolated(
    deep_eval_result: dict[str, Any],
) -> None:
    """Verify crawler route coverage >= 0.80 and all 17 checks run with 0 errors."""
    assert deep_eval_result["crawler_coverage"] >= 0.80, (
        f"Crawler coverage {deep_eval_result['crawler_coverage']:.3f} < 0.80; "
        f"missing={deep_eval_result['missing_known_endpoints']}"
    )
    assert deep_eval_result["scanner_errors"] == [], (
        f"Unexpected scanner errors: {deep_eval_result['scanner_errors']}"
    )
    assert deep_eval_result["all_17_checks_executed"] is True
    assert len(deep_eval_result["executed_checks"]) == 17
    assert len(deep_eval_result["per_check"]) == 17

    # All 4 clean control routes must be crawled and produce zero findings.
    expected_clean = {"/safe/search", "/safe/item", "/safe/redirect", "/safe/form"}
    assert expected_clean.issubset(set(deep_eval_result["clean_control_routes"]))
    assert expected_clean.issubset(set(deep_eval_result["discovered_known_endpoints"]))


def test_vulnbench_quick_profile_passive_only_and_zero_clean_fp(
    vulnbench_url: str,
) -> None:
    """Verify QUICK profile runs passive checks only with zero errors and 0 clean FPs."""
    quick_result = evaluate_target(
        vulnbench_url,
        ground_truth_path=DEFAULT_GROUND_TRUTH_PATH,
        profile=ScanProfile.QUICK,
        rate_limit_rps=50.0,
    )
    assert quick_result["status"] == ScanStatus.COMPLETED.value
    assert quick_result["scanner_errors"] == []
    assert len(quick_result["executed_checks"]) == 8
    assert quick_result["clean_control_fp"] == 0
    assert quick_result["precision"] >= 0.85
    assert quick_result["profile_scoped_metrics"]["recall"] >= 0.80


def test_markdown_report_rendering(deep_eval_result: dict[str, Any]) -> None:
    """Verify Markdown benchmark report contains empirical accuracy & DX sections."""
    bundle = {
        "mode": "single_profile",
        "primary_profile": "deep",
        "generated_at_utc": deep_eval_result["timestamp_utc"],
        "target_name": deep_eval_result["target_name"],
        "target_url": deep_eval_result["target_url"],
        "ground_truth_path": str(Path(DEFAULT_GROUND_TRUTH_PATH)),
        "rate_limit_rps": 50.0,
        "profiles": {"deep": deep_eval_result},
        "primary": deep_eval_result,
    }
    report = render_markdown_report(bundle)
    assert "NFR-08" in report
    assert "Overall Recall" in report
    assert "Clean Control Route" in report
    assert "OWASP ZAP" in report
    assert "DVWA" in report
    assert "Juice Shop" in report
