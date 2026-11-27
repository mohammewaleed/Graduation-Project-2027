"""End-to-end scan lifecycle orchestrator for the OWASP Lite scanner.

Coordinates target scope validation, pre-flight reachability, optional DVWA
lab login, Soft-404 calibration, bounded BFS crawling, isolated plugin
execution, remediation enrichment, live deduplication, and risk scoring.
Pure Python with zero FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

import requests

from backend.scanner.checks import (
    BaseCheck,
    CheckContext,
    get_checks_for_profile,
)
from backend.scanner.crawler import ResponseCache, WebCrawler
from backend.scanner.http_client import (
    RequestLimitExceededError,
    ScanCancelledError,
    ScannerHttpClient,
    Soft404Fingerprint,
)
from backend.scanner.models import (
    AttackSurface,
    EndpointRecord,
    EnrichedFinding,
    FormRecord,
    ScanConfig,
    ScanProfile,
    ScanProgress,
    ScanStatus,
)
from backend.scanner.policy import ScopeGuardrail, ScopeViolationError
from backend.scanner.remediation import RemediationKB
from backend.scanner.scoring import (
    calculate_risk_score,
    compute_fingerprint,
    deduplicate_findings,
    sort_findings_by_severity,
    summarize_findings,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanOutcome:
    """Complete result bundle produced by ``ScanOrchestrator.run_scan``."""

    scan_id: str
    target_url: str
    profile: ScanProfile
    status: ScanStatus
    risk_score: int
    summary: dict[str, int]
    endpoints: list[EndpointRecord] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)
    findings: list[EnrichedFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    requests_sent: int = 0
    duration_seconds: float = 0.0


class ScanOrchestrator:
    """Coordinates crawling, check execution, remediation enrichment, and scoring."""

    def __init__(
        self,
        guardrail: ScopeGuardrail | None = None,
        kb: RemediationKB | None = None,
    ) -> None:
        self.guardrail = guardrail if guardrail is not None else ScopeGuardrail()
        self.kb = kb if kb is not None else RemediationKB()

    def run_scan(
        self,
        config: ScanConfig,
        *,
        scan_id: str = "",
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        finding_callback: Callable[[EnrichedFinding], None] | None = None,
        checks: list[BaseCheck] | None = None,
    ) -> ScanOutcome:
        """Execute a full scan for ``config`` and return a ``ScanOutcome``.

        Raises ``ScopeViolationError`` immediately if ``config.target_url``
        violates ``ScopeGuardrail`` so API callers can return HTTP 403.
        All other runtime failures (unreachable target, individual check
        exceptions, cancellation) are handled cleanly and recorded in the
        returned ``ScanOutcome``.
        """
        started = time.monotonic()
        effective_scan_id = scan_id or str(uuid.uuid4())
        event = cancel_event if cancel_event is not None else threading.Event()
        errors: list[str] = []

        # 1. Strict scope guardrail check (let ScopeViolationError propagate)
        validated_url = self.guardrail.validate_url(config.target_url)

        def emit_progress(progress: ScanProgress) -> None:
            if progress_callback is not None:
                progress_callback(progress)

        def build_outcome(
            status: ScanStatus,
            *,
            surface: AttackSurface | None = None,
            findings_list: list[EnrichedFinding] | None = None,
            pages_crawled: int = 0,
            requests_sent: int = 0,
        ) -> ScanOutcome:
            deduped = deduplicate_findings(findings_list or [])
            ordered = sort_findings_by_severity(deduped)
            summary = summarize_findings(ordered)
            risk_score = calculate_risk_score(ordered)
            return ScanOutcome(
                scan_id=effective_scan_id,
                target_url=validated_url,
                profile=config.profile,
                status=status,
                risk_score=risk_score,
                summary=summary,
                endpoints=list(surface.endpoints) if surface is not None else [],
                forms=list(surface.forms) if surface is not None else [],
                findings=ordered,
                errors=list(errors),
                pages_crawled=pages_crawled,
                requests_sent=requests_sent,
                duration_seconds=round(max(0.0, time.monotonic() - started), 3),
            )

        if event.is_set():
            return build_outcome(ScanStatus.CANCELLED)

        # 2. Build scoped, rate-limited HTTP client
        with ScannerHttpClient(
            guardrail=self.guardrail,
            rate_limit_rps=config.rate_limit_rps,
            max_requests=config.max_requests,
            timeout_s=config.timeout_s,
            cancel_event=event,
            auth_type=config.auth_type,
            auth_value=config.auth_value,
        ) as http_client:
            # 3. Pre-flight reachability check
            try:
                http_client.get(validated_url, follow_redirects=True)
            except ScanCancelledError:
                return build_outcome(
                    ScanStatus.CANCELLED,
                    requests_sent=http_client.requests_sent,
                )
            except (requests.RequestException, RequestLimitExceededError) as exc:
                errors.append(f"Target unreachable: {exc}")
                return build_outcome(
                    ScanStatus.FAILED,
                    requests_sent=http_client.requests_sent,
                )

            # 4. Optional DVWA auto-login and Soft-404 calibration
            if config.auto_login_dvwa:
                try:
                    logged_in = http_client.auto_login_dvwa(
                        validated_url,
                        username=config.dvwa_username,
                        password=config.dvwa_password,
                    )
                    if not logged_in:
                        errors.append(
                            "DVWA auto-login did not complete; continuing scan without DVWA session."
                        )
                except ScanCancelledError:
                    return build_outcome(
                        ScanStatus.CANCELLED,
                        requests_sent=http_client.requests_sent,
                    )
                except (
                    requests.RequestException,
                    RequestLimitExceededError,
                    ScopeViolationError,
                ) as exc:
                    errors.append(f"DVWA auto-login error: {exc}")

            soft_404: Soft404Fingerprint | None = None
            try:
                soft_404 = http_client.calibrate_soft_404(validated_url)
            except ScanCancelledError:
                return build_outcome(
                    ScanStatus.CANCELLED,
                    requests_sent=http_client.requests_sent,
                )
            except (
                requests.RequestException,
                RequestLimitExceededError,
                ScopeViolationError,
            ) as exc:
                errors.append(f"Soft-404 calibration skipped: {exc}")

            if event.is_set():
                return build_outcome(
                    ScanStatus.CANCELLED,
                    requests_sent=http_client.requests_sent,
                )

            # 5. Crawl target attack surface
            pages_crawled = 0
            max_pages = max(1, config.effective_max_pages)
            emit_progress(
                ScanProgress(
                    stage="crawling",
                    percent=5,
                    pages_crawled=0,
                    requests_sent=http_client.requests_sent,
                )
            )

            def on_crawl_progress(crawled: int, reqs: int, _url: str) -> None:
                nonlocal pages_crawled
                pages_crawled = crawled
                pct = min(40, 5 + int((crawled / max_pages) * 35))
                emit_progress(
                    ScanProgress(
                        stage="crawling",
                        percent=pct,
                        pages_crawled=crawled,
                        requests_sent=reqs,
                    )
                )

            crawler = WebCrawler(
                http_client=http_client,
                guardrail=self.guardrail,
                max_depth=config.effective_max_depth,
                max_pages=config.effective_max_pages,
                max_duration_s=config.effective_max_duration_s,
                progress_callback=on_crawl_progress,
            )

            surface = AttackSurface(base_url=validated_url)
            responses = ResponseCache()
            try:
                surface, responses = crawler.crawl(validated_url)
            except ScanCancelledError:
                return build_outcome(
                    ScanStatus.CANCELLED,
                    surface=surface,
                    pages_crawled=pages_crawled,
                    requests_sent=http_client.requests_sent,
                )

            if pages_crawled == 0 and len(responses) > 0:
                pages_crawled = len(responses)

            if event.is_set():
                return build_outcome(
                    ScanStatus.CANCELLED,
                    surface=surface,
                    pages_crawled=pages_crawled,
                    requests_sent=http_client.requests_sent,
                )

            # 6. Load enabled checks for the active profile
            selected_checks = (
                list(checks)
                if checks is not None
                else get_checks_for_profile(config.profile, config.enabled_checks)
            )
            ctx = CheckContext(
                target_url=validated_url,
                http_client=http_client,
                guardrail=self.guardrail,
                surface=surface,
                responses=responses,
                soft_404=soft_404,
                cancel_event=event,
                config=config,
            )

            # 7. Execute each check with per-check exception isolation & live dedup
            live_findings: dict[str, EnrichedFinding] = {}
            total_checks = len(selected_checks)

            for idx, check in enumerate(selected_checks):
                if event.is_set():
                    return build_outcome(
                        ScanStatus.CANCELLED,
                        surface=surface,
                        findings_list=list(live_findings.values()),
                        pages_crawled=pages_crawled,
                        requests_sent=http_client.requests_sent,
                    )

                pct = 40 + int((idx / max(1, total_checks)) * 55)
                emit_progress(
                    ScanProgress(
                        stage="scanning",
                        percent=min(95, pct),
                        pages_crawled=pages_crawled,
                        requests_sent=http_client.requests_sent,
                        current_check=check.id,
                    )
                )

                try:
                    raw_findings = check.run(ctx) or []
                except ScanCancelledError:
                    return build_outcome(
                        ScanStatus.CANCELLED,
                        surface=surface,
                        findings_list=list(live_findings.values()),
                        pages_crawled=pages_crawled,
                        requests_sent=http_client.requests_sent,
                    )
                except RequestLimitExceededError as exc:
                    errors.append(f"Check '{check.id}' halted (request cap): {exc}")
                    break
                except Exception as exc:
                    logger.warning(
                        "Check '%s' raised an unhandled exception in scan %s: %s",
                        check.id,
                        effective_scan_id,
                        exc,
                    )
                    errors.append(f"Check '{check.id}' failed: {exc}")
                    continue

                for raw in raw_findings:
                    explanation, fix = self.kb.build_remediation(
                        raw,
                        target_stack=config.target_stack,
                    )
                    fp = compute_fingerprint(
                        raw.check_id,
                        raw.method,
                        raw.url,
                        raw.parameter,
                    )
                    enriched = EnrichedFinding.from_raw(
                        raw,
                        explanation=explanation,
                        fix=fix,
                        fingerprint=fp,
                    )

                    existing = live_findings.get(fp)
                    if existing is None:
                        live_findings[fp] = enriched
                        if finding_callback is not None:
                            finding_callback(enriched)
                    else:
                        winner = deduplicate_findings([existing, enriched])[0]
                        if winner is enriched:
                            live_findings[fp] = enriched
                            if finding_callback is not None:
                                finding_callback(enriched)

                if event.is_set():
                    return build_outcome(
                        ScanStatus.CANCELLED,
                        surface=surface,
                        findings_list=list(live_findings.values()),
                        pages_crawled=pages_crawled,
                        requests_sent=http_client.requests_sent,
                    )

            # 8. Finalize, score, and emit 100% progress
            outcome = build_outcome(
                ScanStatus.COMPLETED,
                surface=surface,
                findings_list=list(live_findings.values()),
                pages_crawled=pages_crawled,
                requests_sent=http_client.requests_sent,
            )
            emit_progress(
                ScanProgress(
                    stage="completed",
                    percent=100,
                    pages_crawled=pages_crawled,
                    requests_sent=http_client.requests_sent,
                    current_check="",
                )
            )
            return outcome


__all__ = [
    "ScanOrchestrator",
    "ScanOutcome",
]
