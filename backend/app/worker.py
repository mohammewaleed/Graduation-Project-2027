"""Background scan job executor with cooperative cancellation and SSE pub/sub."""

from __future__ import annotations

import json
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import settings
from backend.app.db_models import (
    DEFAULT_SUMMARY_COUNTS,
    Endpoint,
    Finding,
    Scan,
    utcnow,
)
from backend.scanner.models import (
    EnrichedFinding,
    ScanConfig,
    ScanProgress,
    ScanStatus,
)
from backend.scanner.orchestrator import ScanOrchestrator, ScanOutcome
from backend.scanner.policy import ScopeGuardrail

logger = logging.getLogger(__name__)

TERMINAL_SCAN_STATUSES: frozenset[str] = frozenset(
    {
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
)


def _enum_str(value: Any) -> str:
    """Serialize a StrEnum or string cleanly to a plain string."""
    return str(value.value if hasattr(value, "value") else value)


class ScanJobManager:
    """Manages bounded background scan execution, cancellation, and SSE fan-out."""

    def __init__(self, max_workers: int = 2) -> None:
        self._max_workers = max(1, int(max_workers))
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="owasp-scan",
        )
        self._is_shutdown = False
        self._cancel_events: dict[str, threading.Event] = {}
        self._subscribers: dict[str, list[queue.Queue[dict[str, Any]]]] = {}

    def ensure_running(self) -> None:
        """Ensure the worker thread pool is active (safe across lifespan restarts)."""
        with self._lock:
            if self._executor is None or self._is_shutdown:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="owasp-scan",
                )
                self._is_shutdown = False

    def submit_scan(
        self,
        scan_id: str,
        config: ScanConfig,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Enqueue a background scan job and register its cancellation event."""
        with self._lock:
            if self._executor is None or self._is_shutdown:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="owasp-scan",
                )
                self._is_shutdown = False
            cancel_event = self._cancel_events.setdefault(scan_id, threading.Event())
            executor = self._executor

        executor.submit(
            self._run_scan_job,
            scan_id,
            config,
            session_factory,
            cancel_event,
        )

    def cancel_scan(self, scan_id: str) -> bool:
        """Signal cooperative cancellation for an active or queued scan."""
        with self._lock:
            event = self._cancel_events.get(scan_id)
            if event is None:
                return False
            event.set()
            return True

    def subscribe(self, scan_id: str) -> queue.Queue[dict[str, Any]]:
        """Register a thread-safe SSE subscriber queue for ``scan_id``."""
        subscriber_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            self._subscribers.setdefault(scan_id, []).append(subscriber_queue)
        return subscriber_queue

    def unsubscribe(
        self,
        scan_id: str,
        subscriber_queue: queue.Queue[dict[str, Any]],
    ) -> None:
        """Remove a previously registered SSE subscriber queue for ``scan_id``."""
        with self._lock:
            queues = self._subscribers.get(scan_id)
            if not queues:
                return
            try:
                queues.remove(subscriber_queue)
            except ValueError:
                pass
            if not queues:
                self._subscribers.pop(scan_id, None)

    def publish_event(self, scan_id: str, event: dict[str, Any]) -> None:
        """Fan out an event payload to all active SSE subscribers for ``scan_id``."""
        with self._lock:
            subscribers = list(self._subscribers.get(scan_id, ()))
        for subscriber_queue in subscribers:
            try:
                subscriber_queue.put_nowait(event)
            except queue.Full:
                logger.debug("Dropped SSE event for scan %s: subscriber queue full", scan_id)

    def shutdown(self, wait: bool = False) -> None:
        """Cooperatively cancel running scans and shut down the thread pool."""
        with self._lock:
            for event in self._cancel_events.values():
                event.set()
            executor = self._executor
            self._is_shutdown = True
            self._executor = None

        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)

    def _run_scan_job(
        self,
        scan_id: str,
        config: ScanConfig,
        session_factory: sessionmaker[Session],
        cancel_event: threading.Event,
    ) -> None:
        """Worker thread entrypoint executing ``ScanOrchestrator`` and persisting results."""

        def on_progress(progress: ScanProgress) -> None:
            if progress.stage == "crawling":
                db_status = ScanStatus.CRAWLING.value
                db_stage = "crawling"
                db_percent = max(0, min(99, int(progress.percent)))
            elif progress.stage == "scanning":
                db_status = ScanStatus.SCANNING.value
                db_stage = progress.current_check or "scanning"
                db_percent = max(0, min(99, int(progress.percent)))
            else:
                # Keep DB status non-terminal until findings & endpoints commit atomically.
                db_status = ScanStatus.SCANNING.value
                db_stage = "finalizing"
                db_percent = 99

            try:
                with session_factory() as db:
                    scan = db.get(Scan, scan_id)
                    if scan is not None and scan.status not in TERMINAL_SCAN_STATUSES:
                        scan.status = db_status
                        scan.current_stage = db_stage
                        scan.progress_pct = db_percent
                        scan.pages_crawled = int(progress.pages_crawled)
                        scan.requests_sent = int(progress.requests_sent)
                        db.commit()
            except Exception as exc:  # pragma: no cover - defensive DB guard
                logger.warning("Failed to update scan progress for %s: %s", scan_id, exc)

            self.publish_event(
                scan_id,
                {
                    "type": "progress",
                    "scan_id": scan_id,
                    "status": db_status,
                    "stage": progress.stage,
                    "percent": int(progress.percent),
                    "pages_crawled": int(progress.pages_crawled),
                    "requests_sent": int(progress.requests_sent),
                    "current_check": progress.current_check,
                },
            )

        def on_finding(enriched: EnrichedFinding) -> None:
            self.publish_event(
                scan_id,
                {
                    "type": "finding",
                    "scan_id": scan_id,
                    "finding": {
                        "check_id": enriched.check_id,
                        "severity": _enum_str(enriched.severity),
                        "title": enriched.title,
                        "url": enriched.url,
                        "method": enriched.method,
                        "parameter": enriched.parameter,
                    },
                },
            )

        try:
            guardrail = ScopeGuardrail(allowlist=settings.allowlist_hosts)
            orchestrator = ScanOrchestrator(guardrail=guardrail)
            outcome = orchestrator.run_scan(
                config,
                scan_id=scan_id,
                cancel_event=cancel_event,
                progress_callback=on_progress,
                finding_callback=on_finding,
            )
            self._persist_outcome(scan_id, outcome, session_factory)
        except Exception as exc:
            logger.exception("Unhandled error in background scan %s", scan_id)
            self._persist_failure(scan_id, str(exc), session_factory)
        finally:
            with self._lock:
                self._cancel_events.pop(scan_id, None)

    def _persist_outcome(
        self,
        scan_id: str,
        outcome: ScanOutcome,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Persist discovered endpoints, findings, and terminal scan state atomically."""
        terminal_status = _enum_str(outcome.status)
        summary = dict(DEFAULT_SUMMARY_COUNTS)
        for key, value in (outcome.summary or {}).items():
            if key in summary:
                summary[key] = int(value)

        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                logger.warning("Scan %s no longer exists in DB; skipping persistence", scan_id)
            else:
                for ep in outcome.endpoints:
                    db.add(
                        Endpoint(
                            scan_id=scan_id,
                            url=ep.url,
                            method=(ep.method or "GET").upper(),
                            params_json=json.dumps(list(ep.params)),
                            source=ep.source or "link",
                            status_code=int(ep.status_code or 0),
                        )
                    )

                for item in outcome.findings:
                    fix_payload = asdict(item.fix)
                    db.add(
                        Finding(
                            scan_id=scan_id,
                            check_id=item.check_id,
                            owasp_category=str(item.owasp_category),
                            cwe_id=item.cwe_id,
                            severity=_enum_str(item.severity),
                            confidence=_enum_str(item.confidence),
                            title=item.title,
                            endpoint_url=item.url,
                            method=(item.method or "GET").upper(),
                            parameter=item.parameter,
                            evidence_json=json.dumps(dict(item.evidence or {})),
                            explanation=item.explanation,
                            fix_json=json.dumps(fix_payload),
                            triage_status=_enum_str(item.triage_status),
                            triage_note=None,
                            fingerprint=item.fingerprint,
                        )
                    )

                scan.status = terminal_status
                scan.current_stage = terminal_status
                if terminal_status == ScanStatus.COMPLETED.value:
                    scan.progress_pct = 100
                scan.pages_crawled = int(outcome.pages_crawled)
                scan.requests_sent = int(outcome.requests_sent)
                scan.risk_score = int(outcome.risk_score)
                scan.summary_json = json.dumps(summary)
                scan.error_log_json = json.dumps(list(outcome.errors or []))
                if scan.finished_at is None:
                    scan.finished_at = utcnow()
                db.commit()

        self.publish_event(
            scan_id,
            {
                "type": "status",
                "scan_id": scan_id,
                "status": terminal_status,
                "risk_score": int(outcome.risk_score),
                "summary": summary,
                "pages_crawled": int(outcome.pages_crawled),
                "requests_sent": int(outcome.requests_sent),
                "errors": list(outcome.errors or []),
            },
        )

    def _persist_failure(
        self,
        scan_id: str,
        error_message: str,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Record an unexpected scan execution failure and notify SSE subscribers."""
        summary = dict(DEFAULT_SUMMARY_COUNTS)
        errors = [error_message]
        try:
            with session_factory() as db:
                scan = db.get(Scan, scan_id)
                if scan is not None:
                    scan.status = ScanStatus.FAILED.value
                    scan.current_stage = ScanStatus.FAILED.value
                    scan.error_log_json = json.dumps(errors)
                    if scan.finished_at is None:
                        scan.finished_at = utcnow()
                    db.commit()
                    summary = scan.summary
        except Exception as exc:  # pragma: no cover - defensive DB guard
            logger.warning("Failed to record scan failure for %s: %s", scan_id, exc)

        self.publish_event(
            scan_id,
            {
                "type": "status",
                "scan_id": scan_id,
                "status": ScanStatus.FAILED.value,
                "risk_score": 0,
                "summary": summary,
                "errors": errors,
            },
        )


scan_job_manager = ScanJobManager()

__all__ = [
    "ScanJobManager",
    "TERMINAL_SCAN_STATUSES",
    "scan_job_manager",
]
