"""Loader and formatter for the multi-stack developer Remediation Knowledge Base.

Pure Python (standard library only) with zero FastAPI, SQLAlchemy, Starlette,
or Pydantic dependencies.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from backend.scanner.models import FixSnippet, RawFinding, RemediationFix

DEFAULT_KB_PATH = Path(__file__).with_name("kb.json")
SUPPORTED_STACKS: tuple[str, ...] = ("fastapi", "flask", "express", "php", "html")


class RemediationKB:
    """Loads ``kb.json`` and builds stack-ordered remediation guidance for findings."""

    def __init__(self, kb_path: Path | str | None = None) -> None:
        self.kb_path = Path(kb_path) if kb_path is not None else DEFAULT_KB_PATH
        self._rules: dict[str, dict[str, Any]] = self._load_rules(self.kb_path)

    @staticmethod
    def _load_rules(path: Path) -> dict[str, dict[str, Any]]:
        raw_data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw_data, dict) and "rules" in raw_data and isinstance(raw_data["rules"], dict):
            rules_dict = raw_data["rules"]
        elif isinstance(raw_data, dict):
            rules_dict = raw_data
        else:
            raise ValueError(f"Remediation KB at {path} must be a JSON object keyed by check_id.")

        normalized: dict[str, dict[str, Any]] = {}
        for key, value in rules_dict.items():
            if isinstance(value, dict):
                check_id = str(value.get("check_id") or key)
                normalized[check_id] = value
        return normalized

    def get_rule(self, check_id: str) -> dict[str, Any] | None:
        """Return a deep copy of the KB rule dict for ``check_id``, or ``None``."""
        rule = self._rules.get(check_id)
        return copy.deepcopy(rule) if rule is not None else None

    def has_rule(self, check_id: str) -> bool:
        """Return ``True`` if ``check_id`` exists in the loaded knowledge base."""
        return check_id in self._rules

    def list_rule_ids(self) -> list[str]:
        """Return all registered rule IDs in KB order."""
        return list(self._rules.keys())

    def build_remediation(
        self,
        raw: RawFinding,
        target_stack: str = "fastapi",
    ) -> tuple[str, RemediationFix]:
        """Interpolate a plain-English explanation and stack-ordered ``RemediationFix``.

        Extracts ``path`` from ``raw.url`` and formats ``root_cause_template``
        with ``{method}``, ``{path}``, and ``{parameter}``. Orders
        ``FixSnippet`` entries so ``target_stack`` appears first.
        """
        parsed = urlparse(raw.url or "")
        path = parsed.path or "/"
        method = (raw.method or "GET").strip().upper()
        param_label = raw.parameter if raw.parameter else "endpoint response"
        preferred_stack = (target_stack or "fastapi").strip().lower()

        rule = self._rules.get(raw.check_id)
        if rule is None:
            explanation = (
                f"Security issue '{raw.title}' detected on {method} {path} "
                f"({param_label}). Review input handling and server configuration "
                f"for this endpoint."
            )
            fix = RemediationFix(
                summary=f"Remediate {raw.title} on {method} {path}.",
                root_cause=explanation,
                snippets=[],
                references=["https://owasp.org/www-project-top-ten/"],
            )
            return explanation, fix

        template = str(rule.get("root_cause_template") or "")
        try:
            explanation = template.format(
                method=method,
                path=path,
                parameter=param_label,
            )
        except (KeyError, ValueError):
            explanation = (
                f"{template} ({method} {path}, {param_label})"
                if template
                else f"Issue detected at {method} {path} ({param_label})."
            )

        raw_snippets = rule.get("snippets") or []
        all_snippets = [
            FixSnippet(
                stack=str(item.get("stack", "")).strip().lower(),
                language=str(item.get("language", "")).strip().lower(),
                before=str(item.get("before", "")),
                after=str(item.get("after", "")),
            )
            for item in raw_snippets
            if isinstance(item, dict)
        ]

        preferred: list[FixSnippet] = []
        remaining: list[FixSnippet] = []
        for snippet in all_snippets:
            if snippet.stack == preferred_stack:
                preferred.append(snippet)
            else:
                remaining.append(snippet)
        ordered_snippets = preferred + remaining

        references = [str(ref) for ref in (rule.get("references") or []) if ref]
        fix = RemediationFix(
            summary=str(rule.get("summary") or ""),
            root_cause=explanation,
            snippets=ordered_snippets,
            references=references,
        )
        return explanation, fix


__all__ = [
    "DEFAULT_KB_PATH",
    "SUPPORTED_STACKS",
    "RemediationKB",
]
