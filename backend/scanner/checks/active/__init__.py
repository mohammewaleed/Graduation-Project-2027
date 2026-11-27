"""Active non-destructive OWASP Top 10 (2021) security check plugins.

Includes active input-validation checks (``sqli_error_based``,
``sqli_boolean_diff``, ``xss_reflected``), configuration/redirect checks
(``cors_misconfig``, ``open_redirect``), and deep authorization heuristics
(``idor_heuristic``).
"""

from __future__ import annotations

from backend.scanner.checks.active.cors import CORSMisconfigCheck
from backend.scanner.checks.active.idor import IDORHeuristicCheck
from backend.scanner.checks.active.redirect import OpenRedirectCheck
from backend.scanner.checks.active.sqli import (
    SQLiBooleanDiffCheck,
    SQLiErrorBasedCheck,
)
from backend.scanner.checks.active.xss import XSSReflectedCheck

__all__ = [
    "CORSMisconfigCheck",
    "IDORHeuristicCheck",
    "OpenRedirectCheck",
    "SQLiBooleanDiffCheck",
    "SQLiErrorBasedCheck",
    "XSSReflectedCheck",
]
