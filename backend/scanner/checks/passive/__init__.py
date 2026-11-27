"""Passive OWASP Top 10 (2021) security check plugins.

All passive checks operate purely on cached HTTP responses and the crawled
attack surface without sending additional network probes.
"""

from backend.scanner.checks.passive.banners import ServerBannerLeakCheck
from backend.scanner.checks.passive.components import OutdatedJSComponentsCheck
from backend.scanner.checks.passive.cookies import InsecureCookiesCheck
from backend.scanner.checks.passive.csrf import CSRFMissingTokenCheck
from backend.scanner.checks.passive.errors import VerboseErrorPagesCheck
from backend.scanner.checks.passive.headers import (
    MissingSecurityHeadersCheck,
    WeakCSPCheck,
)
from backend.scanner.checks.passive.transport import InsecureTransportCheck

__all__ = [
    "CSRFMissingTokenCheck",
    "InsecureCookiesCheck",
    "InsecureTransportCheck",
    "MissingSecurityHeadersCheck",
    "OutdatedJSComponentsCheck",
    "ServerBannerLeakCheck",
    "VerboseErrorPagesCheck",
    "WeakCSPCheck",
]
