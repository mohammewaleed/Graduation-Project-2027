"""FastAPI application factory with lifespan, security headers, CORS, error envelopes, API routes, and static UI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.config import settings
from backend.app.database import (
    SessionLocal,
    build_engine,
    create_session_factory,
    engine,
    get_db,
    init_db,
)
from backend.app.routers import checks, findings, health, projects, reports, scans
from backend.app.schemas import ErrorDetail, ErrorResponse
from backend.app.worker import ScanJobManager, scan_job_manager
from backend.scanner.policy import ScopeViolationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}

_DOCS_PATHS: frozenset[str] = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})

_DOCS_CSP: str = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)

_DEFAULT_HTTP_ERROR_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "TOO_MANY_REQUESTS",
}


def create_app(database_url: str | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance.

    When ``database_url`` is provided, creates an isolated SQLAlchemy engine,
    session factory, dependency override for ``get_db``, and dedicated
    ``ScanJobManager`` so tests never mutate the default ``./data/scanner.db``.
    """
    if database_url is not None:
        app_engine = build_engine(database_url)
        app_session_factory = create_session_factory(app_engine)
        app_job_manager = ScanJobManager()
        init_db(app_engine)
    else:
        app_engine = engine
        app_session_factory = SessionLocal
        app_job_manager = scan_job_manager

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        init_db(app_engine)
        app_job_manager.ensure_running()
        try:
            yield
        finally:
            app_job_manager.shutdown(wait=False)

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Lightweight OWASP Top 10 vulnerability scanner tailored for "
            "web developers and student projects."
        ),
        lifespan=lifespan,
    )

    application.state.db_engine = app_engine
    application.state.session_factory = app_session_factory
    application.state.scan_job_manager = app_job_manager

    if database_url is not None:

        def _override_get_db():
            db = app_session_factory()
            try:
                yield db
            finally:
                db.close()

        application.dependency_overrides[get_db] = _override_get_db

    @application.exception_handler(ScopeViolationError)
    async def scope_violation_handler(
        _request: Request,
        exc: ScopeViolationError,
    ) -> JSONResponse:
        payload = ErrorResponse(
            error=ErrorDetail(
                code=getattr(exc, "code", None) or "TARGET_NOT_ALLOWED",
                message=str(exc),
                details={"allowed_hosts": settings.allowlist_hosts},
            )
        )
        return JSONResponse(status_code=403, content=payload.model_dump())

    @application.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        _request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        fallback_code = _DEFAULT_HTTP_ERROR_CODES.get(
            exc.status_code,
            f"HTTP_{exc.status_code}",
        )
        detail = exc.detail
        if isinstance(detail, dict):
            if "error" in detail and isinstance(detail["error"], dict):
                err = detail["error"]
                code = str(err.get("code") or fallback_code)
                message = str(err.get("message") or "Request failed.")
                details = err.get("details")
            else:
                code = str(detail.get("code") or fallback_code)
                message = str(
                    detail.get("message") or detail.get("detail") or "Request failed."
                )
                details = detail.get("details")
        else:
            code = fallback_code
            message = str(detail) if detail else "Request failed."
            details = None

        payload = ErrorResponse(
            error=ErrorDetail(code=code, message=message, details=details)
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=payload.model_dump(),
            headers=exc.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        payload = ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message="Request validation failed.",
                details=jsonable_encoder(exc.errors()),
            )
        )
        return JSONResponse(status_code=422, content=payload.model_dump())

    @application.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        is_docs = request.url.path in _DOCS_PATHS
        for header_name, header_value in SECURITY_HEADERS.items():
            if is_docs and header_name == "Content-Security-Policy":
                response.headers.setdefault(header_name, _DOCS_CSP)
            else:
                response.headers.setdefault(header_name, header_value)
        if not request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # Register all REST & SSE API routers BEFORE mounting the static frontend at '/'.
    application.include_router(health.router)
    application.include_router(projects.router)
    application.include_router(scans.router)
    application.include_router(findings.router)
    application.include_router(reports.router)
    application.include_router(checks.router)

    if FRONTEND_DIR.is_dir():
        application.mount(
            "/",
            StaticFiles(directory=str(FRONTEND_DIR), html=True),
            name="frontend",
        )

    return application


app = create_app()
