"""Health check router for readiness and liveness probes."""

from fastapi import APIRouter

from backend.app.config import settings
from backend.app.database import check_db_health

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def get_health() -> dict[str, object]:
    """Return service health, version, and database connectivity status."""
    db_status = check_db_health()
    overall_status = "ok" if db_status["status"] == "up" else "degraded"
    return {
        "status": overall_status,
        "version": settings.app_version,
        "database": db_status,
    }
