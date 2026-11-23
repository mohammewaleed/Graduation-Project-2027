"""SQLAlchemy 2.0 database engine, session factory, and health check helpers."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.config import settings


class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy ORM models."""


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """Create parent directory for file-backed SQLite databases if missing."""
    url = make_url(database_url)
    db_path = url.database
    if not db_path or db_path == ":memory:" or db_path.startswith("file:"):
        return
    Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def build_engine(database_url: str | None = None) -> Engine:
    """Construct a SQLAlchemy 2.0 Engine with SQLite WAL pragma support."""
    url_str = database_url or settings.database_url
    parsed_url = make_url(url_str)
    is_sqlite = parsed_url.drivername.startswith("sqlite")

    connect_args: dict[str, object] = {}
    if is_sqlite:
        _ensure_sqlite_parent_dir(url_str)
        connect_args["check_same_thread"] = False

    db_engine = create_engine(
        url_str,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    if is_sqlite:

        @event.listens_for(db_engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA foreign_keys=ON;")
            finally:
                cursor.close()

    return db_engine


engine: Engine = build_engine()
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Yield a scoped SQLAlchemy session for FastAPI route dependencies."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_health(db_engine: Engine | None = None) -> dict[str, str]:
    """Verify database connectivity and return dialect and status metadata."""
    target_engine = db_engine or engine
    dialect = target_engine.dialect.name
    try:
        with target_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"dialect": dialect, "status": "up"}
    except Exception:
        return {"dialect": dialect, "status": "down"}
