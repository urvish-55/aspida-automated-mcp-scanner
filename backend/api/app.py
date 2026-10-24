"""FastAPI application factory.

Creates the app, initializes the database, installs middleware, and mounts the
API router. Also serves the built frontend (frontend/dist) when present, so a
single `uvicorn backend.api.app:app` process can run the whole product.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.middleware import ApiKeyAuthMiddleware, RateLimitMiddleware
from backend.api.routes import router
from backend.api.routes_v2 import router_v2
from backend.core.config import PROJECT_ROOT, get_settings
from backend.core.logging import configure_logging
from backend.core.version import APP_VERSION
from backend.database.session import dispose_engine, init_db

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.debug)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await init_db()
        if settings.auth_required:
            from backend.security.auth import expected_digest

            expected_digest()  # fail fast on a bad API_KEY; creates data/api_key on first start
        yield
        await dispose_engine()

    app = FastAPI(
        title=settings.app_name,
        version=APP_VERSION,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    # Innermost first: auth runs after rate limiting and CORS handling.
    app.add_middleware(ApiKeyAuthMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "PATCH"],
        allow_headers=["*"],
    )

    app.include_router(router)
    app.include_router(router_v2)

    if FRONTEND_DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str):  # type: ignore[no-untyped-def]
            candidate = FRONTEND_DIST / full_path
            if full_path and candidate.is_file() and candidate.resolve().is_relative_to(FRONTEND_DIST.resolve()):
                return FileResponse(candidate)
            return FileResponse(FRONTEND_DIST / "index.html")

    return app


app = create_app()
