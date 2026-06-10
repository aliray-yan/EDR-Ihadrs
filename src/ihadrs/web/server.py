"""
Module: web.server
Purpose: Serves the IHADRS web dashboard (HTML/CSS/JS) via FastAPI static files.
         Mounts on the existing API server or runs standalone.
Owner: web
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

_STATIC_DIR   = Path(__file__).parent / "static"
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def mount_web_dashboard(app: Any) -> None:
    """
    Mount static files and dashboard route onto an existing FastAPI app.

    Args:
        app: The FastAPI application instance from api.server.
    """
    try:
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        # Serve static assets (CSS, JS)
        app.mount(
            "/static",
            StaticFiles(directory=str(_STATIC_DIR)),
            name="static",
        )

        # Serve the dashboard HTML
        @app.get("/", include_in_schema=False)
        async def serve_dashboard():
            return FileResponse(str(_TEMPLATE_DIR / "dashboard.html"))

    except Exception as exc:
        import warnings
        warnings.warn(f"Could not mount web dashboard: {exc}")


def create_standalone_web_app(config: Any) -> Any:
    """
    Create a minimal FastAPI app that serves just the web dashboard.
    Proxies API calls to the IHADRS API server.
    Used when running: ihadrs webui
    """
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(title="IHADRS Web Dashboard", docs_url=None, redoc_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.mount(
        "/static",
        StaticFiles(directory=str(_STATIC_DIR)),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(str(_TEMPLATE_DIR / "dashboard.html"))

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "component": "web_dashboard"}

    return app