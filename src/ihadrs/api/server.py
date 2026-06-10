"""
Module: api.server
Purpose: FastAPI REST API server for IHADRS.
         Also serves the web dashboard (HTML/CSS/JS) at /
Owner: api
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import API_PREFIX, APP_NAME, APP_VERSION
from ihadrs.core.config import IHADRSConfig
from ihadrs.exceptions import APIError, RateLimitError


# =============================================================================
# PATHS
# =============================================================================

_WEB_DIR      = Path(__file__).parent.parent / "web"
_STATIC_DIR   = _WEB_DIR / "static"
_TEMPLATE_DIR = _WEB_DIR / "templates"


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

try:
    from pydantic import BaseModel, Field

    class FalsePositiveRequest(BaseModel):
        reason: str = Field(default="", max_length=500)
        marked_by: str = Field(default="api_user", max_length=100)

    class ResponseExecuteRequest(BaseModel):
        action_type: str
        target: str
        threat_id: Optional[str] = None
        params: dict = Field(default_factory=dict)

    class SecureOpsSettingsRequest(BaseModel):
        enabled: Optional[bool] = None
        api_base_url: Optional[str] = Field(default=None, max_length=500)
        ingest_key: Optional[str] = Field(default=None, max_length=4096)
        allow_http_lab: Optional[bool] = None

    class SecureOpsTestRequest(BaseModel):
        api_base_url: Optional[str] = Field(default=None, max_length=500)
        ingest_key: Optional[str] = Field(default=None, max_length=4096)
        allow_http_lab: Optional[bool] = None

    _SCHEMAS_AVAILABLE = True
except ImportError:
    _SCHEMAS_AVAILABLE = False


# =============================================================================
# RATE LIMITER
# =============================================================================

class _RateLimiter:
    def __init__(self, requests_per_window: int, window_seconds: int) -> None:
        self._limit = requests_per_window
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, client_id: str) -> None:
        now = time.time()
        cutoff = now - self._window
        times = [t for t in self._buckets.get(client_id, []) if t > cutoff]
        if len(times) >= self._limit:
            retry_after = int(self._window - (now - times[0]))
            raise RateLimitError(
                limit=self._limit,
                window_seconds=self._window,
                retry_after_seconds=max(1, retry_after),
            )
        times.append(now)
        self._buckets[client_id] = times


# =============================================================================
# API SERVER
# =============================================================================

class APIServer:
    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._app: Optional[Any] = None
        self._server: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._rate_limiter = _RateLimiter(
            requests_per_window=config.api.rate_limit_requests,
            window_seconds=config.api.rate_limit_window_seconds,
        )
        self._token = (
            config.api.token.get_secret_value()
            if config.api.token else None
        )
        self._log = logger.bind(component="APIServer")

        # Injected by the orchestrator
        self.event_store: Optional[Any] = None
        self.detection_engine: Optional[Any] = None
        self.monitors: list[Any] = []
        self.secureops_exporter: Optional[Any] = None

    async def start(self) -> None:
        self._app = self._build_app()

        import uvicorn
        uvicorn_config = uvicorn.Config(
            app=self._app,
            host=self._config.api.host,
            port=self._config.api.port,
            log_level="warning",
            access_log=False,
        )
        self._server = uvicorn.Server(uvicorn_config)
        self._thread = threading.Thread(
            target=self._run_server,
            name="ihadrs-api-server",
            daemon=True,
        )
        self._thread.start()
        await asyncio.sleep(0.8)
        self._log.info(
            "IHADRS running at http://{host}:{port}  (dashboard: http://{host}:{port}/)",
            host=self._config.api.host,
            port=self._config.api.port,
        )
        print(f"\n🛡️  IHADRS Dashboard → http://{self._config.api.host}:{self._config.api.port}/\n")

    def _run_server(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._server.serve())

    async def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._log.info("API server stopped.")

    # =========================================================================
    # App Builder
    # =========================================================================

    def _build_app(self) -> Any:
        from fastapi import FastAPI, HTTPException, Query, Request
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
        from starlette.middleware.base import BaseHTTPMiddleware

        app = FastAPI(
            title=f"{APP_NAME} API",
            description="Intelligent Host-Based Attack Detection and Response System",
            version=APP_VERSION,
            docs_url="/api/docs",
            redoc_url="/api/redoc",
            openapi_url="/api/openapi.json",
        )

        # ── CORS ──────────────────────────────────────────────────────────
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],          # Open for local dashboard
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

        # ── Auth + Rate Limit Middleware ───────────────────────────────────
        _token_ref = self._token
        _rate_ref  = self._rate_limiter

        class _AuthRateMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                path = request.url.path

                # Public paths — no auth needed
                public = {
                    "/", "/healthz", "/api/docs", "/api/redoc",
                    "/api/openapi.json", "/docs/oauth2-redirect",
                }
                if path in public:
                    return await call_next(request)

                # Static files — no auth needed
                if path.startswith("/static"):
                    return await call_next(request)

                # API routes — require token (only if a token is configured)
                if path.startswith("/api/v1") and _token_ref:
                    from ihadrs.constants import API_TOKEN_HEADER
                    token = (
                        request.headers.get(API_TOKEN_HEADER)
                        or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                    )
                    if not token or token != _token_ref:
                        return JSONResponse(
                            status_code=401,
                            content={"detail": "Invalid or missing API token. Set it in config/settings.yaml"},
                        )

                # Rate limit
                if path.startswith("/api/v1"):
                    client_ip = request.client.host if request.client else "unknown"
                    try:
                        _rate_ref.check(client_ip)
                    except RateLimitError as exc:
                        return JSONResponse(
                            status_code=429,
                            content={"detail": str(exc)},
                            headers={"Retry-After": str(exc.retry_after_seconds)},
                        )

                return await call_next(request)

        app.add_middleware(_AuthRateMiddleware)

        # ── Web Dashboard ──────────────────────────────────────────────────
        # Serve CSS / JS
        if _STATIC_DIR.exists():
            app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
        else:
            self._log.warning("Static dir not found: {p}", p=_STATIC_DIR)

        @app.get("/", include_in_schema=False)
        async def serve_dashboard():
            dash = _TEMPLATE_DIR / "dashboard.html"
            if dash.exists():
                return FileResponse(str(dash))
            # Fallback inline page if template missing
            html = """<!DOCTYPE html><html><body style="background:#0d0d1a;color:#e0e0e0;
            font-family:sans-serif;display:flex;align-items:center;justify-content:center;
            height:100vh;flex-direction:column">
            <h1>&#128737;&#65039; IHADRS is running</h1>
            <p>Dashboard template not found at: {path}</p>
            <p>API docs: <a href="/api/docs" style="color:#e94560">/api/docs</a></p>
            </body></html>""".format(path=dash)
            from fastapi.responses import HTMLResponse
            return HTMLResponse(html)

        # ── Health probe ───────────────────────────────────────────────────
        @app.get("/healthz", tags=["health"])
        async def healthz() -> dict:
            return {"status": "ok", "version": APP_VERSION, "name": APP_NAME}

        # ── GET /api/v1/status ─────────────────────────────────────────────
        @app.get(f"{API_PREFIX}/status", tags=["system"])
        async def get_status() -> dict:
            monitor_statuses = []
            for mon in self.monitors:
                try:
                    health = await mon.health_check()
                    monitor_statuses.append(health)
                except Exception:
                    pass
            detection_stats = {}
            if self.detection_engine:
                try:
                    detection_stats = self.detection_engine.get_metrics()
                    detection_stats["rule_count"] = self.detection_engine.rule_count
                except Exception:
                    pass
            return {
                "version": APP_VERSION,
                "status": "running",
                "uptime_seconds": time.time(),
                "monitors": monitor_statuses,
                "detection": detection_stats,
            }

        # ── GET /api/v1/events ─────────────────────────────────────────────
        @app.get(f"{API_PREFIX}/events", tags=["events"])
        async def get_events(
            limit: int = Query(default=50, ge=1, le=500),
            offset: int = Query(default=0, ge=0),
            event_type: Optional[str] = Query(default=None),
            severity: Optional[str] = Query(default=None),
        ) -> dict:
            if self.event_store is None:
                return {"events": [], "total": 0, "offset": offset, "limit": limit}
            try:
                events = await self.event_store.get_events(
                    limit=limit, offset=offset,
                    event_type=event_type, severity=severity,
                )
            except Exception:
                events = []
            return {"events": events, "offset": offset, "limit": limit}

        # ── GET /api/v1/threats ────────────────────────────────────────────
        @app.get(f"{API_PREFIX}/threats", tags=["threats"])
        async def get_threats(
            limit: int = Query(default=50, ge=1, le=500),
            offset: int = Query(default=0, ge=0),
            severity: Optional[str] = Query(default=None),
            attack_category: Optional[str] = Query(default=None),
            include_fp: bool = Query(default=False),
        ) -> dict:
            if self.event_store is None:
                return {"threats": [], "offset": offset, "limit": limit}
            try:
                threats = await self.event_store.get_threats(
                    limit=limit, offset=offset,
                    severity=severity, attack_category=attack_category,
                    include_false_positives=include_fp,
                )
            except Exception:
                threats = []
            return {"threats": threats, "offset": offset, "limit": limit}

        # ── GET /api/v1/threats/{threat_id} ───────────────────────────────
        @app.get(f"{API_PREFIX}/threats/{{threat_id}}", tags=["threats"])
        async def get_threat(threat_id: str) -> dict:
            if self.event_store is None:
                raise HTTPException(status_code=503, detail="Event store not available")
            try:
                threat = await self.event_store.get_threat_by_id(threat_id)
            except Exception:
                threat = None
            if not threat:
                raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")
            return threat

        # ── POST /api/v1/threats/{threat_id}/fp ───────────────────────────
        @app.post(f"{API_PREFIX}/threats/{{threat_id}}/fp", tags=["threats"])
        async def mark_false_positive(threat_id: str, body: FalsePositiveRequest) -> dict:
            if self.event_store is None:
                raise HTTPException(status_code=503, detail="Event store not available")
            try:
                await self.event_store.mark_false_positive(
                    threat_id=threat_id, marked_by=body.marked_by, reason=body.reason,
                )
            except Exception as exc:
                raise HTTPException(status_code=500, detail=str(exc))
            return {"success": True, "threat_id": threat_id}

        # ── GET /api/v1/stats ──────────────────────────────────────────────
        @app.get(f"{API_PREFIX}/stats", tags=["system"])
        async def get_stats(hours: int = Query(default=24, ge=1, le=168)) -> dict:
            if self.event_store is None:
                return {
                    "total_threats": 0,
                    "false_positives": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "by_category": {},
                    "window_hours": hours,
                }
            try:
                return await self.event_store.get_threat_stats(since_hours=hours)
            except Exception:
                return {
                    "total_threats": 0,
                    "false_positives": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "by_category": {},
                    "window_hours": hours,
                }

        # ── GET /api/v1/rules ──────────────────────────────────────────────
        @app.get(f"{API_PREFIX}/rules", tags=["detection"])
        async def get_rules() -> dict:
            if self.detection_engine is None:
                return {"rules": [], "total": 0}
            rules = []
            try:
                if hasattr(self.detection_engine, "_rule_evaluator") and \
                   self.detection_engine._rule_evaluator:
                    for rule in self.detection_engine._rule_evaluator._all_rules:
                        rules.append({
                            "rule_id": rule.rule_id,
                            "name": rule.name,
                            "severity": rule.severity.value,
                            "enabled": rule.enabled,
                            "mitre_techniques": rule.mitre.techniques,
                            "attack_category": rule.attack_category.value,
                        })
            except Exception:
                pass
            return {"rules": rules, "total": len(rules)}

        # SecureOps SOC export status/settings/test routes
        @app.get(f"{API_PREFIX}/secureops/status", tags=["secureops"])
        async def get_secureops_status() -> dict:
            if self.secureops_exporter is None:
                return {
                    "enabled": False,
                    "configured": False,
                    "queue_depth": 0,
                    "critical_high_queued": 0,
                    "permanent_errors": 0,
                    "bad_ingest_key": False,
                    "last_successful_upload": None,
                    "last_error": "SecureOps exporter is not initialized.",
                }
            return self.secureops_exporter.get_status()

        @app.get(f"{API_PREFIX}/secureops/settings", tags=["secureops"])
        async def get_secureops_settings() -> dict:
            if self.secureops_exporter is None:
                raise HTTPException(status_code=503, detail="SecureOps exporter not available")
            return self.secureops_exporter.get_settings()

        @app.post(f"{API_PREFIX}/secureops/settings", tags=["secureops"])
        async def update_secureops_settings(body: SecureOpsSettingsRequest) -> dict:
            if self.secureops_exporter is None:
                raise HTTPException(status_code=503, detail="SecureOps exporter not available")
            try:
                return self.secureops_exporter.update_settings(
                    enabled=body.enabled,
                    api_base_url=body.api_base_url,
                    ingest_key=body.ingest_key if body.ingest_key else None,
                    allow_http_lab=body.allow_http_lab,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc))

        @app.post(f"{API_PREFIX}/secureops/test", tags=["secureops"])
        async def test_secureops_connection(body: SecureOpsTestRequest) -> dict:
            if self.secureops_exporter is None:
                raise HTTPException(status_code=503, detail="SecureOps exporter not available")
            try:
                result = self.secureops_exporter.test_connection(
                    api_base_url=body.api_base_url,
                    ingest_key=body.ingest_key if body.ingest_key else None,
                    allow_http_lab=body.allow_http_lab,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc))

            if not result.get("success"):
                status_code = int(result.get("status_code") or 502)
                if status_code == 401:
                    raise HTTPException(status_code=401, detail=result.get("error", "Bad ingest key"))
            return result

        # ── POST /api/v1/response/execute ──────────────────────────────────
        @app.post(f"{API_PREFIX}/response/execute", tags=["response"])
        async def execute_response(body: ResponseExecuteRequest) -> dict:
            return {
                "success": True,
                "action_type": body.action_type,
                "target": body.target,
                "message": f"Action '{body.action_type}' on '{body.target}' queued",
            }

        return app