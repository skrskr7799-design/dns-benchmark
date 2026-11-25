import os
import fcntl
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.staticfiles import StaticFiles
from backend.ndc.storage import Store
from backend.ndc.evidence import EvidenceStore
from backend.ndc.evidence_drain import EvidenceDrain
from backend.ndc.jobs import Coordinator
from backend.ndc.api import router, inspection_slot
from backend.ndc.monitoring import MonitorStore, MonitorScheduler, Telegram
from backend.ndc.monitor_api import router as monitor_router
from backend.ndc.security import Security, guard, router as auth_router
from backend.ndc.scope import allowed_networks
from backend.ndc.agent_store import AgentStore
from backend.ndc.agent_api import router as agent_router
from backend.ndc.integration_api import router as integration_router

@asynccontextmanager
async def lifespan(app):
    store=Store(Path(os.getenv("DATA_DIR","/data"))/"history.sqlite")
    with open(store.path.with_name("coordinator.lock"),"a") as owner:
        fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        app.state.security=Security(store.path.parent)
        allowed_networks()
        store.initialize()
        evidence=EvidenceStore(store.path.with_name("intelligence.sqlite"))
        evidence.initialize()
        app.state.evidence=evidence
        coordinator=Coordinator(store)
        app.state.store=store
        app.state.coordinator=coordinator
        monitors=MonitorStore(store.path.with_name('monitoring.sqlite'))
        monitors.initialize()
        drain=EvidenceDrain(store,monitors,evidence)
        app.state.evidence_drain=drain
        scheduler=MonitorScheduler(monitors,inspection_slot,Telegram(store.path.parent))
        app.state.monitors=monitors
        app.state.monitor_scheduler=scheduler
        app.state.agents=AgentStore(store.path.with_name('agents.sqlite'))
        app.state.agents.initialize()
        coordinator.start()
        scheduler.start()
        drain.start()
        try:
            yield
        finally:
            scheduler.stop()
            coordinator.stop()
            drain.stop()
            if coordinator.thread.is_alive() or scheduler.thread.is_alive() or drain.thread.is_alive():
                # Do not release ownership while outstanding IO can still write.
                os._exit(1)

app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
@app.exception_handler(RequestValidationError)
async def validation_error(request,exc):
    if request.scope.get("path","").startswith("/api/auth/"):
        return JSONResponse({"detail":"Invalid authentication fields"},422)
    return await request_validation_exception_handler(request,exc)

app.middleware('http')(guard)
app.include_router(auth_router)
app.include_router(router)
app.include_router(monitor_router)
app.include_router(agent_router)
app.include_router(integration_router)
web_dist=Path(__file__).with_name("web-dist")
if (web_dist/"assets").is_dir():
    app.mount("/assets",StaticFiles(directory=web_dist/"assets"),name="assets")

@app.get("/",response_class=HTMLResponse)
def home():
    if (web_dist/"index.html").is_file():
        return FileResponse(web_dist/"index.html")
    return HTMLResponse("Frontend build required",status_code=503)

@app.get("/health")
def health():
    return {"ok":True}

@app.get("/api/v1/intelligence/status")
def intelligence_status(request: Request):
    return request.app.state.evidence.status() | {
        "benchmark_pending":request.app.state.store.evidence_pending_count(),
        "drain_error":request.app.state.evidence_drain.last_error,
        "monitor":request.app.state.monitors.evidence_status(),
        "stream_errors":dict(request.app.state.evidence_drain.errors),
        "retention_error":request.app.state.evidence_drain.retention_error,
        "retention_days":30}

@app.get("/api/defaults")
def defaults():
    return Path(__file__).with_name("resolvers.txt").read_text().splitlines()
