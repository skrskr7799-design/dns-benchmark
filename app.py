import os
import fcntl
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from backend.ndc.storage import Store
from backend.ndc.jobs import Coordinator
from backend.ndc.api import router

@asynccontextmanager
async def lifespan(app):
    store=Store(Path(os.getenv("DATA_DIR","/data"))/"history.sqlite")
    with open(store.path.with_name("coordinator.lock"),"a") as owner:
        fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        store.initialize()
        coordinator=Coordinator(store)
        app.state.store=store
        app.state.coordinator=coordinator
        coordinator.start()
        try:
            yield
        finally:
            coordinator.stop()
            if coordinator.thread.is_alive():
                # Do not release ownership while outstanding IO can still write.
                os._exit(1)

app=FastAPI(lifespan=lifespan)
app.include_router(router)
web_dist=Path(__file__).with_name("web-dist")
if (web_dist/"assets").is_dir():
    app.mount("/assets",StaticFiles(directory=web_dist/"assets"),name="assets")

@app.get("/",response_class=HTMLResponse)
def home():
    if (web_dist/"index.html").is_file():
        return FileResponse(web_dist/"index.html")
    return Path(__file__).with_name("index.html").read_text()

@app.get("/health")
def health():
    return {"ok":True}

@app.get("/api/defaults")
def defaults():
    return Path(__file__).with_name("resolvers.txt").read_text().splitlines()
