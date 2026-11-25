import asyncio
import json
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from .models import Run, Profile
from .storage import Busy, TERMINAL

router=APIRouter()

def services(request):
    return request.app.state.store, request.app.state.coordinator

def get_job(store, job_id):
    job=store.get(job_id)
    if job is None:
        raise HTTPException(404,"Run not found")
    return job

def submit(request, body, legacy=False):
    _, coordinator=services(request)
    try:
        return coordinator.submit(body.model_dump(),legacy)
    except Busy as exc:
        raise HTTPException(409,str(exc))

@router.post("/api/run")
def legacy_start(request: Request, body: Run):
    return {"started":True,"run_id":submit(request,body,True)}

@router.get("/api/status")
def legacy_status(request: Request):
    store,_=services(request)
    job_id=store.latest_id()
    if not job_id:
        return {"running":False,"results":[],"done":0,"total":0}
    job=get_job(store,job_id)
    return {"running":job["status"] not in TERMINAL,"run_id":job_id,"state":job["status"],
            "results":job["results"],"done":job["done"],"total":job["total"],"error":job["error"]}

@router.get("/api/history")
def legacy_history(request: Request):
    return services(request)[0].history()

@router.get("/api/v1/capabilities")
def capabilities():
    return {"api_version":1,"engine":"legacy-v0.2","durable_runs":True,"cancel":True,"profiles":True,
            "events":"snapshot-sse","max_active_jobs":8,"protocols":["udp","https","h3","tls","quic"],
            "h3_reuse_verified":False,"authenticated":True}

@router.post("/api/v1/runs",status_code=202)
def create_run(request: Request, body: Run):
    return {"id":submit(request,body)}

@router.get("/api/v1/runs")
def list_runs(request: Request):
    return services(request)[0].list()

@router.get("/api/v1/runs/{job_id}")
def run_detail(request: Request, job_id: str):
    return get_job(services(request)[0],job_id)

@router.post("/api/v1/runs/{job_id}/cancel")
def cancel_run(request: Request, job_id: str):
    job=services(request)[1].cancel(job_id)
    if job is None:
        raise HTTPException(404,"Run not found")
    return job

@router.get("/api/v1/runs/{job_id}/events")
async def events(request: Request, job_id: str):
    store,_=services(request)
    await asyncio.to_thread(get_job,store,job_id)
    async def stream():
        revision=None
        idle=0
        while not await request.is_disconnected() and request.app.state.security.session(request):
            job=await asyncio.to_thread(store.get,job_id)
            if job is None:
                return
            if job["revision"]!=revision:
                revision=job["revision"]
                yield f"id: {revision}\nevent: snapshot\ndata: {json.dumps(job)}\n\n"
                idle=0
            elif idle>=15:
                yield ": heartbeat\n\n"
                idle=0
            if job["status"] in TERMINAL:
                return
            await asyncio.sleep(1)
            idle+=1
    return StreamingResponse(stream(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@router.get("/api/v1/runs/{job_id}/export")
def export_run(request: Request, job_id: str):
    return get_job(services(request)[0],job_id)

@router.get("/api/v1/profiles")
def list_profiles(request: Request):
    return services(request)[0].profiles()

@router.post("/api/v1/profiles",status_code=201)
def create_profile(request: Request, body: Profile):
    return services(request)[0].put_profile(body.model_dump())

@router.put("/api/v1/profiles/{profile_id}")
def update_profile(request: Request, profile_id: str, body: Profile):
    result=services(request)[0].put_profile(body.model_dump(),profile_id)
    if result is None:
        raise HTTPException(404,"Profile not found")
    return result

@router.delete("/api/v1/profiles/{profile_id}",status_code=204)
def delete_profile(request: Request, profile_id: str):
    if not services(request)[0].delete_profile(profile_id):
        raise HTTPException(404,"Profile not found")
    return Response(status_code=204)
