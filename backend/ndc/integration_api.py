import threading
from subprocess import TimeoutExpired
from .integration_worker import bounded
import time
from fastapi import APIRouter, Request, HTTPException
from .integrations import load
from .api import inspection_slot

router=APIRouter(prefix="/api/v1/integrations")
lock=threading.Lock()
last={}
def target(request,name):
    try:
        t,cfg=load(request.app.state.store.path.parent,name+".json")
        if t is None:
            raise HTTPException(409,"Integration not configured")
        return t,cfg
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(422,"Invalid integration configuration")

@router.get("")
def status(request:Request):
    root=request.app.state.store.path.parent
    return {"adguard_configured":(root/"adguard.json").is_file(),"throughput_configured":(root/"throughput.json").is_file()}

def reserve(name,seconds):
    if not inspection_slot.acquire(blocking=False):
        raise HTTPException(409,"Interactive diagnostic already running")
    with lock:
        now=time.monotonic()
        if name in last and now-last[name]<seconds:
            inspection_slot.release()
            raise HTTPException(429,"Integration cooldown active")
        last[name]=now

@router.post("/adguard")
def read_adguard(request:Request):
    _,cfg=target(request,"adguard")
    reserve("adguard",15)
    try:
        try:
            return bounded("adguard",cfg)
        except TimeoutExpired:
            raise HTTPException(504,"Integration deadline exceeded")
        except Exception:
            raise HTTPException(502,"Integration worker failed")
    finally:
        inspection_slot.release()

@router.post("/throughput")
def download_test(request:Request):
    t,cfg=target(request,"throughput")
    if t.username is not None:
        raise HTTPException(422,"Throughput credentials unsupported")
    reserve("throughput",60)
    try:
        try:
            return bounded("throughput",cfg)
        except TimeoutExpired:
            raise HTTPException(504,"Integration deadline exceeded")
        except Exception:
            raise HTTPException(422,"Invalid throughput path")
    finally:
        inspection_slot.release()
