from fastapi import APIRouter, HTTPException, Request, Query, Response
from pydantic import BaseModel
from .models import MonitorConfig
from .monitoring import MonitorBusy

router=APIRouter(prefix="/api/v1/monitoring")
class Enable(BaseModel):
    enabled: bool

def store(request):
    return request.app.state.monitors

@router.get("")
def overview(request:Request):
    s=store(request)
    return {"monitors":s.list(),"incidents":s.incidents(),"delivery":s.delivery_counts(),
            "telegram_enabled":request.app.state.monitor_scheduler.notifier.enabled}

@router.post("/monitors",status_code=201)
def create(request:Request,body:MonitorConfig):
    if body.notify and not request.app.state.monitor_scheduler.notifier.enabled:
        raise HTTPException(422,"Telegram is not configured")
    try:
        return store(request).create(body)
    except MonitorBusy as exc:
        raise HTTPException(409,str(exc))

@router.patch("/monitors/{id}")
def enable(request:Request,id:str,body:Enable):
    try:
        result=store(request).enable(id,body.enabled)
    except MonitorBusy as exc:
        raise HTTPException(409,str(exc))
    if result is None:
        raise HTTPException(404,"Monitor not found")
    return result

@router.delete("/monitors/{id}",status_code=204)
def delete(request:Request,id:str):
    try:
        if not store(request).delete(id):
            raise HTTPException(404,"Monitor not found")
    except MonitorBusy as exc:
        raise HTTPException(409,str(exc))
    return Response(status_code=204)

@router.get("/monitors/{id}/history")
def history(request:Request,id:str,limit:int=Query(200,ge=1,le=1000)):
    if store(request).get(id) is None:
        raise HTTPException(404,"Monitor not found")
    return store(request).history(id,limit)
