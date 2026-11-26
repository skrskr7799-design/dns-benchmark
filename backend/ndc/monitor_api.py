from fastapi import APIRouter, HTTPException, Request, Query, Response
from pydantic import BaseModel,Field,ConfigDict
from .maintenance import MaintenanceConflict
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

class MaintenanceRequest(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    starts_at:float=Field(ge=0,le=253402300799,allow_inf_nan=False)
    ends_at:float=Field(ge=0,le=253402300799,allow_inf_nan=False)

@router.get("/monitors/{id}/maintenance")
def maintenance_list(request:Request,id:str):
    result=store(request).maintenance_list(id)
    if result is None: raise HTTPException(404,"Monitor not found")
    return result

@router.post("/monitors/{id}/maintenance",status_code=201)
def maintenance_create(request:Request,id:str,body:MaintenanceRequest):
    try:
        result=store(request).maintenance_create(id,body.starts_at,body.ends_at)
    except MaintenanceConflict as exc: raise HTTPException(409,str(exc)) from None
    except ValueError as exc: raise HTTPException(422,str(exc)) from None
    if result is None: raise HTTPException(404,"Monitor not found")
    return result

@router.delete("/monitors/{id}/maintenance/{seq}")
def maintenance_cancel(request:Request,id:str,seq:int):
    if not 1<=seq<=9223372036854775807: raise HTTPException(404,"Window not found")
    try:
        result=store(request).maintenance_cancel(id,seq)
    except MaintenanceConflict as exc: raise HTTPException(409,str(exc)) from None
    if result is None: raise HTTPException(404,"Window not found")
    return result
