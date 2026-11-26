"""Authenticated read-only evidence API; no network probes or raw source payloads."""
from typing import Literal
from fastapi import APIRouter,Request,Query,HTTPException
from .evidence import Source,Kind,Outcome,Conflict,Capacity
from .time_machine import SnapshotStore
from .snapshot_probes import Capture
from .snapshot_schedule import ScheduleConfig,ScheduleEnable
from .api import inspection_slot
from pydantic import BaseModel,ConfigDict,Field
from .dns_cohorts import aggregate,NarrowQuery
from .dns_intelligence import rank
from .observatory import analyze
import time

router=APIRouter(prefix="/api/v1/intelligence")
EvidenceKind=Literal["observations","events"]
MAX_SEQ=9223372036854775807

@router.get("/dns/cohorts")
def dns_cohorts(request:Request,since:float=Query(...,ge=0,le=253402300799),
    before:float=Query(...,ge=0,le=253402300799),source:Literal["benchmark","agent"]="benchmark",
    vantage:str|None=Query(None,min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$"),
    profile:str|None=Query(None,pattern=r"^[a-f0-9]{64}$")):
    state=request.app.state
    try:
        rows,usage=state.evidence.dns_cohort_rows(source=source,since=since,before=before,vantage=vantage,profile=profile)
        result=aggregate(rows)
    except NarrowQuery:
        raise HTTPException(422,"Narrow the time range, vantage or profile") from None
    except ValueError:
        raise HTTPException(422,"Invalid cohort range") from None
    producer=({"pending":state.store.evidence_pending_count()} if source=="benchmark" else state.agents.evidence_status())
    result["coverage"]={"time_basis":"received_at","since":since,"before":before,"source":source,
        "vantage":vantage,"profile":profile,"retained_usage_at_read":usage,
        "producer_status_at_response":producer,"stream_error":state.evidence_drain.errors.get(source+"-v1"),
        "complete_window_verified":False,"source_and_derived_status_not_atomic":True}
    return result

@router.get("/dns/ranking")
def dns_ranking(request:Request,since:float=Query(...,ge=0,le=253402300799),
    before:float=Query(...,ge=0,le=253402300799),
    preset:Literal["balanced","reliability","speed"]="balanced",
    profile:str|None=Query(None,pattern=r"^[a-f0-9]{64}$")):
    state=request.app.state
    try:
        rows,usage=state.evidence.dns_cohort_rows(source="benchmark",since=since,before=before,vantage="controller",profile=profile)
        ids={r["record"]["run_id"] for r in rows if r["record"]["run_id"]}
        metadata=state.store.ranking_metadata(ids)
        result=rank(rows,metadata,preset,pending=state.store.evidence_pending_count(),
            stream_error=state.evidence_drain.errors.get("benchmark-v1"))
    except NarrowQuery:
        raise HTTPException(422,"Narrow the ranking time range or profile") from None
    except ValueError:
        raise HTTPException(422,"Invalid ranking parameters") from None
    result["coverage"].update({"time_basis":"received_at","since":since,"before":before,
        "retained_usage_at_read":usage,"source_and_derived_status_not_atomic":True})
    return result

@router.get("/observatory/monitors")
def observatory_monitors(request:Request):
    return [{"id":m["id"],"name":m["config"]["name"],"kind":m["config"]["kind"],
        "enabled":m["enabled"],"interval_seconds":m["config"]["interval_seconds"],
        "state":m["state"],"last_at":m["last_at"]} for m in request.app.state.monitors.list()]

@router.get("/observatory/monitors/{id}")
def observatory_monitor(request:Request,id:str,
    since:float=Query(...,ge=0,le=253402300799),before:float=Query(...,ge=0,le=253402300799)):
    import re
    if not re.fullmatch(r"[a-f0-9]{32}",id):
        raise HTTPException(404,"Monitor not found")
    state=request.app.state
    monitor=state.monitors.get(id)
    if monitor is None:
        raise HTTPException(404,"Monitor not found")
    try:
        now=time.time()
        if before>now+60:
            raise ValueError("Future window")
        rows,usage=state.evidence.observatory_rows(id,since=since,before=before)
        persisted=state.monitors.observatory_snapshot(id,since,before)
        if persisted is None:
            raise HTTPException(404,"Monitor not found")
        result=analyze(rows,monitor,since=since,before=before,now=now,boundaries=persisted["journal"])
        result["persistent"]=persisted
        result["limitations"].append("window_reconstruction_not_authoritative_live_state")
    except NarrowQuery:
        raise HTTPException(422,"Narrow the observatory time range") from None
    except ValueError:
        raise HTTPException(422,"Invalid observatory time range") from None
    result["coverage"]={"retained_usage_at_read":usage,"producer_status_at_response":state.monitors.evidence_status(),
        "stream_error":state.evidence_drain.errors.get("monitor-v1"),"complete_window_verified":False,
        "source_and_derived_status_not_atomic":True}
    return result

class SnapshotRequest(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    request_id:str=Field(pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
    label:str=Field(min_length=1,max_length=80)

def snapshots(request):
    return SnapshotStore(request.app.state.evidence)

@router.get("/time-machine/snapshots")
def snapshot_list(request:Request,before:int|None=Query(None,ge=1,le=MAX_SEQ),limit:int=Query(50,ge=1,le=100)):
    return snapshots(request).list(before=before,limit=limit)

@router.post("/time-machine/snapshots",status_code=201)
def snapshot_create(request:Request,body:SnapshotRequest):
    try:
        return snapshots(request).create(body.request_id,body.label,request.app.state.monitors)
    except (Conflict,Capacity) as exc: raise HTTPException(409,str(exc)) from None
    except ValueError: raise HTTPException(422,"Invalid snapshot request") from None

class ProbeSnapshotRequest(SnapshotRequest):
    probe:Capture

@router.post("/time-machine/probes",status_code=201)
def snapshot_probe(request:Request,body:ProbeSnapshotRequest):
    if not inspection_slot.acquire(blocking=False):
        raise HTTPException(409,"Network inspection already running")
    try:
        return snapshots(request).create_probe(body.request_id,body.label,body.probe)
    except (Conflict,Capacity) as exc: raise HTTPException(409,str(exc)) from None
    except ValueError: raise HTTPException(422,"Invalid probe snapshot") from None
    finally:
        inspection_slot.release()

@router.get("/time-machine/schedules")
def schedule_list(request:Request):
    return request.app.state.snapshot_schedules.list()

@router.post("/time-machine/schedules",status_code=201)
def schedule_create(request:Request,body:ScheduleConfig):
    try:return request.app.state.snapshot_schedules.create(body)
    except Capacity as exc:raise HTTPException(409,str(exc)) from None
    except ValueError:raise HTTPException(422,"Invalid schedule") from None

@router.patch("/time-machine/schedules/{id}")
def schedule_enable(request:Request,id:str,body:ScheduleEnable):
    try:result=request.app.state.snapshot_schedules.enable(id,body.enabled)
    except Conflict as exc:raise HTTPException(409,str(exc)) from None
    if result is None:raise HTTPException(404,"Schedule not found")
    return result

@router.delete("/time-machine/schedules/{id}",status_code=204)
def schedule_delete(request:Request,id:str):
    from fastapi import Response
    try:deleted=request.app.state.snapshot_schedules.delete(id)
    except Conflict as exc:raise HTTPException(409,str(exc)) from None
    if not deleted:raise HTTPException(404,"Schedule not found")
    return Response(status_code=204)

@router.get("/time-machine/compare")
def snapshot_compare(request:Request,older:str=Query(...,min_length=36,max_length=36),newer:str=Query(...,min_length=36,max_length=36)):
    try:
        result=snapshots(request).compare(older,newer)
    except ValueError as exc: raise HTTPException(422,str(exc)) from None
    if result is None: raise HTTPException(404,"Snapshot not found")
    return result

@router.get("/time-machine/snapshots/{id}")
def snapshot_detail(request:Request,id:str):
    result=snapshots(request).get(id)
    if result is None: raise HTTPException(404,"Snapshot not found")
    return result

@router.delete("/time-machine/snapshots/{id}",status_code=204)
def snapshot_delete(request:Request,id:str):
    from fastapi import Response
    try:deleted=snapshots(request).delete(id)
    except Conflict as exc:raise HTTPException(409,str(exc)) from None
    if not deleted:raise HTTPException(404,"Snapshot not found")
    return Response(status_code=204)

@router.get("/{kind}")
def page(request:Request,kind:EvidenceKind,after:int=Query(0,ge=0,le=MAX_SEQ),
    limit:int=Query(100,ge=1,le=200),until:int|None=Query(None,ge=0,le=MAX_SEQ),
    source:Source|None=None,vantage:str|None=Query(None,min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$"),
    probe:Kind|None=None,outcome:Outcome|None=None,
    since:float|None=Query(None,ge=0,le=253402300799),before:float|None=Query(None,ge=0,le=253402300799)):
    try:
        return request.app.state.evidence.page(kind,after=after,limit=limit,until=until,source=source,
            vantage=vantage,probe=probe,outcome=outcome,since=since,before=before)
    except ValueError:
        raise HTTPException(422,"Invalid evidence filters or cursor") from None

@router.get("/{kind}/{id}")
def detail(request:Request,kind:EvidenceKind,id:str):
    import re
    if not re.fullmatch(r"[a-f0-9]{64}",id):
        raise HTTPException(404,"Evidence not found")
    result=request.app.state.evidence.detail(kind,id)
    if result is None:
        raise HTTPException(404,"Evidence not found")
    return result
