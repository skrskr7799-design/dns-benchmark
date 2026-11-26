"""Authenticated read-only evidence API; no network probes or raw source payloads."""
from typing import Literal
from fastapi import APIRouter,Request,Query,HTTPException
from .evidence import Source,Kind,Outcome
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
