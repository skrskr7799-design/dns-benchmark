"""Gated peer control API. No automatic listener or runtime dispatch."""
from typing import Annotated
from fastapi import APIRouter,Request,HTTPException
from starlette.concurrency import run_in_threadpool
from pydantic import Field,model_validator
from .remote_contract import Strict,TaskID
from .peer_contract import PeerDirection,RTTPlan,RTTReport
from .peer_throughput import ThroughputPolicy,ThroughputPlan,ThroughputReport
from .peer_coordination import PeerConflict
from .agent_store import AgentError

router=APIRouter(prefix="/api/v1/agents")
Token=Annotated[str,Field(pattern=r"^[A-Za-z0-9_-]{43}$")]

class Claims(Strict):
    directions:list[PeerDirection]=Field(max_length=64)
class Empty(Strict):pass
class RequestID(Strict):
    id:TaskID
class Leased(RequestID):
    lease:Token
class Ready(Leased):
    grant:Token
class Finish(Leased):
    report:RTTReport|None=None
    echoes:int|None=Field(default=None,ge=0,le=5)
    @model_validator(mode="after")
    def role(self):
        if (self.report is None)==(self.echoes is None):raise ValueError("Exactly one result")
        return self

def store(request):
    s=request.app.state.agents
    if not s.peer_enabled:raise HTTPException(409,"Peer coordination disabled")
    return s

def credential(request):
    header=request.headers.get("authorization","")
    if not header.startswith("Bearer ") or not 40<=len(header[7:])<=128:
        raise HTTPException(401,"Agent credential required")
    return header[7:]

def call(fn,*args,**kwargs):
    try:return fn(*args,**kwargs)
    except AgentError as exc:raise HTTPException(exc.status,exc.message) from None
    except PeerConflict:raise HTTPException(409,"Peer request rejected") from None
    except ValueError:raise HTTPException(422,"Invalid peer payload") from None

async def body(request,model):
    # No default validation responses that could reflect token inputs.
    try:return model.model_validate_json(await request.body())
    except (ValueError,TypeError):raise HTTPException(422,"Invalid peer payload") from None

@router.post("/peer-requests",status_code=202)
def admit(request:Request,plan:RTTPlan):
    return call(store(request).peer_admit,plan)

@router.get("/peer-requests")
def listing(request:Request):
    return call(store(request).peer_list)

@router.get("/peer-requests/{id}")
def detail(request:Request,id:TaskID):
    return call(store(request).peer_detail,id)

@router.post("/peer-requests/{id}/cancel")
def cancel(request:Request,id:TaskID):
    return {"cancelled":call(store(request).peer_cancel,id)}

@router.post("/machine/peer/claims")
async def claims(request:Request):
    s=store(request);cred=credential(request);b=await body(request,Claims)
    await run_in_threadpool(call,s.peer_report_claims,cred,b.directions)
    return {"accepted":True}

@router.post("/machine/peer/offer")
async def offer(request:Request):
    s=store(request);cred=credential(request);await body(request,Empty)
    return await run_in_threadpool(call,s.peer_offer,cred)

@router.post("/machine/peer/prepare")
async def prepare(request:Request):
    s=store(request);cred=credential(request);b=await body(request,RequestID)
    return await run_in_threadpool(call,s.peer_prepare,cred,b.id)

@router.post("/machine/peer/ready")
async def ready(request:Request):
    s=store(request);cred=credential(request);b=await body(request,Ready)
    return await run_in_threadpool(call,s.peer_ready,cred,b.id,b.lease,b.grant)

@router.post("/machine/peer/start")
async def start(request:Request):
    s=store(request);cred=credential(request);b=await body(request,RequestID)
    result=await run_in_threadpool(call,s.peer_start,cred,b.id,True)
    if result.get("state")=="interrupted":raise HTTPException(409,"Grant unavailable")
    return result

@router.post("/machine/peer/status")
async def status(request:Request):
    s=store(request);cred=credential(request);b=await body(request,Leased)
    return await run_in_threadpool(call,s.peer_status,cred,b.id,b.lease)

@router.post("/machine/peer/finish")
async def finish(request:Request):
    s=store(request);cred=credential(request);b=await body(request,Finish)
    return await run_in_threadpool(call,s.peer_finish,cred,b.id,b.lease,report=b.report,echoes=b.echoes)


class GoodputClaims(Strict):
    policies:list[ThroughputPolicy]=Field(max_length=64)

class GoodputFinish(Leased):
    report:ThroughputReport
    @model_validator(mode="after")
    def same_request(self):
        if self.id!=self.report.plan.request_id:raise ValueError("Wrong request")
        return self

def goodput_store(request):
    s=store(request)
    if not s.goodput_enabled or not s.goodput_session_enabled:
        raise HTTPException(409,"Throughput coordination disabled")
    return s

@router.post("/goodput-requests",status_code=202)
async def goodput_admit(request:Request):
    s=goodput_store(request);p=await body(request,ThroughputPlan)
    return await run_in_threadpool(call,s.goodput_admit,p)

@router.get("/goodput-requests")
def goodput_list(request:Request):
    s=goodput_store(request)
    with s.db() as c:
        c.execute("BEGIN IMMEDIATE");s.expire(c)
        return [dict(r) for r in c.execute("""SELECT id,source_id,destination_id,state,created,deadline,finished,
            byte_count,quarantine_until FROM goodput_requests ORDER BY created DESC,id DESC LIMIT 200""")]

@router.get("/goodput-requests/{id}")
def goodput_detail(request:Request,id:TaskID):
    return call(goodput_store(request).goodput_detail,id)

@router.post("/goodput-requests/{id}/cancel")
def goodput_cancel(request:Request,id:TaskID):
    return {"cancelled":call(goodput_store(request).goodput_cancel,id)}

@router.post("/machine/goodput/claims")
async def goodput_claims(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,GoodputClaims)
    await run_in_threadpool(call,s.goodput_report_claims,cred,b.policies)
    return {"accepted":True}

@router.post("/machine/goodput/offer")
async def goodput_offer(request:Request):
    s=goodput_store(request);cred=credential(request);await body(request,Empty)
    return await run_in_threadpool(call,s.goodput_offer,cred)

@router.post("/machine/goodput/prepare")
async def goodput_prepare(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,RequestID)
    return await run_in_threadpool(call,s.goodput_prepare,cred,b.id)

@router.post("/machine/goodput/ready")
async def goodput_ready(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,Ready)
    return await run_in_threadpool(call,s.goodput_ready,cred,b.id,b.lease,b.grant)

@router.post("/machine/goodput/start")
async def goodput_start(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,RequestID)
    result=await run_in_threadpool(call,s.goodput_start,cred,b.id)
    if result.get("state")=="interrupted":raise HTTPException(409,"Grant unavailable")
    return result

@router.post("/machine/goodput/status")
async def goodput_status(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,Leased)
    return await run_in_threadpool(call,s.goodput_status,cred,b.id,b.lease)

@router.post("/machine/goodput/finish")
async def goodput_finish(request:Request):
    s=goodput_store(request);cred=credential(request);b=await body(request,GoodputFinish)
    return await run_in_threadpool(call,s.goodput_finish,cred,b.id,b.lease,b.report)
