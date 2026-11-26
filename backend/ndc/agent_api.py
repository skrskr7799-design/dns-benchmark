from fastapi import APIRouter, Request, HTTPException
from .agent_contract import ControlRenewal, Enrollment, Enroll, Heartbeat, AgentRun, Result, ActiveHeartbeat, Batch, PollV2
from .agent_store import AgentError
from .remote_contract import RemoteRequest,RemoteHeartbeat,RemoteResult,RemoteBatch

router=APIRouter(prefix="/api/v1/agents")
def call(fn,*args):
    try:
        return fn(*args)
    except AgentError as exc:
        raise HTTPException(exc.status,exc.message)
    except ValueError:
        raise HTTPException(422,"Invalid agent payload")

def store(request):
    return request.app.state.agents

def credential(request):
    header=request.headers.get("authorization","")
    if not header.startswith("Bearer ") or not 40<=len(header[7:])<=128:
        raise HTTPException(401,"Agent credential required")
    return header[7:]

@router.get("")
def list_agents(request:Request):
    s=store(request)
    return {"agents":s.list(),"tasks":s.tasks()}

@router.get("/capabilities")
def capabilities(request:Request):
    return store(request).capability_list()

@router.get("/control-trust")
def control_trust(request:Request):
    authority=getattr(request.app.state,"agent_authority",None)
    if authority is None:return {"enabled":False}
    return {"enabled":True,"origin":f"https://{authority.ip}:8443","ca_pem":authority.ca_pem,"sha256":authority.ca_fingerprint}

@router.post("/invite",status_code=201)
def invite(request:Request,body:Enrollment):
    return call(store(request).invite,body.name,body.location)

@router.post("/{id}/rotate")
def rotate(request:Request,id:str):
    return call(store(request).rotate,id)

@router.post("/{id}/revoke")
def revoke(request:Request,id:str):
    call(store(request).revoke,id)
    return {"revoked":True}

@router.post("/{id}/tasks",status_code=202)
def enqueue(request:Request,id:str,body:AgentRun):
    return call(store(request).enqueue,id,body)

@router.post("/{id}/remote-tasks",status_code=202)
def enqueue_remote(request:Request,id:str,body:RemoteRequest):
    return call(store(request).enqueue_remote,id,body)

@router.get("/remote-tasks")
def remote_tasks(request:Request):
    return store(request).remote_tasks()

@router.get("/remote-tasks/{id}")
def remote_detail(request:Request,id:str):
    return call(store(request).remote_detail,id)

@router.post("/remote-tasks/{id}/cancel")
def remote_cancel(request:Request,id:str):
    return call(store(request).remote_cancel,id)

@router.post("/remote-batches",status_code=202)
def create_remote_batch(request:Request,body:RemoteBatch):
    return call(store(request).remote_batch,body)

@router.get("/remote-batches")
def remote_batches(request:Request):
    return store(request).remote_batches()

@router.get("/remote-batches/{id}")
def remote_batch_detail(request:Request,id:str):
    return call(store(request).remote_batch_detail,id)

@router.post("/remote-batches/{id}/cancel")
def remote_batch_cancel(request:Request,id:str):
    return call(store(request).remote_batch_cancel,id)

@router.post("/batches",status_code=202)
def create_batch(request:Request,body:Batch):
    return call(store(request).batch,body)

@router.get("/batches")
def batches(request:Request):
    return store(request).batches()

@router.get("/batches/{id}")
def batch_detail(request:Request,id:str):
    return call(store(request).batch_detail,id)

@router.post("/batches/{id}/cancel")
def cancel_batch(request:Request,id:str):
    return call(store(request).cancel_batch,id)

@router.get("/tasks/{id}")
def detail(request:Request,id:str):
    return call(store(request).detail,id)

@router.post("/tasks/{id}/cancel")
def cancel(request:Request,id:str):
    call(store(request).cancel,id)
    return {"cancelled":True}

# Machine-only routes use separate middleware limits and credentials.
@router.post("/machine/enroll")
def enroll(request:Request,body:Enroll):
    if request.scope.get("ndc_agent_tls"):
        authority=getattr(request.app.state,"agent_authority",None)
        if authority is None or body.csr is None:raise HTTPException(422,"Client CSR required")
        return call(store(request).enroll,body.token,body.csr,authority)
    if body.csr is not None:raise HTTPException(422,"CSR requires dedicated agent TLS listener")
    return call(store(request).enroll,body.token)

@router.post("/machine/renew-control")
def renew_control(request:Request,body:ControlRenewal):
    authority=getattr(request.app.state,"agent_authority",None)
    if authority is None or not request.scope.get("ndc_agent_tls"):raise HTTPException(403,"Dedicated agent TLS required")
    return call(store(request).renew_control,credential(request),body.csr,authority)

@router.post("/machine/poll")
def poll(request:Request,body:Heartbeat):
    return call(store(request).poll,credential(request),body)

@router.post("/machine/v2/poll")
def poll_v2(request:Request,body:PollV2):
    return call(store(request).poll_v2,credential(request),body)

@router.post("/machine/v2/heartbeat")
def remote_heartbeat(request:Request,body:RemoteHeartbeat):
    return call(store(request).remote_heartbeat,credential(request),body)

@router.post("/machine/v2/results/{id}")
def remote_complete(request:Request,id:str,body:RemoteResult):
    return call(store(request).complete_remote,credential(request),id,body)

@router.post("/machine/results/{id}")
def complete(request:Request,id:str,body:Result):
    return call(store(request).complete,credential(request),id,body)

@router.post("/machine/heartbeat")
def heartbeat(request:Request,body:ActiveHeartbeat):
    return call(store(request).heartbeat,credential(request),body)
