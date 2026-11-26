"""First typed remote probe contract. No executable commands or raw payloads."""
import ipaddress
from typing import Literal,Annotated
from pydantic import BaseModel,ConfigDict,Field,field_validator,model_validator
from .models import NetworkTarget
from .evidence import digest,Observation,Measurement

TaskID=Annotated[str,Field(pattern=r"^[a-f0-9]{32}$")]
Lease=Annotated[str,Field(min_length=40,max_length=128)]
ConfigKey=Annotated[str,Field(pattern=r"^[a-f0-9]{64}$")]
Duration=Annotated[float,Field(ge=0,le=300000,allow_inf_nan=False)]
class Strict(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)

class RemoteTCP(NetworkTarget):
    model_config=ConfigDict(extra="forbid",strict=True)
    kind:Literal["tcp"]="tcp"
    port:int=Field(ge=1,le=65535)
    family:Literal["ipv4","ipv6"]="ipv4"

def config_key(config):
    return digest({"contract":"2","engine":"python-network-v2","config":config.model_dump(mode="json")})

class RemoteRequest(Strict):
    request_id:TaskID
    config:RemoteTCP

class RemoteHeartbeat(Strict):
    version:Literal["2"]
    engine:Literal["python-network-v2"]
    task_id:TaskID
    lease:Lease

class TCPObservation(Strict):
    outcome:Literal["success","failure","unknown"]
    stage:Literal["resolve","connect","complete"]
    address:str|None=Field(default=None,max_length=64)
    peer_ip:str|None=Field(default=None,max_length=64)
    dns_ms:Duration|None=None
    connect_ms:Duration|None=None
    total_ms:Duration

    @field_validator("address","peer_ip")
    @classmethod
    def canonical_ip(cls,value):
        if value is None:return None
        if "%" in value:raise ValueError("Scoped address")
        ip=ipaddress.ip_address(value)
        if getattr(ip,"ipv4_mapped",None) is not None:raise ValueError("Mapped address")
        return str(ip)

    @model_validator(mode="after")
    def shape(self):
        if self.outcome=="success":
            if self.stage!="complete" or not self.address or self.peer_ip!=self.address or self.connect_ms is None:
                raise ValueError("Incomplete TCP success")
        elif self.outcome=="failure":
            if self.stage!="connect" or self.address is None or self.peer_ip is not None or self.connect_ms is not None:
                raise ValueError("Invalid connection failure")
        elif self.stage!="resolve" or self.address is not None or self.peer_ip is not None or self.connect_ms is not None:
            raise ValueError("Invalid unresolved result")
        if any(v is not None and v>self.total_ms for v in (self.dns_ms,self.connect_ms)):
            raise ValueError("Phase exceeds total")
        return self

class RemoteResult(Strict):
    version:Literal["2"]
    engine:Literal["python-network-v2"]
    kind:Literal["tcp"]
    lease:Lease
    config_key:ConfigKey
    status:Literal["completed","failed"]
    observation:TCPObservation|None=None
    execution_error:Literal["local_policy_denied","deadline","cancelled","interrupted","internal_error"]|None=None

    @model_validator(mode="after")
    def shape(self):
        if self.status=="completed":
            if self.observation is None or self.execution_error is not None:
                raise ValueError("Completed result requires observation")
        elif self.observation is not None or self.execution_error is None:
            raise ValueError("Execution failure cannot claim a measurement")
        return self

def validate_remote(config,body):
    if config.kind!=body.kind or config_key(config)!=body.config_key:
        raise ValueError("Result does not match leased configuration")
    o=body.observation
    if o and o.address is not None:
        ip=ipaddress.ip_address(o.address)
        if ip.version!=(4 if config.family=="ipv4" else 6):
            raise ValueError("Wrong IP family")
        try:literal=ipaddress.ip_address(config.host)
        except ValueError:literal=None
        if literal is not None and literal!=ip:
            raise ValueError("Address differs from literal target")

def project_remote(task_id,agent_id,config,body):
    o=body.observation
    address=o.address if o else None
    outcome=o.outcome if o else "unknown"
    metrics=tuple(Measurement(name=k,unit="ms",value=v) for k,v in (
        ("dns",o.dns_ms),("connect",o.connect_ms),("total",o.total_ms)) if v is not None) if o else ()
    error=body.execution_error if not o else ("connection_failed" if outcome=="failure" else "resolution_unavailable" if outcome=="unknown" else None)
    return Observation(source_kind="agent",source_id=task_id,source_revision=1,source_part="tcp-v2",
        run_id=task_id,vantage_id="agent:"+agent_id,observed_at=None,
        target_id=digest({"kind":config.kind,"host":config.host,"port":config.port,"address":address}),
        profile_revision=config_key(config),probe_kind="tcp",outcome=outcome,provenance="agent_claim",
        measurements=metrics,protocol="tcp" if address else None,family=config.family if address else None,
        error_code=error,limitations=("agent_claim_not_attested","remote_observation_time_unavailable",
        "single_connection_measurement"))
