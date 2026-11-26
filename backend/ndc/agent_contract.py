from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator
from .models import Run

VERSION="1"
ENGINE="python-dns02"
class AgentRun(Run):
    model_config=ConfigDict(extra="forbid")
    endpoints: list[str]=Field(min_length=1,max_length=1)
    count: int=Field(default=5,ge=1,le=10)
    parallel: Literal[1]=1

class Enrollment(BaseModel):
    name: str=Field(min_length=1,max_length=80)
    location: str=Field(default="",max_length=80)

class Enroll(BaseModel):
    token: str=Field(min_length=40,max_length=128)

class Heartbeat(BaseModel):
    version: Literal["1"]="1"
    engine: Literal["python-dns02"]="python-dns02"

class Result(BaseModel):
    lease: str=Field(min_length=40,max_length=128)
    status: Literal["completed","failed"]
    results: list[dict]=Field(default_factory=list,max_length=2)
    error: str|None=Field(default=None,max_length=250)

class ActiveHeartbeat(Heartbeat):
    task_id: str=Field(pattern=r"^[a-f0-9]{32}$")
    lease: str=Field(min_length=40,max_length=128)

class Batch(BaseModel):
    model_config=ConfigDict(extra="forbid")
    request_id: str=Field(pattern=r"^[a-f0-9]{32}$")
    agent_ids: list[str]=Field(min_length=2,max_length=8)
    config: AgentRun

    @field_validator("agent_ids")
    @classmethod
    def unique_ids(cls,ids):
        import re
        if len(set(ids))!=len(ids) or any(not re.fullmatch(r"[a-f0-9]{32}",i) for i in ids):
            raise ValueError("Invalid or duplicate agent IDs")
        return ids

PROTOCOL_V2="2"
ENGINE_V2="python-network-v2"
CAPABILITY_TTL=45
ProbeKind=Literal["dns","tcp","tls","http","route"]
# Negotiation only; additional probe kinds are not implemented yet.
DISPATCHABLE_V2=("dns",)

class PollV2(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    version:Literal["2"]
    engine:Literal["python-network-v2"]
    capabilities:list[ProbeKind]=Field(max_length=5)

    @field_validator("capabilities")
    @classmethod
    def unique_capabilities(cls,values):
        if len(set(values))!=len(values):
            raise ValueError("Duplicate capabilities")
        return sorted(values)
