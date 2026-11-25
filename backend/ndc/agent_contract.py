from typing import Literal
from pydantic import BaseModel, Field, ConfigDict
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
