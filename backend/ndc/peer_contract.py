"""Local, directional peer RTT authorization primitives.

Not a network service. The caller must establish authenticated TLS and pass
the verified peer identity and actual socket addresses, never request fields.
"""
import ipaddress
import math
import secrets
import hashlib
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Annotated,Literal
from pydantic import Field,field_validator,model_validator
from .remote_contract import Strict,TaskID,ConfigKey,Duration
from .scope import validate_ip

MAX_GRANTS=32
MAX_ISSUES_PER_MINUTE=16
MAX_TTL_SECONDS=60
MAX_SESSION_SECONDS=10
FRAME_BYTES=32
MAX_SAMPLES=5

class PeerDirection(Strict):
    source_agent_id:TaskID
    destination_agent_id:TaskID
    source_ip:str=Field(max_length=64)
    destination_ip:str=Field(max_length=64)
    port:int=Field(ge=1024,le=65535)
    source_certificate:ConfigKey
    destination_certificate:ConfigKey

    @field_validator("source_ip","destination_ip")
    @classmethod
    def literal(cls,value):
        if "%" in value:raise ValueError("Scoped address")
        ip=ipaddress.ip_address(value)
        if getattr(ip,"ipv4_mapped",None) is not None:raise ValueError("Mapped address")
        return str(ip)

    @model_validator(mode="after")
    def direction(self):
        if self.source_agent_id==self.destination_agent_id:
            raise ValueError("Self measurements unsupported")
        if self.source_certificate==self.destination_certificate:
            raise ValueError("Distinct peer certificates required")
        if ipaddress.ip_address(self.source_ip).version!=ipaddress.ip_address(self.destination_ip).version:
            raise ValueError("Mixed address families")
        return self

class RTTPlan(Strict):
    request_id:TaskID
    direction:PeerDirection
    method:Literal["tls-echo-rtt-v1"]="tls-echo-rtt-v1"
    samples:int=Field(default=3,ge=1,le=MAX_SAMPLES)

class RTTSample(Strict):
    index:int=Field(ge=1,le=MAX_SAMPLES)
    status:Literal["echo","unknown"]
    rtt_ms:Duration|None=None

    @model_validator(mode="after")
    def sample(self):
        if (self.status=="echo")!=(self.rtt_ms is not None):
            raise ValueError("Only an actual echo has an RTT")
        if self.rtt_ms is not None and self.rtt_ms>MAX_SESSION_SECONDS*1000:
            raise ValueError("RTT outside session budget")
        return self

class RTTReport(Strict):
    plan:RTTPlan
    samples:list[RTTSample]=Field(max_length=MAX_SAMPLES)

    @model_validator(mode="after")
    def coverage(self):
        if len(self.samples)>self.plan.samples or any(s.index!=i for i,s in enumerate(self.samples,1)):
            raise ValueError("Invalid sample sequence")
        return self

    def summary(self):
        # No packet-loss or one-way latency claim; missing echo is unknown.
        observed=[s.rtt_ms for s in self.samples if s.status=="echo"]
        return {"requested":self.plan.samples,"echoes":len(observed),
            "unknown":self.plan.samples-len(observed),"rtt_ms":observed,
            "method":self.plan.method,"one_way_latency":None}

@dataclass(frozen=True)
class Grant:
    plan:Strict
    expires_at:float

class LocalGrants:
    """Volatile local authorization; consumed atomically before any echo.

    Only local operator configuration may populate approvals. Tokens are
    never stored raw, and restart invalidates all outstanding grants.
    No listener or remote issuance API is provided in this stage.
    """
    plan_type=RTTPlan

    def __init__(self,local_agent_id,approvals,*,clock=time.monotonic):
        self.local_agent_id=local_agent_id
        self.approvals=tuple(PeerDirection.model_validate(a.model_dump(mode="json") if isinstance(a,PeerDirection) else a) for a in approvals)
        if len(self.approvals)>64:raise ValueError("Too many peer approvals")
        if any(a.destination_agent_id!=local_agent_id for a in self.approvals):
            raise ValueError("Approval must target local identity")
        self.clock=clock;self.lock=threading.Lock()
        self._grants={};self._issued=deque();self._last=None

    def _now(self):
        now=self.clock()
        if not math.isfinite(now):raise RuntimeError("Invalid monotonic clock")
        if self._last is not None and now<self._last:
            self._grants.clear()
            raise RuntimeError("Monotonic clock rollback")
        self._last=now
        self._grants={k:v for k,v in self._grants.items() if v.expires_at>now}
        while self._issued and self._issued[0]<=now-60:self._issued.popleft()
        return now

    def _approved(self,direction):
        if direction not in self.approvals:return False
        try:
            return all(validate_ip(ip)==ip for ip in (direction.source_ip,direction.destination_ip))
        except ValueError:return False

    @staticmethod
    def _key(token):
        return hashlib.sha256(token.encode("ascii")).digest()

    def issue(self,plan,ttl=MAX_TTL_SECONDS):
        plan=self.plan_type.model_validate(plan.model_dump(mode="json"))
        if type(ttl) is not int or not 1<=ttl<=MAX_TTL_SECONDS:
            raise ValueError("Invalid grant lifetime")
        with self.lock:
            now=self._now()
            if not self._approved(plan.direction):raise PermissionError("Peer not locally approved")
            if len(self._grants)>=MAX_GRANTS or len(self._issued)>=MAX_ISSUES_PER_MINUTE:
                raise RuntimeError("Peer grant capacity")
            if any(g.plan.request_id==plan.request_id for g in self._grants.values()):
                raise RuntimeError("Request already has a grant")
            token=secrets.token_urlsafe(32)
            self._grants[self._key(token)]=Grant(plan,now+ttl)
            self._issued.append(now)
            return token

    def consume(self,token,plan,*,verified_direction):
        # verified_direction must originate from authenticated connection state.
        if not isinstance(token,str) or len(token)!=43 or not token.isascii():
            return None
        with self.lock:
            now=self._now()
            key=self._key(token);grant=self._grants.get(key)
            if grant is None or grant.plan!=plan or grant.plan.direction!=verified_direction:
                return None
            if not self._approved(grant.plan.direction):return None
            del self._grants[key]
            return min(grant.expires_at,now+MAX_SESSION_SECONDS)

    def revoke_all(self):
        with self.lock:
            self._grants.clear()
