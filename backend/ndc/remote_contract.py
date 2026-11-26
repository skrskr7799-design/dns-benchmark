"""First typed remote probe contract. No executable commands or raw payloads."""
import ipaddress
from typing import Literal,Annotated
from pydantic import BaseModel,ConfigDict,Field,field_validator,model_validator,TypeAdapter
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

class RemoteTLS(RemoteTCP):
    kind:Literal["tls"]="tls"

class RemoteHTTP(RemoteTCP):
    kind:Literal["http"]="http"
    scheme:Literal["http","https"]="https"
    path:str=Field(default="/",max_length=1024)

    @field_validator("path")
    @classmethod
    def plain_path(cls,value):
        if not value.startswith("/") or value.startswith("//") or any(ord(c)<33 or ord(c)>126 or c in "\\?#" for c in value):
            raise ValueError("Plain origin-relative path required")
        return value

class RemoteRoute(RemoteTCP):
    kind:Literal["route"]="route"
    port:Literal[33434]=33434
    max_hops:int=Field(default=8,ge=1,le=8)

RemoteConfig=Annotated[RemoteTCP|RemoteTLS|RemoteHTTP|RemoteRoute,Field(discriminator="kind")]
CONFIG=TypeAdapter(RemoteConfig)

def config_key(config):
    return digest({"contract":"2","engine":"python-network-v2","config":config.model_dump(mode="json")})

class RemoteRequest(Strict):
    request_id:TaskID
    config:RemoteConfig

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

class ServiceObservation(Strict):
    kind:Literal["tls","http"]
    outcome:Literal["success","failure","unknown"]
    stage:Literal["resolve","connect","tls","http","complete"]
    address:str|None=Field(default=None,max_length=64)
    peer_ip:str|None=Field(default=None,max_length=64)
    dns_ms:Duration|None=None
    connect_ms:Duration|None=None
    tls_ms:Duration|None=None
    http_ms:Duration|None=None
    total_ms:Duration
    verified:bool|None=None
    fingerprint:ConfigKey|None=None
    tls_version:Literal["TLSv1.2","TLSv1.3"]|None=None
    http_status:int|None=Field(default=None,ge=200,le=599)

    @field_validator("address","peer_ip")
    @classmethod
    def canonical_ip(cls,value):
        return TCPObservation.canonical_ip(value)

    @model_validator(mode="after")
    def shape(self):
        if any(v is not None and v>self.total_ms for v in (self.dns_ms,self.connect_ms,self.tls_ms,self.http_ms)):
            raise ValueError("Phase exceeds total")
        if self.stage=="resolve":
            if self.outcome!="unknown" or any(v is not None for v in (self.address,self.peer_ip,self.connect_ms,self.tls_ms,self.http_ms,self.verified,self.fingerprint,self.tls_version,self.http_status)):
                raise ValueError("Invalid resolution")
            return self
        if self.address is None:raise ValueError("Missing address")
        if self.stage=="connect":
            if self.outcome!="failure" or any(v is not None for v in (self.peer_ip,self.connect_ms,self.tls_ms,self.http_ms,self.verified,self.fingerprint,self.tls_version,self.http_status)):
                raise ValueError("Invalid connection failure")
            return self
        if self.peer_ip!=self.address or self.connect_ms is None:raise ValueError("Missing peer")
        if self.verified is True:
            if any(v is None for v in (self.fingerprint,self.tls_version,self.tls_ms)):raise ValueError("Missing TLS evidence")
        elif any(v is not None for v in (self.fingerprint,self.tls_version,self.tls_ms)):
            raise ValueError("Unverified TLS evidence")
        if self.stage=="tls":
            if self.outcome!="failure" or self.verified is True or self.http_status is not None or self.http_ms is not None:
                raise ValueError("Invalid TLS failure")
        elif self.verified is False:raise ValueError("Untrusted session")
        if self.kind=="tls":
            if self.stage=="http" or self.http_status is not None or self.http_ms is not None:
                raise ValueError("HTTP data in TLS result")
            if self.stage=="complete" and (self.outcome!="success" or self.verified is not True):
                raise ValueError("Invalid TLS success")
        elif self.stage=="http":
            if self.outcome!="failure" or self.http_status is not None or self.http_ms is not None:
                raise ValueError("Invalid HTTP failure")
        elif self.stage=="complete":
            if self.http_status is None or self.http_ms is None or self.outcome!=("success" if self.http_status<400 else "failure"):
                raise ValueError("Invalid HTTP response")
        return self

class RouteHop(Strict):
    ttl:int=Field(ge=1,le=8)
    status:Literal["hop","destination","timeout","port_unreachable","icmp_error","local_error"]
    address:str|None=Field(default=None,max_length=64)
    rtt_ms:Duration|None=None

    @field_validator("address")
    @classmethod
    def canonical_ip(cls,value):
        return TCPObservation.canonical_ip(value)

    @model_validator(mode="after")
    def shape(self):
        if self.status in ("timeout","local_error") and (self.address is not None or self.rtt_ms is not None):
            raise ValueError("Unknown hop cannot claim an address or RTT")
        if self.status=="destination" and (self.address is None or self.rtt_ms is None):
            raise ValueError("Destination requires address and RTT")
        return self

class RouteObservation(Strict):
    kind:Literal["route"]="route"
    outcome:Literal["success","partial","unknown"]
    stage:Literal["unavailable","resolve","trace"]
    address:str|None=Field(default=None,max_length=64)
    dns_ms:Duration|None=None
    total_ms:Duration
    reached:bool=False
    hops:list[RouteHop]=Field(default_factory=list,max_length=8)

    @field_validator("address")
    @classmethod
    def canonical_ip(cls,value):
        return TCPObservation.canonical_ip(value)

    @model_validator(mode="after")
    def shape(self):
        if self.dns_ms is not None and self.dns_ms>self.total_ms:raise ValueError("Phase exceeds total")
        if self.stage!="trace":
            if self.outcome!="unknown" or self.address is not None or self.hops or self.reached:
                raise ValueError("Invalid unavailable route")
            if self.stage=="unavailable" and self.dns_ms is not None:raise ValueError("No resolution attempted")
            return self
        if self.address is None or not self.hops:raise ValueError("Missing route samples")
        for i,h in enumerate(self.hops,1):
            if h.ttl!=i or (h.rtt_ms is not None and h.rtt_ms>self.total_ms):raise ValueError("Invalid hop sequence or time")
            if h.address is not None and ipaddress.ip_address(h.address).version!=ipaddress.ip_address(self.address).version:
                raise ValueError("Wrong hop address family")
            if h.status in ("destination","local_error") and i!=len(self.hops):raise ValueError("Samples after terminal hop")
            if h.status=="destination" and h.address!=self.address:raise ValueError("Wrong destination")
        reached=self.hops[-1].status=="destination"
        observed=any(h.status=="hop" and h.address is not None for h in self.hops)
        expected="success" if reached else "partial" if observed else "unknown"
        if self.reached!=reached or self.outcome!=expected:raise ValueError("Inconsistent route outcome")
        return self

class RemoteResult(Strict):
    version:Literal["2"]
    engine:Literal["python-network-v2"]
    kind:Literal["tcp","tls","http","route"]
    lease:Lease
    config_key:ConfigKey
    status:Literal["completed","failed"]
    observation:TCPObservation|ServiceObservation|RouteObservation|None=None
    execution_error:Literal["local_policy_denied","deadline","cancelled","interrupted","internal_error"]|None=None

    @model_validator(mode="after")
    def shape(self):
        if self.status=="completed":
            if self.observation is None or self.execution_error is not None:
                raise ValueError("Completed result requires observation")
            if self.kind=="tcp":
                if not isinstance(self.observation,TCPObservation):raise ValueError("Wrong observation kind")
            elif self.kind=="route":
                if not isinstance(self.observation,RouteObservation):raise ValueError("Wrong route observation")
            elif not isinstance(self.observation,ServiceObservation) or self.observation.kind!=self.kind:
                raise ValueError("Wrong observation kind")
        elif self.observation is not None or self.execution_error is None:
            raise ValueError("Execution failure cannot claim a measurement")
        return self

def validate_remote(config,body):
    if config.kind!=body.kind or config_key(config)!=body.config_key:
        raise ValueError("Result does not match leased configuration")
    o=body.observation
    if isinstance(o,RouteObservation):
        if len(o.hops)>config.max_hops:raise ValueError("Too many hops")
        if o.stage=="trace" and not o.reached and o.hops[-1].status!="local_error" and len(o.hops)!=config.max_hops:
            raise ValueError("Incomplete route marked as finished")
    if isinstance(o,ServiceObservation) and isinstance(config,RemoteHTTP):
        if config.scheme=="http" and (o.stage=="tls" or o.verified is not None):
            raise ValueError("TLS evidence for plain HTTP")
        if config.scheme=="https" and o.stage in ("http","complete") and o.verified is not True:
            raise ValueError("HTTPS requires verified TLS")
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
        ("dns",o.dns_ms),("connect",getattr(o,"connect_ms",None)),("total",o.total_ms)) if v is not None) if o else ()
    if isinstance(o,ServiceObservation):
        metrics+=tuple(Measurement(name=k,unit=u,value=v) for k,u,v in (
            ("tls","ms",o.tls_ms),("http","ms",o.http_ms),
            ("tls_verified","boolean",float(o.verified) if o.verified is not None else None),
            ("http_status","count",float(o.http_status) if o.http_status is not None else None)) if v is not None)
    if isinstance(o,RouteObservation):
        if o.stage=="trace":
            metrics+=(Measurement(name="hops_sampled",unit="count",value=float(len(o.hops))),
                Measurement(name="destination_reached",unit="boolean",value=1.0 if o.reached else None))
            metrics+=tuple(Measurement(name="hop_"+str(h.ttl)+"_rtt",unit="ms",value=h.rtt_ms) for h in o.hops if h.rtt_ms is not None)
    error=body.execution_error if not o else (("http_status_failure" if o.stage=="complete" else o.stage+"_failed") if outcome=="failure" else "resolution_unavailable" if outcome=="unknown" else None)
    if isinstance(o,RouteObservation):
        error=("route_unavailable" if o.stage=="unavailable" else "resolution_unavailable" if o.stage=="resolve"
            else "route_incomplete" if not o.reached else None)
    return Observation(source_kind="agent",source_id=task_id,source_revision=1,source_part=config.kind+"-v2",
        run_id=task_id,vantage_id="agent:"+agent_id,observed_at=None,
        target_id=digest({"kind":config.kind,"host":config.host,"port":config.port,"address":address}),
        profile_revision=config_key(config),probe_kind=config.kind,outcome=outcome,provenance="agent_claim",
        measurements=metrics,protocol=("udp" if config.kind=="route" else "http/1.1" if isinstance(o,ServiceObservation) and o.http_status is not None else "tcp") if address else None,family=config.family if address else None,
        error_code=error,limitations=("agent_claim_not_attested","remote_observation_time_unavailable",
        "udp_error_queue_ecmp_possible" if config.kind=="route" else "single_connection_measurement"))
