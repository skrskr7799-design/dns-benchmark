"""Standalone, explicitly approved directional application-goodput probe.

Not wired to agent runtime or controller. Fixed synthetic traffic only.
A paced bounded transfer measures delivery at the offered load, not link capacity.
"""
import errno
import hashlib
import hmac
import os
import socket
import struct
import time
from typing import Literal
from pydantic import Field,model_validator
from .remote_contract import Strict,TaskID,ConfigKey
from .peer_contract import PeerDirection,LocalGrants,MAX_SESSION_SECONDS,MAX_TTL_SECONDS
from .peer_transport import (Receiver,PeerDenied,PeerCancelled,PeerDeadline,checked_ip,
    credentials,fingerprint,family,address,check,wait,perform,read_exact,write_exact,error_code,ACK)

ALPN="ndc-goodput/1"
MAGIC=b"NDP1"
CHUNK=16384
MAX_BYTES=4*1024*1024
MAX_RATE=8_000_000
MAX_OFFER_SECONDS=6
HEADER=struct.Struct("!4s43s32sII")
RECEIPT=struct.Struct("!IQ32s")

class ThroughputPolicy(Strict):
    direction:PeerDirection
    byte_count:int=Field(ge=65536,le=MAX_BYTES,multiple_of=CHUNK)
    rate_bps:int=Field(ge=256000,le=MAX_RATE)
    @model_validator(mode="after")
    def budget(self):
        if self.byte_count*8>self.rate_bps*MAX_OFFER_SECONDS:raise ValueError("Transfer exceeds pacing window")
        return self

class ThroughputPlan(Strict):
    request_id:TaskID
    policy:ThroughputPolicy
    method:Literal["tls-paced-goodput-v1"]="tls-paced-goodput-v1"
    @property
    def direction(self):return self.policy.direction

class ThroughputReport(Strict):
    plan:ThroughputPlan
    received_bytes:int=Field(ge=65536,le=MAX_BYTES)
    receiver_elapsed_us:int=Field(gt=0,le=MAX_SESSION_SECONDS*1_000_000)
    payload_sha256:ConfigKey
    @model_validator(mode="after")
    def complete(self):
        if self.received_bytes!=self.plan.policy.byte_count:raise ValueError("Only complete receipt is measurable")
        # Receiver independently paces reads. Allow 1ms for rounding, not
        # a claimed throughput above the approved offered load.
        if (self.receiver_elapsed_us+1000)*self.plan.policy.rate_bps<self.received_bytes*8*1_000_000:
            raise ValueError("Receipt outside pacing budget")
        return self
    def summary(self):
        return {"received_bytes":self.received_bytes,"receiver_elapsed_us":self.receiver_elapsed_us,
            "offered_rate_bps":self.plan.policy.rate_bps,
            "application_goodput_bps":round(self.received_bytes*8*1_000_000/self.receiver_elapsed_us,2),
            "link_capacity_bps":None,"method":self.plan.method}

class ThroughputGrants(LocalGrants):
    plan_type=ThroughputPlan
    def __init__(self,local_agent_id,policies,*,clock=time.monotonic):
        self.policies=tuple(ThroughputPolicy.model_validate(p.model_dump(mode="json")) for p in policies)
        if len(self.policies)>64:raise ValueError("Too many throughput policies")
        directions={p.direction.model_dump_json():p.direction for p in self.policies}
        super().__init__(local_agent_id,directions.values(),clock=clock)
    def issue(self,plan,ttl=MAX_TTL_SECONDS):
        plan=ThroughputPlan.model_validate(plan.model_dump(mode="json"))
        if plan.policy not in self.policies:raise PermissionError("Throughput policy not approved")
        return super().issue(plan,ttl)
    def consume(self,token,plan,*,verified_direction):
        if not isinstance(plan,ThroughputPlan) or plan.policy not in self.policies:return None
        return super().consume(token,plan,verified_direction=verified_direction)

def pace(rate,deadline,cancel):
    # Wait before each chunk; no catch-up burst if the scheduler stalls.
    end=time.monotonic()+CHUNK*8/rate
    while True:
        check(deadline,cancel)
        left=end-time.monotonic()
        if left<=0:return
        cancel.wait(min(left,.1,max(0,deadline-time.monotonic())))

def frame(plan,token):
    if not isinstance(token,str) or len(token)!=43 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in token):
        raise PeerDenied("Invalid grant")
    return HEADER.pack(MAGIC,token.encode("ascii"),plan.request_id.encode("ascii"),plan.policy.byte_count,plan.policy.rate_bps)

class ThroughputReceiver(Receiver):
    alpn=ALPN
    def __init__(self,ip,port,grants,**files):
        if not isinstance(grants,ThroughputGrants):raise ValueError("Separate throughput grants required")
        super().__init__(ip,port,grants,**files)

    def serve_once(self,cancel):
        if self.used:raise RuntimeError("One-shot receiver already used")
        self.used=True;deadline=time.monotonic()+MAX_SESSION_SECONDS
        try:
            raw,_=perform(self.listener,self.listener.accept,deadline,cancel)
            self.close()
            with raw:
                source=checked_ip(raw.getpeername()[0]);dest=checked_ip(raw.getsockname()[0])
                if not any(a.source_ip==source and a.destination_ip==dest for a in self.approvals):
                    raise PeerDenied("Unapproved socket")
                raw.setblocking(False)
                with self.ctx.wrap_socket(raw,server_side=True,do_handshake_on_connect=False) as tls:
                    perform(tls,tls.do_handshake,deadline,cancel)
                    pin=fingerprint(tls,ALPN)
                    candidates=[a for a in self.approvals if a.source_ip==source and a.destination_ip==dest and a.source_certificate==pin]
                    if len(candidates)!=1:raise PeerDenied("Peer identity not approved")
                    magic,token,id,count,rate=HEADER.unpack(read_exact(tls,HEADER.size,deadline,cancel))
                    if magic!=MAGIC:raise PeerDenied("Wrong throughput protocol")
                    d=candidates[0]
                    plan=ThroughputPlan(request_id=id.decode("ascii"),policy=ThroughputPolicy(direction=d,byte_count=count,rate_bps=rate))
                    grant=self.grants.consume(token.decode("ascii"),plan,verified_direction=d)
                    if grant is None:raise PeerDenied("Grant denied")
                    deadline=min(deadline,grant)
                    write_exact(tls,ACK,deadline,cancel)
                    start=time.monotonic();digest=hashlib.sha256()
                    for _ in range(count//CHUNK):
                        pace(rate,deadline,cancel)
                        digest.update(read_exact(tls,CHUNK,deadline,cancel))
                    check(deadline,cancel)
                    elapsed=max(1,round((time.monotonic()-start)*1_000_000))
                    report=ThroughputReport(plan=plan,received_bytes=count,receiver_elapsed_us=elapsed,payload_sha256=digest.hexdigest())
                    write_exact(tls,RECEIPT.pack(count,elapsed,digest.digest()),deadline,cancel)
                    return report,None
        except (OSError,ValueError,PeerDenied,PeerDeadline,PeerCancelled) as exc:
            return None,error_code(exc)
        finally:self.close()

def measure_throughput(plan,token,policies,cancel,*,cert,key,ca):
    plan=ThroughputPlan.model_validate(plan.model_dump(mode="json"));d=plan.direction
    deadline=time.monotonic()+MAX_SESSION_SECONDS
    try:
        if plan.policy not in policies:raise PeerDenied("Local throughput policy required")
        source=checked_ip(d.source_ip);dest=checked_ip(d.destination_ip)
        ctx,fp=credentials(cert,key,ca,server=False,alpn=ALPN)
        if not hmac.compare_digest(fp,d.source_certificate):raise PeerDenied("Local pin mismatch")
        payload=frame(plan,token)
        check(deadline,cancel)
        with socket.socket(family(dest),socket.SOCK_STREAM) as raw:
            raw.setblocking(False);raw.bind(address(source,0))
            code=raw.connect_ex(address(dest,d.port))
            if code not in (0,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY):raise OSError(code,"Connect failed")
            if code:
                wait(raw,deadline,cancel,write=True)
                if raw.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR):raise OSError("Connect failed")
            if checked_ip(raw.getsockname()[0])!=source or checked_ip(raw.getpeername()[0])!=dest:
                raise PeerDenied("Socket direction mismatch")
            with ctx.wrap_socket(raw,server_hostname=dest,do_handshake_on_connect=False) as tls:
                perform(tls,tls.do_handshake,deadline,cancel)
                if not hmac.compare_digest(fingerprint(tls,ALPN),d.destination_certificate):raise PeerDenied("Destination pin mismatch")
                write_exact(tls,payload,deadline,cancel)
                if read_exact(tls,1,deadline,cancel)!=ACK:raise PeerDenied("Grant not acknowledged")
                digest=hashlib.sha256()
                for _ in range(plan.policy.byte_count//CHUNK):
                    pace(plan.policy.rate_bps,deadline,cancel)
                    chunk=os.urandom(CHUNK)
                    write_exact(tls,chunk,deadline,cancel);digest.update(chunk)
                count,elapsed,received_digest=RECEIPT.unpack(read_exact(tls,RECEIPT.size,deadline,cancel))
                check(deadline,cancel)
                if not hmac.compare_digest(digest.digest(),received_digest):raise PeerDenied("Receipt digest mismatch")
                return ThroughputReport(plan=plan,received_bytes=count,receiver_elapsed_us=elapsed,payload_sha256=received_digest.hex()),None
    except (OSError,ValueError,PeerDenied,PeerDeadline,PeerCancelled) as exc:
        return None,error_code(exc)
