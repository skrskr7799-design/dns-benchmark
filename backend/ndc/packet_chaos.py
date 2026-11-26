"""Actual UDP DNS exchanges confined to two ephemeral IPv4 loopback sockets.

Faults implemented by the fixture, not by changing kernel network settings.
No user-specified target, external DNS, namespace or elevated privileges.
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Literal
import dns.message
import dns.rcode
import dns.rrset
from pydantic import BaseModel,ConfigDict,Field
from .bounded_worker import bounded_worker

class PacketExperiment(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    seed:int=Field(default=42,ge=0,le=2147483647)
    samples:int=Field(default=6,ge=1,le=8)
    delay_ms:int=Field(default=40,ge=0,le=100)
    loss_pct:int=Field(default=0,ge=0,le=100)
    dns:Literal["normal","servfail","timeout"]="normal"
    timeout_ms:int=Field(default=150,ge=50,le=300)

def exchange(cfg,index,phase):
    fault=phase=="fault"
    bucket=int.from_bytes(hashlib.sha256(f"{cfg.seed}:{index}".encode()).digest()[:8],"big")%10000
    drop=fault and (cfg.dns=="timeout" or bucket<cfg.loss_pct*100)
    delay=cfg.delay_ms/1000 if fault else 0
    stop=threading.Event();errors=[];received=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        server.bind(("127.0.0.1",0));client.bind(("127.0.0.1",0))
        server.settimeout(.5);client.settimeout(cfg.timeout_ms/1000)
        client.connect(server.getsockname())
        query=dns.message.make_query("fixture.invalid.","A")
        def respond():
            try:
                wire,peer=server.recvfrom(4096)
                if peer!=client.getsockname():raise ValueError("Unexpected fixture peer")
                q=dns.message.from_wire(wire);received.append(True)
                if drop or stop.wait(delay):return
                answer=dns.message.make_response(q)
                if fault and cfg.dns=="servfail":answer.set_rcode(dns.rcode.SERVFAIL)
                else:answer.answer.append(dns.rrset.from_text(q.question[0].name,1,"IN","A","192.0.2.1"))
                server.sendto(answer.to_wire(),peer)
            except Exception as exc:errors.append(type(exc).__name__)
        thread=threading.Thread(target=respond,daemon=True);thread.start()
        start=time.monotonic();outcome="fixture_error";elapsed=None
        try:
            client.send(query.to_wire())
            try:
                answer=dns.message.from_wire(client.recv(4096))
                elapsed=(time.monotonic()-start)*1000
                if not query.is_response(answer):raise ValueError("Response mismatch")
                if answer.rcode()==dns.rcode.SERVFAIL:outcome="dns_servfail"
                elif answer.rcode()==dns.rcode.NOERROR and len(answer.answer)==1 and answer.answer[0].name==query.question[0].name and [r.to_text() for r in answer.answer[0]]==["192.0.2.1"]:outcome="success"
            except socket.timeout:
                elapsed=(time.monotonic()-start)*1000;outcome="timeout"
        finally:
            stop.set();thread.join(1)
            if thread.is_alive():raise RuntimeError("Fixture worker did not stop")
        if errors or not received:outcome="fixture_error"
    return {"index":index,"phase":phase,"outcome":outcome,"elapsed_ms":round(elapsed,3) if elapsed is not None else None,
        "fixture_dropped":drop,"fixture_received":bool(received)}

def execute(cfg):
    rows=[exchange(cfg,i,phase) for phase in ("baseline","fault") for i in range(cfg.samples)]
    return {"status":"completed","methodology":"loopback-udp-dns-fixture-v1","profile":cfg.model_dump(mode="json"),"rows":rows,
        "baseline_success":sum(r["phase"]=="baseline" and r["outcome"]=="success" for r in rows),
        "fault_success":sum(r["phase"]=="fault" and r["outcome"]=="success" for r in rows),
        "limitations":["actual_loopback_udp_not_external_network","fixture_fault_injection_not_kernel_netem","no_interface_changes","no_external_target","not_link_packet_loss_or_capacity"]}

def run(cfg):
    env={k:v for k,v in os.environ.items() if k in ("PATH","LANG","LC_ALL","PYTHONPATH")}
    try:return json.loads(bounded_worker([sys.executable,"-m","backend.ndc.packet_chaos"],cfg.model_dump_json(),timeout=10,max_output=32768,env=env))
    except subprocess.TimeoutExpired:raise RuntimeError("Packet fixture deadline") from None

if __name__=="__main__":
    print(json.dumps(execute(PacketExperiment.model_validate_json(sys.stdin.read(4096))),allow_nan=False))
