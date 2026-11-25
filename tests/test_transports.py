import asyncio
import datetime
import os
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import dns.message
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import DataReceived as H2Data, StreamEnded
from backend.ndc.probes.dns import query, measure, measure_both

def answer(wire):
    q=dns.message.from_wire(wire)
    r=dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text(q.question[0].name,60,"IN","A","192.0.2.1"))
    return r.to_wire()

def cert_files(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"resolver.test")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("resolver.test")]),critical=False)
        .sign(key,hashes.SHA256()))
    crt=root/"cert.pem"; pem=root/"key.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return crt,pem

class Fixture:
    def __init__(self,mode,crt,key):
        self.mode=mode; self.crt=crt; self.key=key
        self.connections=0; self.requests=0
        self.ready=threading.Event()
        self.loop=asyncio.new_event_loop()
        self.thread=threading.Thread(target=self.run,daemon=True)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(5):
            raise RuntimeError("fixture startup timeout")
        if hasattr(self,"error"):
            raise self.error
        return self

    def run(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.server,self.port=self.loop.run_until_complete(self.start())
        except Exception as exc:
            self.error=exc; self.ready.set(); self.loop.close(); return
        self.ready.set()
        self.loop.run_forever()
        self.server.close()
        if hasattr(self.server,"wait_closed"):
            self.loop.run_until_complete(self.server.wait_closed())
        pending=asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending,return_exceptions=True))
        self.loop.close()

    def __exit__(self,*args):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        assert not self.thread.is_alive()

    async def start(self):
        fixture=self
        if self.mode in ("h3","quic"):
            class Server(QuicConnectionProtocol):
                def __init__(self,*a,**kw):
                    super().__init__(*a,**kw)
                    self.h3=H3Connection(self._quic) if fixture.mode=="h3" else None
                    self.bodies={}
                def quic_event_received(self,event):
                    if isinstance(event,HandshakeCompleted):
                        fixture.connections+=1
                    for e in self.h3.handle_event(event) if self.h3 else [event]:
                        if not isinstance(e,(HeadersReceived,DataReceived,StreamDataReceived)):
                            continue
                        body=self.bodies.setdefault(e.stream_id,bytearray())
                        if not isinstance(e,HeadersReceived):
                            body.extend(e.data)
                        end=e.end_stream if isinstance(e,StreamDataReceived) else e.stream_ended
                        if not end:
                            continue
                        fixture.requests+=1
                        wire=answer(bytes(body) if self.h3 else bytes(body[2:]))
                        if self.h3:
                            self.h3.send_headers(e.stream_id,[(b":status",b"200"),(b"content-type",b"application/dns-message")])
                            self.h3.send_data(e.stream_id,wire,end_stream=True)
                        else:
                            self._quic.send_stream_data(e.stream_id,struct.pack("!H",len(wire))+wire,end_stream=True)
                        self.bodies.pop(e.stream_id,None)
                        self.transmit()
            cfg=QuicConfiguration(is_client=False,alpn_protocols=["h3" if self.mode=="h3" else "doq"])
            cfg.load_cert_chain(str(self.crt),str(self.key))
            server=await serve("127.0.0.1",0,configuration=cfg,create_protocol=Server)
            return server,server._transport.get_extra_info("sockname")[1]
        ctx=None
        if self.mode!="tcp":
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.crt,self.key)
            if self.mode=="https":
                ctx.set_alpn_protocols(["h2"])
        server=await asyncio.start_server(self.stream,"127.0.0.1",0,ssl=ctx)
        return server,server.sockets[0].getsockname()[1]

    async def stream(self,reader,writer):
        self.connections+=1
        try:
            if self.mode=="https":
                conn=H2Connection(config=H2Configuration(client_side=False))
                conn.initiate_connection()
                writer.write(conn.data_to_send())
                buffers={}
                while data:=await reader.read(65535):
                    for e in conn.receive_data(data):
                        if isinstance(e,H2Data):
                            buffers.setdefault(e.stream_id,bytearray()).extend(e.data)
                            conn.acknowledge_received_data(e.flow_controlled_length,e.stream_id)
                        if isinstance(e,StreamEnded):
                            self.requests+=1
                            wire=answer(bytes(buffers.pop(e.stream_id)))
                            conn.send_headers(e.stream_id,[(":status","200"),("content-type","application/dns-message")])
                            conn.send_data(e.stream_id,wire,end_stream=True)
                    writer.write(conn.data_to_send())
                    await writer.drain()
            else:
                while True:
                    size=struct.unpack("!H",await reader.readexactly(2))[0]
                    wire=answer(await reader.readexactly(size))
                    self.requests+=1
                    writer.write(struct.pack("!H",len(wire))+wire)
                    await writer.drain()
        except (asyncio.IncompleteReadError,ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

class TransportTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.crt,self.key=cert_files(Path(temp.name))
        env=patch.dict(os.environ,{"NDC_CA_FILE":str(self.crt),"NDC_ALLOWED_CIDRS":"127.0.0.1/32"})
        env.start(); self.addCleanup(env.stop)

    def test_sessions(self):
        for scheme,protocol in [("h3","h3"),("quic","doq"),("https","h2"),("tls","dot"),("tcp","tcp")]:
            with self.subTest(scheme=scheme),Fixture(scheme,self.crt,self.key) as f:
                hostname="127.0.0.1" if scheme=="tcp" else "resolver.test"
                endpoint=f"{scheme}://{hostname}:{f.port}"+("/dns-query" if scheme in ("https","h3") else "")
                with ExitStack() as stack:
                    resources={}
                    for i in range(3):
                        r=query(endpoint,"example.com","127.0.0.1",stack,resources)
                        self.assertTrue(r.answer)
                        o=resources["observation"]
                        self.assertEqual(o["protocol"],protocol)
                        self.assertEqual(o["peer_ip"],"127.0.0.1")
                        self.assertEqual(o["reused"],i>0)
                self.assertEqual(f.connections,1)
                self.assertEqual(f.requests,3)
                for _ in range(2):
                    with ExitStack() as stack:
                        query(endpoint,"example.com","127.0.0.1",stack,{})
                self.assertEqual(f.connections,3)
                self.assertEqual(f.requests,5)

    def test_wrong_certificate_name(self):
        for scheme in ("h3","quic","https","tls"):
            with self.subTest(scheme=scheme),Fixture(scheme,self.crt,self.key) as f:
                endpoint=f"{scheme}://wrong.test:{f.port}"+("/dns-query" if scheme in ("https","h3") else "")
                with ExitStack() as stack,self.assertRaises(Exception):
                    query(endpoint,"example.com","127.0.0.1",stack,{})
                self.assertEqual(f.requests,0)

    def test_both_100_same_peer_and_corpus(self):
        with Fixture("tcp",self.crt,self.key) as f:
            endpoint=f"tcp://127.0.0.1:{f.port}"
            with patch("backend.ndc.probes.dns.resolve",return_value="127.0.0.1") as resolve:
                cold,warm=list(measure_both(endpoint,100,"ipv4",threading.Event()))
            self.assertEqual(resolve.call_count,1)
            self.assertEqual(cold["ip"],warm["ip"])
            self.assertEqual(cold["bootstrap_ms"],warm["bootstrap_ms"])
            self.assertEqual(cold["ok"],100)
            self.assertEqual(warm["ok"],100)
            self.assertEqual([s["domain"] for s in cold["samples"]],[s["domain"] for s in warm["samples"]])
            self.assertEqual(cold["reuse"]["no"],100)
            self.assertEqual(warm["reuse"]["yes"],100)
            self.assertTrue(warm["warmup"]["ok"])
            self.assertEqual(f.requests,201)
            self.assertEqual(f.connections,101)
            self.assertTrue(all(s["connect_ms"] is not None for s in cold["samples"]))
            self.assertTrue(all(s["connect_ms"] is None for s in warm["samples"]))

    def test_warmup_error_is_explicit(self):
        with patch("backend.ndc.probes.dns.resolve",return_value="127.0.0.1"),patch("backend.ndc.probes.dns.query",side_effect=TimeoutError("fixture")):
            r=measure("udp://127.0.0.1",2,"warm","ipv4",threading.Event())
        self.assertEqual(r["count"],2)
        self.assertEqual(r["ok"],0)
        self.assertIn("TimeoutError",r["warmup_error"])

if __name__=="__main__":
    unittest.main()
