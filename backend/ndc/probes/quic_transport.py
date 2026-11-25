"""Synchronous adapter to a dedicated asyncio QUIC session per benchmark worker."""
import asyncio
import ipaddress
import os
import ssl
import struct
from urllib.parse import urlsplit
import certifi
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated, StreamDataReceived, StreamReset
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived

def normalized(value):
    ip=ipaddress.ip_address(value)
    return str(getattr(ip,"ipv4_mapped",None) or ip)

class Protocol(QuicConnectionProtocol):
    def __init__(self, quic, *, stream_handler=None, h3=False, peer=None):
        super().__init__(quic,stream_handler=stream_handler)
        self.expected_peer=peer
        self.http=H3Connection(quic) if h3 else None
        self.alpn=None
        self.pending={}
        self.closed=False

    def datagram_received(self,data,addr):
        # QUIC migration is deliberately not supported for pinned probes.
        if (normalized(addr[0]),addr[1])==self.expected_peer:
            super().datagram_received(data,addr)

    def quic_event_received(self,event):
        if isinstance(event,HandshakeCompleted):
            self.alpn=event.alpn_protocol
        if isinstance(event,ConnectionTerminated):
            self.closed=True
            for future,_,_ in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("QUIC connection terminated"))
        if isinstance(event,StreamReset):
            entry=self.pending.get(event.stream_id)
            if entry and not entry[0].done():
                entry[0].set_exception(ConnectionError("QUIC stream reset"))
        events=self.http.handle_event(event) if self.http else [event]
        for item in events:
            if not isinstance(item,(HeadersReceived,DataReceived,StreamDataReceived)):
                continue
            entry=self.pending.get(item.stream_id)
            if not entry:
                continue
            future,headers,body=entry
            if future.done():
                continue
            if isinstance(item,HeadersReceived):
                headers.extend(item.headers)
            else:
                body.extend(item.data)
            if len(body)>65537:
                future.set_exception(ValueError("Oversized DNS response"))
            elif item.stream_ended if isinstance(item,(HeadersReceived,DataReceived)) else item.end_stream:
                future.set_result((headers,bytes(body)))

    async def exchange(self,wire,url):
        if self.closed:
            raise ConnectionError("QUIC connection closed")
        stream=self._quic.get_next_available_stream_id()
        future=asyncio.get_running_loop().create_future()
        self.pending[stream]=(future,[],bytearray())
        try:
            if self.http:
                u=urlsplit(url)
                self.http.send_headers(stream,[(b":method",b"POST"),(b":scheme",b"https"),
                    (b":authority",u.netloc.encode("ascii")),(b":path",(u.path or "/").encode("ascii")),
                    (b"content-type",b"application/dns-message"),(b"accept",b"application/dns-message"),
                    (b"content-length",str(len(wire)).encode())])
                self.http.send_data(stream,wire,end_stream=True)
            else:
                self._quic.send_stream_data(stream,struct.pack("!H",len(wire))+wire,end_stream=True)
            self.transmit()
            headers,body=await future
            if self.http:
                h=dict(headers)
                if h.get(b":status")!=b"200":
                    raise ValueError("HTTP/3 status "+repr(h.get(b":status")))
                if h.get(b"content-type",b"").split(b";")[0].strip().lower()!=b"application/dns-message":
                    raise ValueError("Unexpected DNS content type")
                return body
            if len(body)<2 or len(body)!=2+struct.unpack("!H",body[:2])[0]:
                raise ValueError("Invalid DoQ message framing")
            return body[2:]
        finally:
            self.pending.pop(stream,None)

class QuicSession:
    def __init__(self,endpoint,ip,timeout=5):
        self.endpoint=endpoint
        self.ip=normalized(ip)
        u=urlsplit(endpoint)
        self.port=u.port or (443 if u.scheme=="h3" else 853)
        self.hostname=u.hostname
        self.h3=u.scheme=="h3"
        self.alpn="h3" if self.h3 else "doq"
        self.timeout=timeout
        self.loop=asyncio.new_event_loop()
        self.context=None
        self.protocol=None
        self.handshake_ms=None
        self.requests=0

    async def open(self):
        import time
        config=QuicConfiguration(is_client=True,alpn_protocols=[self.alpn],
            server_name=self.hostname,verify_mode=ssl.CERT_REQUIRED,
            cafile=os.getenv("NDC_CA_FILE") or certifi.where(),idle_timeout=10)
        self.context=connect(self.ip,self.port,configuration=config,
            create_protocol=lambda *a,**kw:Protocol(*a,**kw,h3=self.h3,peer=(self.ip,self.port)))
        start=time.monotonic()
        self.protocol=await self.context.__aenter__()
        self.handshake_ms=(time.monotonic()-start)*1000
        if self.protocol.alpn!=self.alpn:
            raise ValueError("Unexpected QUIC ALPN")

    def __enter__(self):
        try:
            self.loop.run_until_complete(asyncio.wait_for(self.open(),self.timeout))
            return self
        except BaseException:
            self.close()
            raise

    def exchange(self,wire):
        response=self.loop.run_until_complete(asyncio.wait_for(
            self.protocol.exchange(wire,self.endpoint),self.timeout))
        self.requests+=1
        return response

    def close(self):
        if self.loop.is_closed():
            return
        try:
            if self.protocol is not None and self.context is not None:
                self.loop.run_until_complete(asyncio.wait_for(self.context.__aexit__(None,None,None),2))
        except Exception:
            pass
        finally:
            pending=asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending,return_exceptions=True))
            self.loop.close()

    def __exit__(self,*exc):
        self.close()
