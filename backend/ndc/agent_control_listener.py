"""One additional listener sharing the controller's ASGI app and lifespan.

Pinned uvicorn h11 transport adapter: identity comes only from SSLObject.
No second scheduler, process or SQLite ownership lock.
"""
import datetime as dt
import hashlib
import ssl
from contextlib import asynccontextmanager
from cryptography import x509
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol
from .agent_control_pki import peer_fingerprint,peer_public_key,public_bytes

class AgentTLSProtocol(H11Protocol):
    def connection_made(self,transport):
        super().connection_made(transport)
        tls=transport.get_extra_info("ssl_object")
        if tls is None or tls.version()!="TLSv1.3":
            transport.close()
            return
        der=tls.getpeercert(binary_form=True)
        fingerprint=hashlib.sha256(der).hexdigest() if der else None
        cert=x509.load_der_x509_certificate(der) if der else None
        expires=cert.not_valid_after_utc if cert else None
        key=public_bytes(cert.public_key()) if cert else None
        original=self.app
        async def trusted_scope(scope,receive,send):
            scope=dict(scope)
            scope["ndc_agent_tls"]=True
            current=fingerprint if expires is not None and dt.datetime.now(dt.timezone.utc)<expires else None
            scope["ndc_agent_peer"]=current
            token=peer_fingerprint.set(current)
            kt=peer_public_key.set(key if current else None)
            try:await original(scope,receive,send)
            finally:
                peer_public_key.reset(kt)
                peer_fingerprint.reset(token)
        self.app=trusted_scope

@asynccontextmanager
async def agent_listener(app,authority,host="0.0.0.0",port=8443):
    config=uvicorn.Config(app,host=host,port=port,http=AgentTLSProtocol,
        ws="none",lifespan="off",proxy_headers=False,access_log=False,
        timeout_keep_alive=3,timeout_graceful_shutdown=8,limit_concurrency=64)
    config.load()
    config.ssl=authority.server_context()
    server=uvicorn.Server(config)
    server.lifespan=config.lifespan_class(config)
    await server.startup()
    if not server.started:raise RuntimeError("Agent TLS listener not started")
    try:yield server
    finally:await server.shutdown()
