"""Real TLS listener / agent enrollment, plus database binding tests."""
import asyncio
import json
import os
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path
import httpx
from backend.ndc.agent_control_pki import Authority,client_csr,client_context,peer_fingerprint
from backend.ndc.agent_store import AgentStore,AgentError
from backend.ndc.agent_client import Agent
from backend.ndc.agent_control_listener import agent_listener
from fastapi import FastAPI,Request

class ControlTests(unittest.TestCase):
    def test_persistent_ca_and_transactional_binding(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            ca=Authority(p,"100.64.0.9")
            self.assertEqual(ca.ca_fingerprint,Authority(p,"100.64.0.9").ca_fingerprint)
            s=AgentStore(p/"agents.sqlite");s.initialize()
            inv=s.invite("UK","")
            csr=client_csr(p/"key")
            with self.assertRaises(ValueError):s.enroll(inv["token"],"invalid",ca)
            enrolled=s.enroll(inv["token"],csr,ca)
            with self.assertRaises(AgentError):s.enroll(inv["token"],csr,ca)
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            fp=x509.load_pem_x509_certificate(enrolled["certificate"].encode()).fingerprint(hashes.SHA256()).hex()
            for wrong in (None,"0"*64):
                t=peer_fingerprint.set(wrong)
                try:
                    with self.assertRaises(AgentError):s.rate_identity(enrolled["credential"])
                finally:peer_fingerprint.reset(t)
            t=peer_fingerprint.set(fp)
            try:
                self.assertEqual(s.rate_identity(enrolled["credential"]),inv["id"])
                s.rotate(inv["id"])
                with self.assertRaises(AgentError):s.rate_identity(enrolled["credential"])
            finally:peer_fingerprint.reset(t)

    def test_real_tls_transport_and_context(self):
        # Use loopback only as controlled transport fixture; issue IP-SAN leaf
        # specifically for this test, never allow loopback in operator config.
        async def run():
            with tempfile.TemporaryDirectory() as d:
                import ipaddress
                p=Path(d);ca=Authority(p,"100.64.0.9");ca.ip=ipaddress.ip_address("127.0.0.1")
                ca_file=p/"ca.pem";ca_file.write_text(ca.ca_pem)
                cert,fp,_=ca.sign_client("a"*32,client_csr(p/"key"))
                app=FastAPI()
                @app.get("/health")
                def health(request:Request):
                    return {"tls":request.scope.get("ndc_agent_tls"),"peer":peer_fingerprint.get()}
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
                async with agent_listener(app,ca,"127.0.0.1",port):
                    url=f"https://127.0.0.1:{port}/health"
                    async with httpx.AsyncClient(verify=client_context(ca_file),trust_env=False) as h:
                        self.assertEqual((await h.get(url,headers={"x-client-cert":fp})).json(),{"tls":True,"peer":None})
                    async with httpx.AsyncClient(verify=client_context(ca_file,p/"key",cert),trust_env=False) as h:
                        self.assertEqual((await h.get(url)).json(),{"tls":True,"peer":fp})
                    async with httpx.AsyncClient(trust_env=False) as h:
                        with self.assertRaises(httpx.ConnectError):await h.get(url)
        asyncio.run(run())

if __name__=="__main__":unittest.main()
