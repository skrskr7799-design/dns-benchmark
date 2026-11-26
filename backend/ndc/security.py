import asyncio
import ipaddress
import json
import tempfile
import stat
import hashlib
import re
import hmac
import os
import secrets
import time
import threading
from collections import deque
from pathlib import Path
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

COOKIE="ndc_session"
TTL=12*3600
router=APIRouter()

class Credentials(BaseModel):
    password: str=Field(min_length=1,max_length=256)
    username: str|None=Field(default=None,max_length=64)

class OwnerSetup(BaseModel):
    username: str
    password: str

LOCAL_NETWORKS=tuple(ipaddress.ip_network(n) for n in ('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10','::1/128','fc00::/7'))

def local_address(value):
    if value=='localhost':
        return True
    try:
        ip=ipaddress.ip_address(value)
        if getattr(ip,'ipv4_mapped',None):
            ip=ip.ipv4_mapped
        return any(ip in n for n in LOCAL_NETWORKS if ip.version==n.version)
    except ValueError:
        return False

def local_hostname(value):
    host=value.lower().rstrip(".")
    if local_address(host):
        return True
    # .local is a destination name, never proof of a private source address.
    return len(host)<=253 and host.endswith(".local") and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label)
        for label in host.split("."))

def direct_local(request):
    return bool(request.client and local_address(request.client.host) and local_hostname(request.url.hostname or '') and not any(h in request.headers for h in ('forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-real-ip')))

def private_file(path):
    if path.is_symlink():
        raise RuntimeError('Credential file must not be a symlink')
    if not path.exists():
        return False
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_size>4096:
        raise RuntimeError('Credential file must be a private regular file (0600)')
    return True

class Security:
    def __init__(self, data_dir):
        self.root=Path(data_dir)
        self.account_path=self.root/"owner-account.json"
        legacy=self.root/"owner-password"
        self.username=None
        self.salt=secrets.token_bytes(32)
        self.verifier=None
        self.sessions={}
        self.lock=threading.Lock()
        self.attempts=deque()
        self.setup_attempts=deque()
        self.writes=deque()
        self.agent_requests=deque()
        self.agent_enrollments=deque()
        self.agent_active=deque()
        self.agent_ingress=deque()
        self.agent_windows={}
        self.secure_policy=os.getenv("NDC_SECURE_COOKIE","auto")
        if self.secure_policy not in ("0","1","auto"):
            raise RuntimeError("Invalid NDC_SECURE_COOKIE")
        self.origin=os.getenv("NDC_ORIGIN","").rstrip("/")
        if private_file(self.account_path):
            try:
                a=json.loads(self.account_path.read_text())
                if a["version"]!=1 or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}",a["username"]):
                    raise ValueError()
                self.salt=bytes.fromhex(a["salt"])
                self.verifier=bytes.fromhex(a["verifier"])
                if len(self.salt)!=32 or len(self.verifier)!=64:
                    raise ValueError()
                self.username=a["username"]
            except (ValueError,KeyError,TypeError):
                raise RuntimeError("Invalid owner-account.json") from None
        else:
            password=legacy.read_text().rstrip("\r\n") if private_file(legacy) else os.getenv("NDC_OWNER_PASSWORD")
            if password is not None:
                if not 16<=len(password)<=256:
                    raise RuntimeError("Configure owner-password in DATA_DIR (16–256 characters)")
                self.verifier=self.hash(password)

    @property
    def setup_required(self):
        return self.verifier is None

    def cookie_secure(self,request):
        if self.secure_policy!="auto":
            return self.secure_policy=="1"
        return not (request.url.scheme=="http" and direct_local(request) and not self.origin.startswith("https://"))

    def setup(self,username,password):
        if not self.limit(self.setup_attempts,5):
            raise HTTPException(429,"Too many setup attempts")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}",username) or not 16<=len(password)<=256:
            raise HTTPException(422,"Username 3–64 (letters, digits, ._-); password 16–256 characters")
        with self.lock:
            if not self.setup_required or self.account_path.exists() or self.account_path.is_symlink():
                raise HTTPException(409,"Owner already configured")
            if (self.root/"owner-password").exists() or (self.root/"owner-password").is_symlink():
                raise HTTPException(409,"Owner already configured; restart controller")
            salt=secrets.token_bytes(32)
            verifier=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1)
            fd,tmp=tempfile.mkstemp(prefix=".owner-",dir=self.root)
            try:
                with os.fdopen(fd,"w") as out:
                    os.fchmod(out.fileno(),0o600)
                    json.dump({"version":1,"username":username,"salt":salt.hex(),"verifier":verifier.hex()},out)
                    out.flush()
                    os.fsync(out.fileno())
                try:
                    os.link(tmp,self.account_path)
                except FileExistsError:
                    raise HTTPException(409,"Owner already configured") from None
                self.salt,self.verifier,self.username=salt,verifier,username
                directory=os.open(self.root,os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                os.unlink(tmp)
        return self.issue_session()

    def hash(self,password):
        return hashlib.scrypt(password.encode(),salt=self.salt,n=16384,r=8,p=1)

    def same_origin(self,request):
        origin=request.headers.get("origin")
        if request.headers.get("sec-fetch-site") in ("cross-site","same-site"):
            return False
        expected=self.origin or str(request.base_url).rstrip("/")
        return origin is None or origin==expected

    def limit(self,queue,max_count):
        now=time.monotonic()
        with self.lock:
            while queue and queue[0]<=now-60:
                queue.popleft()
            if len(queue)>=max_count:
                return False
            queue.append(now)
            return True

    def agent_limit(self,agent_id,active):
        # Two non-borrowing lanes; idle traffic cannot spend the active
        # allowance. Keys are verified, stable agent IDs, never bearer tokens.
        now=time.monotonic()
        with self.lock:
            for key,queue in list(self.agent_windows.items()):
                while queue and queue[0]<=now-60:queue.popleft()
                if not queue:del self.agent_windows[key]
            global_queue=self.agent_active if active else self.agent_requests
            while global_queue and global_queue[0]<=now-60:global_queue.popleft()
            key=(agent_id,active)
            own=self.agent_windows.get(key)
            if len(global_queue)>=(240 if active else 480) or (own is not None and len(own)>=(100 if active else 80)):
                return False
            if own is None:
                if len(self.agent_windows)>=64:return False
                own=self.agent_windows[key]=deque()
            own.append(now);global_queue.append(now)
            return True

    def login(self,password,username=None):
        if not self.limit(self.attempts,10):
            raise HTTPException(429,"Too many login attempts")
        if self.setup_required:
            raise HTTPException(409,"Initial setup required")
        valid=hmac.compare_digest(self.hash(password),self.verifier)
        if not valid or (self.username is not None and username!=self.username):
            raise HTTPException(401,"Invalid password")
        return self.issue_session()

    def issue_session(self):
        token=secrets.token_urlsafe(32)
        csrf=secrets.token_urlsafe(32)
        with self.lock:
            now=time.monotonic()
            self.sessions={k:v for k,v in self.sessions.items() if v[0]>now}
            while len(self.sessions)>=32:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[self.key(token)]=(now+TTL,csrf)
        return token,csrf

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode()).digest()

    def session(self,request):
        token=request.cookies.get(COOKIE,"")
        if not token or len(token)>128:
            return None
        with self.lock:
            key=self.key(token)
            entry=self.sessions.get(key)
            if entry and entry[0]>time.monotonic():
                return entry[1]
            self.sessions.pop(key,None)
            return None

    def logout(self,request):
        with self.lock:
            self.sessions.pop(self.key(request.cookies.get(COOKIE,"")),None)

def matches_csrf(value,expected):
    return hmac.compare_digest(value.encode("utf-8"),expected.encode("utf-8"))

async def bounded_body(request):
    data=bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(data)+len(chunk)>131072:
                    return JSONResponse({"detail":"Request too large"},413)
                data.extend(chunk)
    except TimeoutError:
        return JSONResponse({"detail":"Request body timeout"},408)
    request._body=bytes(data)
    return None

async def guard(request,call_next):
    path=request.scope.get("path","")
    hosts=request.headers.getlist("host")
    if not path.startswith("/") or len(hosts)!=1 or not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:.]+\])(?::[0-9]{1,5})?",hosts[0]):
        return JSONResponse({"detail":"Invalid request target or Host"},400)
    if request.method not in ("GET","HEAD","POST","PATCH","PUT","DELETE","OPTIONS"):
        return JSONResponse({"detail":"Unsupported HTTP method"},405)
    machine=bool(re.fullmatch(r"/api/v1/agents/machine/(?:enroll|renew-control|poll|heartbeat|v2/(?:poll|heartbeat|results/[a-f0-9]{32})|results/[a-f0-9]{32}|(?:peer|goodput)/(?:claims|offer|prepare|ready|start|status|finish))",path)) and request.method=="POST"
    # Never allow an unrecognized machine path to fall through to owner auth
    # or framework slash redirection.
    if path.startswith("/api/v1/agents/machine/") and not machine:
        return JSONResponse({"detail":"Unknown machine endpoint"},404)
    tls_channel=bool(request.scope.get("ndc_agent_tls"))
    if tls_channel and not machine and not (path=="/health" and request.method=="GET"):
        return JSONResponse({"detail":"Agent TLS API only"},404)
    if machine and getattr(request.app.state,"agent_authority",None) is not None and not tls_channel:
        return JSONResponse({"detail":"Dedicated agent TLS required"},403)
    if tls_channel and machine and not path.endswith("/enroll") and not request.scope.get("ndc_agent_peer"):
        return JSONResponse({"detail":"Client certificate required"},401)
    if not path.startswith("/api/") and request.headers.get("range"):
        return JSONResponse({"detail":"Range requests unsupported"},416)
    if not path.startswith("/api/"):
        response=await call_next(request)
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["X-Frame-Options"]="DENY"
        response.headers["Referrer-Policy"]="no-referrer"
        return response
    security=request.app.state.security
    if machine:
        if security.setup_required:
            return JSONResponse({"detail":"Initial setup required"},403)
        headers={"Cache-Control":"no-store"}
        if request.headers.get("origin") or request.cookies.get(COOKIE):
            return JSONResponse({"detail":"Machine credentials only"},403,headers=headers)
        if path.endswith("/enroll"):
            if not security.limit(security.agent_enrollments,30):
                return JSONResponse({"detail":"Agent rate limit"},429,headers=headers|{"Retry-After":"60"})
        else:
            # Bound all authentication attempts before touching SQLite. This
            # is still a shared ingress ceiling, not a DoS availability guarantee.
            if not security.limit(security.agent_ingress,1200):
                return JSONResponse({"detail":"Agent ingress limit"},429,headers=headers|{"Retry-After":"60"})
            values=request.headers.getlist("authorization")
            if len(values)!=1 or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}",values[0]):
                return JSONResponse({"detail":"Agent credential required"},401,headers=headers)
            from .agent_store import AgentError
            try:
                agent_id=await run_in_threadpool(request.app.state.agents.rate_identity,values[0][7:])
            except AgentError as exc:
                return JSONResponse({"detail":"Invalid agent credential"},exc.status,headers=headers)
            # Only continuation endpoints use the reserved lane. Initial
            # preparation/ready/start and regular polling use idle allowance.
            active=bool(re.search(r"/(?:heartbeat|status|finish|results/[a-f0-9]{32})$",path))
            if not security.agent_limit(agent_id,active):
                return JSONResponse({"detail":"Agent rate limit"},429,headers=headers|{"Retry-After":"60"})
        failure=await bounded_body(request)
        if failure is not None:
            return failure
        response=await call_next(request)
        response.headers["Cache-Control"]="no-store"
        return response
    public=path in ("/api/auth/login","/api/auth/session","/api/auth/setup")
    write=request.method not in ("GET","HEAD","OPTIONS")
    csrf=security.session(request)
    if not public and not csrf:
        return JSONResponse({"detail":"Authentication required"},401,headers={"Cache-Control":"no-store"})
    if write:
        if not security.same_origin(request):
            return JSONResponse({"detail":"Origin rejected"},403)
        if path in ("/api/auth/login","/api/auth/setup"):
            if request.headers.get("x-ndc-request")!="1":
                return JSONResponse({"detail":"Missing login request header"},403)
        elif not csrf or not matches_csrf(request.headers.get("x-csrf-token",""),csrf):
            return JSONResponse({"detail":"CSRF rejected"},403)
        if path not in ("/api/auth/login","/api/auth/setup") and not security.limit(security.writes,60):
            return JSONResponse({"detail":"Write rate limit"},429)
        # Bound JSON bodies even for chunked requests.
        failure=await bounded_body(request)
        if failure is not None:
            return failure
    response=await call_next(request)
    response.headers["Cache-Control"]="no-store"
    response.headers["X-Content-Type-Options"]="nosniff"
    return response

@router.get("/api/auth/session")
def session(request:Request):
    csrf=request.app.state.security.session(request)
    security=request.app.state.security
    return {"authenticated":bool(csrf),"csrf":csrf,"setup_required":security.setup_required,"username_required":security.username is not None,"setup_available":security.setup_required and direct_local(request) and not (request.url.scheme=="http" and security.cookie_secure(request))}

@router.post("/api/auth/setup",status_code=201)
def setup(request:Request,body:OwnerSetup,response:Response):
    security=request.app.state.security
    if not direct_local(request) or request.headers.get("origin")!=str(request.base_url).rstrip("/"):
        raise HTTPException(403,"Initial setup requires direct trusted local access")
    if request.url.scheme=="http" and security.cookie_secure(request):
        raise HTTPException(403,"Use HTTPS for setup with secure cookies")
    token,csrf=security.setup(body.username,body.password)
    response.set_cookie(COOKIE,token,max_age=TTL,httponly=True,secure=security.cookie_secure(request),samesite="strict",path="/")
    return {"authenticated":True,"csrf":csrf,"setup_required":False,"username_required":True}

@router.post("/api/auth/login")
def login(request:Request,body:Credentials,response:Response):
    security=request.app.state.security
    token,csrf=security.login(body.password,body.username)
    security.logout(request)
    response.set_cookie(COOKIE,token,max_age=TTL,httponly=True,secure=security.cookie_secure(request),samesite="strict",path="/")
    return {"authenticated":True,"csrf":csrf,"setup_required":False,"username_required":security.username is not None}

@router.post("/api/auth/logout")
def logout(request:Request,response:Response):
    security=request.app.state.security
    security.logout(request)
    response.delete_cookie(COOKIE,path="/",secure=security.cookie_secure(request),httponly=True,samesite="strict")
    return {"authenticated":False,"csrf":None,"setup_required":security.setup_required,"username_required":security.username is not None}
