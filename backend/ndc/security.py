import asyncio
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
from pydantic import BaseModel, Field

COOKIE="ndc_session"
TTL=12*3600
router=APIRouter()

class Credentials(BaseModel):
    password: str=Field(min_length=1,max_length=256)

class Security:
    def __init__(self, data_dir):
        path=Path(data_dir)/"owner-password"
        if path.is_symlink():
            raise RuntimeError("owner-password must not be a symlink")
        if path.exists():
            info=path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_size>4096:
                raise RuntimeError("owner-password must be a private regular file (0600)")
        password=path.read_text().rstrip("\r\n") if path.exists() else os.getenv("NDC_OWNER_PASSWORD","")
        if not 16<=len(password)<=256:
            raise RuntimeError("Configure owner-password in DATA_DIR (16–256 characters)")
        self.salt=secrets.token_bytes(32)
        self.verifier=self.hash(password)
        self.sessions={}
        self.lock=threading.Lock()
        self.attempts=deque()
        self.writes=deque()
        self.agent_requests=deque()
        self.agent_enrollments=deque()
        self.secure=os.getenv("NDC_SECURE_COOKIE","1")!="0"
        self.origin=os.getenv("NDC_ORIGIN","").rstrip("/")

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

    def login(self,password):
        if not self.limit(self.attempts,10):
            raise HTTPException(429,"Too many login attempts")
        if not hmac.compare_digest(self.hash(password),self.verifier):
            raise HTTPException(401,"Invalid password")
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
    path=request.url.path
    if not path.startswith("/api/"):
        response=await call_next(request)
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["X-Frame-Options"]="DENY"
        response.headers["Referrer-Policy"]="no-referrer"
        return response
    security=request.app.state.security
    machine=bool(re.fullmatch(r"/api/v1/agents/machine/(?:enroll|poll|heartbeat|results/[a-f0-9]{32})",path)) and request.method=="POST"
    if machine:
        queue=security.agent_enrollments if path.endswith("/enroll") else security.agent_requests
        if not security.limit(queue,30 if path.endswith("/enroll") else 600):
            return JSONResponse({"detail":"Agent rate limit"},429)
        if request.headers.get("origin") or request.cookies.get(COOKIE):
            return JSONResponse({"detail":"Machine credentials only"},403)
        failure=await bounded_body(request)
        if failure is not None:
            return failure
        response=await call_next(request)
        response.headers["Cache-Control"]="no-store"
        return response
    public=path in ("/api/auth/login","/api/auth/session")
    write=request.method not in ("GET","HEAD","OPTIONS")
    csrf=security.session(request)
    if not public and not csrf:
        return JSONResponse({"detail":"Authentication required"},401,headers={"Cache-Control":"no-store"})
    if write:
        if not security.same_origin(request):
            return JSONResponse({"detail":"Origin rejected"},403)
        if path=="/api/auth/login":
            if request.headers.get("x-ndc-request")!="1":
                return JSONResponse({"detail":"Missing login request header"},403)
        elif not csrf or not matches_csrf(request.headers.get("x-csrf-token",""),csrf):
            return JSONResponse({"detail":"CSRF rejected"},403)
        if path!="/api/auth/login" and not security.limit(security.writes,60):
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
    return {"authenticated":bool(csrf),"csrf":csrf}

@router.post("/api/auth/login")
def login(request:Request,body:Credentials,response:Response):
    security=request.app.state.security
    token,csrf=security.login(body.password)
    security.logout(request)
    response.set_cookie(COOKIE,token,max_age=TTL,httponly=True,secure=security.secure,samesite="strict",path="/")
    return {"authenticated":True,"csrf":csrf}

@router.post("/api/auth/logout")
def logout(request:Request,response:Response):
    security=request.app.state.security
    security.logout(request)
    response.delete_cookie(COOKIE,path="/",secure=security.secure,httponly=True,samesite="strict")
    return {"authenticated":False,"csrf":None}
