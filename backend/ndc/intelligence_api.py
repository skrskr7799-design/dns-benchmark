"""Authenticated read-only evidence API; no network probes or raw source payloads."""
from typing import Literal
from fastapi import APIRouter,Request,Query,HTTPException
from .evidence import Source,Kind,Outcome

router=APIRouter(prefix="/api/v1/intelligence")
EvidenceKind=Literal["observations","events"]
MAX_SEQ=9223372036854775807

@router.get("/{kind}")
def page(request:Request,kind:EvidenceKind,after:int=Query(0,ge=0,le=MAX_SEQ),
    limit:int=Query(100,ge=1,le=200),until:int|None=Query(None,ge=0,le=MAX_SEQ),
    source:Source|None=None,vantage:str|None=Query(None,min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$"),
    probe:Kind|None=None,outcome:Outcome|None=None,
    since:float|None=Query(None,ge=0,le=253402300799),before:float|None=Query(None,ge=0,le=253402300799)):
    try:
        return request.app.state.evidence.page(kind,after=after,limit=limit,until=until,source=source,
            vantage=vantage,probe=probe,outcome=outcome,since=since,before=before)
    except ValueError:
        raise HTTPException(422,"Invalid evidence filters or cursor") from None

@router.get("/{kind}/{id}")
def detail(request:Request,kind:EvidenceKind,id:str):
    import re
    if not re.fullmatch(r"[a-f0-9]{64}",id):
        raise HTTPException(404,"Evidence not found")
    result=request.app.state.evidence.detail(kind,id)
    if result is None:
        raise HTTPException(404,"Evidence not found")
    return result
