import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, field_validator, model_validator
import dns.name, dns.reversename, dns.exception

class Run(BaseModel):
    endpoints: list[str] = Field(min_length=1, max_length=40)
    count: int = Field(default=10, ge=1, le=100)
    mode: Literal["cold", "warm", "both"] = "cold"
    family: Literal["auto", "ipv4", "ipv6"] = "ipv4"
    parallel: int = Field(default=1, ge=1, le=2)

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, endpoints):
        for endpoint in endpoints:
            if len(endpoint) > 2048 or any(c.isspace() for c in endpoint):
                raise ValueError("Invalid endpoint")
            u = urlsplit(endpoint)
            if u.scheme not in ("https", "h3", "tls", "quic", "udp", "tcp") or not u.hostname or u.username or u.password or u.fragment or u.query:
                raise ValueError("Invalid endpoint")
            if u.scheme not in ('https','h3') and u.path not in ('','/'):
                raise ValueError('Unexpected path')
            if '%' in u.hostname:
                raise ValueError('Invalid hostname')
            if u.scheme in ("udp","tcp"):
                ipaddress.ip_address(u.hostname)
            if u.port is not None and not 1 <= u.port <= 65535:
                raise ValueError("Invalid port")
        return endpoints

class Profile(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    config: Run

class Inspect(BaseModel):
    name: str = Field(min_length=1,max_length=253)
    qtype: Literal["A","AAAA","CNAME","MX","TXT","NS","SOA","CAA","PTR","SRV","HTTPS","SVCB","DS","DNSKEY","RRSIG"]="A"
    endpoints: list[str] = Field(min_length=1,max_length=4)
    family: Literal["auto","ipv4","ipv6"]="ipv4"
    dnssec: bool=False
    checking_disabled: bool=False
    tcp_fallback: bool=False

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls,endpoints):
        return Run(endpoints=endpoints).endpoints

    @model_validator(mode="after")
    def canonical_name(self):
        if any(c.isspace() or ord(c)<32 or c in "/\\@" for c in self.name):
            raise ValueError("Invalid DNS name")
        if self.qtype=="PTR":
            try:
                ip=ipaddress.ip_address(self.name)
            except ValueError:
                pass
            else:
                if getattr(ip,"scope_id",None):
                    raise ValueError("Scoped IP is not supported")
                self.name=dns.reversename.from_address(str(ip)).to_text()
                return self
        try:
            self.name=dns.name.from_text(self.name).canonicalize().to_text()
        except (dns.exception.DNSException,UnicodeError,ValueError) as exc:
            raise ValueError("Invalid DNS name") from exc
        return self

class NetworkTarget(BaseModel):
    host: str=Field(min_length=1,max_length=253)
    port: int=Field(default=443,ge=1,le=65535)
    family: Literal["ipv4","ipv6","both"]="ipv4"

    @field_validator("host")
    @classmethod
    def validate_host(cls,value):
        if "%" in value:
            raise ValueError("Scoped addresses are unsupported")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        try:
            host=value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid hostname") from exc
        if not host or len(host)>253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label) for label in host.split(".")):
            raise ValueError("Invalid hostname")
        return host

class Connectivity(NetworkTarget):
    kind: Literal["tcp","http","https","icmp"]="tcp"
    count: int=Field(default=3,ge=1,le=5)
    path: str=Field(default="/",max_length=1024)

    @field_validator("path")
    @classmethod
    def validate_path(cls,value):
        if not value.startswith("/") or value.startswith("//") or any(ord(c)<33 or ord(c)>126 or c in "\\?#" for c in value):
            raise ValueError("Use a plain origin-relative ASCII path without query or fragment")
        return value

class RouteTarget(NetworkTarget):
    max_hops: int=Field(default=12,ge=1,le=20)
    attempts: int=Field(default=1,ge=1,le=2)
    port: Literal[33434]=33434

class MonitorConfig(Connectivity):
    name: str=Field(min_length=1,max_length=100)
    kind: Literal["tcp","http","https","tls","dns"]="tcp"
    family: Literal["ipv4","ipv6"]="ipv4"
    count: Literal[1]=1
    endpoint: str="https://cloudflare-dns.com/dns-query"
    interval_seconds: int=Field(default=300,ge=60,le=86400)
    failure_count: int=Field(default=3,ge=1,le=10)
    recovery_count: int=Field(default=2,ge=1,le=10)
    latency_ms: float|None=Field(default=None,gt=0,le=60000)
    expiry_days: int=Field(default=14,ge=1,le=90)
    enabled: bool=True
    notify: bool=False

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls,value):
        return Run(endpoints=[value]).endpoints[0]
