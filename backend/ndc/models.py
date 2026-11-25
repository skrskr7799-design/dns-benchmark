import ipaddress
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, field_validator

class Run(BaseModel):
    endpoints: list[str] = Field(min_length=1, max_length=40)
    count: int = Field(default=10, ge=1, le=100)
    mode: Literal["cold", "warm"] = "cold"
    family: Literal["auto", "ipv4", "ipv6"] = "ipv4"
    parallel: int = Field(default=1, ge=1, le=2)

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, endpoints):
        for endpoint in endpoints:
            if len(endpoint) > 2048 or any(c.isspace() for c in endpoint):
                raise ValueError("Invalid endpoint")
            u = urlsplit(endpoint)
            if u.scheme not in ("https", "h3", "tls", "quic", "udp") or not u.hostname or u.username or u.password or u.fragment or u.query:
                raise ValueError("Invalid endpoint")
            if u.scheme not in ('https','h3') and u.path not in ('','/'):
                raise ValueError('Unexpected path')
            if '%' in u.hostname:
                raise ValueError('Invalid hostname')
            if u.scheme == "udp":
                ipaddress.ip_address(u.hostname)
            if u.port is not None and not 1 <= u.port <= 65535:
                raise ValueError("Invalid port")
        return endpoints

class Profile(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    config: Run
