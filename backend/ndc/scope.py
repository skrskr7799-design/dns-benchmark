import ipaddress
import os

class ScopeError(ValueError):
    pass

# Never allow metadata/link-local, even if an operator adds a broad CIDR.
DENIED=tuple(ipaddress.ip_network(x) for x in (
    "169.254.0.0/16","fe80::/10","0.0.0.0/8","224.0.0.0/4","ff00::/8",
    "240.0.0.0/4","168.63.129.16/32","100.100.100.200/32","fd00:ec2::254/128",
    "64:ff9b::/96","64:ff9b:1::/48","2002::/16","2001::/32"))
def allowed_networks():
    return tuple(ipaddress.ip_network(x.strip(),strict=True) for x in os.getenv("NDC_ALLOWED_CIDRS","").split(",") if x.strip())

def validate_ip(value,networks=None):
    ip=ipaddress.ip_address(value)
    if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip=ip.ipv4_mapped
    if any(ip in n for n in DENIED) or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ScopeError("Destination blocked")
    if ip.is_global:
        return str(ip)
    if any(ip in n for n in (allowed_networks() if networks is None else networks)):
        return str(ip)
    raise ScopeError("Destination outside permitted scope")
