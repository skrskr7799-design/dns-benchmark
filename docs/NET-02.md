# NET-02 — Route Analyzer candidate

Based on NET-01 fix 6cf55f6. Original NET-01 CI failed only at Playwright
exact accessible-name selection; backend network integration passed.
Fix explicitly labels the two selects. NET-01 rerun must pass before acceptance.

New authenticated POST /api/v1/network/routes, shared interactive diagnostic
semaphore, existing write limits and destination scope. Linux UDP traceroute
uses IP_RECVERR/IPV6_RECVERR and MSG_ERRQUEUE, no raw sockets, subprocess,
NET_RAW or privileged container. One scoped target, fixed UDP destination
port 33434, 1–2 attempts per TTL, at most 20 hops, one second per probe,
IPv4/IPv6/both. System DNS resolution may exceed socket deadline.
Nonce correlates returned payload; truncated/unmatched quotes ignored.
ICMP offender address is observed, not independently authenticated. No
traffic is sent to intermediate addresses, no reverse DNS, ASN or geo lookup.
A port-unreachable response from the pinned destination is evidence of
arrival; other ICMP errors and silence are not arrival. Missing hop replies
are not evidence of packet loss. Fresh sockets may change ECMP path;
the display is a sequence of observed replies, not a guaranteed single route.
No arbitrary port ranges or packet payloads. Target authorization assumed.
Capability indicates socket setup only, not successful routing.
Results are interactive and exportable, not persisted. No cancellation
of immediate probes; request bounded except OS DNS resolution. Distributed
comparison, Paris traceroute, TCP/ICMP methods, ASN and maps deferred.
Preview 8107 separate data directory and password. Main unchanged.
CI adds parser/loopback tests plus browser rendering. Acceptance pending
CI and real network test; prior lockfile/security/transport gates remain.
