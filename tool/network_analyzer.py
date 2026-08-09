"""
network_analyzer.py - The actual "wireshark + netstat" combination.

netstat/psutil tells you WHICH PROCESS owns a connection - an IP and a
port, nothing more. tshark tells you WHAT'S ACTUALLY HAPPENING on that
connection - the real protocol, a TLS SNI hostname, an HTTP Host
header, a DNS query. Neither alone gives you the full picture: psutil
can't see inside the traffic, and tshark alone can capture a socket
without knowing which of the machine's hundred processes it belongs
to. Correlating them by local port gives you both halves at once: "PID
4821 is talking to 203.0.113.4:443, and it's actually TLS to
sketchy-domain.example, not whatever the bare IP would suggest."
"""

from __future__ import annotations
import math
from collections import Counter, defaultdict

import network

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 9001, 9050}
TLS_PROTOCOLS = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSL", "SSLv2", "SSLv3"}


def correlate(packets: list[dict]) -> list[dict]:
    """Attaches an owning PID to each captured packet by matching local
    port against the live connection table. Best-effort: a connection
    that's already closed by the time we check the table won't resolve,
    and a very short capture may catch packets for a port that closes
    before correlation runs."""
    conns = network.all_connections()
    port_to_pid = {c["lport"]: c["pid"] for c in conns if c.get("lport") is not None and c.get("pid") is not None}

    enriched = []
    for p in packets:
        sport = _to_int(p.get("sport"))
        dport = _to_int(p.get("dport"))
        pid = port_to_pid.get(sport)
        if pid is None:
            pid = port_to_pid.get(dport)
        enriched.append({**p, "pid": pid})
    return enriched


def _to_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def summarize_by_process(enriched_packets: list[dict]) -> dict:
    """Groups packets by owning PID: protocols used, hostnames actually
    observed (SNI/HTTP/DNS), remote endpoints, packet/byte counts - a
    per-process network summary instead of a raw packet firehose."""
    by_pid = defaultdict(lambda: {
        "packet_count": 0, "byte_count": 0, "protocols": Counter(),
        "hostnames": set(), "remote_endpoints": set(),
    })
    for p in enriched_packets:
        pid = p.get("pid")
        if pid is None:
            continue
        bucket = by_pid[pid]
        bucket["packet_count"] += 1
        length = _to_int(p.get("length"))
        if length:
            bucket["byte_count"] += length
        if p.get("protocol"):
            bucket["protocols"][p["protocol"]] += 1
        for host_field in ("tls_sni", "http_host", "dns_query"):
            if p.get(host_field):
                bucket["hostnames"].add(p[host_field])
        dst, dport = p.get("dst"), p.get("dport")
        if dst and dport:
            bucket["remote_endpoints"].add(f"{dst}:{dport}")

    return {
        pid: {
            "packet_count": b["packet_count"],
            "byte_count": b["byte_count"],
            "protocols": dict(b["protocols"]),
            "hostnames": sorted(b["hostnames"]),
            "remote_endpoints": sorted(b["remote_endpoints"]),
        }
        for pid, b in by_pid.items()
    }


def flag_summary(summary: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    protocols = summary.get("protocols", {})
    hostnames = summary.get("hostnames", [])
    endpoints = summary.get("remote_endpoints", [])

    saw_http = protocols.get("HTTP", 0) > 0
    saw_tls = any(protocols.get(p, 0) > 0 for p in TLS_PROTOCOLS)
    if saw_http and not saw_tls:
        score += 15
        reasons.append("Plaintext HTTP with no TLS seen for this process - anything sent is readable on the wire")

    for host in hostnames:
        base = host.split(".")[0]
        ent = _entropy(base)
        if ent > 3.6 and len(base) >= 10:
            score += 25
            reasons.append(f"High-entropy hostname observed in traffic ('{host}') - consistent with DGA-generated or randomly-named infrastructure")

    remote_ports = set()
    for ep in endpoints:
        try:
            remote_ports.add(int(ep.rsplit(":", 1)[1]))
        except (ValueError, IndexError):
            continue
    hits = remote_ports & SUSPICIOUS_PORTS
    if hits:
        score += 30
        reasons.append(f"Traffic seen on commonly-abused port(s): {sorted(hits)}")

    if summary.get("packet_count", 0) >= 200:
        score += 10
        reasons.append(f"High packet volume from this process during the capture window ({summary['packet_count']} packets)")

    return min(score, 100), reasons


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
