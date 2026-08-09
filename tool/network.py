"""
network.py - Per-process network visibility and lightweight flagging.

psutil gives us live connections (local/remote IP:port, state) per
process - real signal, no shell-outs needed. True deep packet inspection,
TLS SNI extraction, or statistically rigorous beaconing detection would
need a packet capture layer this module doesn't have; what's here is a
heuristic first pass: unusual ports, high connection fan-out, and a
basic entropy check against recently resolved hostnames (via the DNS
client cache) as a rough, honest stand-in for DGA detection.
"""

from __future__ import annotations
import json
import math
import socket
import subprocess
from collections import Counter

import psutil

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 8080, 8443, 9001, 9050}


def process_connections(pid: int) -> list[dict]:
    try:
        proc = psutil.Process(pid)
        try:
            conns = proc.net_connections(kind="inet")
        except AttributeError:
            conns = proc.connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
    except Exception:
        return []

    results = []
    for c in conns:
        raddr = c.raddr
        results.append({
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr": f"{raddr.ip}:{raddr.port}" if raddr else "",
            "status": c.status,
            "family": "tcp" if c.type == socket.SOCK_STREAM else "udp",
        })
    return results


def flag_connections(pid: int, conns: list[dict]) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    if not conns:
        return score, reasons

    remote_ports = set()
    for c in conns:
        if c["raddr"]:
            try:
                port = int(c["raddr"].rsplit(":", 1)[1])
                remote_ports.add(port)
            except (ValueError, IndexError):
                continue

    hits = remote_ports & SUSPICIOUS_PORTS
    if hits:
        score += 30
        reasons.append(f"Connected to commonly-abused port(s): {sorted(hits)}")

    established = [c for c in conns if c["status"] == "ESTABLISHED"]
    if len(established) >= 8:
        score += 20
        reasons.append(f"Unusually high number of open connections ({len(established)})")

    return score, reasons


def recent_dns_lookups() -> list[dict]:
    """Uses PowerShell's Get-DnsClientCache instead of parsing
    'ipconfig /displaydns' text - ipconfig's field labels are localized
    on non-English Windows, which breaks text parsing silently; the
    PowerShell cmdlet's object properties are not.

    Process-agnostic (Windows doesn't expose which process triggered
    which DNS lookup without ETW), but it's real, zero-extra-dependency
    visibility into what's been resolved recently - and a first pass at
    DGA-style detection: short, high-entropy hostnames are worth a
    second look."""
    ps_script = "Get-DnsClientCache | Select-Object -ExpandProperty Entry | ConvertTo-Json -Compress"
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        if isinstance(data, str):
            data = [data]
    except Exception:
        return []

    results = []
    for host in set(data):
        base = host.split(".")[0]
        ent = _entropy(base)
        results.append({"hostname": host, "entropy": round(ent, 2), "suspicious": ent > 3.6 and len(base) >= 10})
    return sorted(results, key=lambda r: -r["entropy"])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def all_connections() -> list[dict]:
    """System-wide connection table with owning PID - the 'netstat' half
    of pairing with tshark's packet-level visibility. Unlike the
    per-process version above, this queries the OS's global connection
    table directly rather than iterating every process."""
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []

    results = []
    for c in conns:
        results.append({
            "pid": c.pid,
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "lport": c.laddr.port if c.laddr else None,
            "status": c.status,
        })
    return results
