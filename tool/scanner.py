"""
scanner.py - Process enumeration and metadata collection.

Wraps psutil to build a snapshot of every running process, including
executable path, command line, parent/child relationships, and basic
resource usage. This is the data source everything else (heuristics,
persistence cross-referencing, UI) is built on top of.
"""

from __future__ import annotations
from datetime import datetime

import psutil

PROCESS_FIELDS = [
    "pid", "ppid", "name", "exe", "cmdline",
    "username", "create_time", "status", "cpu_percent", "memory_info",
]


def snapshot() -> list[dict]:
    """Return a list of dicts, one per currently running process.

    Note: cpu_percent reads 0.0 on the very first snapshot of a run,
    since psutil measures it relative to the previous call. It becomes
    accurate from the second 'refresh' onward.

    Processes we can't fully inspect (AccessDenied - usually other
    users' processes, or protected system processes, when not running
    elevated) are still included with whatever we could read, since
    "I can't see into this" is itself useful signal.
    """
    processes = []
    for proc in psutil.process_iter(PROCESS_FIELDS):
        try:
            info = dict(proc.info)
            mem = info.get("memory_info")
            info["memory_mb"] = round(mem.rss / (1024 * 1024), 1) if mem else None
            info.pop("memory_info", None)
            if info.get("create_time"):
                info["started"] = datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
            else:
                info["started"] = "unknown"
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            processes.append({
                "pid": proc.pid, "ppid": None, "name": _safe_name(proc),
                "exe": None, "cmdline": None, "username": None,
                "cpu_percent": 0.0, "memory_mb": None, "started": "unknown",
                "status": "access-denied",
            })
    return processes


def _safe_name(proc: psutil.Process) -> str:
    try:
        return proc.name()
    except Exception:
        return "unknown"


def build_tree(processes: list[dict]) -> dict:
    """Index processes by pid and attach each one's list of child pids -
    lets the UI print a parent/child tree instead of a flat list, which
    is often the fastest way to spot how a malicious process chain-launched
    (e.g. winword.exe -> cmd.exe -> powershell.exe)."""
    by_pid = {p["pid"]: {**p, "children": []} for p in processes}
    for p in processes:
        ppid = p.get("ppid")
        if ppid in by_pid and ppid != p["pid"]:
            by_pid[ppid]["children"].append(p["pid"])
    return by_pid
