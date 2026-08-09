"""
audit.py - Append-only local log of every scan and every action taken
(kill/suspend) - "Command Logging / Audit Mode". Useful for incident
write-ups afterward, and it's what powers respawn detection: if a
process with the same name+path reappears shortly after being killed,
that's a watchdog, not a coincidence.
"""

from __future__ import annotations
import json
import os
import time

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taskguard_audit.log")


def log_event(event_type: str, details: dict) -> None:
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event_type, **details}
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def read_log(limit: int = 50) -> list[dict]:
    if not os.path.exists(LOG_PATH):
        return []
    lines = []
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return lines[-limit:]


def check_respawns(current_processes: list[dict], window_seconds: int = 30) -> list[dict]:
    """Cross-references recent successful 'kill' log entries against the
    current snapshot - a process with the same name+path reappearing
    shortly after being killed suggests a watchdog/respawner."""
    events = read_log(limit=200)
    now = time.time()
    recent_kills = []
    for e in events:
        if e.get("event") != "kill" or not e.get("success"):
            continue
        try:
            t = time.mktime(time.strptime(e["time"], "%Y-%m-%d %H:%M:%S"))
        except (ValueError, KeyError):
            continue
        if now - t <= window_seconds:
            recent_kills.append(e)

    alerts = []
    for kill in recent_kills:
        for p in current_processes:
            if p.get("name") == kill.get("name") and p.get("exe") == kill.get("exe") and kill.get("exe"):
                alerts.append({
                    "pid": p.get("pid"), "name": p.get("name"), "exe": p.get("exe"),
                    "note": f"Reappeared within {window_seconds}s of being killed - possible watchdog/respawn",
                })
    return alerts
