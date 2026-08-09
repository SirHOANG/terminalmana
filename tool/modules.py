"""
modules.py - Loaded module (DLL) inspection for a process.

Uses psutil's memory_maps(), which on Windows enumerates the DLLs mapped
into a process's address space with their file paths - genuine signal
for spotting a legitimate process that's had something extra side-loaded
into it: a module loaded from an unusual path is a classic DLL
injection / sideloading indicator.
"""

from __future__ import annotations

import psutil

SUSPICIOUS_MODULE_MARKERS = [
    r"\appdata\local\temp", r"\appdata\roaming", r"\users\public",
    r"\programdata", r"\downloads", r"\windows\temp",
]


def list_modules(pid: int) -> list[dict]:
    try:
        proc = psutil.Process(pid)
        maps = proc.memory_maps()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
    except Exception:
        return []

    results = []
    for m in maps:
        path = getattr(m, "path", "") or ""
        results.append({"path": path, "rss_kb": getattr(m, "rss", 0) // 1024})
    return results


def flag_modules(modules: list[dict]) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    for m in modules:
        path = (m.get("path") or "").lower()
        for marker in SUSPICIOUS_MODULE_MARKERS:
            if marker in path:
                score += 35
                reasons.append(f"Loaded module from unusual location: {m.get('path')}")
                break
    return min(score, 60), reasons
