"""
resource.py - Tracks CPU usage per PID across multiple scans and flags
*sustained* high usage rather than momentary spikes. A momentary spike
is normal (compiling, exporting video, a game loading); a process
quietly burning significant CPU for minutes at a stretch - especially
one that otherwise looks unremarkable - is the classic cryptominer /
resource-abuse pattern. Call record() on every scan/refresh (cheap) and
flag_sustained_usage() whenever you want the current read.
"""

from __future__ import annotations
import time

_history: dict[int, list[tuple[float, float]]] = {}  # pid -> [(timestamp, cpu_percent), ...]
_WINDOW_SECONDS = 120
_SUSTAINED_THRESHOLD = 60.0
_MIN_SAMPLES = 3


def record(processes: list[dict]) -> None:
    now = time.time()
    seen_pids = set()
    for p in processes:
        pid = p.get("pid")
        if pid is None:
            continue
        cpu = p.get("cpu_percent") or 0.0
        seen_pids.add(pid)
        _history.setdefault(pid, []).append((now, cpu))
        _history[pid] = [(t, c) for t, c in _history[pid] if now - t <= _WINDOW_SECONDS]

    for pid in list(_history.keys()):
        if pid not in seen_pids:
            del _history[pid]


def flag_sustained_usage() -> list[dict]:
    alerts = []
    for pid, samples in _history.items():
        if len(samples) < _MIN_SAMPLES:
            continue
        avg_cpu = sum(c for _, c in samples) / len(samples)
        if avg_cpu >= _SUSTAINED_THRESHOLD:
            span = samples[-1][0] - samples[0][0]
            alerts.append({"pid": pid, "avg_cpu": round(avg_cpu, 1), "span_seconds": round(span, 1), "samples": len(samples)})
    return sorted(alerts, key=lambda a: -a["avg_cpu"])


def reset() -> None:
    _history.clear()
