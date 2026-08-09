"""
live.py - A real-time auto-refreshing process view, for cases where
polling once per 'refresh' isn't fast enough to catch short-lived
activity. Still fundamentally a polling loop, just a fast one (every
couple of seconds instead of on-demand) - genuine event-driven
visibility, with nothing missed between samples, is what etw_bridge.py
is for.
"""

from __future__ import annotations
import time

from rich.live import Live
from rich.table import Table

import scanner
import heuristics

TIER_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "white",
}


def _build_table(scored: list[dict]) -> Table:
    table = Table(title=f"Live - {time.strftime('%H:%M:%S')} (Ctrl+C to stop)", expand=True)
    table.add_column("PID", justify="right", width=7)
    table.add_column("Name", width=22)
    table.add_column("Score", justify="right", width=6)
    table.add_column("CPU%", justify="right", width=6)
    table.add_column("Path", overflow="fold")
    ordered = sorted(scored, key=lambda p: -p.get("score", 0))[:25]
    for p in ordered:
        style = TIER_STYLE.get(p.get("tier"), "white")
        table.add_row(
            str(p.get("pid", "")), str(p.get("name") or "?"), str(p.get("score", 0)),
            f"{p.get('cpu_percent') or 0:.1f}", p.get("exe") or "(no path)", style=style,
        )
    return table


def watch(interval_seconds: float = 2.0, persistence_entries: list[dict] | None = None, max_iterations: int | None = None) -> None:
    """max_iterations is for testing only - real usage runs until Ctrl+C."""
    persistence_entries = persistence_entries or []
    iterations = 0
    with Live(refresh_per_second=1) as live:
        try:
            while max_iterations is None or iterations < max_iterations:
                processes = scanner.snapshot()
                scored = []
                for p in processes:
                    score, reasons = heuristics.score_process(p, persistence_entries)
                    scored.append({**p, "score": score, "tier": heuristics.tier(score), "reasons": reasons})
                live.update(_build_table(scored))
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            pass
