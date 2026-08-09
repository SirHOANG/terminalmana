"""
ui.py - Terminal rendering using rich. All display logic lives here so
main.py stays focused on the command loop.
"""

from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

TIER_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "white",
}

TIER_BORDER = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "white",
}


def render_process_table(scored_processes: list[dict]) -> None:
    table = Table(title="Running Processes", expand=True, show_lines=False)
    table.add_column("PID", justify="right", width=7)
    table.add_column("Name", width=22)
    table.add_column("Score", justify="right", width=6)
    table.add_column("CPU%", justify="right", width=6)
    table.add_column("Mem MB", justify="right", width=8)
    table.add_column("Path", overflow="fold")

    ordered = sorted(scored_processes, key=lambda p: -p.get("score", 0))
    for p in ordered:
        style = TIER_STYLE.get(p.get("tier"), "white")
        table.add_row(
            str(p.get("pid", "")),
            str(p.get("name") or "?"),
            str(p.get("score", 0)),
            f"{p.get('cpu_percent') or 0:.1f}",
            f"{p.get('memory_mb') or 0:.1f}",
            p.get("exe") or "(no path / access denied)",
            style=style,
        )
    console.print(table)


def render_process_detail(p: dict) -> None:
    cmdline = " ".join(p.get("cmdline") or []) or "(unavailable)"
    lines = [
        f"[bold]PID[/bold]: {p.get('pid')}    [bold]PPID[/bold]: {p.get('ppid')}",
        f"[bold]Name[/bold]: {p.get('name')}",
        f"[bold]Path[/bold]: {p.get('exe') or '(unavailable)'}",
        f"[bold]User[/bold]: {p.get('username') or 'unknown'}",
        f"[bold]Started[/bold]: {p.get('started')}",
        f"[bold]Command line[/bold]: {cmdline}",
        f"[bold]Suspicion score[/bold]: {p.get('score', 0)} ({p.get('tier', 'low')})",
    ]
    reasons = p.get("reasons") or []
    if reasons:
        lines.append("")
        lines.append("[bold]Why it was flagged:[/bold]")
        for r in reasons:
            lines.append(f"  - {r}")
    border = TIER_BORDER.get(p.get("tier"), "white")
    console.print(Panel("\n".join(lines), title=f"Process {p.get('pid')}", border_style=border))


def render_persistence_table(entries: list[dict]) -> None:
    table = Table(title="Auto-start / Persistence Locations", expand=True)
    table.add_column("Source", width=22)
    table.add_column("Name", width=25)
    table.add_column("Command", overflow="fold")
    for e in entries:
        table.add_row(str(e.get("source", "")), str(e.get("name", "")), str(e.get("command", "")))
    console.print(table)


def render_process_tree(by_pid: dict) -> None:
    roots = [pid for pid, p in by_pid.items() if p.get("ppid") not in by_pid]
    for pid in roots:
        _print_branch(by_pid, pid, "")


def _print_branch(by_pid: dict, pid, prefix: str) -> None:
    p = by_pid.get(pid)
    if not p:
        return
    style = TIER_STYLE.get(p.get("tier"), "white")
    console.print(f"{prefix}[{style}]{p.get('name')} (PID {pid}, score {p.get('score', 0)})[/{style}]")
    for child_pid in p.get("children", []):
        _print_branch(by_pid, child_pid, prefix + "  ")


def render_connections(pid: int, conns: list[dict], score: int, reasons: list[str]) -> None:
    table = Table(title=f"Connections - PID {pid}", expand=True)
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("Status")
    table.add_column("Proto", width=6)
    for c in conns:
        table.add_row(c.get("laddr", ""), c.get("raddr", "") or "-", c.get("status", ""), c.get("family", ""))
    console.print(table)
    if reasons:
        style = "red" if score >= 30 else "yellow"
        for r in reasons:
            console.print(f"  ! {r}", style=style)


def render_dns(lookups: list[dict]) -> None:
    table = Table(title="Recent DNS Lookups", expand=True)
    table.add_column("Hostname", overflow="fold")
    table.add_column("Entropy", justify="right", width=8)
    table.add_column("Flag", width=6)
    for entry in lookups[:60]:
        style = "yellow" if entry.get("suspicious") else "white"
        table.add_row(entry.get("hostname", ""), str(entry.get("entropy", "")), "!" if entry.get("suspicious") else "", style=style)
    console.print(table)


def render_modules(pid: int, mods: list[dict], score: int, reasons: list[str]) -> None:
    table = Table(title=f"Loaded Modules - PID {pid} ({len(mods)} total)", expand=True)
    table.add_column("Path", overflow="fold")
    table.add_column("RSS KB", justify="right", width=10)
    for m in mods[:100]:
        table.add_row(m.get("path", ""), str(m.get("rss_kb", "")))
    console.print(table)
    if reasons:
        for r in reasons:
            console.print(f"  ! {r}", style="red" if score >= 35 else "yellow")


def print_key_reasons(score: int, reasons: list[str]) -> None:
    if not reasons:
        print_message("No flags.", style="green")
        return
    style = "red" if score >= 35 else ("yellow" if score > 0 else "green")
    for r in reasons:
        console.print(f"  - {r}", style=style)
    console.print(f"Score: {score}", style=style)


def render_pipes(pipes: list[dict]) -> None:
    table = Table(title="Named Pipes", expand=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Flag", width=6)
    for p in sorted(pipes, key=lambda x: not x.get("flagged")):
        style = "yellow" if p.get("flagged") else "white"
        table.add_row(p.get("name", ""), "!" if p.get("flagged") else "", style=style)
    console.print(table)


def render_ads(streams: list[dict]) -> None:
    if not streams:
        print_message("No alternate data streams found.", style="green")
        return
    table = Table(title="Alternate Data Streams", expand=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Stream", overflow="fold")
    for s in streams:
        table.add_row(s.get("path", ""), s.get("stream", ""), style="yellow")
    console.print(table)


def render_canary_alerts(alerts: list[dict]) -> None:
    if not alerts:
        print_message("All canary files intact.", style="green")
        return
    for a in alerts:
        console.print(f"  !! {a.get('path')} - {a.get('issue')}", style="bold red")


def render_audit_log(entries: list[dict]) -> None:
    table = Table(title="Audit Log", expand=True)
    table.add_column("Time", width=19)
    table.add_column("Event", width=10)
    table.add_column("Detail", overflow="fold")
    for e in entries:
        detail = ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("time", "event"))
        table.add_row(e.get("time", ""), e.get("event", ""), detail)
    console.print(table)


def render_respawns(alerts: list[dict]) -> None:
    if not alerts:
        print_message("No respawns detected in the recent window.", style="green")
        return
    for a in alerts:
        console.print(f"  !! PID {a.get('pid')} ({a.get('name')}) - {a.get('note')}", style="bold red")


def render_pcap_summary(summaries: dict, name_lookup: dict) -> None:
    if not summaries:
        print_message("No traffic could be attributed to a process (short capture, or the connections closed before correlation ran).", style="yellow")
        return
    table = Table(title="Network Activity by Process (tshark capture)", expand=True)
    table.add_column("PID", justify="right", width=7)
    table.add_column("Name", width=18)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Packets", justify="right", width=8)
    table.add_column("Protocols", width=18)
    table.add_column("Hostnames seen", overflow="fold")

    ordered = sorted(summaries.items(), key=lambda kv: -kv[1].get("_score", 0))
    for pid, s in ordered:
        score = s.get("_score", 0)
        style = "bold red" if score >= 60 else ("yellow" if score >= 15 else "white")
        protocols = ", ".join(f"{k}:{v}" for k, v in s.get("protocols", {}).items())
        hostnames = ", ".join(s.get("hostnames", [])) or "-"
        table.add_row(
            str(pid), name_lookup.get(pid, "?"), str(score), str(s.get("packet_count", 0)),
            protocols, hostnames, style=style,
        )
    console.print(table)

    for pid, s in ordered:
        for r in s.get("_reasons", []):
            style = "bold red" if s.get("_score", 0) >= 60 else "yellow"
            console.print(f"  !! PID {pid} ({name_lookup.get(pid, '?')}): {r}", style=style)


def print_message(msg: str, style: str = "white") -> None:
    console.print(msg, style=style)
