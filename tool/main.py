"""
main.py - Entry point. A command-driven loop, so you don't need a full
curses/textual app just to list, inspect, and act on processes.

Run with: python main.py
Run your terminal as Administrator - without it, some processes, most
services, and HKLM values will be invisible or unkillable.
"""

from __future__ import annotations
import sys

if sys.platform != "win32":
    print("This tool is Windows-only - it reads the registry, services, and Task Scheduler.")
    sys.exit(1)

import ctypes

import scanner
import persistence
import heuristics
import signature
import actions
import ui
import network
import modules
import packed
import audit
import baseline
import canary
import artifacts
import hidden_process
import live
import resource_monitor
import etw_bridge
import pcap_bridge
import network_analyzer


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


CRITICAL_PROCESS_NAMES = set(heuristics.SYSTEM_PROCESS_HOMES.keys()) | {"system", "registry"}

HELP_TEXT = """
Core:
  list              All processes, sorted by suspicion score
  tree              Processes as a parent/child tree
  info <pid>        Full detail for one process
  refresh           Re-scan processes and persistence locations
  autostart         Everything configured to run at boot/login

Deeper inspection (on-demand, a bit slower):
  sig <pid>         Check a process's Authenticode signature
  net <pid>         That process's live connections - instant, psutil only, no tshark needed
  modules <pid>     Loaded DLLs for that process, flagged
  packed <pid>      Entropy check on the executable (packed/obfuscated?)
  baseline <pid>    Has this name/path/hash been seen before on this machine?

>>> Network Connection Analyzer (Wireshark + netstat combined) <<<
  pcap interfaces   List capture interfaces tshark can see
  pcap <seconds>    Capture live traffic, correlate to owning processes, flag
                    suspicious hostnames/protocols (needs tshark - see README)

System-wide:
  dns               Recently resolved hostnames, flagged by entropy
  pipes             Active named pipes, flagged if randomly-generated-looking
  ads <path>        Check a file/folder for alternate data streams
  canary deploy     Drop ransomware decoy files in common folders
  canary check      Check whether any canary file was touched
  respawns          Check if anything killed recently has come back
  audit             Show the local action/event log
  hidden            Cross-check psutil vs tasklist for hidden-process gaps
  resource          Show processes with sustained (not spike) high CPU
  watch             Live auto-refreshing view, Ctrl+C to return here
  etw start/stop    Start/stop the real-time ETW helper (needs a build - see etw_monitor/)

Actions:
  kill <pid>        Terminate a process
  suspend <pid>     Freeze a process without killing it

  help              Show this message
  quit              Exit
"""


def score_all(processes: list[dict], persistence_entries: list[dict]) -> list[dict]:
    scored = []
    for p in processes:
        score, reasons = heuristics.score_process(p, persistence_entries)
        scored.append({**p, "score": score, "reasons": reasons, "tier": heuristics.tier(score)})
    return scored


def do_scan() -> tuple[list[dict], list[dict], list[dict]]:
    processes = scanner.snapshot()
    persist_entries = persistence.scan_all()
    scored = score_all(processes, persist_entries)
    resource_monitor.record(processes)
    audit.log_event("scan", {"process_count": len(processes), "persistence_count": len(persist_entries)})
    return processes, persist_entries, scored


def find_pid(scored: list[dict], pid: int) -> dict | None:
    return next((p for p in scored if p["pid"] == pid), None)


def main() -> None:
    if not is_admin():
        ui.print_message(
            "Not running as Administrator - some processes/services will be invisible "
            "or unkillable. Right-click the terminal and 'Run as Administrator' for "
            "the full picture.",
            style="yellow",
        )

    ui.print_message("Scanning processes and persistence locations...", style="cyan")
    processes, persist_entries, scored = do_scan()
    ui.print_message(f"Found {len(processes)} processes, {len(persist_entries)} auto-start entries.\n")
    print(HELP_TEXT)

    while True:
        try:
            raw = input(">> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None

        if cmd in ("quit", "exit"):
            break

        elif cmd == "help":
            print(HELP_TEXT)

        elif cmd == "list":
            ui.render_process_table(scored)

        elif cmd == "tree":
            by_pid = scanner.build_tree(scored)
            ui.render_process_tree(by_pid)

        elif cmd == "autostart":
            ui.render_persistence_table(persist_entries)

        elif cmd == "info":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: info <pid>", style="red")
                continue
            match = find_pid(scored, int(arg))
            if not match:
                ui.print_message(f"No process with PID {arg} in the current snapshot. Try 'refresh'.", style="red")
                continue
            ui.render_process_detail(match)

        elif cmd == "sig":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: sig <pid>", style="red")
                continue
            match = find_pid(scored, int(arg))
            if not match or not match.get("exe"):
                ui.print_message("No path available for that PID to check.", style="red")
                continue
            ui.print_message("Checking signature (shells out to PowerShell, a few seconds)...", style="cyan")
            info = signature.check_signature(match["exe"])
            ui.print_message(f"Path: {match['exe']}\nStatus: {info.get('status')}\nSigner: {info.get('signer') or 'none'}")

        elif cmd == "net":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: net <pid>", style="red")
                continue
            pid = int(arg)
            conns = network.process_connections(pid)
            score, reasons = network.flag_connections(pid, conns)
            ui.render_connections(pid, conns, score, reasons)

        elif cmd == "dns":
            ui.print_message("Reading DNS client cache...", style="cyan")
            ui.render_dns(network.recent_dns_lookups())

        elif cmd == "modules":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: modules <pid>", style="red")
                continue
            pid = int(arg)
            mods = modules.list_modules(pid)
            score, reasons = modules.flag_modules(mods)
            ui.render_modules(pid, mods, score, reasons)

        elif cmd == "packed":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: packed <pid>", style="red")
                continue
            match = find_pid(scored, int(arg))
            if not match or not match.get("exe"):
                ui.print_message("No path available for that PID to check.", style="red")
                continue
            score, reasons = packed.assess(match["exe"])
            ui.print_key_reasons(score, reasons)

        elif cmd == "baseline":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: baseline <pid>", style="red")
                continue
            match = find_pid(scored, int(arg))
            if not match or not match.get("exe"):
                ui.print_message("No path available for that PID to check.", style="red")
                continue
            ui.print_message("Hashing and checking against local baseline...", style="cyan")
            score, reasons = baseline.check_and_record(match.get("name", ""), match["exe"])
            ui.print_key_reasons(score, reasons)

        elif cmd == "pipes":
            ui.render_pipes(artifacts.list_named_pipes())

        elif cmd == "ads":
            if not arg:
                ui.print_message("Usage: ads <full path>", style="red")
                continue
            path = " ".join(parts[1:])
            ui.render_ads(artifacts.scan_alternate_data_streams(path))

        elif cmd == "canary":
            if arg == "deploy":
                deployed = canary.deploy()
                ui.print_message(f"Deployed/confirmed {len(deployed)} canary file(s).", style="green")
            elif arg == "check":
                ui.render_canary_alerts(canary.check())
            else:
                ui.print_message("Usage: canary deploy | canary check", style="red")

        elif cmd == "respawns":
            ui.render_respawns(audit.check_respawns(processes))

        elif cmd == "audit":
            ui.render_audit_log(audit.read_log())

        elif cmd == "hidden":
            ui.print_message("Cross-checking psutil vs tasklist.exe...", style="cyan")
            disc = hidden_process.find_discrepancies()
            if disc.get("note"):
                ui.print_message(disc["note"], style="yellow")
            else:
                ui.print_message(f"Visible to psutil only: {disc['visible_to_psutil_only']}")
                ui.print_message(f"Visible to tasklist only: {disc['visible_to_tasklist_only']}")
                if not disc["visible_to_psutil_only"] and not disc["visible_to_tasklist_only"]:
                    ui.print_message("No discrepancies.", style="green")

        elif cmd == "resource":
            alerts = resource_monitor.flag_sustained_usage()
            if not alerts:
                ui.print_message("No sustained high-CPU processes yet (needs a few scans of history first).", style="green")
            else:
                for a in alerts:
                    ui.print_message(
                        f"  !! PID {a['pid']}: avg {a['avg_cpu']}% CPU over {a['span_seconds']}s ({a['samples']} samples)",
                        style="red",
                    )

        elif cmd == "watch":
            ui.print_message("Starting live view - Ctrl+C to stop and return here.", style="cyan")
            live.watch(persistence_entries=persist_entries)

        elif cmd == "etw":
            if arg == "start":
                ok, msg = etw_bridge.start()
                ui.print_message(msg, style="green" if ok else "yellow")
            elif arg == "stop":
                ok, msg = etw_bridge.stop()
                ui.print_message(msg, style="green" if ok else "yellow")
            else:
                ui.print_message("Usage: etw start | etw stop", style="red")

        elif cmd == "pcap":
            if not pcap_bridge.tshark_path():
                diag = pcap_bridge.diagnose()
                ui.print_message("tshark not found. Here's exactly where I looked:", style="red")
                for c in diag["checks"]:
                    mark = "FOUND" if c["found"] else "  --  "
                    ui.print_message(f"  [{mark}] {c['method']}: {c['checked']}")
                ui.print_message(
                    "\nIf every line above says nothing was found: Wireshark/tshark isn't actually "
                    "installed on this machine yet (having the source zip doesn't install the app) - "
                    "get it from wireshark.org/download.html and make sure 'TShark' stays checked in "
                    "the installer's component list.\n"
                    "If you believe it IS installed somewhere: run 'where tshark' in a plain cmd/PowerShell "
                    "window (not through this tool) to find its real path, then tell me that path directly.",
                    style="yellow",
                )
                continue
            if arg == "interfaces":
                for line in pcap_bridge.list_interfaces():
                    ui.print_message(line)
                continue
            seconds = int(arg) if arg and arg.isdigit() else 15
            ui.print_message(f"Capturing for {seconds}s (needs Administrator to open a capture device)...", style="cyan")
            packets = pcap_bridge.capture(duration_seconds=seconds)
            if not packets:
                ui.print_message("No packets captured - not elevated, no traffic, or tshark couldn't open a device.", style="yellow")
                continue
            enriched = network_analyzer.correlate(packets)
            summaries = network_analyzer.summarize_by_process(enriched)
            for pid, s in summaries.items():
                s["_score"], s["_reasons"] = network_analyzer.flag_summary(s)
            name_lookup = {p["pid"]: p.get("name", "?") for p in scored}
            ui.render_pcap_summary(summaries, name_lookup)

        elif cmd == "kill":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: kill <pid>", style="red")
                continue
            pid = int(arg)
            match = find_pid(scored, pid)
            name = (match.get("name") or "").lower() if match else ""
            if name in CRITICAL_PROCESS_NAMES:
                ui.print_message(
                    f"'{name}' is a core Windows process. Killing it will likely crash or "
                    f"log off the system, even if this particular instance is legitimate. "
                    f"If you believe THIS instance is malware masquerading under that name, "
                    f"check its path with 'info {pid}' first - the real one runs from "
                    f"{heuristics.SYSTEM_PROCESS_HOMES.get(name, 'a system folder')}.",
                    style="bold red",
                )
            confirm = input(f"Kill PID {pid} ({name or 'unknown'})? This cannot be undone. [y/N] ").strip().lower()
            if confirm == "y":
                ok, msg = actions.kill_process(pid)
                ui.print_message(msg, style="green" if ok else "red")
            else:
                ui.print_message("Cancelled.")

        elif cmd == "suspend":
            if not arg or not arg.isdigit():
                ui.print_message("Usage: suspend <pid>", style="red")
                continue
            ok, msg = actions.suspend_process(int(arg))
            ui.print_message(msg, style="green" if ok else "red")

        elif cmd == "refresh":
            ui.print_message("Re-scanning...", style="cyan")
            processes, persist_entries, scored = do_scan()
            ui.print_message(f"Found {len(processes)} processes, {len(persist_entries)} auto-start entries.")

        else:
            ui.print_message(f"Unknown command '{cmd}'. Type 'help' for a list.", style="red")


if __name__ == "__main__":
    main()