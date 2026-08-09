"""
etw_bridge.py - Launches the C# EtwMonitor.exe helper (if it's been
built - see etw_monitor/README.md) and streams its real-time process
start/stop events into the audit log, catching short-lived processes a
polling-based scan would miss entirely. That's the actual reason this
component exists.

This only activates if EtwMonitor.exe has been built and is found next
to this file, or on PATH. Everything else in TaskGuard works without
it - this is an optional enhancement, not a dependency.
"""

from __future__ import annotations
import json
import os
import subprocess
import threading

import audit

_process = None
_thread = None
_stop_flag = threading.Event()


def find_exe() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "etw_monitor", "bin", "Release", "net8.0", "EtwMonitor.exe"),
        os.path.join(here, "etw_monitor", "bin", "Debug", "net8.0", "EtwMonitor.exe"),
        os.path.join(here, "EtwMonitor.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    from shutil import which
    return which("EtwMonitor.exe") or which("EtwMonitor")


def _reader_loop(proc) -> None:
    try:
        for line in iter(proc.stdout.readline, ""):
            if _stop_flag.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            audit.log_event(f"etw_{event.get('type', 'unknown')}", event)
    except Exception:
        pass


def start() -> tuple[bool, str]:
    global _process, _thread
    if _process is not None and _process.poll() is None:
        return False, "Already running."

    exe = find_exe()
    if not exe:
        return False, "EtwMonitor.exe not found - build it first (see etw_monitor/README.md), then run 'etw start' again."

    _stop_flag.clear()
    try:
        _process = subprocess.Popen(
            [exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
    except Exception as e:
        return False, f"Failed to launch {exe}: {e}"

    _thread = threading.Thread(target=_reader_loop, args=(_process,), daemon=True)
    _thread.start()
    return True, f"Streaming real-time process events from {exe} into the audit log. Use 'audit' to see them."


def stop() -> tuple[bool, str]:
    global _process
    if _process is None or _process.poll() is not None:
        return False, "Not running."
    _stop_flag.set()
    _process.terminate()
    _process = None
    return True, "Stopped."


def is_running() -> bool:
    return _process is not None and _process.poll() is None
