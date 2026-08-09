"""
artifacts.py - Two lower-level filesystem/IPC artifacts worth checking:

Named pipes: enumerating \\\\.\\pipe\\ shows active inter-process
communication channels - some malware and post-exploitation frameworks
use named pipes for internal or lateral communication, often with
randomly generated or oddly formatted names.

Alternate Data Streams (NTFS ADS): a way to hide data "behind" a normal
file without changing its visible size - a known technique for stashing
a payload where a casual look won't find it.
"""

from __future__ import annotations
import os
import re
import subprocess

KNOWN_PIPE_PREFIXES = (
    "microsoft", "chrome", "mojo", "msse", "wkssvc", "srvsvc", "lsass",
    "netlogon", "samr", "spoolss", "eventlog", "winreg", "atsvc", "scerpc",
    "ntsvcs", "plugplay", "browser", "vscode", "docker", "openssh", "crashpad",
)


def list_named_pipes() -> list[dict]:
    try:
        names = os.listdir(r"\\.\pipe\\")
    except OSError:
        return []

    results = []
    for name in names:
        lower = name.lower()
        known = any(lower.startswith(p) for p in KNOWN_PIPE_PREFIXES)
        looks_random = bool(re.fullmatch(r"[a-f0-9]{16,}", lower)) or bool(re.fullmatch(r"[a-z0-9]{20,}", lower))
        results.append({"name": name, "flagged": (not known) and looks_random})
    return results


def scan_alternate_data_streams(path: str) -> list[dict]:
    """Shells out to 'dir /r', which lists ADS on a file/folder - simpler
    and more robust than reimplementing NTFS stream enumeration by hand."""
    if not path or not os.path.exists(path):
        return []
    try:
        proc = subprocess.run(["cmd", "/c", "dir", "/r", path], capture_output=True, text=True, timeout=15)
        output = proc.stdout
    except Exception:
        return []

    streams = []
    for line in output.splitlines():
        line = line.strip()
        if line.endswith(":$DATA"):
            token = line.split()[-1]
            if "::$DATA" not in token:  # skip the file's own unnamed default stream
                streams.append({"path": path, "stream": token})
    return streams
