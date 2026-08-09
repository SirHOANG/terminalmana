"""
heuristics.py - Suspicion scoring for a running process.

This is not signature-based antivirus - it doesn't know about specific
malware families. It flags *behavioral and positional* red flags that
malware disproportionately exhibits: masquerading as a system process,
running from a location legitimate software rarely installs to,
obfuscated command lines, living-off-the-land binary abuse, and so on.
Treat the score as "worth a closer look," not a verdict - some
legitimate portable apps and dev tools will trip a flag or two. Use the
reasons list to judge for yourself.
"""

from __future__ import annotations

SUSPICIOUS_PATH_MARKERS = {
    r"\appdata\local\temp": 25,
    r"\appdata\roaming": 15,
    r"\windows\temp": 25,
    r"\users\public": 30,
    r"\programdata": 15,
    r"\downloads": 20,
    r"\$recycle.bin": 40,
}

# Name -> the one folder its real, Microsoft-signed binary lives in.
SYSTEM_PROCESS_HOMES = {
    "svchost.exe": r"c:\windows\system32",
    "csrss.exe": r"c:\windows\system32",
    "lsass.exe": r"c:\windows\system32",
    "explorer.exe": r"c:\windows",
    "winlogon.exe": r"c:\windows\system32",
    "services.exe": r"c:\windows\system32",
    "smss.exe": r"c:\windows\system32",
    "wininit.exe": r"c:\windows\system32",
    "spoolsv.exe": r"c:\windows\system32",
    "taskhostw.exe": r"c:\windows\system32",
}

OBFUSCATION_MARKERS = {
    "-enc ": 40, "-encodedcommand": 40, "-windowstyle hidden": 35,
    "-w hidden": 35, "-nop": 15, "-noprofile": 10,
    "frombase64string": 40, "downloadstring": 45, "invoke-expression": 30,
    "iex(": 30, "bypass": 20, "-noninteractive": 5,
}

# Living-off-the-land binaries: legitimate Windows tools with known,
# well-documented abuse patterns (see the LOLBAS project). Only patterns
# genuinely distinctive of abuse are included on purpose - broad matches
# on normal dev/admin usage would just be noise.
LOLBINS_SUSPICIOUS_ARGS = {
    "certutil.exe": ["-urlcache", "-decode", "-decodehex", "/urlcache"],
    "mshta.exe": ["http://", "https://", "javascript:", "vbscript:"],
    "rundll32.exe": ["javascript:", ".sct", "url.dll"],
    "regsvr32.exe": ["/i:http", "scrobj.dll"],
    "bitsadmin.exe": ["/transfer", "/download"],
    "wmic.exe": ["process call create", "/node:"],
    "cscript.exe": ["http://", "https://"],
    "wscript.exe": ["http://", "https://"],
}

NORMALLY_PARENTLESS = {"system", "system idle process", "registry", "secure system"}


def score_process(proc: dict, persistence_entries: list[dict] | None = None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    exe = (proc.get("exe") or "").lower()
    name = (proc.get("name") or "").lower()
    cmdline = " ".join(proc.get("cmdline") or []).lower()
    username = proc.get("username") or ""

    if proc.get("status") == "access-denied":
        score += 10
        reasons.append("Could not inspect this process (access denied - try running elevated)")
    elif not exe:
        score += 8
        reasons.append("No executable path reported")

    for marker, weight in SUSPICIOUS_PATH_MARKERS.items():
        if marker in exe:
            score += weight
            readable = marker.strip("\\")
            reasons.append(f"Running from {readable} - not a typical install location")
            break

    if name in SYSTEM_PROCESS_HOMES and exe:
        home = SYSTEM_PROCESS_HOMES[name]
        if not exe.startswith(home):
            score += 60
            reasons.append(f"Named '{name}' but not running from {home} - likely masquerading as a system process")

    for marker, weight in OBFUSCATION_MARKERS.items():
        if marker in cmdline:
            score += weight
            reasons.append(f"Command line contains '{marker.strip()}' - commonly used to hide intent")

    for lolbin, patterns in LOLBINS_SUSPICIOUS_ARGS.items():
        if name == lolbin:
            for pattern in patterns:
                if pattern in cmdline:
                    score += 45
                    reasons.append(f"{name} invoked with a pattern commonly abused to fetch or run code ('{pattern}')")
                    break

    if proc.get("ppid") in (None, 0) and name not in NORMALLY_PARENTLESS:
        score += 10
        reasons.append("No normal parent process")

    if persistence_entries:
        for entry in persistence_entries:
            cmd = (entry.get("command") or "").lower()
            if exe and exe in cmd:
                score += 15
                reasons.append(f"Also configured to auto-start via {entry.get('source')}")
                break

    # Privilege is a multiplier, not a standalone flag - most legitimate
    # Windows services also run as SYSTEM, so treating that alone as
    # suspicious would flag half the OS. It only adds weight once
    # something else already raised a concern.
    if "system" in username.lower() and score >= 25:
        score += 15
        reasons.append(f"Running as {username} while already flagged - higher impact if this is malicious")

    return min(score, 100), reasons


def tier(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "low"
