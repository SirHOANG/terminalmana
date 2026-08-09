"""
pcap_bridge.py - tshark integration for TaskGuard.

Deliberately does NOT vendor or link against Wireshark's own source
(the epan/ dissection engine you sent over) - that's a ~5 million line
C/C++ codebase with its own CMake/Qt/GLib build, and it's GPLv2, which
has real implications for anything that statically links or embeds it.
tshark.exe (Wireshark's command-line analyzer) and dumpcap.exe (its
capture engine) are separate executables specifically built to be
driven by other programs - shelling out to tshark as its own process
and reading its output is the standard, sanctioned way to build on
Wireshark's dissection engine without touching a line of its source or
its license boundary. This is how pyshark and most Wireshark-adjacent
tooling actually works.

Uses tshark's field-extraction mode (-T fields), not the full nested
-T json - the full JSON is enormous (a single bare TCP packet is 100+
lines) and mostly irrelevant here. Verified against real captured
traffic during development: HTTP Host and TLS SNI extraction both
confirmed working against synthetic-but-real packets generated and
captured in the same session. DNS query extraction uses the same,
extremely standard field name but wasn't independently re-verified the
same way - flagged here for honesty, not because there's a specific
reason to doubt it.

Requires tshark on PATH (ships with Wireshark, or installs standalone),
and - like essentially all packet capture - Administrator/elevated
privileges on Windows to actually open a capture device.
"""

from __future__ import annotations
import os
import shutil
import subprocess
import sys

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "_ws.col.Protocol", "frame.len",
    "tls.handshake.extensions_server_name", "http.host", "dns.qry.name",
]

# Wireshark's Windows installer doesn't reliably add itself to PATH -
# whether it does depends on the installer version and which options
# were ticked, and installing via a package manager in one shell
# doesn't update PATH in a shell already open elsewhere. Fall back to
# where it actually lives before giving up.
_COMMON_INSTALL_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def tshark_path() -> str | None:
    return diagnose()["found"]


def diagnose() -> dict:
    """Runs the same search tshark_path() does, but keeps a record of
    every location checked and what was found there - turns a bare
    'not found' into something you can actually act on. Use this
    directly when tshark_path() comes back None and it's not obvious
    why."""
    checks = []

    path_hit = shutil.which("tshark") or shutil.which("tshark.exe")
    checks.append({"method": "PATH", "checked": "tshark / tshark.exe via PATH", "found": path_hit})
    if path_hit:
        return {"found": path_hit, "checks": checks}

    for candidate in _COMMON_INSTALL_PATHS:
        exists = os.path.exists(candidate)
        checks.append({"method": "common install path", "checked": candidate, "found": candidate if exists else None})
        if exists:
            return {"found": candidate, "checks": checks}

    if sys.platform == "win32":
        reg_path = _tshark_path_from_registry()
        reg_exists = bool(reg_path and os.path.exists(reg_path))
        checks.append({
            "method": "registry (Uninstall keys, DisplayName contains 'Wireshark')",
            "checked": reg_path or "no matching DisplayName found in HKLM Uninstall keys",
            "found": reg_path if reg_exists else None,
        })
        if reg_exists:
            return {"found": reg_path, "checks": checks}
    else:
        checks.append({"method": "registry", "checked": "skipped - not Windows", "found": None})

    return {"found": None, "checks": checks}


def _tshark_path_from_registry() -> str | None:
    """Searches the standard Windows uninstall-info registry tree for an
    entry whose DisplayName contains 'Wireshark' and reads its
    InstallLocation - this is the same general convention essentially
    every Windows installer (including Wireshark's NSIS-based one)
    follows, so it doesn't depend on guessing a Wireshark-specific key.
    Untestable from this sandbox (no winreg on Linux) like the rest of
    the registry-reading code in this project - reasoned through
    carefully, not run."""
    if sys.platform != "win32":
        return None
    import winreg

    uninstall_roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, base in uninstall_roots:
        try:
            with winreg.OpenKey(hive, base) as root:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, subkey_name) as sub:
                            try:
                                display_name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            except FileNotFoundError:
                                continue
                            if "wireshark" not in display_name.lower():
                                continue
                            try:
                                install_dir, _ = winreg.QueryValueEx(sub, "InstallLocation")
                            except FileNotFoundError:
                                continue
                            candidate = os.path.join(install_dir, "tshark.exe")
                            if os.path.exists(candidate):
                                return candidate
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
    return None


def list_interfaces() -> list[str]:
    exe = tshark_path()
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "-D"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def capture(duration_seconds: int = 15, interface: str | None = None, bpf_filter: str | None = None) -> list[dict]:
    """Runs tshark for a fixed duration and returns one dict per packet.
    Returns an empty list (never raises) if tshark isn't found, isn't
    elevated enough to open a device, or the capture otherwise fails -
    the caller is responsible for telling the person why nothing came
    back, since this function can't distinguish "no traffic" from
    "couldn't capture" from its own return value alone."""
    exe = tshark_path()
    if not exe:
        return []

    cmd = [exe, "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|", "-E", "quote=n", "-a", f"duration:{duration_seconds}"]
    if interface:
        cmd += ["-i", interface]
    if bpf_filter:
        cmd += ["-f", bpf_filter]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_seconds + 20)
    except Exception:
        return []

    return parse_fields_output(proc.stdout)


def parse_fields_output(output: str) -> list[dict]:
    """Split out so it can be tested against a saved sample without
    needing a live capture."""
    packets = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        parts += [""] * (len(FIELDS) - len(parts))
        row = dict(zip(FIELDS, parts))
        packets.append({
            "time": row.get("frame.time_epoch") or None,
            "src": row.get("ip.src") or row.get("ipv6.src") or None,
            "dst": row.get("ip.dst") or row.get("ipv6.dst") or None,
            "sport": row.get("tcp.srcport") or row.get("udp.srcport") or None,
            "dport": row.get("tcp.dstport") or row.get("udp.dstport") or None,
            "protocol": row.get("_ws.col.Protocol") or None,
            "length": row.get("frame.len") or None,
            "tls_sni": row.get("tls.handshake.extensions_server_name") or None,
            "http_host": row.get("http.host") or None,
            "dns_query": row.get("dns.qry.name") or None,
        })
    return packets