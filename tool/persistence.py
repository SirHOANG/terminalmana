"""
persistence.py - Enumerate the places malware commonly uses to survive
a reboot, logon, or re-launch itself after being killed. This is the
"how did it run" half of the picture - scanner.py shows what's running
right now, this shows what's *configured* to run.

Covers: Registry Run/RunOnce keys, Startup folders, Windows Services,
Scheduled Tasks, Image File Execution Options (debugger hijacking), the
Winlogon Shell/Userinit values, AppInit_DLLs, Active Setup StubPaths,
and the HKCU Windows\\Load value.
"""

from __future__ import annotations
import os
import json
import subprocess
import winreg

import psutil

RUN_KEYS = [
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
APPINIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
ACTIVE_SETUP_KEY = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
LOAD_KEY_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"


def scan_run_keys() -> list[dict]:
    results = []
    for label, hive, subkey in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    results.append({"source": f"{label}\\{subkey}", "name": name, "command": value})
                    i += 1
        except FileNotFoundError:
            continue
    return results


def scan_startup_folders() -> list[dict]:
    folders = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    if appdata:
        folders.append(("User Startup", os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))
    if programdata:
        folders.append(("All Users Startup", os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup")))

    results = []
    for label, folder in folders:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                results.append({"source": label, "name": fname, "command": os.path.join(folder, fname)})
    return results


def scan_services() -> list[dict]:
    results = []
    for svc in psutil.win_service_iter():
        try:
            d = svc.as_dict()
        except Exception:
            continue
        results.append({
            "source": "Service",
            "name": d.get("name"),
            "command": d.get("binpath"),
            "status": d.get("status"),
            "pid": d.get("pid"),
        })
    return results


def scan_scheduled_tasks() -> list[dict]:
    """Uses PowerShell's Get-ScheduledTask instead of schtasks.exe.
    schtasks' CSV column headers are localized on non-English Windows
    installs, which silently breaks name-based parsing. PowerShell object
    properties (TaskName, State, Actions...) are not localized."""
    results = []
    ps_script = (
        "Get-ScheduledTask | ForEach-Object { "
        "$acts = ($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join '; '; "
        "[PSCustomObject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; "
        "State=$_.State.ToString(); Actions=$acts } "
        "} | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return results
        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        for row in data:
            action = (row.get("Actions") or "").strip()
            if not action:
                continue
            results.append({
                "source": "Scheduled Task",
                "name": f"{row.get('TaskPath', '')}{row.get('TaskName', '')}",
                "command": action,
                "status": row.get("State"),
            })
    except Exception:
        pass
    return results


def scan_ifeo() -> list[dict]:
    """A 'Debugger' value here means Windows launches that program instead
    of the real target every time the target tries to run - a classic
    hijack (e.g. attaching to sethc.exe / Sticky Keys)."""
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY) as key:
            i = 0
            while True:
                try:
                    target = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, target) as sub:
                        try:
                            debugger, _ = winreg.QueryValueEx(sub, "Debugger")
                            results.append({"source": "IFEO Debugger hijack", "name": target, "command": debugger})
                        except FileNotFoundError:
                            pass
                except OSError:
                    pass
    except FileNotFoundError:
        pass
    return results


def scan_winlogon() -> list[dict]:
    """Shell should be explorer.exe, Userinit should point at userinit.exe.
    Anything else means something inserts itself into every logon."""
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY) as key:
            for value_name in ("Shell", "Userinit"):
                try:
                    value, _ = winreg.QueryValueEx(key, value_name)
                except FileNotFoundError:
                    continue
                results.append({"source": "Winlogon", "name": value_name, "command": value})
    except FileNotFoundError:
        pass
    return results


def scan_appinit_dlls() -> list[dict]:
    """DLLs listed here load into every process that loads user32.dll -
    a classic (if rarer on modern Windows, since it needs a policy bit
    set) injection technique."""
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, APPINIT_KEY) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
            except FileNotFoundError:
                value = None
            if value and str(value).strip():
                results.append({"source": "AppInit_DLLs", "name": "AppInit_DLLs", "command": value})
    except FileNotFoundError:
        pass
    return results


def scan_active_setup() -> list[dict]:
    """Active Setup StubPath commands run once per user, the first time
    that user logs on after a component's Version value changes - a
    real, if lesser-known, persistence spot."""
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ACTIVE_SETUP_KEY) as key:
            i = 0
            while True:
                try:
                    component = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, component) as sub:
                        try:
                            stub, _ = winreg.QueryValueEx(sub, "StubPath")
                        except FileNotFoundError:
                            continue
                        results.append({"source": "Active Setup", "name": component, "command": stub})
                except OSError:
                    continue
    except FileNotFoundError:
        pass
    return results


def scan_shell_load() -> list[dict]:
    """HKCU ...\\Windows 'Load' value - an older, less common, but still
    real per-user autostart, separate from the standard Run keys."""
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, LOAD_KEY_PATH) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "Load")
            except FileNotFoundError:
                value = None
            if value and str(value).strip():
                results.append({"source": "HKCU Windows\\Load", "name": "Load", "command": value})
    except FileNotFoundError:
        pass
    return results


def scan_all() -> list[dict]:
    """Run every persistence check and return one flat list."""
    entries = []
    entries += scan_run_keys()
    entries += scan_startup_folders()
    entries += scan_services()
    entries += scan_scheduled_tasks()
    entries += scan_ifeo()
    entries += scan_winlogon()
    entries += scan_appinit_dlls()
    entries += scan_active_setup()
    entries += scan_shell_load()
    return entries
