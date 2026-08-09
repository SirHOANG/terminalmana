"""
actions.py - Taking action on a process once you've decided it's bad.
Every action gets written to audit.py's log automatically.
"""

from __future__ import annotations
import psutil

import audit


def kill_process(pid: int) -> tuple[bool, str]:
    """Terminate a process by PID.

    On Windows, psutil's terminate() and kill() both map to the same
    TerminateProcess() call - there's no SIGTERM/SIGKILL distinction like
    on Unix, so this always asks for an immediate, non-negotiable stop."""
    name, exe = None, None
    try:
        info_proc = psutil.Process(pid)
        name = info_proc.name()
        exe = info_proc.exe()
    except Exception:
        pass

    try:
        proc = psutil.Process(pid)
        proc.kill()
        proc.wait(timeout=3)
        audit.log_event("kill", {"pid": pid, "name": name, "exe": exe, "success": True})
        return True, f"Killed PID {pid} ({name})"
    except psutil.NoSuchProcess:
        audit.log_event("kill", {"pid": pid, "name": name, "exe": exe, "success": False, "reason": "no such process"})
        return False, f"PID {pid} no longer exists"
    except psutil.AccessDenied:
        audit.log_event("kill", {"pid": pid, "name": name, "exe": exe, "success": False, "reason": "access denied"})
        return False, f"Access denied killing PID {pid} - re-run this tool as Administrator"
    except psutil.TimeoutExpired:
        audit.log_event("kill", {"pid": pid, "name": name, "exe": exe, "success": False, "reason": "timeout"})
        return False, f"PID {pid} did not exit within the timeout"
    except Exception as e:
        audit.log_event("kill", {"pid": pid, "name": name, "exe": exe, "success": False, "reason": str(e)})
        return False, f"Unexpected error killing PID {pid}: {e}"


def suspend_process(pid: int) -> tuple[bool, str]:
    """Freeze a process without killing it - useful when you want to stop
    it acting (encrypting files, phoning home) but keep it around for
    further inspection instead of destroying the evidence outright."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.suspend()
        audit.log_event("suspend", {"pid": pid, "name": name, "success": True})
        return True, f"Suspended PID {pid} ({name})"
    except psutil.NoSuchProcess:
        return False, f"PID {pid} no longer exists"
    except psutil.AccessDenied:
        return False, f"Access denied suspending PID {pid} - re-run this tool as Administrator"
    except Exception as e:
        return False, f"Unexpected error suspending PID {pid}: {e}"
