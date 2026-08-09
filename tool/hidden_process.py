"""
hidden_process.py - Cross-view process enumeration: compare what psutil
sees against what tasklist.exe reports. Different code paths under the
hood mean a PID visible to one but invisible to the other is worth a
look - but be honest about what this catches: naive, user-mode-only
hiding tricks. It will NOT catch a genuine kernel-level DKOM rootkit
that's unlinked itself from the process list both of these are
ultimately reading from - that class of hiding is invisible to every
user-mode enumeration method equally. Real detection of that needs
kernel-level tooling (see the README's note on why that's out of scope
here). This is a real, legitimate check; just not a silver bullet.
"""

from __future__ import annotations
import csv
import io
import subprocess

import psutil


def tasklist_pids() -> set[int]:
    try:
        proc = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return set()
    except Exception:
        return set()
    return _parse_tasklist_csv(proc.stdout)


def _parse_tasklist_csv(output: str) -> set[int]:
    """Parses positionally (column index 1 = PID), not by header name -
    tasklist's headers are localized on non-English Windows, but the
    column order is not."""
    pids = set()
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 2:
            continue
        try:
            pids.add(int(row[1]))
        except ValueError:
            continue
    return pids


def psutil_pids() -> set[int]:
    return set(psutil.pids())


def find_discrepancies() -> dict:
    """Returns which PIDs each method saw that the other didn't."""
    tl = tasklist_pids()
    ps = psutil_pids()
    if not tl:
        return {"visible_to_psutil_only": [], "visible_to_tasklist_only": [], "note": "tasklist.exe unavailable or returned nothing"}
    return {
        "visible_to_psutil_only": sorted(ps - tl),
        "visible_to_tasklist_only": sorted(tl - ps),
        "note": None,
    }
