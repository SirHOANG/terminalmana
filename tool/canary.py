"""
canary.py - Ransomware canary files: a handful of decoy files dropped
into common user folders that a real user has no reason to touch, but
that mass file-encrypting ransomware will hit indiscriminately while
sweeping a drive. Checking their hash/existence is a fast, strong signal
that something is actively encrypting or deleting files right now -
independent of any process-level heuristic, and it catches malware
before it's even been identified as a process worth looking at.
"""

from __future__ import annotations
import hashlib
import json
import os
import time

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taskguard_canaries.json")

CANARY_CONTENT = (
    b"TaskGuard canary file - do not delete. If this file changes "
    b"unexpectedly, something is modifying files across your system.\n"
) * 20

DEFAULT_LOCATIONS_ENV = ["USERPROFILE", "APPDATA"]
DEFAULT_SUBDIRS = ["Documents", "Desktop", "Pictures", ""]
DEFAULT_NAMES = ["Invoice_2024_backup.docx", "Family_Photos_2019_backup.zip", "passwords_backup.txt"]


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deploy(names: list[str] | None = None) -> list[str]:
    """Drop canary files if they don't already exist. Returns the list of
    canary file paths now being tracked. No-ops safely if none of the
    expected Windows user-folder environment variables are set."""
    names = names or DEFAULT_NAMES
    manifest = _load_manifest()

    for env_var in DEFAULT_LOCATIONS_ENV:
        base = os.environ.get(env_var)
        if not base:
            continue
        for sub in DEFAULT_SUBDIRS:
            folder = os.path.join(base, sub) if sub else base
            if not os.path.isdir(folder):
                continue
            for name in names:
                path = os.path.join(folder, name)
                if not os.path.exists(path):
                    try:
                        with open(path, "wb") as f:
                            f.write(CANARY_CONTENT)
                    except OSError:
                        continue
                if os.path.exists(path):
                    manifest[path] = {"hash": _hash(CANARY_CONTENT), "deployed": time.strftime("%Y-%m-%d %H:%M:%S")}

    _save_manifest(manifest)
    return list(manifest.keys())


def check() -> list[dict]:
    """Compare each tracked canary against its recorded hash. Any
    mismatch or disappearance is reported."""
    manifest = _load_manifest()
    alerts = []
    for path, meta in manifest.items():
        if not os.path.exists(path):
            alerts.append({"path": path, "issue": "MISSING - file was deleted"})
            continue
        try:
            with open(path, "rb") as f:
                current = f.read()
        except OSError:
            alerts.append({"path": path, "issue": "UNREADABLE - permissions changed?"})
            continue
        if _hash(current) != meta.get("hash"):
            alerts.append({"path": path, "issue": "MODIFIED - content no longer matches"})
    return alerts


def _load_manifest() -> dict:
    if not os.path.exists(MANIFEST_PATH):
        return {}
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_manifest(manifest: dict) -> None:
    try:
        with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    except OSError:
        pass
