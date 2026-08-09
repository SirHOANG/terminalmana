"""
baseline.py - A tiny local "have I seen this before" store, keyed by
process name, tracking known paths and file hashes. No internet, no
VirusTotal key required - this is the offline half of a reputation
system: the first time a given binary is seen it's neutral, but if the
same *name* later shows up from a *different* path or with a *different*
hash, that's real signal - legitimate apps don't usually relocate or get
silently modified.

Pairs naturally with the hash-reputation approach from OpenShield if you
want to layer an online lookup on top later.
"""

from __future__ import annotations
import hashlib
import json
import os

STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taskguard_baseline.json")


def _load() -> dict:
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save(store: dict) -> None:
    try:
        with open(STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
    except OSError:
        pass


def hash_file(path: str, chunk_size: int = 1024 * 1024) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def check_and_record(name: str, exe: str) -> tuple[int, list[str]]:
    """Returns (score, reasons). Records this sighting either way."""
    if not name or not exe:
        return 0, []

    store = _load()
    key = name.lower()
    file_hash = hash_file(exe)
    score = 0
    reasons = []

    known = store.get(key)
    if known:
        known_paths = [p.lower() for p in known.get("paths", [])]
        known_hashes = known.get("hashes", [])
        if exe.lower() not in known_paths:
            score += 25
            reasons.append(f"'{name}' seen before, but never at this path")
            known.setdefault("paths", []).append(exe)
        if file_hash and file_hash not in known_hashes:
            score += 20
            reasons.append(f"'{name}' seen before, but this exact file (hash) is new")
            known.setdefault("hashes", []).append(file_hash)
        if not reasons:
            reasons.append(f"'{name}' matches a previously seen path and hash - consistent")
    else:
        store[key] = {"paths": [exe], "hashes": [file_hash] if file_hash else []}
        reasons.append(f"First time seeing '{name}' on this machine (via this tool) - establishing baseline")

    _save(store)
    return score, reasons
