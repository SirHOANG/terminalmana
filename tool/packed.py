"""
packed.py - Lightweight packed/obfuscated binary detection via byte
entropy. Packed, encrypted, or heavily obfuscated executables (common in
malware trying to evade static AV signatures) tend to have high-entropy
sections, because compression/encryption flattens the statistical
patterns normal code and data have. This is a coarse, well-established
first-pass heuristic - not a packer identifier (that needs signature
databases like PEiD/Detect It Easy) - so treat a high score as "worth
unpacking and looking closer at," not proof. Legitimate installers with
compressed/encrypted embedded resources can also read high.
"""

from __future__ import annotations
import math
from collections import Counter

CHUNK_SIZE = 256 * 1024  # entropy of a leading chunk is usually enough;
                          # cap the read for very large binaries


def file_entropy(path: str) -> float | None:
    try:
        with open(path, "rb") as f:
            data = f.read(CHUNK_SIZE)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if not data:
        return None
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def assess(path: str) -> tuple[int, list[str]]:
    ent = file_entropy(path)
    if ent is None:
        return 0, ["Could not read the file to check entropy (missing or access denied)"]
    score = 0
    reasons = []
    if ent >= 7.5:
        score = 35
        reasons.append(f"High file entropy ({ent:.2f}/8.0) - consistent with packing, encryption, or compression")
    elif ent >= 7.0:
        score = 15
        reasons.append(f"Elevated file entropy ({ent:.2f}/8.0) - worth a closer look")
    else:
        reasons.append(f"File entropy {ent:.2f}/8.0 - not indicative of packing")
    return score, reasons
