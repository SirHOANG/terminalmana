"""
signature.py - Authenticode signature verification, on demand.

Shells out to PowerShell's Get-AuthenticodeSignature rather than calling
WinVerifyTrust directly via ctypes - the ctypes struct layout for trust
verification is easy to get subtly wrong and hard to unit test without a
live Windows box, while Get-AuthenticodeSignature is a stable, well
documented cmdlet. The trade-off is spawning powershell.exe, which takes
a second or two - fine for checking one flagged process on demand, too
slow to run against every process on every refresh.
"""

from __future__ import annotations
import json
import subprocess


def check_signature(path: str) -> dict:
    """Returns {"status": ..., "signer": ...} for a single file path."""
    if not path:
        return {"status": "unknown", "signer": None}

    escaped = path.replace('"', '`"')
    ps_script = (
        f'$sig = Get-AuthenticodeSignature -FilePath "{escaped}" -ErrorAction SilentlyContinue; '
        '[PSCustomObject]@{ Status=$sig.Status.ToString(); '
        'Signer=($sig.SignerCertificate.Subject) } | ConvertTo-Json -Compress'
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {"status": "unknown", "signer": None}
        data = json.loads(proc.stdout)
        return {"status": data.get("Status", "unknown"), "signer": data.get("Signer")}
    except Exception:
        return {"status": "unknown", "signer": None}
