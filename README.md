# Terminalmana

**A terminal-based process monitor and malware triage tool for Windows**

Terminalmana is a lightweight, interactive command-line alternative to Windows Task Manager, built specifically for manual malware analysis and triage.  

Many modern malware families detect the presence of `taskmgr.exe` (by process name or window title) and immediately hide processes, terminate themselves, or change behavior. Terminalmana avoids that detection surface by running entirely in the terminal.

> **Windows only.**  
> Run your terminal **as Administrator**. Without elevated privileges, many processes, services, and HKLM registry keys will be invisible or unkillable.
> AND MAKE SURE INSTALL THE WIRESHARK AND NCAP FIRST BEFORE USE THIS TOOL

---

## Why Terminalmana?

- Stealthier than Task Manager against malware that watches for `taskmgr.exe`
- Rich suspicion scoring based on real attacker behaviors (not just signatures)
- Deep persistence enumeration
- On-demand deep inspection (signatures, network, modules, packing, baseline)
- Network correlation using real packet data via tshark
- Canary files for ransomware detection
- Audit logging of every scan and action
- Process tree view, kill, and suspend with safety warnings

---

## Requirements

- **Windows** (primary target)
- Python 3.10+
- Administrator privileges (strongly recommended)
- **Wireshark + Npcap** (required for network capture / `pcap` commands)
- Optional: .NET SDK (only if you want to build the experimental ETW monitor)

---

## Quick Start

```bash
cd tool
pip install -r requirements.txt
python main.py
