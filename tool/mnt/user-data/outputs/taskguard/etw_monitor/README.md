# EtwMonitor

Real-time process start/stop visibility for TaskGuard, via ETW (Event
Tracing for Windows) instead of polling. Optional - TaskGuard's Python
side works completely fine without this.

## Status: unverified, untested, needs a real build

This was written in a Linux sandbox with no .NET SDK and no network
access to nuget.org - it has never been compiled, let alone run. See
the header comment in `Program.cs` for the full explanation and why
that's a smaller risk here than it sounds (C# fails loud at compile
time on a wrong API call, not silent at runtime).

## Building it

Requires the .NET 8 SDK on Windows.

```
cd etw_monitor
dotnet build -c Release
```

If it doesn't compile: the errors will point at whatever TraceEvent API
call doesn't match this version of the library - fix the property/method
name it's complaining about and rebuild. This is genuinely the expected
first step, not a sign something's badly wrong.

Once it builds, run it **as Administrator** (ETW kernel sessions require
elevation) in its own terminal:

```
bin\Release\net8.0\EtwMonitor.exe
```

It should print a line to stderr saying it's running, then start
printing one JSON line per process start/stop event to stdout as things
happen on the system. Open Notepad in another window and confirm a
`process_start` event for `notepad.exe` shows up - that's the sanity
check that it's actually working before trusting it for anything else.

## Wiring it into TaskGuard

From the main `taskguard` tool, `etw start` will look for the built
`EtwMonitor.exe` next to `etw_monitor/` and, if found, launch it and
stream its events into the audit log automatically. `etw stop` ends it.
If it's not built yet, `etw start` says so rather than failing silently.

## What it doesn't do yet

Only process start/stop for now. Network connection events and image
(DLL) load events are natural next additions once this base version is
confirmed working - both need TraceEvent APIs this was intentionally
kept away from initially, to keep the first real build-and-test cycle
as small as possible.
