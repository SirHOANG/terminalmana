// EtwMonitor - real-time process start/stop visibility via ETW (Event
// Tracing for Windows), consumed through the Microsoft.Diagnostics.Tracing
// TraceEvent library.
//
// WHY THIS EXISTS: the Python side of TaskGuard can only see processes
// that are running *at the moment it polls*. Anything that starts and
// exits between refreshes - a real technique: spawn a short-lived
// helper, do something, exit before anyone looks - is invisible to
// polling, no matter how fast you poll. ETW's kernel process provider
// fires an event the instant a process starts or stops, so nothing in
// between gets missed. This is the actual, specific reason a native
// helper belongs in this project instead of trying to do it in Python:
// .NET's ETW tooling (this TraceEvent library) is mature and
// well-documented; Python doesn't have an equivalent.
//
// ================================================================
// STATUS: UNVERIFIED. This has never been compiled or run.
// ================================================================
// The sandbox this was written in has no Windows box, no .NET SDK, and
// no network path to nuget.org to even fetch the TraceEvent package for
// a build check. Every line here is written from documented API
// knowledge, not from a working build.
//
// The good news: C# is statically typed, so if a property name below
// is wrong (e.g. TraceEvent's actual field is named slightly
// differently than what's used here), `dotnet build` will fail with an
// explicit, specific compiler error - not a silent bug. That's the
// first thing to run after pulling this onto a real Windows machine:
//
//     cd etw_monitor
//     dotnet build
//
// and fix whatever it complains about. Given that, this is a
// reasonable starting point to iterate from, not a finished, trusted
// component - please don't treat its output as reliable until it's
// actually built and run once against real activity you can compare it
// to (e.g. open Notepad and confirm a process_start event for
// notepad.exe shows up).
//
// Output: one JSON object per line on stdout - simple to consume from
// anything, including etw_bridge.py on the Python side.

using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Text.Json;

class Program
{
    const string SessionName = "TaskGuardEtwSession";

    static void Main(string[] args)
    {
        bool elevated = TraceEventSession.IsElevated() ?? false;
        if (!elevated)
        {
            Console.Error.WriteLine("EtwMonitor needs to run as Administrator - ETW kernel sessions require it.");
            Environment.Exit(1);
        }

        try
        {
            RunSession();
        }
        catch (Exception ex)
        {
            // A session name must be unique system-wide. If a previous
            // run of this crashed without cleaning up, its session may
            // still be registered and EnableKernelProvider() fails.
            // Stop whatever's there and try exactly once more.
            Console.Error.WriteLine($"Session start failed ({ex.Message}). Trying to clear a stale session with the same name and retry once.");
            try
            {
                using var stale = new TraceEventSession(SessionName);
                stale.Stop();
            }
            catch
            {
                // best effort - if there was nothing to clean up, that's fine too
            }
            RunSession();
        }
    }

    static void RunSession()
    {
        using var session = new TraceEventSession(SessionName);

        Console.CancelKeyPress += (sender, eventArgs) =>
        {
            eventArgs.Cancel = true;
            session.Stop();
        };

        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

        session.Source.Kernel.ProcessStart += data => Emit(new
        {
            type = "process_start",
            time = DateTime.UtcNow.ToString("o"),
            pid = data.ProcessID,
            ppid = data.ParentID,
            name = data.ImageFileName,
            cmdline = data.CommandLine,
        });

        session.Source.Kernel.ProcessStop += data => Emit(new
        {
            type = "process_stop",
            time = DateTime.UtcNow.ToString("o"),
            pid = data.ProcessID,
            name = data.ImageFileName,
        });

        Console.Error.WriteLine("EtwMonitor running - streaming process start/stop events to stdout. Ctrl+C to stop.");
        session.Source.Process();
    }

    static void Emit(object evt)
    {
        Console.WriteLine(JsonSerializer.Serialize(evt));
        Console.Out.Flush();
    }
}
