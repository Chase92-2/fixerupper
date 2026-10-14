"""Diagnose crash-related events using a knowledge base of well-known event IDs."""
from collections import Counter
from typing import Dict, List

from .parser import Event

# (provider substring or "", event id) -> (title, explanation, suggestion, severity)
KNOWLEDGE = [
    ("Kernel-Power", 41, "Unexpected shutdown / system crash",
     "The system rebooted without cleanly shutting down (power loss, BSOD, or hang).",
     "Check PSU/power, overheating, and drivers; inspect BugcheckCode in the event data and minidumps.", "critical"),
    ("", 6008, "Previous shutdown was unexpected",
     "The prior system shutdown was not clean.", "Correlate with Kernel-Power 41 and BugCheck events.", "high"),
    ("BugCheck", 1001, "Blue Screen (BugCheck)",
     "Windows recovered from a bugcheck (BSOD).",
     "Look up the bugcheck code, update/rollback drivers, run `sfc /scannow` and memory diagnostics.", "critical"),
    ("Application Error", 1000, "Application crash",
     "An application terminated due to an unhandled exception.",
     "Note the faulting module; update or reinstall the application and the module's owner.", "high"),
    ("Application Hang", 1002, "Application hang",
     "An application stopped responding.", "Check for updates, third-party shell extensions, or disk stalls.", "medium"),
    ("Windows Error Reporting", 1001, "Windows Error Reporting crash report",
     "A fault bucket was reported for a crashed program.", "Review the report details for the faulting module.", "medium"),
    ("Service Control Manager", 7034, "Service terminated unexpectedly",
     "A service crashed.", "Check the service's recovery options and its own logs.", "high"),
    ("Service Control Manager", 7031, "Service terminated unexpectedly (restart action)",
     "A service crashed and a recovery action was taken.", "Investigate why the service exits.", "medium"),
    ("Service Control Manager", 7000, "Service failed to start",
     "A service did not start.", "Check dependencies and service account permissions.", "medium"),
    ("Disk", 7, "Bad block on disk", "The disk reported a bad block.",
     "Back up data and run `chkdsk /r`; check SMART health.", "critical"),
    ("Disk", 11, "Disk controller error", "The driver detected a controller error.",
     "Check cables/controller and storage drivers.", "high"),
    ("Ntfs", 55, "File system corruption", "NTFS found corruption on a volume.", "Run `chkdsk /f`.", "high"),
    ("WHEA-Logger", 18, "Fatal hardware error (WHEA)", "A fatal hardware error was reported by the CPU/platform.",
     "Check CPU temperature, overclocking, RAM and firmware.", "critical"),
    ("WHEA-Logger", 17, "Corrected hardware error (WHEA)", "A recoverable hardware error occurred.",
     "Monitor; frequent occurrences indicate failing hardware.", "medium"),
    ("Display", 4101, "Display driver stopped responding", "The GPU driver timed out and recovered.",
     "Update/clean-install the GPU driver; check GPU temperature.", "medium"),
    ("volmgr", 161, "Dump file creation failed", "Crash dump could not be written.",
     "Verify page file settings and free disk space.", "medium"),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _lookup(ev: Event):
    generic = None
    for prov, eid, title, expl, fix, sev in KNOWLEDGE:
        if eid != ev.event_id:
            continue
        if prov and prov.lower() in ev.provider.lower():
            return (prov, title, expl, fix, sev)
        if not prov and generic is None:
            generic = (prov, title, expl, fix, sev)
    return generic


def analyze(events: List[Event]) -> Dict:
    findings = []
    for ev in events:
        hit = _lookup(ev)
        if hit:
            _, title, expl, fix, sev = hit
            findings.append({"title": title, "explanation": expl, "suggestion": fix, "severity": sev,
                             "event_id": ev.event_id, "provider": ev.provider, "time": ev.time,
                             "details": ev.data})
        elif ev.level in ("Critical", "Error"):
            findings.append({"title": "Unrecognized %s event" % ev.level.lower(),
                             "explanation": ev.message or "No message available.",
                             "suggestion": "Search the provider and event ID in Microsoft documentation.",
                             "severity": "high" if ev.level == "Critical" else "low",
                             "event_id": ev.event_id, "provider": ev.provider, "time": ev.time,
                             "details": ev.data})
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["time"]))
    return {
        "total_events": len(events),
        "by_level": dict(Counter(e.level for e in events)),
        "by_provider": dict(Counter(e.provider for e in events).most_common(10)),
        "finding_count": len(findings),
        "findings": findings,
    }
