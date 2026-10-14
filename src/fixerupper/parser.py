"""Parse Windows Event Viewer exports (XML / JSON / CSV) into Event objects.

Untrusted input: XML is parsed with DTDs/entities rejected to prevent
entity-expansion attacks, and input size is bounded by the caller.
"""
import csv
import io
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List
import xml.etree.ElementTree as ET


class ParseError(ValueError):
    """Raised for empty or malformed input."""


@dataclass
class Event:
    event_id: int
    provider: str = ""
    level: str = "Information"
    time: str = ""
    channel: str = ""
    computer: str = ""
    message: str = ""
    data: Dict[str, str] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


LEVELS = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose", "0": "Information"}


def _norm_level(value) -> str:
    v = str(value or "").strip()
    return LEVELS.get(v, v.capitalize() if v else "Information")


def _to_int(value) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise ParseError("Invalid EventID: %r" % (value,))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(text: str) -> List[Event]:
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
        raise ParseError("XML with DOCTYPE/ENTITY declarations is not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError("Malformed XML: %s" % exc)
    nodes = [root] if _local(root.tag) == "Event" else [e for e in root.iter() if _local(e.tag) == "Event"]
    events = []
    for node in nodes:
        info = {}
        data = {}
        message = ""
        for el in node.iter():
            name = _local(el.tag)
            if name == "EventID":
                info["id"] = el.text
            elif name == "Provider":
                info["provider"] = el.get("Name", "")
            elif name == "Level":
                info["level"] = el.text
            elif name == "TimeCreated":
                info["time"] = el.get("SystemTime", "")
            elif name == "Channel":
                info["channel"] = el.text or ""
            elif name == "Computer":
                info["computer"] = el.text or ""
            elif name == "Data":
                key = el.get("Name") or "Data%d" % len(data)
                data[key] = (el.text or "").strip()
            elif name == "Message":
                message = (el.text or "").strip()
        if "id" not in info:
            raise ParseError("Event without EventID")
        events.append(Event(_to_int(info["id"]), info.get("provider", ""), _norm_level(info.get("level")),
                            info.get("time", ""), info.get("channel", ""), info.get("computer", ""), message, data))
    return events


def _from_record(rec: dict) -> Event:
    low = {str(k).strip().lower().replace(" ", ""): v for k, v in rec.items()}
    eid = low.get("eventid", low.get("id"))
    if eid in (None, ""):
        raise ParseError("Record without EventID")
    return Event(
        _to_int(eid),
        str(low.get("provider", low.get("source", "")) or ""),
        _norm_level(low.get("level", low.get("levelname", ""))),
        str(low.get("time", low.get("timecreated", low.get("date andtime", ""))) or ""),
        str(low.get("channel", low.get("logname", "")) or ""),
        str(low.get("computer", "") or ""),
        str(low.get("message", "") or ""),
    )


def _parse_json(text: str) -> List[Event]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError("Malformed JSON: %s" % exc)
    if isinstance(obj, dict):
        obj = [obj]
    if not isinstance(obj, list) or not all(isinstance(r, dict) for r in obj):
        raise ParseError("JSON must be an object or a list of objects")
    return [_from_record(r) for r in obj]


def _parse_csv(text: str) -> List[Event]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ParseError("CSV has no header row")
    return [_from_record(r) for r in reader]


def parse_events(content) -> List[Event]:
    """Parse bytes/str content, auto-detecting XML, JSON or CSV."""
    if isinstance(content, (bytes, bytearray)):
        if content[:8] == b"ElfFile\x00":
            raise ParseError("Binary .evtx files are not supported; export from Event Viewer as XML or CSV "
                             "(or run: wevtutil qe System /f:xml)")
        for enc in ("utf-8-sig", "utf-16"):
            try:
                content = content.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise ParseError("Input is not valid text")
    text = content.lstrip("\ufeff").strip()
    if not text:
        raise ParseError("Input is empty")
    if text.startswith("<"):
        events = _parse_xml(text)
    elif text[0] in "[{":
        events = _parse_json(text)
    else:
        events = _parse_csv(text)
    if not events:
        raise ParseError("No events found in input")
    return events
