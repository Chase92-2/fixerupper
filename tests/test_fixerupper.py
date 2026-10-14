import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from fixerupper.analyzer import analyze
from fixerupper.parser import ParseError, parse_events
from fixerupper.server import make_handler

XML = """<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID><Level>1</Level>
<TimeCreated SystemTime="2024-01-01T00:00:00Z"/><Channel>System</Channel><Computer>PC</Computer></System>
<EventData><Data Name="BugcheckCode">159</Data></EventData></Event></Events>"""


class ParserTests(unittest.TestCase):
    def test_xml(self):
        ev = parse_events(XML.encode())[0]
        self.assertEqual((ev.event_id, ev.level, ev.data["BugcheckCode"]), (41, "Critical", "159"))

    def test_csv_and_json(self):
        c = parse_events("Level,Source,Event ID\nError,Application Error,1000\n")
        self.assertEqual(c[0].event_id, 1000)
        j = parse_events(json.dumps([{"EventID": 7034, "Provider": "Service Control Manager"}]))
        self.assertEqual(j[0].event_id, 7034)

    def test_bad_inputs(self):
        for bad in ["", "   ", "<a><b>", "{bad", "<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>",
                    b"ElfFile\x00abc", b"\xff\xfe\x00", "[1,2]", "<Event><System/></Event>"]:
            with self.assertRaises(ParseError, msg=repr(bad)):
                parse_events(bad)


class AnalyzerTests(unittest.TestCase):
    def test_findings(self):
        r = analyze(parse_events(XML))
        self.assertEqual(r["finding_count"], 1)
        self.assertEqual(r["findings"][0]["severity"], "critical")

    def test_unknown_error_event(self):
        r = analyze(parse_events("Level,Provider,EventID\nError,Foo,99999\nInformation,Foo,1\n"))
        self.assertEqual(r["finding_count"], 1)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(1000))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, data):
        req = urllib.request.Request(self.base + "/api/analyze", data=data, method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_api(self):
        self.assertEqual(self.post(XML.encode())[0], 200)
        self.assertEqual(self.post(b"")[0], 400)
        self.assertEqual(self.post(b"x" * 2000)[0], 413)

    def test_index(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn(b"FixerUpper", r.read())


if __name__ == "__main__":
    unittest.main()
