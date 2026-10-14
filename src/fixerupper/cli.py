import argparse
import json
import sys

from . import __version__
from .analyzer import analyze
from .parser import ParseError, parse_events
from .server import serve


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fixerupper", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("analyze", help="analyze an exported log file and print JSON")
    a.add_argument("file")
    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        try:
            with open(args.file, "rb") as fh:
                print(json.dumps(analyze(parse_events(fh.read())), indent=2))
        except (OSError, ParseError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        return 0
    serve(getattr(args, "host", None), getattr(args, "port", None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
