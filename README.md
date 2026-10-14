# fixerupper
Windows Event Viewer crash analyzer with modern UI to diagnose and explain system issues.

## Prerequisites
Python 3.9+ (no third-party runtime dependencies).

## Install
```
pip install -e .        # from a checkout
```

## Run
```
fixerupper serve [--host 127.0.0.1] [--port 8765]   # web UI
fixerupper analyze events.xml                       # JSON report on stdout
```
Settings may also come from environment variables (see `.env.example`).

## Usage walkthrough
1. In Event Viewer choose **Action → Save All Events As…** and save as XML or CSV
   (or `wevtutil qe System /f:xml > events.xml`; JSON arrays are accepted too).
2. Start `fixerupper serve`, open http://127.0.0.1:8765, choose the file, click **Analyze**.
3. Findings (BSODs, unexpected shutdowns, app crashes, service failures, disk/WHEA errors)
   are listed by severity with an explanation and suggested fix.

## Test / build
```
python -m unittest discover -s tests -v
python -m build          # needs `pip install build`; produces sdist and wheel in dist/
```

## Troubleshooting
- *"Binary .evtx files are not supported"*: export as XML/CSV first.
- *"Input is empty" / "Malformed XML"*: re-export; ensure the file is complete.
- *File too large*: raise `FIXERUPPER_MAX_BYTES` (default 20 MB).
- Port in use: pass `--port`.

## Security
Files are processed locally; the server binds to localhost by default, rejects XML with
DTD/entity declarations, and enforces an upload size limit.

## Known limitations
Native `.evtx` parsing and live log reading are not implemented.
