# Contributing

1. `python -m venv .venv && . .venv/bin/activate` (Windows: `.venv\Scripts\activate`)
2. `pip install -e .`
3. Run tests: `python -m unittest discover -s tests -v`
4. Add event knowledge in `src/fixerupper/analyzer.py` (`KNOWLEDGE`) with a test.
5. Build a distributable: `pip install build && python -m build`.

Never commit real logs containing personal data or secrets; use `.env.example` for config templates.
