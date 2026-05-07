# Contributing

Thanks for helping make AI coding agents safer.

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest
```

On macOS or Linux:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

## Good First Contributions

- Add focused detection fixtures in `examples/`.
- Add tests for false positives and false negatives.
- Improve agent integration docs for a specific IDE or agent host.
- Add narrowly scoped detection rules with clear evidence and recommendations.

## Rule Quality Bar

Every new detection rule should answer:

- What risky agent behavior does this catch?
- Where does it appear: chat, tool output, shell command, file path, or MCP config?
- What is the recommended control?
- What test proves it catches the risky case?
- What test or example helps avoid noisy false positives?

## Security Reports

Please read `SECURITY.md` before sharing vulnerability details.
