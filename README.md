# code-snipe

Codebase intelligence toolkit. Point it at any repo, get real bugs back. Zero config, zero dependencies, 3 seconds.

```bash
pip install code-snipe
snipe /path/to/repo
```

## What it does

code-snipe scans a codebase and produces:

- **Bug predictions** — Markov chain analysis of git history predicts which files will have the next bug
- **Import graph** — AST-parsed dependency map across Python, TypeScript, Go, and Rust
- **Anomaly detection** — Statistical deviation analysis flags files that don't fit the pattern
- **Architecture map** — Auto-detects entry points, routes, models, and services

All output lands in a `.seraph/` folder: `wiring_map.json`, `predictions.json`, `anomalies.json`, `report.md`.

## Quick start

```bash
# Scan any repo
snipe .

# Scan with JSON output (pipe to other tools)
snipe . --json 2>/dev/null

# Architecture map
snipe-map .

# Import analysis (dead imports, circular deps, missing __init__.py)
snipe-imports --repo

# Full recon (code smells + import fires + env audit)
snipe-recon .

# AST-aware code search
snipe-hunt "pattern" --path src/
```

## Example output

```
$ snipe ~/projects/starlette

Seraph scanning /home/user/projects/starlette...
[1/4] Scanning files...             68 files (13,930 LOC)
[2/4] Building import graph...      313 edges
[3/4] Analyzing git history...      117 commits (7 bug fixes)
[4/4] Detecting anomalies...        19 anomalies (0 critical)

Report saved to /home/user/projects/starlette/.seraph/
  wiring_map.json        (48 KB)
  predictions.json       (2 KB)
  anomalies.json         (8 KB)
  report.md              (4 KB)

Top 5 Bug Predictions:
  1. templating.py                                    0.694
  2. middleware/errors.py                              0.412
  3. staticfiles.py                                   0.389
  4. responses.py                                     0.301
  5. routing.py                                       0.265
```

## Tools

### `snipe` / `snipe-scan` — Seraph scanner

The core tool. Analyzes import structure, git history, bug probability, and statistical anomalies.

```bash
snipe /path/to/repo              # Full scan
snipe . --json                   # JSON to stdout
snipe . --top 10                 # Top 10 predictions
snipe . --days 180               # Last 6 months of git history
snipe . --threshold 3.0          # Higher anomaly threshold (fewer results)
snipe . -o /tmp/report           # Custom output directory
```

### `snipe-map` — Cartographer

Architecture mapper. Detects FastAPI/Flask/Django entry points, routes, Pydantic/SQLAlchemy models, services, config files.

```bash
snipe-map .                      # Full architecture map
snipe-map src/ --json            # JSON output
```

### `snipe-imports` — Import Wiz

Import graph analyzer. Finds dead imports, circular dependencies, missing `__init__.py`, orphan modules, lazy imports, conditional imports.

```bash
snipe-imports .                  # Current directory
snipe-imports src/main.py        # Single file
snipe-imports src/auth/ src/core # Multiple folders
snipe-imports . --json           # JSON output
```

### `snipe-recon` — Recon

Aggregates code smells, import fires, and environment variable audits into one report.

```bash
snipe-recon .                    # Full recon
snipe-recon src/ --json          # JSON output
snipe-recon . --search "session" # Search mode with blast radius
```

### `snipe-hunt` — Lightning search

AST-aware code search. Two-pass: ripgrep file filter + threaded AST context extraction. Falls back to pure Python if ripgrep isn't installed.

```bash
snipe-hunt "authenticate"        # Search current dir
snipe-hunt "def.*route" --regex  # Regex search
snipe-hunt "session" --path src/ # Search specific path
```

## Requirements

- Python 3.10+
- `git` on PATH (for bug predictions — gracefully skipped if missing)
- `rg` (ripgrep) optional (for faster code search — falls back to Python)

No pip dependencies. Pure stdlib.

## How it works

**Bug predictions**: Builds a Markov transition matrix from git commit co-change patterns. Files that frequently change alongside bug-fix commits get higher probability scores. More git history = better predictions.

**Import graph**: Full AST parsing for Python (catches lazy imports, conditional imports, TYPE_CHECKING guards). Regex-based for TypeScript/Go/Rust. Outputs a directed graph of all import relationships.

**Anomaly detection**: Computes statistical baselines (file size, complexity, import fan-in/fan-out) and flags files that deviate beyond a configurable sigma threshold.

## License

MIT
