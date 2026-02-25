# code-snipe

Code-snipe one-shots entire repos. Thats it.

We ingested famous repos and found all the bugs in like a second. Pointed it at Starlette (10K stars, the foundation under FastAPI) — 53 assert statements that silently disappear under `python -O`. Pointed it at FastAPI (82K stars) — 3 more in the hot path. About 3 seconds.

The bug predictor (the metacognitive mirror) came from me not understanding what Markov chains were. I was trying to build something else entirely and accidentally created this thing that watches how your codebase changes over time and tells you where the next bug is going to be. I cant really explain it but I can talk the smack because I know it works. We validated it on 3 major repos and it flagged the exact files where bugs were later confirmed.

Try it. Run `snipe`, then `snipe-map`, `snipe-imports` and you get a full wiring map of the whole codebase. Hone in with `snipe-hunt`.

```bash
pip install code-snipe
snipe /path/to/any/repo
```

Zero config. Zero dependencies. Pure Python stdlib.

## What you get

Run `snipe .` and you get a `.seraph/` folder with:

- **wiring_map.json** — every import relationship in your codebase, AST-parsed
- **predictions.json** — ranked list of files most likely to have the next bug
- **anomalies.json** — files that statistically don't fit the pattern
- **report.md** — human-readable summary of everything

Then use the other tools to go deeper:

```bash
snipe-map .              # Architecture map — entry points, routes, models, services
snipe-imports .          # Import analysis — dead imports, circular deps, orphans
snipe-recon .            # Full recon — code smells + import fires + env audit
snipe-hunt "pattern"     # AST-aware code search — find anything, fast
```

## Real output from a real repo

```
$ snipe ~/projects/starlette

Seraph scanning /home/user/projects/starlette...
[1/4] Scanning files...             68 files (13,930 LOC)
[2/4] Building import graph...      313 edges
[3/4] Analyzing git history...      117 commits (7 bug fixes)
[4/4] Detecting anomalies...        19 anomalies (0 critical)

Report saved to /home/user/projects/starlette/.seraph/

Top 5 Bug Predictions:
  1. templating.py                                    0.694
  2. middleware/errors.py                              0.412
  3. staticfiles.py                                   0.389
  4. responses.py                                     0.301
  5. routing.py                                       0.265
```

templating.py scored 0.694. We looked at it. There's an `assert bool(directory) ^ bool(env)` on line 91 that vanishes under `python -O` — meaning both args can be None and you get an `AttributeError` on first template access instead of a clear error. The tool called it.

## The tools

### `snipe` — The scanner

The core. Import graph + git history + Markov bug predictions + anomaly detection.

```bash
snipe .                          # Scan current repo
snipe . --json 2>/dev/null       # JSON to stdout, pipe anywhere
snipe . --top 10                 # Top 10 predictions
snipe . --days 180               # Last 6 months of history only
snipe . --threshold 3.0          # Higher bar for anomalies
```

### `snipe-map` — Architecture mapper

Walks your AST and finds every entry point, route, model, and service. FastAPI, Flask, Django, Pydantic, SQLAlchemy, dataclasses — it detects them all.

```bash
snipe-map .
snipe-map src/ --json
```

### `snipe-imports` — Import analyzer

Full import graph with problem detection: dead imports, circular dependencies, missing `__init__.py`, orphan modules, lazy imports inside functions, conditional imports behind `TYPE_CHECKING`.

```bash
snipe-imports .                  # Current directory
snipe-imports src/main.py        # Single file deep dive
snipe-imports src/auth/ src/core # Multiple folders
snipe-imports . --json           # Machine-readable
```

### `snipe-recon` — Full recon

Runs everything — code smells (naked JSON parsing, unsafe SQL, bare except, debug leftovers), import fires, and env var audits. One command, full picture.

```bash
snipe-recon .
snipe-recon . --search "session" # Search mode with blast radius
```

### `snipe-hunt` — Code search

AST-aware search. Uses ripgrep for the initial file pass, then threads through AST context extraction so you get real structural matches, not just grep hits. Falls back to pure Python if ripgrep isn't installed.

```bash
snipe-hunt "authenticate"
snipe-hunt "def.*route" --regex
snipe-hunt "session" --path src/
```

## How it actually works

**Bug predictions**: Git commits tell a story. When `routing.py` and `middleware.py` change together in a bug fix, that's a signal. Code-snipe builds a Markov transition matrix from every commit in your history — files that frequently co-change with bug fixes get higher probability scores. More history = better predictions. The math is simple. The signal is real.

**Import graph**: Full AST parsing for Python — not regex, actual `ast.parse()`. Catches lazy imports buried inside functions, conditional imports behind `if TYPE_CHECKING:`, re-exports, star imports. Regex fallback for TypeScript, Go, and Rust. The output is a directed graph of every dependency relationship in your codebase.

**Anomaly detection**: Computes statistical baselines across your codebase — file size, complexity, import fan-in, fan-out — then flags anything that deviates beyond a configurable sigma threshold. If one file is 3x the size of everything else and has twice the imports, you probably already know about it. But you might not know about the quiet ones.

## Requirements

- Python 3.10+
- `git` on PATH (for bug predictions — gracefully degrades without it)
- `rg` (ripgrep) optional, for faster code search

No pip dependencies. Pure stdlib. That's the whole point.

## Built with Claude

Human + AI. I knew what to look for, Claude knew how to build it. The bugs we found are real. The PRs we submitted are real. The rejections we got are real too — turns out FastAPIs maintainer already knew about the assert pattern and chose to keep it. Thats open source.

Everyone is using AI to write code and no ones admitting it. We are. Co-authored, co-built, no corporate beige vomit. The tool finds the bugs. The judgment call is yours.

## License

MIT
