"""
anomaly.py — Baseline computation and deviation detection.

For each directory in a repository, computes baselines for file metrics
(LOC, import count, function count, complexity) and flags files that
deviate significantly from their directory peers.

No external dependencies. Pure stdlib (ast, pathlib, statistics, subprocess,
dataclasses, math, re, collections).
"""

from __future__ import annotations

import ast
import math
import os
import re
import statistics
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directory names to skip during traversal (mirrors scanner.py)
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        "dist",
        "build",
        ".eggs",
        ".seraph",
        ".svelte-kit",
        ".next",
        ".nuxt",
        ".turbo",
        ".ruff_cache",
        ".pytest_cache",
        "coverage",
        ".coverage",
        "target",
    }
)

SKIP_DIR_SUFFIXES: tuple[str, ...] = (".egg-info",)

# Only analyze actual source code files — not docs, data, or generated artifacts.
# Files with extensions NOT in this set are silently skipped.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Python
        ".py", ".pyi",
        # TypeScript / JavaScript
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
        # Svelte / Vue
        ".svelte", ".vue",
        # Systems
        ".go", ".rs", ".java", ".rb", ".cs",
        # C/C++
        ".c", ".cpp", ".h", ".hpp", ".cc", ".cxx",
        # Shell
        ".sh", ".bash", ".zsh",
    }
)

# File size limit — skip files larger than 2 MB
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024

# Minimum files in a directory to compute its own baseline;
# smaller directories are merged into their parent.
MIN_FILES_FOR_BASELINE: int = 3

# Absolute thresholds for "god file" detection (not statistical)
GOD_FILE_MIN_LOC: int = 500
GOD_FILE_MIN_FUNCTIONS: int = 20
GOD_FILE_MIN_IMPORTS: int = 15

# Severity bands (number of standard deviations)
SEVERITY_CRITICAL: float = 4.0
SEVERITY_WARNING: float = 3.0
# Everything >= threshold (default 2.0) is at least "info"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DirectoryBaseline:
    """Per-directory aggregate metrics over all files in that directory."""

    directory: str
    file_count: int
    mean_loc: float
    stddev_loc: float
    mean_imports: float
    stddev_imports: float
    mean_functions: float
    stddev_functions: float
    mean_complexity: float
    stddev_complexity: float


@dataclass
class Anomaly:
    """A single anomalous file metric."""

    path: str
    anomaly_type: str  # "oversized" | "high_complexity" | "import_heavy" | "high_churn" | "god_file"
    value: float
    baseline_mean: float
    baseline_stddev: float
    deviation: float  # signed σ from mean
    severity: str  # "critical" | "warning" | "info"
    description: str


@dataclass
class AnomalyReport:
    """Full anomaly scan result."""

    anomalies: list[Anomaly]
    baselines: dict[str, DirectoryBaseline]
    total_files_scanned: int
    total_anomalies: int


# ---------------------------------------------------------------------------
# Internal file-metric dataclass
# ---------------------------------------------------------------------------


@dataclass
class _FileMetrics:
    path: str          # relative to repo root
    directory: str     # immediate parent directory (relative to root)
    loc: int
    import_count: int
    function_count: int
    class_count: int
    complexity: float  # max nesting depth proxy
    churn: int = 0     # git commit count in last 90 days


# ---------------------------------------------------------------------------
# Python metric extraction (ast-based)
# ---------------------------------------------------------------------------


class _NestingDepthVisitor(ast.NodeVisitor):
    """
    Walks the AST and tracks the maximum nesting depth of control-flow nodes
    (if / for / while / with / try) inside function bodies.
    """

    CONTROL_FLOW_NODES = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.ExceptHandler,
    )

    def __init__(self) -> None:
        self._depth: int = 0
        self.max_depth: int = 0
        self._in_function: bool = False

    def _enter_control(self) -> None:
        if self._in_function:
            self._depth += 1
            if self._depth > self.max_depth:
                self.max_depth = self._depth

    def _leave_control(self) -> None:
        if self._in_function:
            self._depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        was_in_function = self._in_function
        self._in_function = True
        self.generic_visit(node)
        self._in_function = was_in_function

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_If(self, node: ast.If) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()

    def visit_For(self, node: ast.For) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_While(self, node: ast.While) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()

    def visit_With(self, node: ast.With) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_Try(self, node: ast.Try) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._enter_control()
        self.generic_visit(node)
        self._leave_control()


def _metrics_python(source: str) -> tuple[int, int, int, int, float]:
    """
    Parse a Python source string and return:
        (loc, import_count, function_count, class_count, max_nesting_depth)
    Returns (0, 0, 0, 0, 0.0) on parse error.
    """
    # LOC: non-empty, non-comment lines
    loc = sum(
        1
        for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return loc, 0, 0, 0, 0.0

    import_count = 0
    function_count = 0
    class_count = 0

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_count += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_count += 1
        elif isinstance(node, ast.ClassDef):
            class_count += 1

    visitor = _NestingDepthVisitor()
    visitor.visit(tree)

    return loc, import_count, function_count, class_count, float(visitor.max_depth)


# ---------------------------------------------------------------------------
# TypeScript / JavaScript metric extraction (regex-based)
# ---------------------------------------------------------------------------

_TS_IMPORT_RE = re.compile(r"\bimport\b|\brequire\s*\(")
_TS_FUNC_RE = re.compile(
    r"\bfunction\s+\w+|\basync\s+function\b|=>\s*\{|\b\w+\s*\([^)]*\)\s*\{"
)
_TS_CLASS_RE = re.compile(r"\bclass\s+\w+")
_TS_OPEN_BRACE_RE = re.compile(r"\{")
_TS_CLOSE_BRACE_RE = re.compile(r"\}")


def _metrics_ts_js(source: str) -> tuple[int, int, int, int, float]:
    """
    Analyse TypeScript/JavaScript source via regex and return:
        (loc, import_count, function_count, class_count, max_nesting_depth)
    """
    lines = source.splitlines()
    loc = sum(1 for line in lines if line.strip())
    import_count = sum(1 for line in lines if _TS_IMPORT_RE.search(line))
    function_count = sum(1 for line in lines if _TS_FUNC_RE.search(line))
    class_count = sum(1 for line in lines if _TS_CLASS_RE.search(line))

    # Rough nesting depth via brace counting
    depth = 0
    max_depth = 0
    for ch in source:
        if ch == "{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == "}":
            depth = max(0, depth - 1)

    return loc, import_count, function_count, class_count, float(max_depth)


# ---------------------------------------------------------------------------
# Generic metric extraction (LOC only)
# ---------------------------------------------------------------------------


def _metrics_generic(source: str) -> tuple[int, int, int, int, float]:
    loc = sum(1 for line in source.splitlines() if line.strip())
    return loc, 0, 0, 0, 0.0


# ---------------------------------------------------------------------------
# File dispatch
# ---------------------------------------------------------------------------

_PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py", ".pyi"})
_TS_JS_EXTENSIONS: frozenset[str] = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


def _extract_metrics(file_path: Path, rel_path: str, dir_key: str) -> _FileMetrics | None:
    """
    Read *file_path* and compute its metrics.
    Returns None if the file cannot be read, is too large, or is not source code.
    """
    # Only analyze source code files — skip docs, data, configs, images
    suffix = file_path.suffix.lower()
    if suffix not in SOURCE_EXTENSIONS:
        return None

    try:
        size = file_path.stat().st_size
    except OSError:
        return None

    if size > MAX_FILE_SIZE_BYTES:
        return None

    # Quick binary check
    try:
        with file_path.open("rb") as fh:
            chunk = fh.read(8192)
        if b"\x00" in chunk:
            return None
    except OSError:
        return None

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    suffix = file_path.suffix.lower()

    if suffix in _PYTHON_EXTENSIONS:
        loc, imports, funcs, classes, complexity = _metrics_python(source)
    elif suffix in _TS_JS_EXTENSIONS:
        loc, imports, funcs, classes, complexity = _metrics_ts_js(source)
    else:
        loc, imports, funcs, classes, complexity = _metrics_generic(source)

    return _FileMetrics(
        path=rel_path,
        directory=dir_key,
        loc=loc,
        import_count=imports,
        function_count=funcs,
        class_count=classes,
        complexity=complexity,
    )


# ---------------------------------------------------------------------------
# Git churn
# ---------------------------------------------------------------------------


def _collect_churn(repo_path: Path) -> dict[str, int]:
    """
    Run `git log --since="90 days ago" --format="" --name-only --no-merges`
    and count how many commits touched each file in the last 90 days.

    Returns an empty dict if git is unavailable or the directory is not a repo.
    """
    churn: dict[str, int] = defaultdict(int)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "log",
                '--since=90 days ago',
                "--format=",
                "--name-only",
                "--no-merges",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {}

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped:
                churn[stripped] += 1

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {}

    return dict(churn)


# ---------------------------------------------------------------------------
# Baseline computation
# ---------------------------------------------------------------------------


def _should_skip_dir(dirname: str) -> bool:
    if dirname in SKIP_DIRS:
        return True
    return any(dirname.endswith(s) for s in SKIP_DIR_SUFFIXES)


def _discover_files(repo_path: Path) -> list[_FileMetrics]:
    """Walk the repo and collect metrics for all recognised source files."""
    metrics: list[_FileMetrics] = []

    for dirpath_str, dirnames, filenames in os.walk(repo_path):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        dirpath = Path(dirpath_str)
        try:
            dir_rel = str(dirpath.relative_to(repo_path))
        except ValueError:
            dir_rel = "."

        for filename in filenames:
            file_path = dirpath / filename
            try:
                rel_path = str(file_path.relative_to(repo_path))
            except ValueError:
                continue

            fm = _extract_metrics(file_path, rel_path, dir_rel)
            if fm is not None and fm.loc > 0:
                metrics.append(fm)

    return metrics


def _merge_into_parent(dir_key: str) -> str:
    """Return the parent directory key, or '.' if already at root."""
    p = Path(dir_key)
    parent = str(p.parent)
    return parent if parent != dir_key else "."


def _compute_baselines(
    metrics: list[_FileMetrics],
) -> dict[str, DirectoryBaseline]:
    """
    Group files by directory, merge small directories into their parent,
    then compute mean/stddev for each metric.
    """
    # Group by immediate directory
    dir_to_metrics: dict[str, list[_FileMetrics]] = defaultdict(list)
    for fm in metrics:
        dir_to_metrics[fm.directory].append(fm)

    # Merge small directories into parent — repeat until stable
    changed = True
    while changed:
        changed = False
        for dir_key in list(dir_to_metrics.keys()):
            if len(dir_to_metrics[dir_key]) < MIN_FILES_FOR_BASELINE:
                parent = _merge_into_parent(dir_key)
                if parent != dir_key:
                    for fm in dir_to_metrics[dir_key]:
                        fm.directory = parent
                    dir_to_metrics[parent].extend(dir_to_metrics.pop(dir_key))
                    changed = True
                    break  # restart iteration — dict changed

    # Compute stats
    baselines: dict[str, DirectoryBaseline] = {}
    for dir_key, file_metrics in dir_to_metrics.items():
        if not file_metrics:
            continue

        locs = [fm.loc for fm in file_metrics]
        imports = [fm.import_count for fm in file_metrics]
        funcs = [fm.function_count for fm in file_metrics]
        complexities = [fm.complexity for fm in file_metrics]

        def _mean(vals: list) -> float:
            return statistics.mean(vals) if vals else 0.0

        def _stdev(vals: list) -> float:
            return statistics.pstdev(vals) if len(vals) > 1 else 0.0

        baselines[dir_key] = DirectoryBaseline(
            directory=dir_key,
            file_count=len(file_metrics),
            mean_loc=_mean(locs),
            stddev_loc=_stdev(locs),
            mean_imports=_mean(imports),
            stddev_imports=_stdev(imports),
            mean_functions=_mean(funcs),
            stddev_functions=_stdev(funcs),
            mean_complexity=_mean(complexities),
            stddev_complexity=_stdev(complexities),
        )

    return baselines


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def _severity(deviation: float) -> str:
    if deviation >= SEVERITY_CRITICAL:
        return "critical"
    if deviation >= SEVERITY_WARNING:
        return "warning"
    return "info"


def _deviation(value: float, mean: float, stddev: float) -> float:
    """Signed standard deviations from the mean. Returns 0 if stddev is 0."""
    if stddev == 0.0:
        return 0.0
    return (value - mean) / stddev


def _filename(path: str) -> str:
    return Path(path).name


def _detect_statistical_anomalies(
    metrics: list[_FileMetrics],
    baselines: dict[str, DirectoryBaseline],
    threshold: float,
) -> list[Anomaly]:
    """Flag files whose metrics exceed *threshold* σ above their directory mean."""
    anomalies: list[Anomaly] = []

    for fm in metrics:
        bl = baselines.get(fm.directory)
        if bl is None:
            continue

        fname = _filename(fm.path)

        # --- oversized (LOC) ---
        if bl.stddev_loc > 0:
            dev = _deviation(fm.loc, bl.mean_loc, bl.stddev_loc)
            if dev >= threshold:
                anomalies.append(
                    Anomaly(
                        path=fm.path,
                        anomaly_type="oversized",
                        value=float(fm.loc),
                        baseline_mean=bl.mean_loc,
                        baseline_stddev=bl.stddev_loc,
                        deviation=dev,
                        severity=_severity(dev),
                        description=(
                            f"{fname} is {fm.loc:,} LOC — "
                            f"{dev:.1f}\u03c3 above directory mean of "
                            f"{bl.mean_loc:.0f} LOC"
                        ),
                    )
                )

        # --- high_complexity (nesting depth) ---
        if bl.stddev_complexity > 0 and fm.complexity > 0:
            dev = _deviation(fm.complexity, bl.mean_complexity, bl.stddev_complexity)
            if dev >= threshold:
                anomalies.append(
                    Anomaly(
                        path=fm.path,
                        anomaly_type="high_complexity",
                        value=fm.complexity,
                        baseline_mean=bl.mean_complexity,
                        baseline_stddev=bl.stddev_complexity,
                        deviation=dev,
                        severity=_severity(dev),
                        description=(
                            f"{fname} has nesting depth {fm.complexity:.0f} — "
                            f"{dev:.1f}\u03c3 above directory mean of "
                            f"{bl.mean_complexity:.1f}"
                        ),
                    )
                )

        # --- import_heavy ---
        if bl.stddev_imports > 0 and fm.import_count > 0:
            dev = _deviation(fm.import_count, bl.mean_imports, bl.stddev_imports)
            if dev >= threshold:
                anomalies.append(
                    Anomaly(
                        path=fm.path,
                        anomaly_type="import_heavy",
                        value=float(fm.import_count),
                        baseline_mean=bl.mean_imports,
                        baseline_stddev=bl.stddev_imports,
                        deviation=dev,
                        severity=_severity(dev),
                        description=(
                            f"{fname} has {fm.import_count} imports — "
                            f"{dev:.1f}\u03c3 above directory mean of "
                            f"{bl.mean_imports:.1f}"
                        ),
                    )
                )

    return anomalies


def _detect_god_files(metrics: list[_FileMetrics]) -> list[Anomaly]:
    """
    Flag files that meet ALL absolute god-file thresholds:
    LOC > 500, function count > 20, import count > 15.
    """
    anomalies: list[Anomaly] = []
    for fm in metrics:
        if (
            fm.loc > GOD_FILE_MIN_LOC
            and fm.function_count > GOD_FILE_MIN_FUNCTIONS
            and fm.import_count > GOD_FILE_MIN_IMPORTS
        ):
            fname = _filename(fm.path)
            anomalies.append(
                Anomaly(
                    path=fm.path,
                    anomaly_type="god_file",
                    value=float(fm.loc),
                    baseline_mean=float(GOD_FILE_MIN_LOC),
                    baseline_stddev=0.0,
                    deviation=0.0,
                    severity="warning",
                    description=(
                        f"{fname} is a god file: "
                        f"{fm.loc:,} LOC, {fm.function_count} functions, "
                        f"{fm.import_count} imports"
                    ),
                )
            )
    return anomalies


def _detect_churn_anomalies(
    metrics: list[_FileMetrics],
    churn_map: dict[str, int],
    threshold: float,
) -> list[Anomaly]:
    """
    Flag files whose git churn exceeds *threshold* σ above their directory mean.
    Churn is looked up from *churn_map* (path → commit count).
    """
    if not churn_map:
        return []

    # Attach churn counts to metrics (in-place on churn field)
    for fm in metrics:
        fm.churn = churn_map.get(fm.path, 0)

    # Group churn by directory
    dir_churn: dict[str, list[int]] = defaultdict(list)
    for fm in metrics:
        dir_churn[fm.directory].append(fm.churn)

    # Compute per-directory churn baseline
    dir_churn_baseline: dict[str, tuple[float, float]] = {}
    for dir_key, values in dir_churn.items():
        mean = statistics.mean(values) if values else 0.0
        stddev = statistics.pstdev(values) if len(values) > 1 else 0.0
        dir_churn_baseline[dir_key] = (mean, stddev)

    anomalies: list[Anomaly] = []
    for fm in metrics:
        bl = dir_churn_baseline.get(fm.directory)
        if bl is None:
            continue
        mean, stddev = bl
        if stddev == 0.0:
            continue
        dev = _deviation(fm.churn, mean, stddev)
        if dev >= threshold:
            fname = _filename(fm.path)
            anomalies.append(
                Anomaly(
                    path=fm.path,
                    anomaly_type="high_churn",
                    value=float(fm.churn),
                    baseline_mean=mean,
                    baseline_stddev=stddev,
                    deviation=dev,
                    severity=_severity(dev),
                    description=(
                        f"{fname} changed {fm.churn} times in 90 days — "
                        f"{dev:.1f}\u03c3 above directory mean of "
                        f"{mean:.1f}"
                    ),
                )
            )

    return anomalies


# ---------------------------------------------------------------------------
# Deduplication: keep the worst anomaly per (path, type)
# ---------------------------------------------------------------------------


def _dedup_anomalies(anomalies: list[Anomaly]) -> list[Anomaly]:
    """Keep the single highest-deviation anomaly for each (path, type) pair."""
    best: dict[tuple[str, str], Anomaly] = {}
    for a in anomalies:
        key = (a.path, a.anomaly_type)
        existing = best.get(key)
        if existing is None or a.deviation > existing.deviation:
            best[key] = a
    return list(best.values())


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _sort_key(a: Anomaly) -> tuple[int, float]:
    return (_SEVERITY_ORDER.get(a.severity, 3), -a.deviation)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_anomalies(repo_path: str, threshold: float = 2.0) -> AnomalyReport:
    """
    Scan *repo_path* for files that deviate from their directory peers.

    Args:
        repo_path: Absolute or relative path to the repository root.
        threshold: Standard deviations above directory mean to flag.
                   Default is 2.0 (2σ).

    Returns:
        AnomalyReport with anomalies sorted by severity, per-directory
        baselines, and summary counts.
    """
    root = Path(repo_path).resolve()

    # 1. Collect file metrics
    all_metrics = _discover_files(root)

    # 2. Compute directory baselines (merges small dirs into parent)
    baselines = _compute_baselines(all_metrics)

    # 3. Statistical anomalies (oversized, high_complexity, import_heavy)
    anomalies: list[Anomaly] = _detect_statistical_anomalies(
        all_metrics, baselines, threshold
    )

    # 4. Absolute god-file detection
    anomalies.extend(_detect_god_files(all_metrics))

    # 5. Git churn anomalies (best-effort, silent on failure)
    churn_map = _collect_churn(root)
    anomalies.extend(_detect_churn_anomalies(all_metrics, churn_map, threshold))

    # 6. Deduplicate and sort
    anomalies = _dedup_anomalies(anomalies)
    anomalies.sort(key=_sort_key)

    return AnomalyReport(
        anomalies=anomalies,
        baselines=baselines,
        total_files_scanned=len(all_metrics),
        total_anomalies=len(anomalies),
    )
