"""
import_graph.py — Directed import graph builder.

Builds a graph of file-level import relationships across a repository.

Python analysis uses the `ast` module with `ast.walk()` over the FULL tree,
catching lazy imports inside function/method bodies — the gap that ImportWiz's
`^import` regex approach misses (77/~400 imports in FastAPI are in function
bodies, i.e. 19% invisible to regex-only tools).

TypeScript/JavaScript analysis uses regex for `import … from`, `require()`,
and dynamic `import()`.

No external dependencies. Pure stdlib.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from code_snipe.seraph.scanner import RepoScan

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class NodeInfo:
    """Metadata for a single source file node."""

    path: str
    language: str
    loc: int
    is_entry_point: bool


@dataclass
class Edge:
    """A directed import edge from *source* file to *target* file."""

    source: str
    target: str
    import_name: str


@dataclass
class ImportGraph:
    """Full import graph for a scanned repository."""

    nodes: dict[str, NodeInfo] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    fan_in: dict[str, int] = field(default_factory=dict)
    fan_out: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived views
    # ------------------------------------------------------------------

    def hot_files(self, top_n: int = 10) -> list[tuple[str, int]]:
        """Return the top *top_n* files by fan_in (most imported)."""
        return sorted(self.fan_in.items(), key=lambda kv: -kv[1])[:top_n]

    def god_files(self, top_n: int = 10) -> list[tuple[str, int]]:
        """Return the top *top_n* files by LOC."""
        return sorted(
            ((path, info.loc) for path, info in self.nodes.items()),
            key=lambda kv: -kv[1],
        )[:top_n]

    def orphan_files(self) -> list[str]:
        """Return files with both fan_in=0 and fan_out=0."""
        return [
            path
            for path in self.nodes
            if self.fan_in.get(path, 0) == 0 and self.fan_out.get(path, 0) == 0
        ]


# ---------------------------------------------------------------------------
# Language detection helpers
# ---------------------------------------------------------------------------

_PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py"})
_TS_JS_EXTENSIONS: frozenset[str] = frozenset({".ts", ".tsx", ".js", ".jsx"})

# Patterns that indicate a Python entry point (beyond __main__ / specific names).
_PYTHON_ENTRY_PATTERNS: re.Pattern[str] = re.compile(
    r"@app\.route|@router\.|uvicorn\.run|click\.command|argparse"
)

# Regex for TypeScript/JavaScript import statements.
# Matches:
#   import ... from '...' / import ... from "..."
#   require('...') / require("...")
#   import('...') / import("...")   (dynamic)
_TS_IMPORT_RE: re.Pattern[str] = re.compile(
    r"""
    (?:
        from\s+['"]([^'"]+)['"]       # import ... from 'module'
        |
        require\(\s*['"]([^'"]+)['"]\s*\)  # require('module')
        |
        import\(\s*['"]([^'"]+)['"]\s*\)   # import('module')  dynamic
    )
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------


def _parse_python_imports(
    source: str,
) -> Iterator[tuple[str, int, str]]:
    """
    Yield (module_name, level, alias) tuples for every import in *source*.

    Uses ast.walk() over the COMPLETE tree — catches imports nested inside
    functions, methods, try/except blocks, and conditional branches.

    Yields:
        (module, level, name) where:
          module — dotted module string (may be empty for bare `from . import x`)
          level  — number of leading dots (0 = absolute, 1 = relative, …)
          name   — the imported name or alias (used for display only)
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, 0, alias.asname or alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level or 0
            for alias in node.names:
                yield module, level, alias.asname or alias.name


def _is_python_entry_point(source: str, filename: str) -> bool:
    """Return True if the file looks like a Python entry point."""
    entry_names = {"main.py", "app.py", "cli.py", "__main__.py"}
    if filename in entry_names:
        return True
    if 'if __name__ == "__main__"' in source or "if __name__ == '__main__'" in source:
        return True
    if _PYTHON_ENTRY_PATTERNS.search(source):
        return True
    return False


def _resolve_python_import(
    module: str,
    level: int,
    source_file: Path,
    repo_root: Path,
    file_set: frozenset[str],
) -> str | None:
    """
    Attempt to resolve a Python import to a relative file path within the repo.

    Returns the relative-path string (using forward slashes) if a file is
    found in *file_set*, otherwise None (external / unresolvable import).

    Args:
        module: Dotted module name (e.g. "fastapi.routing" or "" for star import).
        level:  Number of leading dots (0 = absolute, >=1 = relative).
        source_file: Path of the file that contains the import, relative to root.
        repo_root: Absolute repo root Path (unused here — paths already relative).
        file_set: Set of all known relative source file path strings.
    """
    if level > 0:
        # Relative import — anchor to the source file's package directory.
        parts = list(source_file.parent.parts)
        # Climb 'level-1' levels up (level=1 → same package, level=2 → parent, …)
        for _ in range(level - 1):
            if parts:
                parts.pop()
        base_parts = parts
    else:
        base_parts = []

    if module:
        base_parts = base_parts + module.split(".")

    # Try candidate paths:
    #   foo/bar.py
    #   foo/bar/__init__.py
    candidates = [
        "/".join(base_parts) + ".py",
        "/".join(base_parts) + "/__init__.py",
    ]

    for candidate in candidates:
        if candidate in file_set:
            return candidate

    # Try partial matches: for `from foo.bar import baz`, baz might be a module.
    if base_parts:
        extended = base_parts + ["__init__.py"]
        candidate = "/".join(extended)
        if candidate in file_set:
            return candidate

    return None


# ---------------------------------------------------------------------------
# TypeScript / JavaScript analysis
# ---------------------------------------------------------------------------


def _is_ts_entry_point(source: str, filename: str) -> bool:
    """Return True if the file looks like a TS/JS entry point."""
    entry_names = {"main.ts", "main.js", "index.ts", "index.js", "app.ts", "app.js"}
    if filename in entry_names:
        return True
    return False


def _resolve_ts_import(
    raw_module: str,
    source_file: Path,
    file_set: frozenset[str],
) -> str | None:
    """
    Attempt to resolve a TypeScript/JavaScript import to a repo-relative path.

    Handles relative imports only (starting with '.' or '..').  Absolute
    specifiers (e.g. bare 'react', '@scope/pkg') are external — return None.

    Args:
        raw_module: The raw import path from the source (e.g. './utils', '../core').
        source_file: Relative path of the importing file.
        file_set: Set of all known relative source file path strings.
    """
    if not raw_module.startswith("."):
        # Bare or scoped package — external, skip.
        return None

    # Resolve relative to the source file's directory.
    source_dir = source_file.parent
    target = (source_dir / raw_module).resolve()

    # Build repo-relative string.
    try:
        rel = target.relative_to(Path("/"))
        rel_str = str(rel)
    except ValueError:
        rel_str = str(target)

    # Strip leading slash artifacts from resolve().
    # We work with plain string manipulation since we lost the real root.
    # Recompute without resolve() to avoid platform path issues.
    parts = list(source_file.parent.parts)
    for segment in raw_module.split("/"):
        if segment == "..":
            if parts:
                parts.pop()
        elif segment and segment != ".":
            parts.append(segment)

    base = "/".join(parts) if parts else ""

    ts_extensions = [".ts", ".tsx", ".js", ".jsx"]
    candidates: list[str] = []

    if base:
        # Exact path with extensions.
        for ext in ts_extensions:
            candidates.append(base + ext)
        # Index file.
        for ext in ts_extensions:
            candidates.append(base + "/index" + ext)
    else:
        for ext in ts_extensions:
            candidates.append("index" + ext)

    for candidate in candidates:
        if candidate in file_set:
            return candidate

    return None


# ---------------------------------------------------------------------------
# Core analysis per file
# ---------------------------------------------------------------------------


def _analyse_file(
    rel_path: Path,
    repo_root: Path,
    language: str,
    file_set: frozenset[str],
) -> tuple[NodeInfo, list[tuple[str, str, str]]]:
    """
    Analyse a single file and return its NodeInfo plus raw import edges.

    Returns:
        (NodeInfo, [(source_rel_str, target_rel_str, import_name), ...])
    """
    abs_path = repo_root / rel_path
    rel_str = str(rel_path).replace("\\", "/")

    try:
        source = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""

    loc = sum(1 for line in source.splitlines() if line.strip())

    raw_edges: list[tuple[str, str, str]] = []

    if language == "Python":
        is_entry = _is_python_entry_point(source, rel_path.name)
        for module, level, name in _parse_python_imports(source):
            target = _resolve_python_import(
                module, level, rel_path, repo_root, file_set
            )
            if target is not None and target != rel_str:
                import_label = ("." * level + module) if module else ("." * level)
                raw_edges.append((rel_str, target, import_label or name))

    elif language in ("TypeScript", "JavaScript"):
        is_entry = _is_ts_entry_point(source, rel_path.name)
        for match in _TS_IMPORT_RE.finditer(source):
            raw_module = match.group(1) or match.group(2) or match.group(3)
            if not raw_module:
                continue
            target = _resolve_ts_import(raw_module, rel_path, file_set)
            if target is not None and target != rel_str:
                raw_edges.append((rel_str, target, raw_module))

    else:
        is_entry = False

    node = NodeInfo(
        path=rel_str,
        language=language,
        loc=loc,
        is_entry_point=is_entry,
    )
    return node, raw_edges


# ---------------------------------------------------------------------------
# Language lookup helper (scanner already has this but we avoid circular dep)
# ---------------------------------------------------------------------------

_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".cpp": "C/C++",
    ".c": "C/C++",
    ".h": "C/C++",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_import_graph(scan: RepoScan) -> ImportGraph:
    """
    Build a directed import graph from a RepoScan.

    Analysis depth:
    - Python: full AST walk via ast.walk() — catches lazy/nested imports.
    - TypeScript/JavaScript: regex over the full file text.
    - Other languages: nodes created, no edges extracted.

    Args:
        scan: A RepoScan produced by scanner.scan_repo().

    Returns:
        ImportGraph with nodes, edges, fan_in, and fan_out populated.
    """
    repo_root = scan.root

    # Build a fast lookup set of all known relative paths (forward slashes).
    file_set: frozenset[str] = frozenset(
        str(p).replace("\\", "/") for p in scan.source_files
    )

    nodes: dict[str, NodeInfo] = {}
    all_raw_edges: list[tuple[str, str, str]] = []

    for rel_path in scan.source_files:
        language = _EXTENSION_TO_LANGUAGE.get(rel_path.suffix.lower(), "Unknown")
        node, raw_edges = _analyse_file(rel_path, repo_root, language, file_set)
        nodes[node.path] = node
        all_raw_edges.extend(raw_edges)

    # Deduplicate edges (same source/target pair can appear multiple times if
    # a file imports from the same module in multiple places — normalise).
    seen_edges: set[tuple[str, str]] = set()
    edges: list[Edge] = []
    for source, target, import_name in all_raw_edges:
        key = (source, target)
        if key in seen_edges:
            continue
        # Only emit edges where both endpoints are known nodes.
        if source in nodes and target in nodes:
            seen_edges.add(key)
            edges.append(Edge(source=source, target=target, import_name=import_name))

    # Compute fan_in / fan_out from the deduplicated edge list.
    fan_in: dict[str, int] = {path: 0 for path in nodes}
    fan_out: dict[str, int] = {path: 0 for path in nodes}

    for edge in edges:
        fan_out[edge.source] = fan_out.get(edge.source, 0) + 1
        fan_in[edge.target] = fan_in.get(edge.target, 0) + 1

    return ImportGraph(
        nodes=nodes,
        edges=edges,
        fan_in=fan_in,
        fan_out=fan_out,
    )
