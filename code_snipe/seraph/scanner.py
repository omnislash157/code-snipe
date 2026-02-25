"""
scanner.py — Language detection and source file discovery.

Given a repo root path, walks the directory tree, detects languages by
file extension, counts lines of code, and returns a RepoScan dataclass.

No external dependencies. Pure stdlib.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Extension → language name
EXTENSION_MAP: dict[str, str] = {
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

# Directory names to skip entirely during traversal
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
        ".svelte-kit",
        ".next",
        ".nuxt",
        ".turbo",
        ".ruff_cache",
        ".pytest_cache",
        "coverage",
        ".coverage",
        "target",
        ".seraph",
    }
)

# Suffix patterns for egg-info directories (checked via endswith)
SKIP_DIR_SUFFIXES: tuple[str, ...] = (".egg-info",)

# Maximum file size to read (1 MB)
MAX_FILE_SIZE_BYTES: int = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class RepoScan:
    """Results of scanning a repository for source files."""

    root: Path
    languages: dict[str, int] = field(default_factory=dict)
    primary_language: str = ""
    source_files: list[Path] = field(default_factory=list)
    total_loc: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _should_skip_dir(dirname: str) -> bool:
    """Return True if a directory should be excluded from traversal."""
    if dirname in SKIP_DIRS:
        return True
    for suffix in SKIP_DIR_SUFFIXES:
        if dirname.endswith(suffix):
            return True
    return False


def _is_binary(path: Path) -> bool:
    """
    Quick binary-file heuristic: read the first 8 KB and look for null bytes.

    Returns True if the file appears to be binary.
    """
    try:
        with path.open("rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _count_lines(path: Path) -> int:
    """
    Count non-empty lines in a text file.

    Returns 0 on any read error.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_repo(repo_path: str) -> RepoScan:
    """
    Walk *repo_path* and collect all recognised source files.

    Args:
        repo_path: Absolute or relative path to the repository root.

    Returns:
        RepoScan populated with language counts, source file paths, and LOC.
    """
    root = Path(repo_path).resolve()

    languages: dict[str, int] = {}
    source_files: list[Path] = []
    total_loc: int = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune unwanted directories in-place so os.walk won't descend.
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            suffix = file_path.suffix.lower()

            language = EXTENSION_MAP.get(suffix)
            if language is None:
                continue

            # Skip files that are too large.
            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_SIZE_BYTES:
                continue

            # Skip binary files.
            if _is_binary(file_path):
                continue

            loc = _count_lines(file_path)

            # Record relative path from repo root.
            rel_path = file_path.relative_to(root)
            source_files.append(rel_path)

            languages[language] = languages.get(language, 0) + 1
            total_loc += loc

    # Determine the primary language (most files).
    primary_language = (
        max(languages, key=lambda lang: languages[lang]) if languages else ""
    )

    return RepoScan(
        root=root,
        languages=languages,
        primary_language=primary_language,
        source_files=source_files,
        total_loc=total_loc,
    )
