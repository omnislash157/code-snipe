"""
ripgrep.py - rg subprocess wrapper for Pass 1 file filtering.

10-50x faster than Python ThreadPoolExecutor for finding files with matches.
Falls back to Python if rg is not installed.
"""

import logging
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Directories to skip
IGNORE_DIRS = [
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
    "node_modules", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", ".svelte-kit", "target",
    ".idea", ".vscode", "coverage",
    "vendor", ".env",
]

# Check if rg is available (cached at import time)
RG_PATH = shutil.which("rg")


def rg_matching_files(
    pattern: re.Pattern | str,
    root_path: Path,
    file_extensions: set[str] | None = None,
) -> list[Path]:
    """
    Use ripgrep to find files containing pattern. Pass 1 of the blitz.

    Args:
        pattern: Compiled regex or string pattern
        root_path: Directory to search
        file_extensions: Optional set of extensions to filter (e.g. {'.py', '.ts'})

    Returns:
        List of Path objects for files with matches
    """
    if not RG_PATH:
        return []

    # Extract pattern string
    if isinstance(pattern, re.Pattern):
        pat_str = pattern.pattern
    else:
        pat_str = pattern

    cmd = [
        RG_PATH,
        "--files-with-matches",
        "--pcre2",
        "-i",  # case insensitive
        "--no-messages",  # suppress file errors
    ]

    # Add ignore globs
    for d in IGNORE_DIRS:
        cmd.extend(["--glob", f"!{d}/"])

    # Add file type filters
    if file_extensions:
        for ext in file_extensions:
            ext_clean = ext.lstrip(".")
            cmd.extend(["--glob", f"*.{ext_clean}"])

    cmd.append(pat_str)
    cmd.append(str(root_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0 and result.stdout.strip():
            return [Path(line) for line in result.stdout.strip().split("\n") if line]
        return []

    except subprocess.TimeoutExpired:
        logger.warning("ripgrep timed out after 10s")
        return []
    except Exception as e:
        logger.warning(f"ripgrep failed: {e}")
        return []


def python_matching_files(
    pattern: re.Pattern,
    files: list[Path],
) -> list[Path]:
    """Python fallback for Pass 1 when rg is not available."""
    matching = []
    for filepath in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            if pattern.search(content):
                matching.append(filepath)
        except Exception:
            pass
    return matching
