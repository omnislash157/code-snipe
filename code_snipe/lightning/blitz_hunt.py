"""
blitz_hunt.py - The core. Fast in, fast out.

Lightning class with hunt(), list_files(), _process_file().
Uses ripgrep for Pass 1 (file filtering), ThreadPoolExecutor for Pass 2 (AST context).
"""

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .models import CodeChunk, FileHit, LightningResult
from .pattern_splinter import build_code_pattern, get_identifier_variations
from .block_blast import find_python_blocks, find_blocks_regex, find_blocks
from .context_strike import find_matches, expand_and_merge
from .ripgrep import rg_matching_files, python_matching_files, RG_PATH

logger = logging.getLogger(__name__)

# Hardcoded optimal defaults — no consumer ever overrides these
TOKEN_RADIUS = 100
MERGE_GAP = 50
MAX_CHUNKS_PER_FILE = 5


class Lightning:
    """
    AST-aware code search. Finds patterns with function/class context.

    Point at specific folders, not repo root:
        Lightning("core/").hunt("db_query")
        Lightning("auth/").hunt("token")
    """

    LANGUAGE_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".svelte": "svelte",
        ".vue": "vue",
        ".rs": "rust",
        ".go": "go",
        ".rb": "ruby",
        ".java": "java",
        ".kt": "kotlin",
        ".swift": "swift",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".php": "php",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".md": "markdown",
        ".html": "html",
        ".css": "css",
        ".scss": "scss",
        ".sql": "sql",
    }

    IGNORE_DIRS = {
        ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
        "node_modules", ".venv", "venv", "env",
        "dist", "build", ".next", ".nuxt", ".svelte-kit", "target",
        ".idea", ".vscode", "coverage",
        "vendor", ".env",
    }

    def __init__(self, root_path: str, extensions: set[str] | None = None):
        self.root_path = Path(root_path).resolve()
        self.extensions = extensions or set(self.LANGUAGE_EXTENSIONS.keys())
        self._files_cache: list[Path] | None = None

    @property
    def files(self) -> list[Path]:
        """Get list of searchable files (cached after first call)."""
        if self._files_cache is None:
            self._files_cache = []
            for path in self.root_path.rglob("*"):
                if path.is_file():
                    if any(part in self.IGNORE_DIRS for part in path.parts):
                        continue
                    if path.suffix in self.extensions:
                        self._files_cache.append(path)
        return self._files_cache

    def list_files(self, pattern: str = None) -> list[Path]:
        """List files. Glob replacement."""
        if pattern:
            return [f for f in self.files if f.match(pattern)]
        return self.files

    def _process_file(
        self,
        filepath: Path,
        pattern: re.Pattern,
        context_lines: int,
    ) -> FileHit | None:
        """Process single file — Pass 2 AST context extraction."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        lang = self.LANGUAGE_EXTENSIONS.get(filepath.suffix, "text")
        blocks = find_blocks(content, lang)
        matches = find_matches(content, pattern, blocks)

        if not matches:
            return None

        chunks = expand_and_merge(
            content,
            matches,
            blocks,
            token_radius=TOKEN_RADIUS,
            merge_gap=MERGE_GAP,
            smart_expand=True,
            context_lines=context_lines,
        )

        if len(chunks) > MAX_CHUNKS_PER_FILE:
            chunks = chunks[:MAX_CHUNKS_PER_FILE]

        return FileHit(
            filepath=str(filepath),
            relative_path=str(filepath.relative_to(self.root_path)),
            language=lang,
            chunks=chunks,
            total_matches=len(matches),
            total_tokens=sum(c.end_token - c.start_token for c in chunks),
            matches=matches,
        )

    def hunt(
        self,
        term: str,
        *,
        regex: bool = False,
        file_pattern: str | None = None,
        max_files: int = 20,
        context_lines: int = 5,
    ) -> LightningResult:
        """
        Two-pass search: rg file filter, then AST context on matches only.

        Args:
            term: Search term (fuzzy by default, raw regex if regex=True)
            regex: Treat term as raw regex (skip fuzzy matching)
            file_pattern: Glob pattern to filter files (e.g. "*.py")
            max_files: Limit files in results (default 20)
            context_lines: Lines above/below match (default 5)
        """
        start = time.perf_counter()

        if regex:
            pattern = re.compile(term, re.IGNORECASE)
            variations = [term]
        else:
            pattern = build_code_pattern(term)
            variations = get_identifier_variations(term)

        # ── PASS 1: Find files with matches ──────────────────────────
        if RG_PATH and not file_pattern:
            # Fast path: ripgrep
            matching_files = rg_matching_files(pattern, self.root_path, self.extensions)
        else:
            # Python fallback (or when file_pattern needs custom filtering)
            files_to_search = self.files
            if file_pattern:
                files_to_search = [f for f in files_to_search if f.match(file_pattern)]
            matching_files = python_matching_files(pattern, files_to_search)

        files_searched = len(self.files)
        pass1_ms = (time.perf_counter() - start) * 1000
        logger.info(f"Pass 1: {len(matching_files)} files in {pass1_ms:.0f}ms")

        # Cap candidates
        if max_files and len(matching_files) > max_files * 2:
            matching_files = matching_files[: max_files * 2]

        # ── PASS 2: AST context extraction ───────────────────────────
        hits = []
        total_matches = 0

        workers = min(16, len(matching_files) or 1)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._process_file, fp, pattern, context_lines): fp
                for fp in matching_files
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hits.append(result)
                    total_matches += result.total_matches
                    if max_files and len(hits) >= max_files:
                        for f in futures:
                            f.cancel()
                        break

        elapsed_ms = (time.perf_counter() - start) * 1000

        return LightningResult(
            term=term,
            variations=variations,
            files_searched=files_searched,
            files_matched=len(hits),
            total_matches=total_matches,
            hits=hits,
            search_time_ms=elapsed_ms,
        )
