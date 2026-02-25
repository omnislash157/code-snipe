"""Lightning data models. Every struct that flows through the search pipeline."""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CodeBlock:
    """A logical code block (function, class, import)."""

    block_type: str  # 'function', 'class', 'import', 'decorator', 'comment'
    name: str | None
    start_line: int
    end_line: int
    start_char: int
    end_char: int
    docstring: str | None = None


@dataclass
class CodeMatch:
    """A regex match with position + AST context."""

    start_char: int
    end_char: int
    start_token: int
    end_token: int
    matched_text: str
    line_number: int
    containing_block: str | None = None


@dataclass
class CodeChunk:
    """Expanded context window around one or more matches."""

    start_token: int
    end_token: int
    start_line: int
    end_line: int
    text: str
    match_count: int
    is_merged: bool = False
    blocks_included: list[str] = field(default_factory=list)


@dataclass
class FileHit:
    """All matches within a single file."""

    filepath: str
    relative_path: str
    language: str
    chunks: list[CodeChunk]
    total_matches: int
    total_tokens: int
    matches: list[CodeMatch] = field(default_factory=list)


@dataclass
class LightningResult:
    """Complete search result."""

    term: str
    variations: list[str]
    files_searched: int
    files_matched: int
    total_matches: int
    hits: list[FileHit]
    search_time_ms: float

    def to_markdown(self, context_lines: int = 1) -> str:
        """Compact grep-style markdown with AST block names."""
        from .formatters import to_markdown
        return to_markdown(self, context_lines)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict."""
        from .formatters import to_json
        return to_json(self)


# Backward compat aliases
CodeHoundResult = LightningResult
