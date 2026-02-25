"""
Lightning - Modular Code Search Suite

Fast, modular, AST-aware code search.
Every module name hits like a bolt.

Usage:
    from code_snipe.lightning import Lightning

    bolt = Lightning("core/")
    result = bolt.hunt("db_query")           # Fuzzy match
    result = bolt.hunt("def \\w+", regex=True)  # Raw regex
    print(result.to_markdown())

CLI:
    hound 'pattern' core/      # Search
    hound core/ 'pattern'      # Old arg order works
    hound --cooccur 'auth' .   # Co-occurrence
    hound --stats 'ws' core/   # Frequency stats
"""

from .blitz_hunt import Lightning
from .models import (
    CodeBlock,
    CodeMatch,
    CodeChunk,
    FileHit,
    LightningResult,
)
from .pattern_splinter import (
    tokenize,
    detokenize,
    token_count,
    split_identifier,
    build_code_pattern,
    get_identifier_variations,
)
from .block_blast import (
    find_python_blocks,
    find_blocks_regex,
    find_blocks,
    find_containing_block,
)
from .context_strike import (
    find_code_boundary,
    find_matches,
    expand_and_merge,
)

# Backward compatibility aliases
CodeHound = Lightning
CodeHoundResult = LightningResult
Hound = Lightning

__all__ = [
    "Lightning",
    "LightningResult",
    "CodeHound",
    "CodeHoundResult",
    "Hound",
    "CodeBlock",
    "CodeMatch",
    "CodeChunk",
    "FileHit",
    "tokenize",
    "detokenize",
    "token_count",
    "split_identifier",
    "build_code_pattern",
    "get_identifier_variations",
    "find_python_blocks",
    "find_blocks_regex",
    "find_blocks",
    "find_containing_block",
    "find_code_boundary",
    "find_matches",
    "expand_and_merge",
]
