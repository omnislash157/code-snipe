"""
formatters.py - Markdown + JSON output for Lightning results.
"""

from collections import defaultdict
from pathlib import Path
from typing import Any


def to_markdown(result, context_lines: int = 1) -> str:
    """Compact grep-style markdown with AST block names."""
    lines = [
        "# LIGHTNING SEARCH",
        f"**Term:** `{result.term}` | **{result.files_matched} files** | **{result.total_matches} matches** | {result.search_time_ms:.0f}ms",
        "",
    ]

    for hit in result.hits:
        lines.append(f"## {hit.relative_path}")
        lines.append(f"*{hit.total_matches} matches*")
        lines.append("")

        matches_by_block = defaultdict(list)
        for match in hit.matches:
            block_key = match.containing_block or "top-level"
            matches_by_block[block_key].append(match)

        try:
            file_lines = (
                Path(hit.filepath).read_text(encoding="utf-8", errors="replace").split("\n")
            )
        except Exception:
            file_lines = []

        for block_name, matches in matches_by_block.items():
            if block_name != "top-level":
                lines.append(f"**{block_name}**")

            for match in matches:
                line_num = match.line_number
                start_line = max(1, line_num - context_lines)
                end_line = min(len(file_lines), line_num + context_lines)

                for i in range(start_line, end_line + 1):
                    if i <= 0 or i > len(file_lines):
                        continue
                    line_content = file_lines[i - 1]
                    if i == line_num:
                        lines.append(f"  **L{i}:** `{line_content}`  <- MATCH")
                    else:
                        lines.append(f"  L{i}: {line_content}")
                lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def to_json(result) -> dict[str, Any]:
    """JSON-serializable dict."""
    return {
        "term": result.term,
        "variations": result.variations,
        "files_searched": result.files_searched,
        "files_matched": result.files_matched,
        "total_matches": result.total_matches,
        "search_time_ms": result.search_time_ms,
        "hits": [
            {
                "filepath": hit.filepath,
                "relative_path": hit.relative_path,
                "language": hit.language,
                "total_matches": hit.total_matches,
                "chunks": [
                    {
                        "start_line": c.start_line,
                        "end_line": c.end_line,
                        "match_count": c.match_count,
                        "is_merged": c.is_merged,
                        "blocks_included": c.blocks_included,
                        "text": c.text,
                    }
                    for c in hit.chunks
                ],
            }
            for hit in result.hits
        ],
    }
