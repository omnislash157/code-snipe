"""
context_strike.py - Match expansion and daisy-chain merging.

Strikes surrounding context around each match. Expands to function/class
boundaries, merges nearby matches into unified chunks.
"""

import re

from .models import CodeBlock, CodeMatch, CodeChunk
from .pattern_splinter import tokenize, detokenize
from .block_blast import find_containing_block


def find_code_boundary(
    text: str,
    match_char_pos: int,
    direction: str,
    blocks: list[CodeBlock],
    min_tokens: int = 30,
    max_tokens: int = 300,
) -> int:
    """
    Find natural code boundary using AST blocks.

    Expands to include the containing function/class, or uses
    blank line heuristics if no containing block.
    """
    tokens = tokenize(text)
    total_tokens = len(tokens)

    char_to_token = []
    current_char = 0
    for i, token in enumerate(tokens):
        for _ in token:
            char_to_token.append(i)
            current_char += 1

    if match_char_pos >= len(char_to_token):
        match_token = len(tokens) - 1
    else:
        match_token = char_to_token[match_char_pos]

    block = find_containing_block(match_char_pos, blocks)

    if block:
        if direction == "forward":
            if block.end_char < len(char_to_token):
                return min(char_to_token[block.end_char - 1], match_token + max_tokens)
            return min(total_tokens, match_token + max_tokens)
        else:
            if block.start_char < len(char_to_token):
                return max(char_to_token[block.start_char], match_token - max_tokens)
            return max(0, match_token - max_tokens)

    lines = text.split("\n")
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    current_line = 0
    for i, start in enumerate(line_starts):
        if start > match_char_pos:
            current_line = i - 1
            break

    if direction == "forward":
        for i in range(current_line + 1, min(current_line + 50, len(lines))):
            line = lines[i] if i < len(lines) else ""
            if not line.strip() or re.match(r"^(class|def|async\s+def)\s", line):
                target_char = line_starts[i] if i < len(line_starts) else len(text)
                if target_char < len(char_to_token):
                    return min(char_to_token[target_char], match_token + max_tokens)
        return min(total_tokens, match_token + max_tokens)
    else:
        for i in range(current_line - 1, max(current_line - 50, -1), -1):
            if i < 0:
                break
            line = lines[i]
            if not line.strip() or re.match(r"^(class|def|async\s+def)\s", line):
                target_char = line_starts[i + 1] if i + 1 < len(line_starts) else 0
                if target_char < len(char_to_token):
                    return max(char_to_token[target_char], match_token - max_tokens)
        return max(0, match_token - max_tokens)


def find_matches(text: str, pattern: re.Pattern, blocks: list[CodeBlock]) -> list[CodeMatch]:
    """Find all matches with token positions and containing block info."""
    tokens = tokenize(text)
    matches = []

    char_to_token = []
    for i, token in enumerate(tokens):
        for _ in token:
            char_to_token.append(i)

    line_starts = [0]
    for line in text.split("\n"):
        line_starts.append(line_starts[-1] + len(line) + 1)

    for match in pattern.finditer(text):
        char_start = match.start()
        char_end = match.end()

        start_token = (
            char_to_token[char_start] if char_start < len(char_to_token) else len(tokens) - 1
        )
        end_token = (
            char_to_token[char_end - 1] if char_end - 1 < len(char_to_token) else len(tokens) - 1
        )

        line_num = 1
        for i, start in enumerate(line_starts):
            if start > char_start:
                line_num = i
                break

        block = find_containing_block(char_start, blocks)
        block_name = f"{block.block_type}:{block.name}" if block and block.name else None

        matches.append(
            CodeMatch(
                start_char=char_start,
                end_char=char_end,
                start_token=start_token,
                end_token=end_token,
                matched_text=match.group(),
                line_number=line_num,
                containing_block=block_name,
            )
        )

    return matches


def expand_and_merge(
    text: str,
    matches: list[CodeMatch],
    blocks: list[CodeBlock],
    token_radius: int = 100,
    merge_gap: int = 50,
    smart_expand: bool = True,
    context_lines: int = 10,
) -> list[CodeChunk]:
    """
    Expand context around matches and merge nearby chunks.

    smart_expand=True: Expand to block boundaries but cap at context_lines.
    False: Simple token_radius expansion.
    """
    if not matches:
        return []

    tokens = tokenize(text)
    total_tokens = len(tokens)

    lines = text.split("\n")
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    def token_to_line(token_idx: int) -> int:
        char_pos = sum(len(tokens[i]) for i in range(min(token_idx, len(tokens))))
        for i, start in enumerate(line_starts):
            if start > char_pos:
                return i
        return len(lines)

    def line_to_token(line_num: int) -> int:
        if line_num <= 0:
            return 0
        if line_num >= len(line_starts):
            return total_tokens
        char_pos = line_starts[line_num - 1]
        current_char = 0
        for i, token in enumerate(tokens):
            if current_char >= char_pos:
                return i
            current_char += len(token)
        return total_tokens

    expanded_spans = []
    for match in matches:
        if smart_expand:
            block = find_containing_block(match.start_char, blocks)
            if block:
                block_start_line = max(1, text[: block.start_char].count("\n") + 1)
                block_end_line = max(1, text[: block.end_char].count("\n") + 1)
                match_line = match.line_number

                start_line = max(block_start_line, match_line - context_lines)
                end_line = min(block_end_line, match_line + context_lines)

                start = line_to_token(start_line)
                end = line_to_token(end_line)
            else:
                start_line = max(1, match.line_number - context_lines)
                end_line = match.line_number + context_lines
                start = line_to_token(start_line)
                end = line_to_token(end_line)
        else:
            start = max(0, match.start_token - token_radius)
            end = min(total_tokens, match.end_token + token_radius)

        included_blocks = []
        for block in blocks:
            if block.name and block.start_char >= sum(len(tokens[i]) for i in range(start)):
                if block.end_char <= sum(len(tokens[i]) for i in range(end)):
                    included_blocks.append(f"{block.block_type}:{block.name}")

        expanded_spans.append((start, end, 1, included_blocks))

    expanded_spans.sort(key=lambda x: x[0])

    merged = []
    current_start, current_end, current_count, current_blocks = expanded_spans[0]

    for start, end, count, blocks_list in expanded_spans[1:]:
        gap = start - current_end

        if gap <= merge_gap:
            current_end = max(current_end, end)
            current_count += count
            current_blocks = list(set(current_blocks + blocks_list))
        else:
            merged.append((current_start, current_end, current_count, current_blocks))
            current_start, current_end, current_count, current_blocks = (
                start, end, count, blocks_list,
            )

    merged.append((current_start, current_end, current_count, current_blocks))

    chunks = []
    for start, end, count, blocks_list in merged:
        chunk_tokens = tokens[start:end]
        chunk_text = detokenize(chunk_tokens).strip()

        chunks.append(
            CodeChunk(
                start_token=start,
                end_token=end,
                start_line=token_to_line(start),
                end_line=token_to_line(end),
                text=chunk_text,
                match_count=count,
                is_merged=(count > 1),
                blocks_included=blocks_list,
            )
        )

    return chunks
