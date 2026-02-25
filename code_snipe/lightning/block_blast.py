"""
block_blast.py - AST + regex block detection. Blasts through code to find boundaries.

Finds function/class/import blocks in source code. Uses Python's ast module
for .py files, regex fallback for everything else.
"""

import ast
import re

from .models import CodeBlock


def find_python_blocks(source: str) -> list[CodeBlock]:
    """
    Parse Python source and extract logical blocks.

    Returns list of CodeBlock for functions, classes, imports, etc.
    """
    blocks = []
    lines = source.split("\n")

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return find_blocks_regex(source)

    # Calculate line start positions
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    def get_char_pos(lineno: int, col: int) -> int:
        if lineno <= 0 or lineno > len(line_starts):
            return 0
        return line_starts[lineno - 1] + col

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = ast.get_docstring(node)

            start_line = node.lineno
            if node.decorator_list:
                start_line = min(d.lineno for d in node.decorator_list)

            blocks.append(
                CodeBlock(
                    block_type="function",
                    name=node.name,
                    start_line=start_line,
                    end_line=node.end_lineno or node.lineno,
                    start_char=get_char_pos(start_line, 0),
                    end_char=get_char_pos((node.end_lineno or node.lineno) + 1, 0),
                    docstring=docstring,
                )
            )

        elif isinstance(node, ast.ClassDef):
            docstring = ast.get_docstring(node)

            start_line = node.lineno
            if node.decorator_list:
                start_line = min(d.lineno for d in node.decorator_list)

            blocks.append(
                CodeBlock(
                    block_type="class",
                    name=node.name,
                    start_line=start_line,
                    end_line=node.end_lineno or node.lineno,
                    start_char=get_char_pos(start_line, 0),
                    end_char=get_char_pos((node.end_lineno or node.lineno) + 1, 0),
                    docstring=docstring,
                )
            )

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            blocks.append(
                CodeBlock(
                    block_type="import",
                    name=None,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    start_char=get_char_pos(node.lineno, 0),
                    end_char=get_char_pos((node.end_lineno or node.lineno) + 1, 0),
                )
            )

    return sorted(blocks, key=lambda b: b.start_line)


def find_blocks_regex(source: str) -> list[CodeBlock]:
    """Fallback regex-based block detection for non-Python or invalid syntax."""
    blocks = []
    lines = source.split("\n")

    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    def get_char_pos(lineno: int) -> int:
        if lineno <= 0 or lineno > len(line_starts):
            return 0
        return line_starts[lineno - 1]

    func_pattern = re.compile(r"^(\s*)(async\s+)?def\s+(\w+)\s*\(", re.MULTILINE)
    class_pattern = re.compile(r"^(\s*)class\s+(\w+)\s*[:\(]", re.MULTILINE)

    for match in func_pattern.finditer(source):
        indent = len(match.group(1))
        name = match.group(3)
        start_line = source[: match.start()].count("\n") + 1

        end_line = start_line
        for i, line in enumerate(lines[start_line:], start=start_line + 1):
            if line.strip() and not line.startswith(" " * (indent + 1)):
                if not line.strip().startswith("#"):
                    break
            end_line = i

        blocks.append(
            CodeBlock(
                block_type="function",
                name=name,
                start_line=start_line,
                end_line=end_line,
                start_char=get_char_pos(start_line),
                end_char=get_char_pos(end_line + 1),
            )
        )

    for match in class_pattern.finditer(source):
        indent = len(match.group(1))
        name = match.group(2)
        start_line = source[: match.start()].count("\n") + 1

        end_line = start_line
        for i, line in enumerate(lines[start_line:], start=start_line + 1):
            if line.strip() and not line.startswith(" " * (indent + 1)):
                if not line.strip().startswith("#"):
                    break
            end_line = i

        blocks.append(
            CodeBlock(
                block_type="class",
                name=name,
                start_line=start_line,
                end_line=end_line,
                start_char=get_char_pos(start_line),
                end_char=get_char_pos(end_line + 1),
            )
        )

    return sorted(blocks, key=lambda b: b.start_line)


def find_containing_block(char_pos: int, blocks: list[CodeBlock]) -> CodeBlock | None:
    """Find the innermost block containing a character position."""
    containing = None
    for block in blocks:
        if block.start_char <= char_pos < block.end_char:
            if containing is None or (block.end_char - block.start_char) < (
                containing.end_char - containing.start_char
            ):
                containing = block
    return containing


def find_blocks(source: str, language: str) -> list[CodeBlock]:
    """Dispatcher: route to AST or regex based on language."""
    if language == "python":
        return find_python_blocks(source)
    return find_blocks_regex(source)
