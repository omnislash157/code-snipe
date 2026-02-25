#!/usr/bin/env python3
"""
CODE_SMELLS - Runtime Error Detector (replaces analyzers.py)

Finds code patterns that WILL blow up in production.
Not linter territory. Not style. ACTUAL CRASHES.

DROP-IN REPLACEMENT for analyzers.py:
- find_env_vars()     - Backwards compatible
- load_dotenv_vars()  - Backwards compatible
- find_secrets()      - Backwards compatible
- EnvUsage           - Same dataclass
- find_markers()      - DEPRECATED (was noise)
- find_circular()     - DEPRECATED (use SuperGlob)
- find_orphan_files() - DEPRECATED (use SuperGlob)
- compute_ripple()    - DEPRECATED (use HOUND v2)

Categories:
    NAKED_*     - Operations without try/except that commonly fail
    UNSAFE_*    - Security/injection risks
    GOTCHA_*    - Python-specific traps
    DEBUG_*     - Leftover debug code

Usage:
    # New API
    from code_smells import CodeSmells
    result = CodeSmells("/path/to/project").scan()
    print(result.to_markdown())

    # Backwards compatible API
    from code_smells import find_env_vars, load_dotenv_vars, EnvUsage
    dotenv = load_dotenv_vars(root)
    env_usage = find_env_vars(filepath, root, dotenv)

Version: 2.0.0 - The Analyzers Killer
"""

import ast
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# =============================================================================
# CONFIGURATION
# =============================================================================

HEAVY_BAR = "=" * 68
LIGHT_BAR = "-" * 68

IGNORE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "target",
    "vendor",
    ".idea",
    ".vscode",
    "coverage",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "eggs",
    "*.egg-info",
}

# Severity levels
CRITICAL = "CRITICAL"  # Will crash, security hole
HIGH = "HIGH"  # Likely to crash
MEDIUM = "MEDIUM"  # May crash under conditions
LOW = "LOW"  # Code smell, potential issue


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class Smell:
    """Single code smell finding."""

    category: str
    severity: str
    filepath: str
    line_num: int
    code: str
    message: str
    suggestion: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "filepath": self.filepath,
            "line_num": self.line_num,
            "code": self.code,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class EnvUsage:
    """Environment variable usage (backwards compatible with analyzers.py)."""

    var_name: str
    filepath: str
    line_num: int
    has_default: bool
    in_dotenv: bool = False


@dataclass
class ImportInfo:
    """Import information for a file (backwards compatible with analyzers.py)."""

    filepath: str
    imports: list[tuple[int, str]]  # (line_num, import_statement)
    imports_from: set[str]  # Module names this file imports from
    imported_by: set[str] = field(default_factory=set)  # Files that import this


@dataclass
class SmellResult:
    """Complete scan result."""

    path: str
    files_scanned: int
    smells: list[Smell] = field(default_factory=list)
    env_vars: list[EnvUsage] = field(default_factory=list)
    dotenv_vars: set[str] = field(default_factory=set)

    @property
    def critical_count(self) -> int:
        return sum(1 for s in self.smells if s.severity == CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for s in self.smells if s.severity == HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for s in self.smells if s.severity == MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for s in self.smells if s.severity == LOW)

    def summary(self) -> str:
        if not self.smells:
            return "No smells detected"
        return f"{self.critical_count} CRITICAL | {self.high_count} HIGH | {self.medium_count} MEDIUM | {self.low_count} LOW"

    def missing_env_vars(self) -> list[EnvUsage]:
        """Env vars used but not in .env files."""
        return [e for e in self.env_vars if not e.in_dotenv]

    def no_default_env_vars(self) -> list[EnvUsage]:
        """Env vars without defaults (crash if missing)."""
        return [e for e in self.env_vars if not e.has_default]

    def to_markdown(self) -> str:
        lines = [
            HEAVY_BAR,
            "CODE SMELLS REPORT".center(68),
            HEAVY_BAR,
            "",
            f"Path: {self.path}",
            f"Files scanned: {self.files_scanned}",
            f"Total smells: {len(self.smells)}",
            f"Summary: {self.summary()}",
            "",
        ]

        # Environment variables section
        if self.env_vars:
            lines.append(LIGHT_BAR)
            lines.append("ENVIRONMENT VARIABLES")
            lines.append(LIGHT_BAR)

            missing = self.missing_env_vars()
            no_default = self.no_default_env_vars()

            if missing:
                lines.append(f"\nMISSING FROM .env ({len(missing)}):")
                for e in missing[:10]:
                    lines.append(f"  {e.var_name} - {e.filepath}:L{e.line_num}")
                if len(missing) > 10:
                    lines.append(f"  ... and {len(missing) - 10} more")

            if no_default:
                lines.append(f"\nNO DEFAULT VALUE ({len(no_default)}):")
                for e in no_default[:10]:
                    lines.append(f"  {e.var_name} - {e.filepath}:L{e.line_num}")
                if len(no_default) > 10:
                    lines.append(f"  ... and {len(no_default) - 10} more")

            lines.append("")

        # Smells by category
        if self.smells:
            by_category: dict[str, list[Smell]] = defaultdict(list)
            for smell in self.smells:
                by_category[smell.category].append(smell)

            for category in sorted(by_category.keys()):
                cat_smells = by_category[category]
                lines.append(LIGHT_BAR)
                lines.append(f"{category} ({len(cat_smells)})")
                lines.append(LIGHT_BAR)

                for smell in cat_smells[:15]:
                    sev_icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}
                    lines.append(
                        f"[{sev_icon.get(smell.severity, '?')}] {smell.filepath}:L{smell.line_num}"
                    )
                    lines.append(f"    {smell.code[:60]}{'...' if len(smell.code) > 60 else ''}")
                    lines.append(f"    -> {smell.message}")
                    if smell.suggestion:
                        lines.append(f"    FIX: {smell.suggestion}")
                    lines.append("")

                if len(cat_smells) > 15:
                    lines.append(f"... and {len(cat_smells) - 15} more in this category\n")

        return "\n".join(lines)

    def to_triage(self) -> str:
        """
        ADHD-friendly triage view. Shows only what matters:
        - CRITICAL/HIGH = FIX NOW
        - Everything else = summary counts only
        """
        lines = []

        # Header with verdict
        crit_high = self.critical_count + self.high_count
        if crit_high == 0:
            lines.append("ALL CLEAR - No critical issues")
            lines.append(
                f"  {self.files_scanned} files | {self.medium_count} medium | {self.low_count} low"
            )
        else:
            lines.append(f"FIX NOW: {crit_high} issue{'s' if crit_high != 1 else ''}")
            lines.append("")

            # Show critical/high only
            for smell in self.smells:
                if smell.severity in (CRITICAL, HIGH):
                    icon = "!!!" if smell.severity == CRITICAL else "!!"
                    lines.append(f"[{icon}] {smell.category}")
                    lines.append(f"    {smell.filepath}:{smell.line_num}")
                    lines.append(f"    {smell.message}")
                    if smell.suggestion:
                        lines.append(f"    FIX: {smell.suggestion}")
                    lines.append("")

            # Quick counts for rest
            if self.medium_count or self.low_count:
                lines.append(
                    f"Also: {self.medium_count} medium, {self.low_count} low (run --full for details)"
                )

        # Env var warnings (only if missing critical ones)
        no_default = self.no_default_env_vars()
        critical_vars = [e for e in no_default if not e.in_dotenv]
        if critical_vars:
            lines.append("")
            lines.append(f"ENV WARNING: {len(critical_vars)} vars with no default and not in .env")
            for e in critical_vars[:5]:
                lines.append(f"  {e.var_name} ({e.filepath})")
            if len(critical_vars) > 5:
                lines.append(f"  ... and {len(critical_vars) - 5} more")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "files_scanned": self.files_scanned,
            "summary": self.summary(),
            "counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "smells": [s.to_dict() for s in self.smells],
            "env_vars": {
                "total": len(self.env_vars),
                "missing_from_dotenv": len(self.missing_env_vars()),
                "no_default": len(self.no_default_env_vars()),
            },
        }


# =============================================================================
# AST VISITORS FOR ACCURATE DETECTION
# =============================================================================


class NakedOperationVisitor(ast.NodeVisitor):
    """
    Finds operations that should be wrapped in try/except but aren't.
    Uses AST to avoid false positives from comments/strings.
    """

    def __init__(self, filepath: str, source_lines: list[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.smells: list[Smell] = []
        self.in_try_block = False
        self.try_depth = 0

    def visit_Try(self, node: ast.Try):
        """Track when we're inside a try block."""
        self.try_depth += 1
        self.in_try_block = True
        self.generic_visit(node)
        self.try_depth -= 1
        if self.try_depth == 0:
            self.in_try_block = False

    def _get_line(self, lineno: int) -> str:
        """Get source line safely."""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add_smell(
        self, category: str, severity: str, node: ast.AST, message: str, suggestion: str = None
    ):
        """Add a smell if not in try block."""
        if not self.in_try_block:
            self.smells.append(
                Smell(
                    category=category,
                    severity=severity,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    code=self._get_line(node.lineno),
                    message=message,
                    suggestion=suggestion,
                )
            )

    def visit_Call(self, node: ast.Call):
        """Check function calls for naked operations."""
        func_name = self._get_func_name(node)

        # NAKED_JSON: json.loads(), json.load()
        if func_name in ("json.loads", "json.load", "loads", "load"):
            # Check if it's actually json module
            if self._is_json_call(node):
                self._add_smell(
                    "NAKED_JSON",
                    HIGH,
                    node,
                    "json.loads/load without try/except - JSONDecodeError",
                    "Wrap in try/except JSONDecodeError",
                )

        # NAKED_CAST: int(), float() on variables (not literals)
        # Skip safe patterns: int(time.time()), int(os.getenv('X', '123')), etc
        if func_name in ("int", "float") and node.args:
            arg = node.args[0]
            if not isinstance(arg, ast.Constant):
                # Check if arg is a safe call that always returns numeric
                is_safe = False
                if isinstance(arg, ast.Call):
                    inner_name = self._get_func_name(arg)
                    safe_funcs = (
                        "time.time",
                        "len",
                        "sum",
                        "min",
                        "max",
                        "abs",
                        "round",
                        "math.floor",
                        "math.ceil",
                        "math.sqrt",
                    )
                    if inner_name in safe_funcs or inner_name.startswith("len("):
                        is_safe = True
                    # os.getenv with numeric default is safe
                    elif inner_name in ("os.getenv", "getenv", "os.environ.get"):
                        # Check if it has a default (2nd arg) that's numeric
                        if len(arg.args) >= 2:
                            default_arg = arg.args[1]
                            if isinstance(default_arg, ast.Constant):
                                # Default is a string that looks numeric
                                val = str(default_arg.value)
                                if val.replace(".", "").replace("-", "").isdigit():
                                    is_safe = True
                elif isinstance(arg, ast.BinOp):
                    # Arithmetic on numbers: int(x * 1000) etc
                    is_safe = True

                if not is_safe:
                    self._add_smell(
                        "NAKED_CAST",
                        MEDIUM,
                        node,
                        f"{func_name}() on variable - ValueError if not numeric",
                        "Wrap in try/except ValueError or validate first",
                    )

        # NAKED_NEXT: next() without default
        if func_name == "next" and len(node.args) == 1:
            self._add_smell(
                "NAKED_NEXT",
                MEDIUM,
                node,
                "next() without default - StopIteration if empty",
                "Use next(iter, default) or wrap in try/except",
            )

        # NAKED_GETATTR: getattr() without default (3rd arg)
        if func_name == "getattr" and len(node.args) == 2:
            self._add_smell(
                "NAKED_GETATTR",
                MEDIUM,
                node,
                "getattr() without default - AttributeError if missing",
                "Add third argument: getattr(obj, 'attr', None)",
            )

        # NAKED_NETWORK: requests.*, httpx.*, aiohttp.* HTTP methods
        # Only flag actual HTTP calls, not Session() creation
        network_methods = (".get", ".post", ".put", ".delete", ".patch", ".head", ".options")
        if any(func_name.startswith(p) for p in ("requests.", "httpx.", "aiohttp.")):
            if any(func_name.endswith(m) for m in network_methods):
                self._add_smell(
                    "NAKED_NETWORK",
                    HIGH,
                    node,
                    f"{func_name}() without try/except - ConnectionError, Timeout",
                    "Wrap in try/except (requests.RequestException or similar)",
                )

        # NAKED_DB: database connections/queries
        # Only flag if the call chain includes a known DB module
        db_modules = ("psycopg", "mysql", "sqlite", "asyncpg", "aiomysql", "pymongo", "redis")
        func_lower = func_name.lower()
        if any(m in func_lower for m in db_modules):
            if any(p in func_lower for p in ("connect", "execute", "cursor", "query")):
                self._add_smell(
                    "NAKED_DB",
                    HIGH,
                    node,
                    "Database operation without try/except",
                    "Wrap in try/except for connection/query errors",
                )

        # UNSAFE_EVAL: eval(), exec()
        if func_name in ("eval", "exec"):
            self._add_smell(
                "UNSAFE_EVAL",
                CRITICAL,
                node,
                f"{func_name}() is a code injection risk",
                "Use ast.literal_eval() for data, or avoid entirely",
            )

        # UNSAFE_SHELL: subprocess with shell=True
        if func_name in ("subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"):
            if self._has_shell_true(node) or func_name == "os.system":
                self._add_smell(
                    "UNSAFE_SHELL",
                    CRITICAL,
                    node,
                    "Shell command execution - injection risk",
                    "Use subprocess with shell=False and list args",
                )

        # DEBUG_PRINT: print() statements (in non-test files)
        if func_name == "print" and "test_" not in self.filepath:
            self._add_smell(
                "DEBUG_PRINT",
                LOW,
                node,
                "print() statement - use logging instead",
                "Replace with logging.debug/info/warning",
            )

        # DEBUG_BREAKPOINT: breakpoint(), pdb.set_trace()
        if func_name in ("breakpoint", "pdb.set_trace", "ipdb.set_trace"):
            self._add_smell(
                "DEBUG_BREAKPOINT",
                CRITICAL,
                node,
                f"{func_name}() will halt production!",
                "Remove before deploying",
            )

        # DEBUG_ICECREAM: ic() from icecream
        if func_name == "ic":
            self._add_smell(
                "DEBUG_ICECREAM",
                MEDIUM,
                node,
                "ic() debug call - remove before production",
                "Remove or wrap in if DEBUG:",
            )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Check dict[key] and list[index] access."""
        # Skip type annotations - check if we're in a type context
        # Type annotations use ast.Subscript for generics like Dict[str, int]
        if self._is_type_annotation_context(node):
            self.generic_visit(node)
            return

        # Skip if the value being subscripted is a Name that looks like a type
        # (uppercase first letter typically indicates a type)
        if isinstance(node.value, ast.Name):
            name = node.value.id
            # Common type names or uppercase = likely type annotation
            if (
                name
                in (
                    "Dict",
                    "List",
                    "Set",
                    "Tuple",
                    "Optional",
                    "Union",
                    "Callable",
                    "Type",
                    "Any",
                    "Sequence",
                    "Mapping",
                    "Iterable",
                    "Iterator",
                    "Generator",
                )
                or name[0].isupper()
            ):
                self.generic_visit(node)
                return

        # Only flag NAKED_KEY for genuinely risky patterns
        # Skip: db row access, known dict builds, dataclass fields - too much noise
        # Flag: json.loads()['key'], request.json['key'] - external untrusted data
        if isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                line = self._get_line(node.lineno)
                # Only flag if accessing parsed JSON or request data
                if "json.loads" in line or "request.json" in line or ".json()" in line:
                    self._add_smell(
                        "NAKED_KEY",
                        HIGH,
                        node,
                        'dict["key"] on parsed JSON - KeyError if key missing',
                        "Use dict.get('key') or wrap in try/except",
                    )
                # Skip everything else - db rows, known dicts are typically safe
        elif isinstance(node.slice, (ast.Name, ast.BinOp, ast.Call)):
            # list[variable] or list[i+1] - could be IndexError
            # But only flag if it looks like actual runtime indexing
            # Skip things like: for i, x in enumerate(items): items[i]
            # Those are usually safe within loops
            line = self._get_line(node.lineno)

            # Skip if it's in a comprehension-like pattern or return type
            if " -> " not in line and ": " not in line.split("=")[0] if "=" in line else True:
                # Only flag split()[n] patterns - those are genuinely dangerous
                if ".split(" in line or "partition" in line:
                    self._add_smell(
                        "NAKED_INDEX",
                        HIGH,
                        node,
                        "Index on split() result - IndexError if not enough parts",
                        "Check length first: parts = s.split(); val = parts[1] if len(parts) > 1 else default",
                    )

        self.generic_visit(node)

    def _is_type_annotation_context(self, node: ast.AST) -> bool:
        """Check if we're inside a type annotation."""
        # This is a heuristic - type annotations appear in:
        # - function arguments (arg.annotation)
        # - function return types (FunctionDef.returns)
        # - variable annotations (AnnAssign.annotation)
        # Unfortunately AST doesn't give us parent context easily
        # So we check the source line for annotation patterns
        line = self._get_line(node.lineno)
        # If line has : Type or -> Type pattern, likely annotation
        if re.search(r":\s*[A-Z]", line) or re.search(r"->\s*[A-Z]", line):
            return True
        return False

    def visit_Attribute(self, node: ast.Attribute):
        """Detect deep chained attribute access a.b.c.d."""
        depth = self._get_chain_depth(node)
        if depth >= 4:
            self._add_smell(
                "CHAINED_ACCESS",
                MEDIUM,
                node,
                f"Deep attribute chain ({depth} levels) - any can be None",
                "Use getattr with defaults or add None checks",
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check function definitions for gotchas."""
        self._check_mutable_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Check async function definitions."""
        self._check_mutable_defaults(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Check for bare except or overly broad except."""
        if node.type is None:
            self._add_smell_always(
                "GOTCHA_BARE_EXCEPT",
                HIGH,
                node,
                "Bare 'except:' catches everything including KeyboardInterrupt",
                "Use 'except Exception:' at minimum",
            )
        elif isinstance(node.type, ast.Name):
            if node.type.id == "Exception":
                # Check if the body just passes or logs
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    self._add_smell_always(
                        "GOTCHA_SILENT_EXCEPT",
                        MEDIUM,
                        node,
                        "'except Exception: pass' silently swallows errors",
                        "At minimum log the exception",
                    )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Check for assert in business logic."""
        # Skip if it looks like a test assertion
        if "test_" not in self.filepath.lower():
            self._add_smell(
                "GOTCHA_ASSERT",
                MEDIUM,
                node,
                "assert removed with python -O flag",
                "Use explicit if/raise for business logic validation",
            )
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        """Check for file opens - these are actually OK in with blocks."""
        # with open() is fine, but open() alone is not
        self.generic_visit(node)

    def _add_smell_always(
        self, category: str, severity: str, node: ast.AST, message: str, suggestion: str = None
    ):
        """Add a smell regardless of try block (for except handler issues)."""
        self.smells.append(
            Smell(
                category=category,
                severity=severity,
                filepath=self.filepath,
                line_num=node.lineno,
                code=self._get_line(node.lineno),
                message=message,
                suggestion=suggestion,
            )
        )

    def _check_mutable_defaults(self, node):
        """Check for mutable default arguments."""
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_smell_always(
                    "GOTCHA_MUTABLE_DEFAULT",
                    HIGH,
                    node,
                    f"Mutable default argument in {node.name}() - shared across calls!",
                    "Use None as default and create inside function",
                )

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _is_json_call(self, node: ast.Call) -> bool:
        """Check if this is actually a json module call."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id == "json"
        elif isinstance(node.func, ast.Name):
            # Could be `from json import loads`
            return node.func.id in ("loads", "load")
        return False

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if call has shell=True."""
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
                elif isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                    return True
        return False

    def _get_chain_depth(self, node: ast.Attribute) -> int:
        """Count depth of chained attribute access."""
        depth = 1
        current = node.value
        while isinstance(current, ast.Attribute):
            depth += 1
            current = current.value
        return depth


class OpenFileVisitor(ast.NodeVisitor):
    """Separate visitor for file open detection - needs context awareness."""

    def __init__(self, filepath: str, source_lines: list[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.smells: list[Smell] = []
        self.in_try = False
        self.in_with = False

    def visit_Try(self, node):
        old = self.in_try
        self.in_try = True
        self.generic_visit(node)
        self.in_try = old

    def visit_With(self, node):
        old = self.in_with
        self.in_with = True
        self.generic_visit(node)
        self.in_with = old

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Check for open() or Path().read_text/write_text
        if func_name == "open" and not self.in_try and not self.in_with:
            self.smells.append(
                Smell(
                    category="NAKED_FILE",
                    severity=HIGH,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    code=self._get_line(node.lineno),
                    message="open() without with-block or try/except",
                    suggestion="Use 'with open(...) as f:' pattern",
                )
            )

        if func_name in ("read_text", "read_bytes", "write_text", "write_bytes"):
            if not self.in_try:
                self.smells.append(
                    Smell(
                        category="NAKED_FILE",
                        severity=MEDIUM,
                        filepath=self.filepath,
                        line_num=node.lineno,
                        code=self._get_line(node.lineno),
                        message=f"Path.{func_name}() without try/except",
                        suggestion="Wrap in try/except FileNotFoundError",
                    )
                )

        self.generic_visit(node)

    def _get_line(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""


# =============================================================================
# REGEX-BASED DETECTORS (for non-AST patterns)
# =============================================================================

# Environment variable patterns
# NOTE: Order matters - more specific patterns first to avoid double-matching
# e.g., decouple.env must use word boundary to not match inside os.getenv
ENV_PATTERNS = [
    (r'os\.getenv\(["\'](\w+)["\'](?:\s*,\s*([^)]+))?\)', "os.getenv"),
    (r'os\.environ\[["\'](\w+)["\']\]', "os.environ[]"),
    (r'os\.environ\.get\(["\'](\w+)["\'](?:\s*,\s*([^)]+))?\)', "os.environ.get"),
    (r'(?<![a-zA-Z])env\(["\'](\w+)["\']', "decouple.env"),  # negative lookbehind to skip getenv
    (r'(?<![a-zA-Z])config\(["\'](\w+)["\']', "decouple.config"),  # same for config
]

# Hardcoded secrets patterns
SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?:secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
    (r'(?:api_key|apikey)\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded API key"),
    (r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded token"),
    (r'(?:aws_access_key_id|aws_secret)\s*=\s*["\'][A-Z0-9]{16,}["\']', "AWS credential"),
    (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "Private key in code"),
    (r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT token"),
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s', "SQL with % formatting"),
    (r'(?:execute|cursor\.execute)\s*\(\s*f["\']', "SQL with f-string"),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\+', "SQL with concatenation"),
    (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\.format\(', "SQL with .format()"),
]


def _find_env_vars(content: str, filepath: str, dotenv_vars: set[str]) -> list[EnvUsage]:
    """Find environment variable usage."""
    env_vars = []
    seen = set()  # Dedupe by (var_name, line_num)
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for pattern, _ in ENV_PATTERNS:
            for match in re.finditer(pattern, line):
                var_name = match.group(1)

                # Dedupe - only keep first match per var per line
                key = (var_name, line_num)
                if key in seen:
                    continue
                seen.add(key)

                # Check for default value
                has_default = False
                if match.lastindex and match.lastindex >= 2 and match.group(2):
                    has_default = True
                elif "environ[" in pattern:
                    # environ[] access never has default
                    has_default = False

                env_vars.append(
                    EnvUsage(
                        var_name=var_name,
                        filepath=filepath,
                        line_num=line_num,
                        has_default=has_default,
                        in_dotenv=var_name in dotenv_vars,
                    )
                )

    return env_vars


def _find_secrets(content: str, filepath: str) -> list[Smell]:
    """Find hardcoded secrets."""
    smells = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        # Skip obvious test/example values
        if any(
            x in line.lower()
            for x in ["example", "test", "dummy", "placeholder", "xxx", "changeme"]
        ):
            continue

        for pattern, desc in SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                smells.append(
                    Smell(
                        category="UNSAFE_SECRET",
                        severity=CRITICAL,
                        filepath=filepath,
                        line_num=line_num,
                        code=stripped[:60] + ("..." if len(stripped) > 60 else ""),
                        message=desc,
                        suggestion="Use environment variables or secrets manager",
                    )
                )
                break

    return smells


def _find_sql_injection(content: str, filepath: str) -> list[Smell]:
    """Find SQL injection vulnerabilities."""
    smells = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in SQL_INJECTION_PATTERNS:
            if re.search(pattern, line):
                smells.append(
                    Smell(
                        category="UNSAFE_SQL",
                        severity=CRITICAL,
                        filepath=filepath,
                        line_num=line_num,
                        code=stripped[:60] + ("..." if len(stripped) > 60 else ""),
                        message=f"SQL injection risk: {desc}",
                        suggestion="Use parameterized queries: cursor.execute('SELECT * FROM x WHERE id = %s', (id,))",
                    )
                )
                break

    return smells


def _load_dotenv_vars(root: Path) -> set[str]:
    """Load variable names from .env files."""
    env_files = [
        root / ".env",
        root / ".env.example",
        root / ".env.local",
        root / ".env.development",
        root / ".env.production",
    ]

    vars_found = set()
    for env_file in env_files:
        if env_file.exists():
            try:
                for line in env_file.read_text().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        var_name = line.split("=")[0].strip()
                        vars_found.add(var_name)
            except Exception:
                pass

    return vars_found


# =============================================================================
# MAIN CLASS
# =============================================================================


class CodeSmells:
    """
    Runtime error detector. Finds code that WILL crash.

    Usage:
        smells = CodeSmells("/path/to/project")
        result = smells.scan()
        print(result.to_markdown())
    """

    def __init__(self, path: str = ".", project_root: str = None):
        self.path = Path(path).resolve()
        self.scan_root = self.path if self.path.is_dir() else self.path.parent
        # Project root for .env lookup - walk up to find .git or .env
        if project_root:
            self.project_root = Path(project_root).resolve()
        else:
            self.project_root = self._find_project_root()

    def _find_project_root(self) -> Path:
        """Walk up from scan path to find project root (.git, .env, pyproject.toml)."""
        current = self.scan_root
        for _ in range(10):  # Max 10 levels up
            if (current / ".git").exists():
                return current
            if (current / ".env").exists():
                return current
            if (current / "pyproject.toml").exists():
                return current
            parent = current.parent
            if parent == current:
                break
            current = parent
        return self.scan_root  # Fallback to scan root

    def scan(self) -> SmellResult:
        """Scan path for code smells."""
        files_to_scan: list[Path] = []

        if self.path.is_file():
            files_to_scan = [self.path]
        else:
            for filepath in self.path.rglob("*.py"):
                if any(part in IGNORE_DIRS for part in filepath.parts):
                    continue
                files_to_scan.append(filepath)

        # Load .env vars from project root (not scan path)
        dotenv_vars = _load_dotenv_vars(self.project_root)

        # Scan files in parallel
        all_smells: list[Smell] = []
        all_env_vars: list[EnvUsage] = []

        if files_to_scan:
            with ThreadPoolExecutor(max_workers=min(32, len(files_to_scan))) as executor:
                futures = {
                    executor.submit(self._scan_file, fp, dotenv_vars): fp for fp in files_to_scan
                }
                for future in as_completed(futures):
                    smells, env_vars = future.result()
                    all_smells.extend(smells)
                    all_env_vars.extend(env_vars)

        # Sort by severity
        severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
        all_smells.sort(key=lambda s: (severity_order.get(s.severity, 99), s.filepath, s.line_num))

        return SmellResult(
            path=str(self.path),
            files_scanned=len(files_to_scan),
            smells=all_smells,
            env_vars=all_env_vars,
            dotenv_vars=dotenv_vars,
        )

    def scan_file(self, filepath: str) -> SmellResult:
        """Scan a single file."""
        fp = Path(filepath)
        if not fp.is_absolute():
            fp = self.scan_root / fp

        dotenv_vars = _load_dotenv_vars(self.project_root)
        smells, env_vars = self._scan_file(fp, dotenv_vars)

        return SmellResult(
            path=str(fp),
            files_scanned=1,
            smells=smells,
            env_vars=env_vars,
            dotenv_vars=dotenv_vars,
        )

    def _scan_file(
        self, filepath: Path, dotenv_vars: set[str]
    ) -> tuple[list[Smell], list[EnvUsage]]:
        """Internal file scanning."""
        smells: list[Smell] = []
        env_vars: list[EnvUsage] = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return smells, env_vars

        try:
            rel_path = str(filepath.relative_to(self.scan_root))
        except ValueError:
            rel_path = str(filepath)

        lines = content.split("\n")

        # AST-based detection
        try:
            tree = ast.parse(content)

            # Naked operations visitor
            visitor = NakedOperationVisitor(rel_path, lines)
            visitor.visit(tree)
            smells.extend(visitor.smells)

            # File open visitor
            file_visitor = OpenFileVisitor(rel_path, lines)
            file_visitor.visit(tree)
            smells.extend(file_visitor.smells)

        except SyntaxError:
            # Can't parse, skip AST-based checks
            pass

        # Regex-based detection
        env_vars.extend(_find_env_vars(content, rel_path, dotenv_vars))
        smells.extend(_find_secrets(content, rel_path))
        smells.extend(_find_sql_injection(content, rel_path))

        return smells, env_vars


# =============================================================================
# BACKWARDS COMPATIBLE API (replaces analyzers.py)
# =============================================================================


def find_env_vars(filepath: Path, root: Path, dotenv_vars: set[str]) -> list[EnvUsage]:
    """
    Find all environment variable usage in a file.

    Backwards compatible with analyzers.py API.

    Args:
        filepath: Path to the file to analyze
        root: Project root for relative path calculation
        dotenv_vars: Set of variable names present in .env

    Returns:
        List of EnvUsage objects
    """
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    try:
        rel_path = str(filepath.relative_to(root))
    except ValueError:
        rel_path = str(filepath)

    return _find_env_vars(content, rel_path, dotenv_vars)


def load_dotenv_vars(root: Path) -> set[str]:
    """
    Load variable names from .env files.

    Backwards compatible with analyzers.py API.

    Args:
        root: Project root path

    Returns:
        Set of variable names found in .env files
    """
    return _load_dotenv_vars(root)


def find_secrets(filepath: Path, root: Path) -> list[Smell]:
    """
    Find potential hardcoded secrets in a file.

    Backwards compatible with analyzers.py API.

    Args:
        filepath: Path to the file to analyze
        root: Project root for relative path calculation

    Returns:
        List of Smell objects for potential secrets
    """
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    try:
        rel_path = str(filepath.relative_to(root))
    except ValueError:
        rel_path = str(filepath)

    return _find_secrets(content, rel_path)


# =============================================================================
# DEPRECATION STUBS (point to new locations)
# =============================================================================


def find_markers(*args, **kwargs):
    """DEPRECATED: Removed - was noise, not signal.

    TODO/FIXME/HACK markers are IDE territory. CodeSmells focuses on
    actual runtime errors, not documentation markers.
    """
    import warnings

    warnings.warn(
        "find_markers() removed from analyzers. "
        "Use your IDE for TODO/FIXME tracking. "
        "CodeSmells focuses on actual runtime errors.",
        DeprecationWarning,
        stacklevel=2,
    )
    return []


def find_circular_imports(*args, **kwargs):
    """DEPRECATED: Use SuperGlob instead.

    SuperGlob detects circular imports as part of comprehensive import analysis.

    Usage:
        from superglob import superglob
        result = superglob("/path/to/project")
        circular = [p for p in result.problems if p.category == "CIRCULAR_IMPORT"]
    """
    import warnings

    warnings.warn(
        "find_circular_imports() moved to SuperGlob. "
        "Use: superglob(path).problems for CIRCULAR_IMPORT detection.",
        DeprecationWarning,
        stacklevel=2,
    )
    return []


def find_orphan_files(*args, **kwargs):
    """DEPRECATED: Use SuperGlob instead.

    SuperGlob detects orphan modules as part of comprehensive import analysis.

    Usage:
        from superglob import superglob
        result = superglob("/path/to/project")
        orphans = [p for p in result.problems if p.category == "ORPHAN_MODULE"]
    """
    import warnings

    warnings.warn(
        "find_orphan_files() moved to SuperGlob. "
        "Use: superglob(path).problems for ORPHAN_MODULE detection.",
        DeprecationWarning,
        stacklevel=2,
    )
    return []


def compute_ripple(*args, **kwargs):
    """DEPRECATED: Use SuperGlob for import mapping instead.

    SuperGlob provides file-level import analysis. For blast radius,
    use RECON which combines SuperGlob + CodeHound.

    Usage:
        from superglob import superglob
        result = superglob('path/to/folder')
        print(result.to_markdown())
    """
    import warnings

    warnings.warn(
        "compute_ripple() deprecated. Use: superglob(path) for import analysis "
        "or recon(term, path) for full blast radius.",
        DeprecationWarning,
        stacklevel=2,
    )
    return set()


def is_entrypoint(filepath: Path, root: Path = None) -> bool:
    """
    Check if file is an entrypoint (has __main__ block or is named main.py).

    Kept for backwards compatibility.
    """
    if filepath.name in ("main.py", "__main__.py"):
        return True
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        return "if __name__" in content and "__main__" in content
    except Exception:
        return False


# Legacy data classes for backwards compatibility
# RiskItem is now Smell, but we alias it
RiskItem = Smell


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main class
    "CodeSmells",
    # Data classes
    "Smell",
    "EnvUsage",
    "ImportInfo",
    "SmellResult",
    # Backwards compatible functions
    "find_env_vars",
    "load_dotenv_vars",
    "find_secrets",
    "is_entrypoint",
    # Deprecated (will warn)
    "find_markers",
    "find_circular_imports",
    "find_orphan_files",
    "compute_ripple",
    # Legacy alias
    "RiskItem",
    # Severity constants
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]


# =============================================================================
# CLI
# =============================================================================


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="CodeSmells - Find code that will crash")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument(
        "--triage", "-t", action="store_true", help="Quick triage: show only CRITICAL/HIGH issues"
    )
    parser.add_argument("--env", "-e", action="store_true", help="Show only env var issues")
    parser.add_argument("--critical", "-c", action="store_true", help="Show only critical issues")
    parser.add_argument("--high", action="store_true", help="Show critical + high issues")
    parser.add_argument("--no-print", action="store_true", help="Exclude DEBUG_PRINT findings")
    parser.add_argument("--summary", "-s", action="store_true", help="Show summary only")
    parser.add_argument("--full", "-f", action="store_true", help="Full report (default)")

    args = parser.parse_args()

    scanner = CodeSmells(args.path)
    result = scanner.scan()

    # Filter smells based on flags
    filtered_smells = result.smells
    if args.no_print:
        filtered_smells = [s for s in filtered_smells if s.category != "DEBUG_PRINT"]
    if args.critical:
        filtered_smells = [s for s in filtered_smells if s.severity == CRITICAL]
    elif args.high:
        filtered_smells = [s for s in filtered_smells if s.severity in (CRITICAL, HIGH)]

    if args.json:
        output = result.to_dict()
        output["smells"] = [s.to_dict() for s in filtered_smells]
        print(json.dumps(output, indent=2))
    elif args.triage:
        print(result.to_triage())
    elif args.env:
        print(f"Environment Variables in {result.path}")
        print(LIGHT_BAR)
        missing = result.missing_env_vars()
        no_default = result.no_default_env_vars()

        if missing:
            print(f"\nMISSING FROM .env ({len(missing)}):")
            for e in missing:
                print(f"  {e.var_name} - {e.filepath}:L{e.line_num}")

        if no_default:
            print(f"\nNO DEFAULT ({len(no_default)}):")
            for e in no_default:
                print(f"  {e.var_name} - {e.filepath}:L{e.line_num}")

        if not missing and not no_default:
            print("All env vars accounted for!")
    elif args.summary:
        crit = sum(1 for s in filtered_smells if s.severity == CRITICAL)
        high = sum(1 for s in filtered_smells if s.severity == HIGH)
        med = sum(1 for s in filtered_smells if s.severity == MEDIUM)
        low = sum(1 for s in filtered_smells if s.severity == LOW)
        print(f"CodeSmells: {result.path}")
        print(f"Files: {result.files_scanned} | Findings: {len(filtered_smells)}")
        print(f"  {crit} CRITICAL | {high} HIGH | {med} MEDIUM | {low} LOW")

        # Category breakdown
        from collections import Counter

        cats = Counter(s.category for s in filtered_smells)
        if cats:
            print("\nBy category:")
            for cat, count in sorted(cats.items(), key=lambda x: -x[1])[:10]:
                print(f"  {count:4d}  {cat}")
    elif args.critical:
        print(f"CRITICAL Issues in {result.path}")
        print(LIGHT_BAR)
        if filtered_smells:
            for s in filtered_smells:
                print(f"[!!!] {s.filepath}:L{s.line_num}")
                print(f"      {s.code}")
                print(f"      {s.message}")
                if s.suggestion:
                    print(f"      FIX: {s.suggestion}")
                print()
        else:
            print("No critical issues found!")
    elif args.high:
        print(f"CRITICAL + HIGH Issues in {result.path}")
        print(LIGHT_BAR)
        if filtered_smells:
            for s in filtered_smells:
                icon = "!!!" if s.severity == CRITICAL else "!!"
                print(f"[{icon}] {s.filepath}:L{s.line_num}")
                print(f"      {s.code}")
                print(f"      {s.message}")
                if s.suggestion:
                    print(f"      FIX: {s.suggestion}")
                print()
        else:
            print("No critical/high issues found!")
    else:
        # Replace smells with filtered for output
        result.smells = filtered_smells
        print(result.to_markdown())


if __name__ == "__main__":
    main()
