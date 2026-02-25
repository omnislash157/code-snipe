#!/usr/bin/env python3
"""
import_wiz.py - Import Map + Problem Detector

Point at paths. Get all imports + problems.

Usage:
    import_wiz(".")                              # Current directory
    import_wiz("auth/auth_service.py")           # Single file
    import_wiz("file1.py", "file2.py", "auth/")  # Multiple paths

Returns:
    - All imports with line numbers
    - Import classification: standard, lazy, conditional, dynamic, type-only
    - Problems: dead imports, circular, missing deps, orphans

Version: 4.0.0
"""

import ast
import json
import os
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
BOX_TOP = "+" + "=" * 66 + "+"
BOX_BOT = "+" + "=" * 66 + "+"

LAZY_THRESHOLD = 30

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

IMPORT_PATTERNS = {
    ".py": [r"^import\s+", r"^from\s+\S+\s+import\s+"],
    ".js": [r"^import\s+", r"^const\s+\S+\s*=\s*require\s*\(", r"^let\s+\S+\s*=\s*require\s*\("],
    ".ts": [r"^import\s+"],
    ".jsx": [r"^import\s+"],
    ".tsx": [r"^import\s+"],
    ".go": [r"^import\s+"],
    ".rs": [r"^use\s+", r"^extern\s+crate\s+"],
    ".rb": [r"^require\s+", r"^require_relative\s+", r"^load\s+"],
}

STDLIB_MODULES = {
    "abc",
    "aifc",
    "argparse",
    "array",
    "ast",
    "asynchat",
    "asyncio",
    "asyncore",
    "atexit",
    "audioop",
    "base64",
    "bdb",
    "binascii",
    "binhex",
    "bisect",
    "builtins",
    "bz2",
    "calendar",
    "cgi",
    "cgitb",
    "chunk",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "compileall",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "cProfile",
    "crypt",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "distutils",
    "doctest",
    "email",
    "encodings",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "idlelib",
    "imaplib",
    "imghdr",
    "imp",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "lib2to3",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "mailcap",
    "marshal",
    "math",
    "mimetypes",
    "mmap",
    "modulefinder",
    "multiprocessing",
    "netrc",
    "nis",
    "nntplib",
    "numbers",
    "operator",
    "optparse",
    "os",
    "ossaudiodev",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pipes",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posix",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtpd",
    "smtplib",
    "sndhdr",
    "socket",
    "socketserver",
    "spwd",
    "sqlite3",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "sunau",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "telnetlib",
    "tempfile",
    "termios",
    "test",
    "textwrap",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uu",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "_thread",
    "__future__",
}

CONFLICTING_GROUPS = {
    "orm": {
        "sqlalchemy": "SQLAlchemy ORM",
        "peewee": "Peewee ORM",
        "django": "Django ORM",
        "tortoise": "Tortoise ORM",
        "psycopg2": "Raw psycopg2 (no ORM)",
        "asyncpg": "Raw asyncpg (no ORM)",
    },
    "http_client": {
        "requests": "requests (sync)",
        "httpx": "httpx (async/sync)",
        "aiohttp": "aiohttp (async)",
        "urllib3": "urllib3 (low-level)",
    },
    "config": {
        "dotenv": "python-dotenv",
        "environs": "environs",
        "decouple": "python-decouple",
        "dynaconf": "dynaconf",
        "pydantic_settings": "pydantic-settings",
    },
    "serialization": {
        "dataclasses": "stdlib dataclasses",
        "pydantic": "Pydantic models",
        "attrs": "attrs",
        "marshmallow": "Marshmallow schemas",
    },
    "task_queue": {
        "celery": "Celery",
        "rq": "Redis Queue",
        "dramatiq": "Dramatiq",
        "huey": "Huey",
    },
    "cli": {
        "argparse": "stdlib argparse",
        "click": "Click",
        "typer": "Typer",
        "fire": "Fire",
    },
}

CONFIG_PATTERNS = [
    ("pyproject.toml", "pyproject"),
    ("setup.py", "setup_py"),
    ("setup.cfg", "setup_cfg"),
    ("requirements.txt", "requirements"),
    ("requirements-dev.txt", "requirements"),
    ("requirements-test.txt", "requirements"),
    ("dev-requirements.txt", "requirements"),
    ("Pipfile", "pipfile"),
]


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class ImportLine:
    """Single import statement."""

    line_num: int
    content: str
    is_lazy: bool = False
    import_type: str = "standard"


@dataclass
class FileImports:
    """All imports from a single file."""

    filepath: str
    relative_path: str
    line_count: int
    imports: list[ImportLine] = field(default_factory=list)

    @property
    def lazy_count(self) -> int:
        return sum(1 for i in self.imports if i.is_lazy)


@dataclass
class Problem:
    """Single detected problem."""

    category: str
    severity: str
    location: str
    details: list[str] = field(default_factory=list)
    suggestion: str | None = None

    def to_markdown(self) -> str:
        lines = [f"[{self.category}] {self.severity}"]
        lines.append(f"  {self.location}")
        for detail in self.details:
            lines.append(f"    - {detail}")
        if self.suggestion:
            lines.append(f"    -> {self.suggestion}")
        return "\n".join(lines)


@dataclass
class ConfigFile:
    """Parsed configuration file."""

    path: str
    config_type: str
    package_name: str | None = None
    dependencies: set[str] = field(default_factory=set)
    dev_dependencies: set[str] = field(default_factory=set)
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class SuperGlobResult:
    """Complete superglob result - imports + problems."""

    path: str
    files_scanned: int
    total_imports: int
    lazy_imports: int
    files: list[FileImports] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)

    def problem_summary(self) -> str:
        if not self.problems:
            return "No problems detected"
        c = sum(1 for p in self.problems if p.severity == "CRITICAL")
        h = sum(1 for p in self.problems if p.severity == "HIGH")
        m = sum(1 for p in self.problems if p.severity == "MEDIUM")
        l = sum(1 for p in self.problems if p.severity == "LOW")
        return f"{c} CRITICAL | {h} HIGH | {m} MEDIUM | {l} LOW"

    def to_markdown(self) -> str:
        lines = [
            BOX_TOP,
            f"|{'SUPERGLOB'.center(66)}|",
            BOX_BOT,
            "",
            f"Path: {self.path}",
            f"Scanned: {self.files_scanned} files | {self.total_imports} imports | {self.lazy_imports} lazy",
            f"Configs: {', '.join(Path(c).name for c in self.config_files) if self.config_files else 'none'}",
            "",
        ]

        # Problems section
        if self.problems:
            lines.append(HEAVY_BAR)
            lines.append(f"PROBLEMS: {self.problem_summary()}")
            lines.append(HEAVY_BAR)

            by_severity = defaultdict(list)
            for p in self.problems:
                by_severity[p.severity].append(p)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity not in by_severity:
                    continue
                lines.append(f"\n### {severity} ###")
                for p in by_severity[severity]:
                    lines.append(p.to_markdown())
            lines.append("")

        # Imports section
        lines.append(HEAVY_BAR)
        lines.append("IMPORTS")
        lines.append(HEAVY_BAR)

        for file in self.files:
            lines.append("")
            lines.append(f"{file.relative_path} ({file.line_count} lines)")
            lines.append(LIGHT_BAR)

            if not file.imports:
                lines.append("  (no imports)")
            else:
                for imp in file.imports:
                    marker = ""
                    if imp.import_type == "conditional":
                        marker = " <- conditional"
                    elif imp.import_type == "type_checking":
                        marker = " <- type-only"
                    elif imp.import_type == "dynamic":
                        marker = " <- dynamic"
                    elif imp.import_type == "lazy" or imp.is_lazy:
                        marker = " <- lazy"
                    lines.append(f"  L{imp.line_num:<4} {imp.content}{marker}")

        lines.append("")
        lines.append(HEAVY_BAR)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "files_scanned": self.files_scanned,
            "total_imports": self.total_imports,
            "lazy_imports": self.lazy_imports,
            "config_files": self.config_files,
            "problems": {
                "summary": self.problem_summary(),
                "items": [
                    {
                        "category": p.category,
                        "severity": p.severity,
                        "location": p.location,
                        "details": p.details,
                        "suggestion": p.suggestion,
                    }
                    for p in self.problems
                ],
            },
            "files": [
                {
                    "path": f.relative_path,
                    "line_count": f.line_count,
                    "imports": [
                        {
                            "line": i.line_num,
                            "content": i.content,
                            "lazy": i.is_lazy,
                            "type": i.import_type,
                        }
                        for i in f.imports
                    ],
                }
                for f in self.files
            ],
        }


# =============================================================================
# IMPORT EXTRACTION
# =============================================================================


def _get_import_patterns(filepath: Path) -> list[re.Pattern]:
    suffix = filepath.suffix.lower()
    patterns = IMPORT_PATTERNS.get(suffix, IMPORT_PATTERNS[".py"])
    return [re.compile(p) for p in patterns]


def _extract_imports(filepath: Path) -> FileImports:
    """Extract ALL imports with AST-aware classification."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return FileImports(
            filepath=str(filepath), relative_path=str(filepath), line_count=0, imports=[]
        )

    lines = content.split("\n")
    imports: list[ImportLine] = []

    if filepath.suffix == ".py":
        try:
            tree = ast.parse(content)
            imports = _extract_imports_ast(tree, lines)
        except SyntaxError:
            imports = _extract_imports_regex(lines, filepath)
    else:
        imports = _extract_imports_regex(lines, filepath)

    return FileImports(
        filepath=str(filepath),
        relative_path=str(filepath),
        line_count=len(lines),
        imports=imports,
    )


def _extract_imports_ast(tree: ast.AST, lines: list) -> list[ImportLine]:
    """AST-based import extraction for Python."""
    imports = []

    type_checking_ranges = set()
    try_ranges = []
    func_ranges = []

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
                for n in ast.walk(node):
                    if hasattr(n, "lineno"):
                        type_checking_ranges.add(n.lineno)
            elif isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING":
                for n in ast.walk(node):
                    if hasattr(n, "lineno"):
                        type_checking_ranges.add(n.lineno)

        if isinstance(node, ast.Try):
            try_start = node.lineno
            try_end = max(
                (n.lineno for n in ast.walk(node) if hasattr(n, "lineno")), default=try_start
            )
            try_ranges.append((try_start, try_end))

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_start = node.lineno
            func_end = max(
                (n.lineno for n in ast.walk(node) if hasattr(n, "lineno")), default=func_start
            )
            func_ranges.append((func_start, func_end))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            line_num = node.lineno
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

            import_type = "standard"
            is_lazy = line_num > LAZY_THRESHOLD

            if line_num in type_checking_ranges:
                import_type = "type_checking"
                is_lazy = False

            for try_start, try_end in try_ranges:
                if try_start <= line_num <= try_end:
                    import_type = "conditional"
                    break

            for func_start, func_end in func_ranges:
                if func_start < line_num <= func_end:
                    is_lazy = True
                    if import_type == "standard":
                        import_type = "lazy"
                    break

            imports.append(
                ImportLine(
                    line_num=line_num,
                    content=line_content,
                    is_lazy=is_lazy,
                    import_type=import_type,
                )
            )

        elif isinstance(node, ast.Call):
            is_dynamic = False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                is_dynamic = True
            elif isinstance(node.func, ast.Name) and node.func.id == "__import__":
                is_dynamic = True

            if is_dynamic:
                line_num = node.lineno
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                imports.append(
                    ImportLine(
                        line_num=line_num, content=line_content, is_lazy=True, import_type="dynamic"
                    )
                )

    return sorted(imports, key=lambda x: x.line_num)


def _extract_imports_regex(lines: list, filepath: Path) -> list[ImportLine]:
    """Fallback regex extraction."""
    patterns = _get_import_patterns(filepath)
    imports = []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern in patterns:
            if pattern.match(stripped):
                imports.append(
                    ImportLine(
                        line_num=line_num,
                        content=stripped,
                        is_lazy=line_num > LAZY_THRESHOLD,
                        import_type="standard",
                    )
                )
                break

    return imports


# =============================================================================
# CONFIG PARSING
# =============================================================================


def _discover_configs(root: Path) -> list[ConfigFile]:
    """Find and parse all config files."""
    configs = []

    for pattern, config_type in CONFIG_PATTERNS:
        path = root / pattern
        if path.exists():
            configs.append(_parse_config(path, config_type))

    return configs


def _parse_config(path: Path, config_type: str) -> ConfigFile:
    """Parse a config file."""
    config = ConfigFile(path=str(path), config_type=config_type)

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        config.parse_errors.append(str(e))
        return config

    if config_type == "pyproject":
        try:
            import tomllib

            data = tomllib.loads(content)
            project = data.get("project", {})
            config.package_name = project.get("name")
            for dep in project.get("dependencies", []):
                match = re.match(r"^([a-zA-Z0-9_-]+)", dep)
                if match:
                    config.dependencies.add(match.group(1).lower().replace("-", "_"))
        except ImportError:
            match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                config.package_name = match.group(1)
        except Exception as e:
            config.parse_errors.append(str(e))

    elif config_type == "setup_py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "setup":
                        for kw in node.keywords:
                            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                config.package_name = kw.value.value
                            elif kw.arg == "install_requires" and isinstance(kw.value, ast.List):
                                for e in kw.value.elts:
                                    if isinstance(e, ast.Constant):
                                        match = re.match(r"^([a-zA-Z0-9_-]+)", e.value)
                                        if match:
                                            config.dependencies.add(
                                                match.group(1).lower().replace("-", "_")
                                            )
        except Exception as e:
            config.parse_errors.append(str(e))

    elif config_type == "requirements":
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                if match:
                    config.dependencies.add(match.group(1).lower().replace("-", "_"))

    return config


# =============================================================================
# PROBLEM DETECTORS
# =============================================================================


def _extract_module(content: str) -> tuple[str | None, str | None, bool]:
    """Extract (root_module, full_path, is_relative) from import."""
    content = content.strip()

    if content.startswith("from ."):
        match = re.match(r"^from\s+(\.+)([^\s]*)\s+import", content)
        if match:
            module = match.group(2)
            return (module.split(".")[0] if module else None, module, True)

    match = re.match(r"^from\s+([^\s]+)\s+import", content)
    if match:
        full_path = match.group(1)
        return (full_path.split(".")[0], full_path, False)

    match = re.match(r"^import\s+([^\s,]+)", content)
    if match:
        full_path = match.group(1)
        return (full_path.split(".")[0], full_path, False)

    return (None, None, False)


def _detect_no_config(configs: list[ConfigFile], root: Path) -> list[Problem]:
    """Detect missing or incomplete project configuration."""
    problems = []

    packaging = [c for c in configs if c.config_type in ("pyproject", "setup_py", "setup_cfg")]

    if not packaging:
        problems.append(
            Problem(
                category="NO_PACKAGE_CONFIG",
                severity="CRITICAL",
                location="(project root)",
                details=[
                    "No pyproject.toml, setup.py, or setup.cfg found",
                    "This project cannot be pip installed",
                    "Package-style imports will fail externally",
                ],
                suggestion="Create pyproject.toml with [project] section",
            )
        )
    elif not any(c.package_name for c in packaging):
        problems.append(
            Problem(
                category="UNNAMED_PACKAGE",
                severity="HIGH",
                location=packaging[0].path,
                details=["Config exists but no package name defined"],
                suggestion="Add 'name' field to [project] section",
            )
        )

    # Check for __init__.py files without declared packages
    if packaging and not any(c.package_name for c in packaging):
        init_files = list(root.rglob("__init__.py"))
        if init_files:
            problems.append(
                Problem(
                    category="UNDECLARED_PACKAGES",
                    severity="MEDIUM",
                    location="(project structure)",
                    details=[
                        f"Found {len(init_files)} __init__.py but no packages declared in config"
                    ],
                    suggestion="Add packages to [tool.setuptools.packages] or use find_packages()",
                )
            )

    return problems


def _detect_relative_no_init(files: list[FileImports], root: Path) -> list[Problem]:
    """Detect relative imports in folders without __init__.py."""
    problems = []
    checked_dirs: set[str] = set()

    for file in files:
        file_path = Path(file.relative_path)
        file_dir = file_path.parent

        for imp in file.imports:
            if not imp.content.strip().startswith("from ."):
                continue

            # Already checked this directory
            dir_key = str(file_dir)
            if dir_key in checked_dirs:
                continue

            # Check if __init__.py exists
            init_path = root / file_dir / "__init__.py"
            if not init_path.exists() and str(file_dir) != ".":
                checked_dirs.add(dir_key)
                problems.append(
                    Problem(
                        category="RELATIVE_NO_INIT",
                        severity="HIGH",
                        location=f"{file_dir}/",
                        details=[
                            "Relative imports used but no __init__.py",
                            f"Found in: {file.relative_path}:{imp.line_num}",
                        ],
                        suggestion=f"Create {file_dir}/__init__.py or use absolute imports",
                    )
                )

    return problems


def _detect_unused_deps(files: list[FileImports], configs: list[ConfigFile]) -> list[Problem]:
    """Detect dependencies in requirements but never imported."""
    problems = []

    all_deps = set()
    for c in configs:
        all_deps.update(c.dependencies)

    if not all_deps:
        return problems

    # Collect all imported modules
    imported: set[str] = set()
    for file in files:
        for imp in file.imports:
            mod, _, _ = _extract_module(imp.content)
            if mod:
                imported.add(mod.lower().replace("-", "_"))

    # Find unused (skip meta-packages)
    meta_packages = {"setuptools", "wheel", "pip", "build", "twine"}

    for dep in all_deps:
        dep_normalized = dep.lower().replace("-", "_")
        if dep_normalized in meta_packages:
            continue

        # Handle common variations
        variations = {dep_normalized, dep_normalized.replace("_", "")}

        if not any(v in imported for v in variations):
            problems.append(
                Problem(
                    category="UNUSED_DEPENDENCY",
                    severity="LOW",
                    location=f"'{dep}'",
                    details=["In requirements but never imported"],
                    suggestion="Remove if not needed (may be indirect dependency)",
                )
            )

    return problems


def _detect_circular(files: list[FileImports]) -> list[Problem]:
    """Detect circular imports."""
    problems = []
    graph: dict[str, set[str]] = defaultdict(set)
    stems: dict[str, str] = {}

    for file in files:
        stem = Path(file.relative_path).stem
        stems[stem] = file.relative_path
        for imp in file.imports:
            mod, _, is_rel = _extract_module(imp.content)
            if mod and not is_rel:
                graph[stem].add(mod)

    checked: set[tuple[str, str]] = set()
    for a, imports_a in graph.items():
        for b in imports_a:
            if b in graph:
                pair = tuple(sorted([a, b]))
                if pair in checked:
                    continue
                checked.add(pair)
                if a in graph.get(b, set()):
                    problems.append(
                        Problem(
                            category="CIRCULAR_IMPORT",
                            severity="HIGH",
                            location=f"{stems.get(a, a)} <-> {stems.get(b, b)}",
                            details=[f"{a} imports {b}", f"{b} imports {a}"],
                            suggestion="Move shared code to third module or use lazy import",
                        )
                    )

    return problems


def _detect_dead_imports(files: list[FileImports], local_modules: set[str]) -> list[Problem]:
    """Detect imports from non-existent local files."""
    problems = []

    for file in files:
        for imp in file.imports:
            if imp.content.strip().startswith("from ."):
                match = re.match(r"^from\s+\.+([^\s.]+)", imp.content)
                if match:
                    target = match.group(1)
                    if target and target not in local_modules:
                        problems.append(
                            Problem(
                                category="DEAD_IMPORT",
                                severity="HIGH",
                                location=f"{file.relative_path}:{imp.line_num}",
                                details=[f"Import: {imp.content}", f"Module '{target}' not found"],
                                suggestion="Fix import path or create missing module",
                            )
                        )

    return problems


def _detect_missing_deps(
    files: list[FileImports], configs: list[ConfigFile], local_modules: set[str]
) -> list[Problem]:
    """Detect imports not in requirements."""
    problems = []

    all_deps = set()
    for c in configs:
        all_deps.update(c.dependencies)
        all_deps.update(c.dev_dependencies)

    if not all_deps and not any(c.config_type == "requirements" for c in configs):
        return problems

    unknown: dict[str, list[str]] = defaultdict(list)

    for file in files:
        for imp in file.imports:
            mod, _, is_rel = _extract_module(imp.content)
            if not mod or is_rel:
                continue

            normalized = mod.lower().replace("-", "_")
            if (
                normalized in STDLIB_MODULES
                or normalized in local_modules
                or normalized in all_deps
            ):
                continue

            unknown[normalized].append(file.relative_path)

    for mod, filelist in unknown.items():
        problems.append(
            Problem(
                category="MISSING_DEPENDENCY",
                severity="HIGH" if len(filelist) >= 2 else "MEDIUM",
                location=f"'{mod}'",
                details=[
                    f"Imported in {len(filelist)} file(s) but not in requirements",
                    *[f"  - {f}" for f in filelist[:5]],
                ],
                suggestion=f"Add '{mod}' to requirements.txt",
            )
        )

    return problems


def _detect_frankenstein(files: list[FileImports]) -> list[Problem]:
    """Detect mixing of conflicting libraries."""
    problems = []

    all_imports: dict[str, set[str]] = defaultdict(set)
    for file in files:
        for imp in file.imports:
            mod, _, _ = _extract_module(imp.content)
            if mod:
                all_imports[mod.lower().replace("-", "_")].add(file.relative_path)

    for group_name, packages in CONFLICTING_GROUPS.items():
        found = [
            (pkg, desc, all_imports[pkg]) for pkg, desc in packages.items() if pkg in all_imports
        ]

        if len(found) >= 2:
            if group_name == "serialization" and {f[0] for f in found} == {
                "dataclasses",
                "pydantic",
            }:
                continue

            details = [f"Multiple {group_name} approaches:"]
            for pkg, desc, filelist in found:
                details.append(f"  {desc} in {len(filelist)} files")

            problems.append(
                Problem(
                    category="FRANKENSTEIN",
                    severity="MEDIUM",
                    location=f"{group_name} conflict",
                    details=details,
                    suggestion=f"Standardize on one {group_name} approach",
                )
            )

    return problems


def _detect_orphans(files: list[FileImports]) -> list[Problem]:
    """Detect modules nothing imports."""
    problems = []

    imported: set[str] = set()
    for file in files:
        for imp in file.imports:
            mod, _, _ = _extract_module(imp.content)
            if mod:
                imported.add(mod)

    # Entry points and route files - not orphans even if nothing imports them
    entry_patterns = [
        "cli",
        "main",
        "server",
        "app",
        "run",
        "start",
        "worker",
        "manage",
        "wsgi",
        "asgi",
        "routes",
        "router",
        "endpoints",
        "views",
        "handlers",
        "api",
    ]

    for file in files:
        stem = Path(file.relative_path).stem

        if stem.startswith("__") or stem.startswith("test_") or stem.endswith("_test"):
            continue
        # Skip if name contains entry/route patterns
        if any(p in stem.lower() for p in entry_patterns):
            continue
        # Skip files ending in _routes, _router, _api, _views, _handlers
        if any(
            stem.lower().endswith(f"_{p}")
            for p in ["routes", "router", "api", "views", "handlers", "endpoints"]
        ):
            continue

        if stem not in imported:
            problems.append(
                Problem(
                    category="ORPHAN_MODULE",
                    severity="LOW",
                    location=file.relative_path,
                    details=["No files import this module"],
                    suggestion="Delete if unused or document as entry point",
                )
            )

    return problems


# =============================================================================
# MAIN FUNCTION
# =============================================================================


def import_wiz(*paths: str) -> SuperGlobResult:
    """
    Import map + problem detector.

    Args:
        *paths: Files, folders, or mix. Defaults to "." if none provided.
                Examples:
                    import_wiz(".")
                    import_wiz("auth/auth_service.py")
                    import_wiz("file1.py", "file2.py", "auth/")

    Returns:
        SuperGlobResult with imports and problems for all paths
    """
    if not paths:
        paths = (".",)

    # Collect files from all paths
    files_to_scan: list[Path] = []
    roots: list[Path] = []

    for path in paths:
        target = Path(path).resolve()
        if target.is_file():
            files_to_scan.append(target)
            roots.append(target.parent)
        else:
            roots.append(target)
            for filepath in target.rglob("*.py"):
                if any(part in IGNORE_DIRS for part in filepath.parts):
                    continue
                files_to_scan.append(filepath)

    files_to_scan.sort()

    # Use common ancestor as root, or first root if no common ancestor
    if roots:
        try:
            root = Path(os.path.commonpath([str(r) for r in roots]))
        except ValueError:
            root = roots[0]
    else:
        root = Path(".").resolve()

    # Extract imports in parallel
    file_imports: list[FileImports] = []
    total_imports = 0
    lazy_imports = 0

    if files_to_scan:
        with ThreadPoolExecutor(max_workers=min(32, len(files_to_scan))) as executor:
            futures = {executor.submit(_extract_imports, fp): fp for fp in files_to_scan}
            for future in as_completed(futures):
                result = future.result()
                try:
                    result.relative_path = str(futures[future].relative_to(root))
                except ValueError:
                    result.relative_path = str(futures[future])

                file_imports.append(result)
                total_imports += len(result.imports)
                lazy_imports += result.lazy_count

    file_imports.sort(key=lambda f: f.relative_path)

    # Discover configs
    configs = _discover_configs(root)

    # Build local modules set
    local_modules: set[str] = set()
    for f in file_imports:
        stem = Path(f.relative_path).stem
        local_modules.add(stem)
        for part in Path(f.relative_path).parts[:-1]:
            local_modules.add(part)

    # Detect problems
    problems: list[Problem] = []
    problems.extend(_detect_no_config(configs, root))
    problems.extend(_detect_relative_no_init(file_imports, root))
    problems.extend(_detect_circular(file_imports))
    problems.extend(_detect_dead_imports(file_imports, local_modules))
    problems.extend(_detect_missing_deps(file_imports, configs, local_modules))
    problems.extend(_detect_frankenstein(file_imports))
    problems.extend(_detect_unused_deps(file_imports, configs))
    problems.extend(_detect_orphans(file_imports))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    problems.sort(key=lambda p: severity_order.get(p.severity, 99))

    # Build path display
    if len(paths) == 1:
        path_display = str(paths[0])
    else:
        path_display = f"{len(paths)} paths: {', '.join(str(p) for p in paths[:3])}" + (
            "..." if len(paths) > 3 else ""
        )

    return SuperGlobResult(
        path=path_display,
        files_scanned=len(file_imports),
        total_imports=total_imports,
        lazy_imports=lazy_imports,
        files=file_imports,
        problems=problems,
        config_files=[c.path for c in configs],
    )


# Keep extract_imports available for recon.py compatibility
extract_imports = _extract_imports

# Backwards compatibility alias
superglob = import_wiz


# =============================================================================
# CLI
# =============================================================================


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="import_wiz - Import map + problem detector",
        epilog="Examples:\n"
        "  import_wiz.py .                     # Current directory\n"
        "  import_wiz.py auth/auth_service.py  # Single file\n"
        "  import_wiz.py file1.py file2.py     # Multiple files\n"
        "  import_wiz.py auth/ core/           # Multiple folders\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files and/or folders to scan")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")

    args = parser.parse_args()

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")

    result = import_wiz(*args.paths)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.to_markdown())


if __name__ == "__main__":
    main()
