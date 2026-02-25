"""
cartographer.py - Codebase Architectural Mapper

One command -> complete architectural overview. The first tool an AI reads
to understand what it's looking at.

Detects:
- Entry points (FastAPI, Flask, Django, CLI, scripts)
- API routes (with HTTP method + path)
- Services (business logic classes)
- Models (dataclasses, Pydantic, SQLAlchemy)
- Config files (.env, yaml, toml)
- Background tasks (Celery, APScheduler, asyncio)

Usage:
    from cartographer import Cartographer

    carto = Cartographer(".")
    code_map = carto.scan()
    print(code_map.to_markdown())

Version: 1.0.0
"""

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================


class EntryPointType(Enum):
    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO = "django"
    SCRIPT = "script"
    CLI_TYPER = "typer"
    CLI_CLICK = "click"
    MAIN_FUNC = "main_function"


@dataclass
class EntryPoint:
    filepath: str
    line_num: int
    entry_type: EntryPointType
    app_variable: str | None = None


@dataclass
class Route:
    filepath: str
    line_num: int
    method: str
    path: str
    handler: str
    router_name: str | None = None


@dataclass
class Service:
    name: str
    filepath: str
    line_num: int
    service_type: str
    methods: list[str] = field(default_factory=list)
    singleton_getter: str | None = None


@dataclass
class Model:
    name: str
    filepath: str
    line_num: int
    model_type: str
    fields: list[str] = field(default_factory=list)


@dataclass
class ConfigFile:
    filepath: str
    file_type: str
    variables: list[str] = field(default_factory=list)


@dataclass
class BackgroundTask:
    name: str
    filepath: str
    line_num: int
    task_type: str


@dataclass
class CodeMap:
    """The complete architectural map."""

    root_path: str
    project_name: str
    entry_points: list[EntryPoint] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    config_files: list[ConfigFile] = field(default_factory=list)
    background_tasks: list[BackgroundTask] = field(default_factory=list)

    @property
    def framework(self) -> str:
        """Detect primary framework from entry points."""
        for ep in self.entry_points:
            if ep.entry_type == EntryPointType.FASTAPI:
                return "FastAPI"
            if ep.entry_type == EntryPointType.FLASK:
                return "Flask"
            if ep.entry_type == EntryPointType.DJANGO:
                return "Django"

        # Check for CLI
        for ep in self.entry_points:
            if ep.entry_type in (EntryPointType.CLI_TYPER, EntryPointType.CLI_CLICK):
                return "CLI Application"

        return "Python Application"

    def to_markdown(self) -> str:
        """One-page architecture overview."""
        lines = [
            f"# CARTOGRAPHER: {self.project_name}",
            "",
            "## Framework",
            f"{self.framework}",
            "",
        ]

        # Entry Points
        if self.entry_points:
            lines.append(f"## Entry Points ({len(self.entry_points)})")
            for ep in self.entry_points:
                app_info = f" (`{ep.app_variable}`)" if ep.app_variable else ""
                lines.append(f"- `{ep.filepath}:{ep.line_num}` - {ep.entry_type.value}{app_info}")
            lines.append("")

        # Routes - grouped by prefix
        if self.routes:
            lines.append(f"## Routes ({len(self.routes)})")
            routes_by_prefix = self._group_routes_by_prefix()
            for prefix, routes in sorted(routes_by_prefix.items()):
                lines.append(f"### {prefix or '/'} ({len(routes)} routes)")
                for route in routes:
                    lines.append(f"  {route.method:6} {route.path} -> {route.handler}")
            lines.append("")

        # Services
        if self.services:
            lines.append(f"## Services ({len(self.services)})")
            for svc in self.services:
                method_count = len(svc.methods)
                singleton_info = (
                    f"\n  - singleton: `{svc.singleton_getter}()`" if svc.singleton_getter else ""
                )
                lines.append(
                    f"- **{svc.name}** (`{svc.filepath}:{svc.line_num}`) - {method_count} methods{singleton_info}"
                )
            lines.append("")

        # Models - grouped by type
        if self.models:
            lines.append(f"## Models ({len(self.models)})")
            models_by_type = self._group_models_by_type()
            for model_type, models in sorted(models_by_type.items()):
                names = ", ".join(m.name for m in models)
                lines.append(f"### {model_type.title()} ({len(models)})")
                lines.append(f"  {names}")
            lines.append("")

        # Config
        if self.config_files:
            lines.append(f"## Config ({len(self.config_files)})")
            for cfg in self.config_files:
                var_info = f" ({len(cfg.variables)} variables)" if cfg.variables else ""
                lines.append(f"- `{cfg.filepath}`{var_info}")
            lines.append("")

        # Background Tasks
        if self.background_tasks:
            lines.append(f"## Background Tasks ({len(self.background_tasks)})")
            for task in self.background_tasks:
                lines.append(
                    f"- `{task.name}` ({task.task_type}) - {task.filepath}:{task.line_num}"
                )
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable output."""
        return {
            "project_name": self.project_name,
            "framework": self.framework,
            "entry_points": [
                {
                    "filepath": ep.filepath,
                    "line": ep.line_num,
                    "type": ep.entry_type.value,
                    "app_var": ep.app_variable,
                }
                for ep in self.entry_points
            ],
            "routes": [
                {
                    "filepath": r.filepath,
                    "line": r.line_num,
                    "method": r.method,
                    "path": r.path,
                    "handler": r.handler,
                }
                for r in self.routes
            ],
            "services": [
                {
                    "name": s.name,
                    "filepath": s.filepath,
                    "line": s.line_num,
                    "type": s.service_type,
                    "methods": s.methods,
                }
                for s in self.services
            ],
            "models": [
                {
                    "name": m.name,
                    "filepath": m.filepath,
                    "line": m.line_num,
                    "type": m.model_type,
                    "fields": m.fields,
                }
                for m in self.models
            ],
            "config_files": [
                {"filepath": c.filepath, "type": c.file_type, "variables": c.variables}
                for c in self.config_files
            ],
            "background_tasks": [
                {"name": t.name, "filepath": t.filepath, "line": t.line_num, "type": t.task_type}
                for t in self.background_tasks
            ],
        }

    def _group_routes_by_prefix(self) -> dict[str, list[Route]]:
        """Group routes by their first path segment."""
        groups: dict[str, list[Route]] = {}
        for route in self.routes:
            parts = route.path.strip("/").split("/")
            prefix = "/" + parts[0] if parts and parts[0] else "/"
            if prefix not in groups:
                groups[prefix] = []
            groups[prefix].append(route)
        return groups

    def _group_models_by_type(self) -> dict[str, list[Model]]:
        """Group models by their type."""
        groups: dict[str, list[Model]] = {}
        for model in self.models:
            if model.model_type not in groups:
                groups[model.model_type] = []
            groups[model.model_type].append(model)
        return groups


# =============================================================================
# AST VISITOR
# =============================================================================


class CartographerVisitor(ast.NodeVisitor):
    """AST visitor that extracts architectural elements."""

    SERVICE_SUFFIXES = ("Service", "Repository", "Controller", "Manager", "Handler", "Provider")
    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

    def __init__(self, filepath: str, source_lines: list[str]):
        self.filepath = filepath
        self.source_lines = source_lines

        self.entry_points: list[EntryPoint] = []
        self.routes: list[Route] = []
        self.services: list[Service] = []
        self.models: list[Model] = []
        self.background_tasks: list[BackgroundTask] = []

        # Track imports for framework detection
        self.imports: set[str] = set()

        # Track app variables for route detection
        self.app_vars: dict[str, str] = {}  # var_name -> framework
        self.router_vars: set[str] = set()

        # Track singleton getters
        self.singleton_getters: dict[str, str] = {}  # return_type -> func_name

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Detect app = FastAPI() / Flask() patterns."""
        if isinstance(node.value, ast.Call):
            func_name = self._extract_call_name(node.value)

            # FastAPI
            if func_name in ("FastAPI", "fastapi.FastAPI"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        self.app_vars[var_name] = "fastapi"
                        self.entry_points.append(
                            EntryPoint(
                                filepath=self.filepath,
                                line_num=node.lineno,
                                entry_type=EntryPointType.FASTAPI,
                                app_variable=var_name,
                            )
                        )

            # Flask
            elif func_name in ("Flask", "flask.Flask"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        self.app_vars[var_name] = "flask"
                        self.entry_points.append(
                            EntryPoint(
                                filepath=self.filepath,
                                line_num=node.lineno,
                                entry_type=EntryPointType.FLASK,
                                app_variable=var_name,
                            )
                        )

            # APIRouter (FastAPI)
            elif func_name in ("APIRouter", "fastapi.APIRouter"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.router_vars.add(target.id)

            # Blueprint (Flask)
            elif func_name in ("Blueprint", "flask.Blueprint"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.router_vars.add(target.id)

            # Typer CLI
            elif func_name in ("Typer", "typer.Typer"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.entry_points.append(
                            EntryPoint(
                                filepath=self.filepath,
                                line_num=node.lineno,
                                entry_type=EntryPointType.CLI_TYPER,
                                app_variable=target.id,
                            )
                        )

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """Detect if __name__ == '__main__' pattern."""
        if self._is_main_check(node.test):
            self.entry_points.append(
                EntryPoint(
                    filepath=self.filepath,
                    line_num=node.lineno,
                    entry_type=EntryPointType.SCRIPT,
                )
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_function(node)

    def _visit_function(self, node):
        """Process function definition."""
        # Check for main() function
        if node.name == "main":
            self.entry_points.append(
                EntryPoint(
                    filepath=self.filepath,
                    line_num=node.lineno,
                    entry_type=EntryPointType.MAIN_FUNC,
                )
            )

        # Check for route decorators
        route = self._parse_route_decorator(node)
        if route:
            self.routes.append(route)

        # Check for background task decorators
        task = self._parse_task_decorator(node)
        if task:
            self.background_tasks.append(task)

        # Check for click.command decorator
        for decorator in node.decorator_list:
            dec_name = self._extract_decorator_name(decorator)
            if dec_name in ("click.command", "command"):
                self.entry_points.append(
                    EntryPoint(
                        filepath=self.filepath,
                        line_num=node.lineno,
                        entry_type=EntryPointType.CLI_CLICK,
                    )
                )

        # Check for singleton getter pattern
        if node.returns:
            return_type = self._extract_name(node.returns)
            if return_type and return_type.endswith(self.SERVICE_SUFFIXES):
                self.singleton_getters[return_type] = node.name

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Detect Service/Model patterns."""
        # Check if it's a service
        if self._is_service_class(node):
            methods = self._extract_public_methods(node)
            service_type = self._get_service_type(node.name)

            # Check for singleton getter
            singleton = self.singleton_getters.get(node.name)

            self.services.append(
                Service(
                    name=node.name,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    service_type=service_type,
                    methods=methods,
                    singleton_getter=singleton,
                )
            )

        # Check if it's a model
        model_type = self._detect_model_type(node)
        if model_type:
            fields = self._extract_model_fields(node, model_type)
            self.models.append(
                Model(
                    name=node.name,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    model_type=model_type,
                    fields=fields,
                )
            )

        self.generic_visit(node)

    def _is_main_check(self, test: ast.expr) -> bool:
        """Check if expression is __name__ == '__main__'."""
        if isinstance(test, ast.Compare):
            if len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                left = test.left
                right = test.comparators[0] if test.comparators else None

                if isinstance(left, ast.Name) and left.id == "__name__":
                    if isinstance(right, ast.Constant) and right.value == "__main__":
                        return True
        return False

    def _parse_route_decorator(self, node) -> Route | None:
        """Extract route info from decorator."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Attribute):
                    # @app.get("/path") or @router.post("/path")
                    method = func.attr.lower()
                    if method in self.HTTP_METHODS:
                        obj_name = self._extract_name(func.value)

                        # Verify it's an app or router
                        if obj_name in self.app_vars or obj_name in self.router_vars:
                            path = (
                                self._extract_string(decorator.args[0]) if decorator.args else "/"
                            )
                            router_name = obj_name if obj_name in self.router_vars else None

                            return Route(
                                filepath=self.filepath,
                                line_num=node.lineno,
                                method=method.upper(),
                                path=path,
                                handler=node.name,
                                router_name=router_name,
                            )

                    # @app.route("/path", methods=["GET", "POST"])
                    elif method == "route":
                        obj_name = self._extract_name(func.value)
                        if obj_name in self.app_vars or obj_name in self.router_vars:
                            path = (
                                self._extract_string(decorator.args[0]) if decorator.args else "/"
                            )
                            methods = self._extract_methods_kwarg(decorator)

                            return Route(
                                filepath=self.filepath,
                                line_num=node.lineno,
                                method=",".join(methods) if methods else "*",
                                path=path,
                                handler=node.name,
                                router_name=obj_name if obj_name in self.router_vars else None,
                            )

            elif isinstance(decorator, ast.Attribute):
                # @app.get (without call - unlikely but handle)
                pass

        return None

    def _parse_task_decorator(self, node) -> BackgroundTask | None:
        """Extract background task info from decorator."""
        for decorator in node.decorator_list:
            dec_name = self._extract_decorator_name(decorator)

            # Celery
            if dec_name in ("celery.task", "shared_task", "task"):
                return BackgroundTask(
                    name=node.name,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    task_type="celery",
                )

            # RQ
            if dec_name == "job":
                return BackgroundTask(
                    name=node.name,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    task_type="rq",
                )

            # APScheduler
            if "scheduled_job" in dec_name:
                return BackgroundTask(
                    name=node.name,
                    filepath=self.filepath,
                    line_num=node.lineno,
                    task_type="apscheduler",
                )

        return None

    def _is_service_class(self, node: ast.ClassDef) -> bool:
        """Check if class is a service/business logic class."""
        return any(node.name.endswith(suffix) for suffix in self.SERVICE_SUFFIXES)

    def _get_service_type(self, name: str) -> str:
        """Extract service type suffix."""
        for suffix in self.SERVICE_SUFFIXES:
            if name.endswith(suffix):
                return suffix
        return "Service"

    def _detect_model_type(self, node: ast.ClassDef) -> str | None:
        """Detect if class is a data model and what type."""
        # Check decorators for @dataclass
        for dec in node.decorator_list:
            dec_name = self._extract_decorator_name(dec)
            if dec_name in ("dataclass", "dataclasses.dataclass"):
                return "dataclass"

        # Check bases
        for base in node.bases:
            base_name = self._extract_name(base)
            if base_name == "BaseModel":
                return "pydantic"
            if base_name in ("Base", "Model", "DeclarativeBase"):
                return "sqlalchemy"
            if base_name == "TypedDict":
                return "typeddict"
            if base_name == "NamedTuple":
                return "namedtuple"
            if base_name and "db.Model" in base_name:
                return "sqlalchemy"

        return None

    def _extract_public_methods(self, node: ast.ClassDef) -> list[str]:
        """Extract public method names from class."""
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_"):
                    methods.append(item.name)
        return methods

    def _extract_model_fields(self, node: ast.ClassDef, model_type: str) -> list[str]:
        """Extract field names from model class."""
        fields = []
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                fields.append(item.target.id)
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        fields.append(target.id)
        return fields

    def _extract_call_name(self, node: ast.Call) -> str:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            obj = self._extract_name(node.func.value)
            return f"{obj}.{node.func.attr}" if obj else node.func.attr
        return ""

    def _extract_name(self, node: ast.expr) -> str | None:
        """Extract name from various node types."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            obj = self._extract_name(node.value)
            return f"{obj}.{node.attr}" if obj else node.attr
        elif isinstance(node, ast.Subscript):
            return self._extract_name(node.value)
        return None

    def _extract_string(self, node: ast.expr) -> str:
        """Extract string value from node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _extract_decorator_name(self, decorator: ast.expr) -> str:
        """Extract decorator name."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            obj = self._extract_name(decorator.value)
            return f"{obj}.{decorator.attr}" if obj else decorator.attr
        elif isinstance(decorator, ast.Call):
            return self._extract_decorator_name(decorator.func)
        return ""

    def _extract_methods_kwarg(self, decorator: ast.Call) -> list[str]:
        """Extract methods=["GET", "POST"] from decorator."""
        for kw in decorator.keywords:
            if kw.arg == "methods":
                if isinstance(kw.value, ast.List):
                    methods = []
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant):
                            methods.append(str(elt.value).upper())
                    return methods
        return []


# =============================================================================
# MAIN CLASS
# =============================================================================


class Cartographer:
    """Scans codebase and builds architectural map."""

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
        ".pytest_cache",
        ".mypy_cache",
        "htmlcov",
        "eggs",
        ".eggs",
        "*.egg-info",
    }

    CONFIG_PATTERNS = {
        ".env": "env",
        ".env.example": "env",
        ".env.local": "env",
        ".env.development": "env",
        ".env.production": "env",
        "config.yaml": "yaml",
        "config.yml": "yaml",
        "settings.yaml": "yaml",
        "settings.yml": "yaml",
        "settings.py": "python",
        "config.py": "python",
        "constants.py": "python",
        "pyproject.toml": "toml",
        "requirements.txt": "requirements",
        "setup.py": "setup",
        "setup.cfg": "setup",
    }

    def __init__(self, root_path: str = "."):
        self.root = Path(root_path).resolve()
        self.project_name = self.root.name

    def scan(self) -> CodeMap:
        """Scan codebase and return architectural map."""
        code_map = CodeMap(
            root_path=str(self.root),
            project_name=self.project_name,
        )

        # Scan Python files
        for filepath in self._iter_python_files():
            elements = self._scan_python_file(filepath)
            code_map.entry_points.extend(elements.get("entry_points", []))
            code_map.routes.extend(elements.get("routes", []))
            code_map.services.extend(elements.get("services", []))
            code_map.models.extend(elements.get("models", []))
            code_map.background_tasks.extend(elements.get("background_tasks", []))

        # Scan config files
        code_map.config_files = self._scan_config_files()

        # Sort routes by path for cleaner output
        code_map.routes.sort(key=lambda r: (r.path, r.method))

        # Sort services by name
        code_map.services.sort(key=lambda s: s.name)

        # Sort models by type then name
        code_map.models.sort(key=lambda m: (m.model_type, m.name))

        return code_map

    def _iter_python_files(self):
        """Iterate over Python files in the codebase."""
        for path in self.root.rglob("*.py"):
            # Skip ignored directories
            if any(part in self.IGNORE_DIRS for part in path.parts):
                continue
            yield path

    def _scan_python_file(self, filepath: Path) -> dict[str, list]:
        """Extract elements from a single Python file."""
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            source_lines = source.split("\n")
        except Exception as e:
            logger.warning(f"Failed to read {filepath}: {e}")
            return {}

        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError) as e:
            logger.warning(f"Parse error in {filepath}: {e}")
            return {}

        # Get relative path for output
        try:
            rel_path = str(filepath.relative_to(self.root))
        except ValueError:
            rel_path = str(filepath)

        visitor = CartographerVisitor(rel_path, source_lines)
        visitor.visit(tree)

        return {
            "entry_points": visitor.entry_points,
            "routes": visitor.routes,
            "services": visitor.services,
            "models": visitor.models,
            "background_tasks": visitor.background_tasks,
        }

    def _scan_config_files(self) -> list[ConfigFile]:
        """Find and parse config files."""
        configs = []

        for pattern, file_type in self.CONFIG_PATTERNS.items():
            # Check root directory
            config_path = self.root / pattern
            if config_path.exists():
                variables = self._extract_config_vars(config_path, file_type)
                try:
                    rel_path = str(config_path.relative_to(self.root))
                except ValueError:
                    rel_path = str(config_path)
                configs.append(
                    ConfigFile(
                        filepath=rel_path,
                        file_type=file_type,
                        variables=variables,
                    )
                )

        # Also check for tenant configs or other nested configs
        for yaml_file in self.root.rglob("*.yaml"):
            if any(part in self.IGNORE_DIRS for part in yaml_file.parts):
                continue
            if yaml_file.name not in self.CONFIG_PATTERNS:
                try:
                    rel_path = str(yaml_file.relative_to(self.root))
                except ValueError:
                    rel_path = str(yaml_file)
                configs.append(
                    ConfigFile(
                        filepath=rel_path,
                        file_type="yaml",
                    )
                )

        for yml_file in self.root.rglob("*.yml"):
            if any(part in self.IGNORE_DIRS for part in yml_file.parts):
                continue
            if yml_file.name not in self.CONFIG_PATTERNS:
                try:
                    rel_path = str(yml_file.relative_to(self.root))
                except ValueError:
                    rel_path = str(yml_file)
                configs.append(
                    ConfigFile(
                        filepath=rel_path,
                        file_type="yaml",
                    )
                )

        return configs

    def _extract_config_vars(self, filepath: Path, file_type: str) -> list[str]:
        """Extract variable names from config file."""
        variables = []

        if file_type == "env":
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        var_name = line.split("=")[0].strip()
                        if var_name:
                            variables.append(var_name)
            except Exception:
                pass

        return variables


# =============================================================================
# CLI
# =============================================================================


def main():
    """Command-line interface."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Cartographer: Codebase architectural mapper",
        epilog="Examples:\n"
        "  cartographer.py .                  # Map current directory\n"
        "  cartographer.py /path/to/project   # Map specific project\n"
        "  cartographer.py . --json           # Output as JSON\n"
        "  cartographer.py . --routes         # Only show routes\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Path to scan (default: current directory)"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--summary", action="store_true", help="Summary counts only")
    parser.add_argument("--routes", action="store_true", help="Only show routes")
    parser.add_argument("--services", action="store_true", help="Only show services")
    parser.add_argument("--models", action="store_true", help="Only show models")
    parser.add_argument("--file", "-f", help="Save output to file")

    args = parser.parse_args()

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")

    carto = Cartographer(args.path)
    code_map = carto.scan()

    # Filter output if requested
    if args.summary:
        output = (
            f"Project: {code_map.project_name}\n"
            f"Framework: {code_map.framework}\n"
            f"Entry Points: {len(code_map.entry_points)}\n"
            f"Routes: {len(code_map.routes)}\n"
            f"Services: {len(code_map.services)}\n"
            f"Models: {len(code_map.models)}\n"
            f"Config Files: {len(code_map.config_files)}\n"
            f"Background Tasks: {len(code_map.background_tasks)}\n"
        )
    elif args.routes:
        lines = [f"# Routes ({len(code_map.routes)})"]
        for r in code_map.routes:
            lines.append(f"{r.method:6} {r.path} -> {r.handler} ({r.filepath}:{r.line_num})")
        output = "\n".join(lines)
    elif args.services:
        lines = [f"# Services ({len(code_map.services)})"]
        for s in code_map.services:
            lines.append(
                f"{s.name} ({s.service_type}) - {s.filepath}:{s.line_num} - {len(s.methods)} methods"
            )
        output = "\n".join(lines)
    elif args.models:
        lines = [f"# Models ({len(code_map.models)})"]
        for m in code_map.models:
            lines.append(f"{m.name} ({m.model_type}) - {m.filepath}:{m.line_num}")
        output = "\n".join(lines)
    elif args.json:
        output = json.dumps(code_map.to_dict(), indent=2)
    else:
        output = code_map.to_markdown()

    # Save or print
    if args.file:
        filepath = Path(args.file)
        filepath.write_text(output, encoding="utf-8")
        print(f"Saved to {filepath}")
    else:
        print(output)


if __name__ == "__main__":
    main()
