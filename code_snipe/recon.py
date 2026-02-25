#!/usr/bin/env python3
"""
RECON v2 - Problem Aggregator

THE FIRE FINDER. One call, see all problems across the codebase.

Aggregates problems from:
    1. SuperGlob  - Import fires (dead imports, circular, missing deps, orphans)
    2. CodeSmells - Runtime crash risks (naked json, unsafe sql, bare except)
    3. Env vars   - Missing from .env

Usage:
    python recon.py                           # All problems (default)
    python recon.py "db_query"                # Search + problems in matched files
    python recon.py --mode env_audit          # All env vars
    python recon.py --mode orphans            # Orphan files only
    python recon.py --mode circular           # Circular imports only

Version: 2.1.0
"""

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Paths to ignore (archive, test fixtures, etc.)
IGNORE_PATHS = {
    "archive",
    ".archive",
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
}

# Pillar 1: CodeHound (AST-aware search)
# Pillar 3: CodeSmells (runtime crash risks)
from code_snipe.analyzers import (
    CodeSmells,
    EnvUsage,
    find_env_vars,
    load_dotenv_vars,
)
from code_snipe.lightning import Lightning as CodeHound

# Pillar 2: ImportWiz (imports + problems)
from code_snipe.import_wiz import import_wiz as superglob_scan

# =============================================================================
# HELPERS
# =============================================================================


def _is_ignored(path: str) -> bool:
    """Check if path should be ignored (archive, etc.)."""
    path_lower = path.lower().replace("\\", "/")
    parts = path_lower.split("/")
    return any(part in IGNORE_PATHS for part in parts)


# =============================================================================
# VISUAL FORMATTING
# =============================================================================

HEAVY_BAR = "=" * 68
LIGHT_BAR = "-" * 68
BOX_TOP = "+" + "=" * 66 + "+"
BOX_BOT = "+" + "=" * 66 + "+"
BOX_SIDE = "|"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class ReconResult:
    """Complete recon result."""

    term: str
    mode: str
    elapsed_ms: float = 0.0
    files_searched: int = 0

    # From CodeHound (only in search mode)
    codehound_hits: list[Any] = field(default_factory=list)
    total_matches: int = 0

    # From SuperGlob - import problems
    import_problems: list[Any] = field(default_factory=list)
    import_map: dict[str, Any] = field(default_factory=dict)

    # From CodeSmells - runtime crash risks
    smells: list[Any] = field(default_factory=list)

    # Env vars
    env_usage: list[EnvUsage] = field(default_factory=list)

    # Blast radius (only in search mode)
    direct_files: set[str] = field(default_factory=set)
    ripple_files: set[str] = field(default_factory=set)

    def to_markdown(self, full: bool = False) -> str:
        """Format as scannable markdown."""
        mode_label = {
            "problems": "ALL PROBLEMS",
            "search": "SEARCH",
            "what_if_i_delete": "BLAST RADIUS",
            "env_audit": "ENV AUDIT",
            "orphans": "ORPHANS",
            "circular": "CIRCULAR IMPORTS",
        }.get(self.mode, self.mode.upper())

        lines = [
            BOX_TOP,
            f"{BOX_SIDE}{'RECON: ' + mode_label:^66}{BOX_SIDE}",
            BOX_BOT,
            "",
            f"Scanned {self.files_searched} files in {self.elapsed_ms:.0f}ms",
        ]
        if self.term:
            lines.append(f"Search term: `{self.term}`")
        lines.append("")

        # === IMPORT PROBLEMS (SuperGlob) ===
        if self.import_problems:
            critical = [p for p in self.import_problems if p.severity == "CRITICAL"]
            high = [p for p in self.import_problems if p.severity == "HIGH"]
            medium = [p for p in self.import_problems if p.severity == "MEDIUM"]
            low = [p for p in self.import_problems if p.severity == "LOW"]

            # For orphans/circular mode, show the LOW severity ones
            if self.mode in ("orphans", "circular"):
                lines.append(HEAVY_BAR)
                label = "ORPHAN FILES" if self.mode == "orphans" else "CIRCULAR IMPORTS"
                lines.append(f"{label}: {len(self.import_problems)} found")
                lines.append(LIGHT_BAR)

                limit = None if full else 25
                for p in self.import_problems[:limit]:
                    lines.append(f"  {p.location}")
                if not full and len(self.import_problems) > 25:
                    lines.append(f"  ... +{len(self.import_problems) - 25} more")
                lines.append("")
            else:
                # Normal mode - show by severity
                total = len(critical) + len(high) + len(medium)
                if total > 0:
                    lines.append(HEAVY_BAR)
                    lines.append(
                        f"IMPORT PROBLEMS: {len(critical)} critical | {len(high)} high | {len(medium)} medium"
                    )
                    lines.append(LIGHT_BAR)

                    if critical:
                        lines.append("\n  CRITICAL:")
                        for p in critical:
                            lines.append(f"    [{p.category}] {p.location}")
                            if p.suggestion:
                                lines.append(f"      -> {p.suggestion}")

                    if high:
                        lines.append("\n  HIGH:")
                        limit = None if full else 15
                        for p in high[:limit]:
                            lines.append(f"    [{p.category}] {p.location}")
                            if p.details:
                                lines.append(f"      {p.details[0]}")
                        if not full and len(high) > 15:
                            lines.append(f"    ... +{len(high) - 15} more")

                    if medium:
                        lines.append("\n  MEDIUM:")
                        limit = None if full else 10
                        for p in medium[:limit]:
                            lines.append(f"    [{p.category}] {p.location}")
                        if not full and len(medium) > 10:
                            lines.append(f"    ... +{len(medium) - 10} more")

                    lines.append("")

        # === CODE SMELLS (Runtime Crash Risks) ===
        if self.smells:
            by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for s in self.smells:
                sev = s.severity.upper() if hasattr(s, "severity") else "MEDIUM"
                if sev in by_severity:
                    by_severity[sev].append(s)

            critical = by_severity["CRITICAL"]
            high = by_severity["HIGH"]
            medium = by_severity["MEDIUM"]

            total = len(critical) + len(high) + len(medium)
            if total > 0:
                lines.append(HEAVY_BAR)
                lines.append(
                    f"CODE SMELLS: {len(critical)} critical | {len(high)} high | {len(medium)} medium"
                )
                lines.append(LIGHT_BAR)

                if critical:
                    lines.append("\n  CRITICAL (will crash):")
                    limit = None if full else 10
                    for s in critical[:limit]:
                        lines.append(f"    [{s.category}] {s.filepath}:{s.line_num}")
                        if s.suggestion:
                            lines.append(f"      -> {s.suggestion}")
                        elif s.code:
                            lines.append(f"      {s.code[:60]}")
                    if not full and len(critical) > 10:
                        lines.append(f"    ... +{len(critical) - 10} more")

                if high:
                    lines.append("\n  HIGH (likely to crash):")
                    limit = None if full else 15
                    for s in high[:limit]:
                        lines.append(f"    [{s.category}] {s.filepath}:{s.line_num}")
                        if s.code:
                            lines.append(f"      {s.code[:50]}")
                    if not full and len(high) > 15:
                        lines.append(f"    ... +{len(high) - 15} more")

                if medium and full:
                    lines.append("\n  MEDIUM:")
                    for s in medium[:20]:
                        lines.append(f"    [{s.category}] {s.filepath}:{s.line_num}")
                    if len(medium) > 20:
                        lines.append(f"    ... +{len(medium) - 20} more")
                elif medium:
                    lines.append(f"\n  MEDIUM: {len(medium)} issues (use --full to see)")

                lines.append("")

        # === ENV VARS ===
        if self.env_usage:
            missing = [e for e in self.env_usage if not e.in_dotenv]
            present = [e for e in self.env_usage if e.in_dotenv]

            lines.append(HEAVY_BAR)
            lines.append(
                f"ENV VARS: {len(self.env_usage)} found | {len(missing)} missing from .env"
            )
            lines.append(LIGHT_BAR)

            if missing:
                lines.append("  Missing from .env:")
                limit = None if full else 15
                for e in missing[:limit]:
                    lines.append(f"    {e.var_name} - {e.filepath}:L{e.line_num}")
                if not full and len(missing) > 15:
                    lines.append(f"    ... +{len(missing) - 15} more")

            if present and full:
                lines.append("\n  Present in .env:")
                seen = set()
                for e in present:
                    if e.var_name not in seen:
                        lines.append(f"    {e.var_name}")
                        seen.add(e.var_name)
            lines.append("")

        # === MATCHES (only in search mode) ===
        if self.codehound_hits:
            lines.append(HEAVY_BAR)
            lines.append(f"MATCHES: {self.total_matches} hits in {len(self.direct_files)} files")
            lines.append(LIGHT_BAR)

            file_limit = None if full else 10
            for hit in self.codehound_hits[:file_limit]:
                lines.append(f"\n  {hit.relative_path}")
                chunk_limit = None if full else 3
                for chunk in hit.chunks[:chunk_limit]:
                    lines.append(
                        f"    L{chunk.start_line}-{chunk.end_line} ({chunk.match_count} matches)"
                    )
                    if chunk.text:
                        preview_lines = chunk.text.strip().split("\n")[:2]
                        for pl in preview_lines:
                            lines.append(f"      {pl[:70]}")
                if not full and len(hit.chunks) > 3:
                    lines.append(f"    ... +{len(hit.chunks) - 3} more chunks")

            if not full and len(self.codehound_hits) > 10:
                lines.append(f"\n  ... +{len(self.codehound_hits) - 10} more files")
            lines.append("")

        # === BLAST RADIUS (only in search mode) ===
        if self.direct_files:
            lines.append(HEAVY_BAR)
            total_blast = len(self.direct_files) + len(self.ripple_files)
            lines.append(f"BLAST RADIUS: {total_blast} files affected")
            lines.append(LIGHT_BAR)

            lines.append("  Direct files:")
            direct_limit = None if full else 5
            for f in list(self.direct_files)[:direct_limit]:
                lines.append(f"    > {f}")
            if not full and len(self.direct_files) > 5:
                lines.append(f"    ... +{len(self.direct_files) - 5} more")

            if self.ripple_files:
                lines.append("\n  Ripple files (import direct):")
                ripple_limit = None if full else 10
                for f in list(self.ripple_files)[:ripple_limit]:
                    lines.append(f"    ~ {f}")
                if not full and len(self.ripple_files) > 10:
                    lines.append(f"    ... +{len(self.ripple_files) - 10} more")
            lines.append("")

        # === SUMMARY ===
        lines.append(HEAVY_BAR)
        lines.append("SUMMARY")
        lines.append(LIGHT_BAR)

        # Count totals
        import_critical = len([p for p in self.import_problems if p.severity == "CRITICAL"])
        import_high = len([p for p in self.import_problems if p.severity == "HIGH"])
        smell_critical = len(
            [s for s in self.smells if getattr(s, "severity", "").upper() == "CRITICAL"]
        )
        smell_high = len([s for s in self.smells if getattr(s, "severity", "").upper() == "HIGH"])
        env_missing = len([e for e in self.env_usage if not e.in_dotenv])

        lines.append(f"  Import problems: {import_critical} critical, {import_high} high")
        lines.append(f"  Code smells: {smell_critical} critical, {smell_high} high")
        lines.append(f"  Env vars missing: {env_missing}")

        total_critical = import_critical + smell_critical
        if total_critical > 0:
            lines.append(f"\n  !! {total_critical} CRITICAL issues - fix these first!")

        lines.append("")
        lines.append(HEAVY_BAR)

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "term": self.term,
            "mode": self.mode,
            "elapsed_ms": self.elapsed_ms,
            "files_searched": self.files_searched,
            "total_matches": self.total_matches,
            "direct_files": list(self.direct_files),
            "ripple_files": list(self.ripple_files),
            "import_problems": [
                {"category": p.category, "severity": p.severity, "location": p.location}
                for p in self.import_problems
            ],
            "smells": [
                {
                    "category": s.category,
                    "severity": s.severity,
                    "file": s.filepath,
                    "line": s.line_num,
                }
                for s in self.smells
            ],
            "env_usage": [
                {
                    "var": e.var_name,
                    "file": e.filepath,
                    "line": e.line_num,
                    "in_dotenv": e.in_dotenv,
                }
                for e in self.env_usage
            ],
        }


# =============================================================================
# MAIN RECON FUNCTION
# =============================================================================


def recon(
    term: str = "",
    root_path: str = ".",
    mode: str = "problems",
    full: bool = False,
    focus_path: str | None = None,
) -> ReconResult:
    """
    Problem aggregator - find all fires in the codebase.

    Args:
        term: Search term (optional - triggers search mode)
        root_path: Project root
        mode: problems (default), search, env_audit, orphans, circular
        full: If True, no truncation in output
        focus_path: Limit analysis to subfolder

    Returns:
        ReconResult with all problems aggregated
    """
    start = time.perf_counter()
    root = Path(root_path).resolve()

    # Auto-detect mode based on term
    if term and mode == "problems":
        mode = "search"

    result = ReconResult(term=term, mode=mode)

    # Determine scan path
    scan_path = str(root / focus_path) if focus_path else str(root)

    # === SUPERGLOB: Import problems ===
    sg_result = superglob_scan(scan_path)
    result.files_searched = sg_result.files_scanned
    result.import_map = {f.filepath: f for f in sg_result.files}

    # Filter problems based on mode (exclude archived files)
    if mode == "orphans":
        result.import_problems = [
            p
            for p in sg_result.problems
            if p.category == "ORPHAN_MODULE" and not _is_ignored(p.location)
        ]
    elif mode == "circular":
        result.import_problems = [
            p
            for p in sg_result.problems
            if p.category == "CIRCULAR_IMPORT" and not _is_ignored(p.location)
        ]
    else:
        # All modes get import problems (CRITICAL/HIGH/MEDIUM), exclude archived
        result.import_problems = [
            p
            for p in sg_result.problems
            if p.severity in ("CRITICAL", "HIGH", "MEDIUM") and not _is_ignored(p.location)
        ]

    # Build reverse import map for ripple calculation
    imported_by: dict[str, set[str]] = {}
    for file_info in sg_result.files:
        for imp in file_info.imports:
            content = imp.content
            module = None
            if content.startswith("from "):
                parts = content.split()
                if len(parts) >= 2:
                    module = parts[1]
            elif content.startswith("import "):
                parts = content.split()
                if len(parts) >= 2:
                    module = parts[1].split(",")[0].strip()
            if module:
                if module not in imported_by:
                    imported_by[module] = set()
                imported_by[module].add(file_info.filepath)

    # Load .env vars
    dotenv_vars = load_dotenv_vars(root)

    # === MODE: problems (default) - show ALL problems ===
    if mode == "problems":
        # Get ALL code smells, exclude archived
        smells_result = CodeSmells(scan_path).scan()
        result.smells = [s for s in smells_result.smells if not _is_ignored(s.filepath)]

        # Get ALL env vars, dedupe, exclude archived
        seen = set()
        for ev in smells_result.env_vars:
            if _is_ignored(ev.filepath):
                continue
            key = (ev.var_name, ev.filepath, ev.line_num)
            if key not in seen:
                seen.add(key)
                ev.in_dotenv = ev.var_name in dotenv_vars
                result.env_usage.append(ev)

    # === MODE: search ===
    elif mode == "search" and term:
        # CodeHound search
        hound = CodeHound(scan_path)
        hound_result = hound.hunt(term, file_pattern="**/*.py", token_radius=100)

        # Filter out archived files from hits
        result.codehound_hits = [h for h in hound_result.hits if not _is_ignored(h.relative_path)]
        result.total_matches = sum(h.total_matches for h in result.codehound_hits)

        # Build direct files (already filtered)
        for hit in result.codehound_hits:
            result.direct_files.add(hit.relative_path)

        # Calculate ripple (exclude archived)
        for direct_file in result.direct_files:
            module_path = direct_file.replace("\\", "/").replace("/", ".").replace(".py", "")
            parts = module_path.split(".")
            for i in range(len(parts)):
                potential_module = ".".join(parts[i:])
                if potential_module in imported_by:
                    for importer in imported_by[potential_module]:
                        if importer not in result.direct_files and not _is_ignored(importer):
                            result.ripple_files.add(importer)

        # Code smells in direct files only (already filtered to non-archived)
        smells_result = CodeSmells(scan_path).scan()
        result.smells = [
            s
            for s in smells_result.smells
            if not _is_ignored(s.filepath)
            and any(
                s.filepath.endswith(df) or df.endswith(s.filepath) for df in result.direct_files
            )
        ]

        # Env vars in direct files
        for filepath in result.direct_files:
            full_path = root / filepath
            if full_path.exists():
                result.env_usage.extend(find_env_vars(full_path, root, dotenv_vars))

    # === MODE: env_audit ===
    elif mode == "env_audit":
        smells_result = CodeSmells(scan_path).scan()
        seen = set()
        for ev in smells_result.env_vars:
            if _is_ignored(ev.filepath):
                continue
            key = (ev.var_name, ev.filepath, ev.line_num)
            if key not in seen:
                seen.add(key)
                ev.in_dotenv = ev.var_name in dotenv_vars
                result.env_usage.append(ev)

    # orphans and circular modes already handled above (just import_problems)

    result.elapsed_ms = (time.perf_counter() - start) * 1000
    return result


# =============================================================================
# CLI
# =============================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="RECON - Problem Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
    problems (default) - All problems: imports + smells + env vars
    search             - Search term + problems in matched files
    env_audit          - All env vars, check against .env
    orphans            - Files nothing imports
    circular           - Circular import chains

Examples:
    python recon.py                     # All problems
    python recon.py "db_query"          # Search + problems
    python recon.py --mode env_audit    # Env var audit
    python recon.py --mode orphans      # Orphan files
    python recon.py --full              # No truncation
        """,
    )

    parser.add_argument("term", nargs="?", default="", help="Search term (triggers search mode)")
    parser.add_argument("--cwd", "-c", default=".", help="Project root")
    parser.add_argument(
        "--mode",
        "-m",
        default="problems",
        choices=["problems", "search", "env_audit", "orphans", "circular"],
    )
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--full", "-f", action="store_true", help="No truncation")
    parser.add_argument("--focus", help="Limit to subfolder")

    args = parser.parse_args()

    result = recon(
        term=args.term,
        root_path=args.cwd,
        mode=args.mode,
        full=args.full,
        focus_path=args.focus,
    )

    if args.json:
        output = json.dumps(result.to_dict(), indent=2)
    else:
        output = result.to_markdown(full=args.full)

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")

    print(output)


if __name__ == "__main__":
    main()
