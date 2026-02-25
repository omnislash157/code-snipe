"""
report.py — Compile all Seraph phase outputs into structured JSON + Markdown.

Runs all four analysis phases (scan, import graph, git history, anomaly
detection) and serialises results to:

    wiring_map.json   — Import graph topology + hot/god/orphan files
    predictions.json  — Ranked bug predictions with risk factors
    anomalies.json    — All anomalies grouped by severity
    report.md         — Human-readable executive summary

No external dependencies. Pure stdlib.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from code_snipe.seraph.scanner import RepoScan, scan_repo
from code_snipe.seraph.import_graph import (
    ImportGraph,
    build_import_graph,
)
from code_snipe.seraph.git_analyzer import (
    GitAnalysis,
    analyze_git_history,
)
from code_snipe.seraph.markov import BugPrediction, predict_bugs
from code_snipe.seraph.anomaly import AnomalyReport, detect_anomalies


# ---------------------------------------------------------------------------
# SeraphReport dataclass
# ---------------------------------------------------------------------------


@dataclass
class SeraphReport:
    """Full compiled output from all four Seraph analysis phases."""

    repo_path: str
    scan: RepoScan
    import_graph: ImportGraph
    git_analysis: GitAnalysis
    predictions: list[BugPrediction]
    anomaly_report: AnomalyReport
    generated_at: str      # ISO 8601 timestamp
    duration_seconds: float


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_report(
    repo_path: str,
    days: int = 365,
    anomaly_threshold: float = 2.0,
    top_n: int = 20,
) -> SeraphReport:
    """
    Run all Seraph analysis phases and compile the results.

    Args:
        repo_path:          Absolute or relative path to the repository root.
        days:               Git history timeframe in days (default 365).
        anomaly_threshold:  Standard deviations above directory mean to flag
                            as anomalous (default 2.0).
        top_n:              Number of bug predictions to return (default 20).

    Returns:
        SeraphReport containing outputs from all four phases.
    """
    t_start = time.monotonic()

    scan = scan_repo(repo_path)
    graph = build_import_graph(scan)
    git_analysis = analyze_git_history(repo_path, days=days)
    predictions = predict_bugs(git_analysis, top_n=top_n)
    anomaly_report = detect_anomalies(repo_path, threshold=anomaly_threshold)

    duration = time.monotonic() - t_start
    generated_at = datetime.now(tz=timezone.utc).isoformat()

    return SeraphReport(
        repo_path=str(Path(repo_path).resolve()),
        scan=scan,
        import_graph=graph,
        git_analysis=git_analysis,
        predictions=predictions,
        anomaly_report=anomaly_report,
        generated_at=generated_at,
        duration_seconds=round(duration, 2),
    )


# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------


def _scan_loc_by_path(scan: RepoScan) -> dict[str, int]:
    """Build a quick path -> LOC lookup from the RepoScan source file list.

    NOTE: The scanner stores LOC in total_loc (aggregate); individual file
    LOC values come from the ImportGraph NodeInfo objects, which re-read each
    file during graph construction.  This helper returns an empty dict — callers
    should use the graph nodes for per-file LOC.
    """
    return {}


def to_json(report: SeraphReport) -> dict:
    """
    Convert a SeraphReport to a fully serialisable dict.

    The dict contains four top-level keys:
        meta          — run metadata (repo, timestamps, duration)
        wiring_map    — import graph summary
        predictions   — ranked bug predictions
        anomalies     — anomaly scan results
    """
    scan = report.scan
    graph = report.import_graph
    git = report.git_analysis
    anom = report.anomaly_report

    # Repo name = last path component
    repo_name = Path(report.repo_path).name

    # ---- wiring_map section ----
    nodes_list = [
        {
            "path": path,
            "language": info.language,
            "loc": info.loc,
            "is_entry_point": info.is_entry_point,
            "fan_in": graph.fan_in.get(path, 0),
            "fan_out": graph.fan_out.get(path, 0),
        }
        for path, info in graph.nodes.items()
    ]

    edges_list = [
        {
            "source": e.source,
            "target": e.target,
            "import_name": e.import_name,
        }
        for e in graph.edges
    ]

    hot = [{"path": p, "fan_in": fi} for p, fi in graph.hot_files(top_n=50)]
    god = [{"path": p, "loc": loc} for p, loc in graph.god_files(top_n=50)]
    orphans = graph.orphan_files()

    wiring_map = {
        "repo": repo_name,
        "primary_language": scan.primary_language,
        "total_files": len(scan.source_files),
        "total_loc": scan.total_loc,
        "total_edges": len(graph.edges),
        "nodes": nodes_list,
        "edges": edges_list,
        "hot_files": hot,
        "god_files": god,
        "orphan_files": orphans,
    }

    # ---- predictions section ----
    predictions_list = [
        {
            "rank": i + 1,
            "path": p.path,
            "probability": p.probability,
            "bug_fix_count": p.bug_fix_count,
            "churn_risk": p.churn_risk,
            "co_change_risk": p.co_change_risk,
            "risk_factors": p.risk_factors,
        }
        for i, p in enumerate(report.predictions)
    ]

    predictions_section = {
        "timeframe_days": git.timeframe_days,
        "total_commits": git.total_commits,
        "bug_fix_commits": len(git.bug_fix_commits),
        "predictions": predictions_list,
    }

    # ---- anomalies section ----
    by_severity: dict[str, int] = {}
    for a in anom.anomalies:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1

    anomalies_list = [
        {
            "path": a.path,
            "type": a.anomaly_type,
            "severity": a.severity,
            "deviation": round(a.deviation, 2),
            "value": a.value,
            "baseline_mean": round(a.baseline_mean, 2),
            "baseline_stddev": round(a.baseline_stddev, 2),
            "description": a.description,
        }
        for a in anom.anomalies
    ]

    anomalies_section = {
        "total_files_scanned": anom.total_files_scanned,
        "total_anomalies": anom.total_anomalies,
        "by_severity": by_severity,
        "anomalies": anomalies_list,
    }

    # ---- top-level envelope ----
    return {
        "meta": {
            "repo": repo_name,
            "repo_path": report.repo_path,
            "generated_at": report.generated_at,
            "duration_seconds": report.duration_seconds,
        },
        "wiring_map": wiring_map,
        "predictions": predictions_section,
        "anomalies": anomalies_section,
    }


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: dict) -> None:
    """Write *data* as pretty-printed JSON to *path*."""
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _build_wiring_map(report: SeraphReport) -> dict:
    full = to_json(report)
    return full["wiring_map"]


def _build_predictions(report: SeraphReport) -> dict:
    full = to_json(report)
    return full["predictions"]


def _build_anomalies(report: SeraphReport) -> dict:
    full = to_json(report)
    return full["anomalies"]


def _build_report_md(report: SeraphReport) -> str:
    """Generate the human-readable Markdown summary."""
    scan = report.scan
    graph = report.import_graph
    git = report.git_analysis
    anom = report.anomaly_report

    # Overview metrics
    total_files = len(scan.source_files)
    total_loc = scan.total_loc
    primary_lang = scan.primary_language
    total_edges = len(graph.edges)
    total_commits = git.total_commits
    bug_fix_count = len(git.bug_fix_commits)
    bug_fix_pct = round(bug_fix_count / total_commits * 100) if total_commits else 0
    total_anomalies = anom.total_anomalies
    by_severity: dict[str, int] = {}
    for a in anom.anomalies:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
    critical_count = by_severity.get("critical", 0)

    lines: list[str] = []

    lines.append("# Seraph Scan Report")
    lines.append("")
    lines.append(f"**Repo:** {report.repo_path}")
    lines.append(f"**Scanned:** {report.generated_at}")
    lines.append(f"**Duration:** {report.duration_seconds}s")
    lines.append("")

    # Overview table
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Files | {total_files:,} |")
    lines.append(f"| Lines of Code | {total_loc:,} |")
    lines.append(f"| Primary Language | {primary_lang} |")
    lines.append(f"| Import Edges | {total_edges:,} |")
    lines.append(f"| Git Commits ({git.timeframe_days}d) | {total_commits:,} |")
    lines.append(
        f"| Bug-Fix Commits | {bug_fix_count:,} ({bug_fix_pct}%) |"
    )
    lines.append(
        f"| Anomalies | {total_anomalies:,} ({critical_count} critical) |"
    )
    lines.append("")

    # Bug predictions table
    lines.append("## Top Bug Predictions")
    lines.append("")
    lines.append(
        "Files most likely to contain bugs, based on git history analysis:"
    )
    lines.append("")
    lines.append("| Rank | File | Probability | Bug Fixes | Risk Factors |")
    lines.append("|------|------|------------|-----------|-------------|")
    for i, pred in enumerate(report.predictions):
        factors_str = ", ".join(pred.risk_factors) if pred.risk_factors else "—"
        # Truncate long factor strings
        if len(factors_str) > 80:
            factors_str = factors_str[:77] + "..."
        lines.append(
            f"| {i + 1} | {pred.path} | {pred.probability:.3f} "
            f"| {pred.bug_fix_count} | {factors_str} |"
        )
    if not report.predictions:
        lines.append("| — | No predictions available | — | — | — |")
    lines.append("")

    # Critical anomalies
    critical_anomalies = [a for a in anom.anomalies if a.severity == "critical"]
    lines.append("## Critical Anomalies")
    lines.append("")
    lines.append("Files that deviate significantly from their peers:")
    lines.append("")
    lines.append("| File | Type | Deviation | Description |")
    lines.append("|------|------|-----------|-------------|")
    for a in critical_anomalies:
        lines.append(
            f"| {a.path} | {a.anomaly_type} | {a.deviation:.1f}\u03c3 "
            f"| {a.description} |"
        )
    if not critical_anomalies:
        lines.append("| — | No critical anomalies | — | — |")
    lines.append("")

    # Hot files
    hot = graph.hot_files(top_n=10)
    lines.append("## Hot Files (Most Imported)")
    lines.append("")
    lines.append("| File | Importers |")
    lines.append("|------|-----------|")
    for path, fan_in in hot:
        lines.append(f"| {path} | {fan_in:,} |")
    if not hot:
        lines.append("| — | No import data available |")
    lines.append("")

    # God files
    god = graph.god_files(top_n=10)
    lines.append("## God Files (Largest)")
    lines.append("")
    lines.append("| File | LOC |")
    lines.append("|------|-----|")
    for path, loc in god:
        lines.append(f"| {path} | {loc:,} |")
    if not god:
        lines.append("| — | No files found |")
    lines.append("")

    # Entry points
    entry_points = [
        (path, info.loc)
        for path, info in graph.nodes.items()
        if info.is_entry_point
    ]
    entry_points.sort(key=lambda t: -t[1])

    lines.append("## Entry Points")
    lines.append("")
    for path, loc in entry_points[:20]:
        lines.append(f"- {path} ({loc:,} LOC)")
    if not entry_points:
        lines.append("- No entry points detected")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by Seraph Portable v0.1*")
    lines.append("")

    return "\n".join(lines)


def save_report(report: SeraphReport, output_dir: Path) -> dict[str, int]:
    """
    Write all four output files to *output_dir*.

    Args:
        report:     A SeraphReport from generate_report().
        output_dir: Destination directory (created if it does not exist).

    Returns:
        Dict mapping filename -> file size in bytes, for progress reporting.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    wiring_path = output_dir / "wiring_map.json"
    predictions_path = output_dir / "predictions.json"
    anomalies_path = output_dir / "anomalies.json"
    report_md_path = output_dir / "report.md"

    _write_json(wiring_path, _build_wiring_map(report))
    _write_json(predictions_path, _build_predictions(report))
    _write_json(anomalies_path, _build_anomalies(report))
    report_md_path.write_text(_build_report_md(report), encoding="utf-8")

    return {
        "wiring_map.json": wiring_path.stat().st_size,
        "predictions.json": predictions_path.stat().st_size,
        "anomalies.json": anomalies_path.stat().st_size,
        "report.md": report_md_path.stat().st_size,
    }
