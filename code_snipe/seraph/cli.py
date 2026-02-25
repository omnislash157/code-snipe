"""
cli.py — Command-line entry point for Portable Seraph.

Usage:
    python -m code_snipe.seraph /path/to/repo
    python -m code_snipe.seraph.cli /path/to/repo --top 10
    python -m code_snipe.seraph.cli . --json --quiet 2>/dev/null

All progress output goes to stderr so stdout stays clean for --json piping.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Progress helpers (all write to stderr)
# ---------------------------------------------------------------------------


def _err(msg: str, end: str = "\n") -> None:
    """Print *msg* to stderr."""
    print(msg, end=end, file=sys.stderr)


def _fmt_bytes(size_bytes: int) -> str:
    """Human-readable file size."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes} B"


def _pad(label: str, width: int = 36) -> str:
    """Left-pad a label string to *width* chars."""
    return label.ljust(width)


# ---------------------------------------------------------------------------
# Core run logic (importable, not CLI-only)
# ---------------------------------------------------------------------------


def run(
    repo_path: str,
    days: int = 365,
    threshold: float = 2.0,
    top_n: int = 20,
    quiet: bool = False,
) -> "SeraphReport":  # noqa: F821
    """
    Execute all Seraph analysis phases with progress output to stderr.

    Args:
        repo_path:  Path to the target repository.
        days:       Git history window in days.
        threshold:  Anomaly detection sigma threshold.
        top_n:      Number of bug predictions to compute.
        quiet:      Suppress all stderr output if True.

    Returns:
        SeraphReport dataclass.
    """
    # Lazy imports so syntax check works without running analysis
    from code_snipe.seraph.scanner import scan_repo
    from code_snipe.seraph.import_graph import build_import_graph
    from code_snipe.seraph.git_analyzer import analyze_git_history
    from code_snipe.seraph.markov import predict_bugs
    from code_snipe.seraph.anomaly import detect_anomalies
    from code_snipe.seraph.report import SeraphReport

    import time as _time
    from datetime import datetime, timezone

    t_start = _time.monotonic()
    abs_path = str(Path(repo_path).resolve())

    if not quiet:
        _err(f"Seraph scanning {abs_path}...")

    # Phase 1: scan
    if not quiet:
        _err(_pad("[1/4] Scanning files..."), end="")
    scan = scan_repo(abs_path)
    if not quiet:
        _err(f"{len(scan.source_files):,} files ({scan.total_loc:,} LOC)")

    # Phase 2: import graph
    if not quiet:
        _err(_pad("[2/4] Building import graph..."), end="")
    graph = build_import_graph(scan)
    if not quiet:
        _err(f"{len(graph.edges):,} edges")

    # Phase 3: git analysis
    if not quiet:
        _err(_pad("[3/4] Analyzing git history..."), end="")
    git_analysis = analyze_git_history(abs_path, days=days)
    bug_fix_count = len(git_analysis.bug_fix_commits)
    if not quiet:
        _err(
            f"{git_analysis.total_commits:,} commits "
            f"({bug_fix_count:,} bug fixes)"
        )

    # Phase 4: anomaly detection
    if not quiet:
        _err(_pad("[4/4] Detecting anomalies..."), end="")
    anomaly_report = detect_anomalies(abs_path, threshold=threshold)
    by_sev: dict[str, int] = {}
    for a in anomaly_report.anomalies:
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
    critical = by_sev.get("critical", 0)
    if not quiet:
        _err(
            f"{anomaly_report.total_anomalies:,} anomalies "
            f"({critical:,} critical)"
        )

    # Predictions (computed from already-fetched git_analysis)
    if git_analysis.total_commits < 10:
        if not quiet:
            _err("")
            if git_analysis.total_commits == 0:
                _err("  warning  No git history — bug predictions skipped.")
            else:
                _err(f"  warning  Only {git_analysis.total_commits} commits — predictions may be unreliable.")
                _err("     Clone with full history for accurate results.")
        predictions = predict_bugs(git_analysis, top_n=top_n) if git_analysis.total_commits > 0 else []
    else:
        predictions = predict_bugs(git_analysis, top_n=top_n)

    duration = _time.monotonic() - t_start
    generated_at = datetime.now(tz=timezone.utc).isoformat()

    return SeraphReport(
        repo_path=abs_path,
        scan=scan,
        import_graph=graph,
        git_analysis=git_analysis,
        predictions=predictions,
        anomaly_report=anomaly_report,
        generated_at=generated_at,
        duration_seconds=round(duration, 2),
    )


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def _print_file_summary(
    output_dir: Path,
    file_sizes: dict[str, int],
    quiet: bool,
) -> None:
    """Print the saved-files block to stderr."""
    if quiet:
        return
    _err("")
    _err(f"Report saved to {output_dir}/")
    for filename, size in file_sizes.items():
        _err(f"  {filename:<22} ({_fmt_bytes(size)})")


def _print_predictions(predictions: list, top_n: int, quiet: bool) -> None:
    """Print top N predictions to stderr."""
    if quiet or not predictions:
        return
    display = predictions[:top_n]
    _err("")
    _err(f"Top {len(display)} Bug Predictions:")
    for i, pred in enumerate(display):
        label = f"{i + 1}. {pred.path}"
        _err(f"  {label:<50} {pred.probability:.3f}")


def _print_critical_anomalies(anomaly_report, quiet: bool) -> None:
    """Print critical anomalies to stderr."""
    if quiet:
        return
    critical = [a for a in anomaly_report.anomalies if a.severity == "critical"]
    if not critical:
        return
    _err("")
    _err("Critical Anomalies:")
    for a in critical:
        filename = Path(a.path).name
        _err(f"  {filename:<40} {a.description}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """
    Parse CLI arguments and execute the Seraph scan.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).
    """
    parser = argparse.ArgumentParser(
        prog="seraph",
        description=(
            "Seraph Portable — codebase intelligence scanner.\n"
            "Analyses import graphs, git history, bug probability, and anomalies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        metavar="REPO",
        help="Path to the repository to scan (default: current directory).",
    )
    parser.add_argument(
        "--days",
        "-d",
        type=int,
        default=365,
        metavar="N",
        help="Git history window in days (default: 365).",
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=2.0,
        metavar="SIGMA",
        help="Anomaly detection threshold in standard deviations (default: 2.0).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        metavar="DIR",
        help=(
            "Output directory for report files "
            "(default: {repo_path}/.seraph/)."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Write full report as JSON to stdout instead of saving files.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all progress output to stderr.",
    )
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=20,
        metavar="N",
        help="Number of bug predictions to include (default: 20).",
    )

    args = parser.parse_args(argv)

    # Validate repo path
    repo = Path(args.repo_path).resolve()
    if not repo.exists():
        _err(f"seraph: error: repository path does not exist: {repo}")
        sys.exit(1)

    # Run the scan
    try:
        report = run(
            repo_path=str(repo),
            days=args.days,
            threshold=args.threshold,
            top_n=args.top,
            quiet=args.quiet,
        )
    except KeyboardInterrupt:
        _err("\nseraph: interrupted by user")
        sys.exit(130)
    except Exception as exc:
        _err(f"seraph: error: {exc}")
        raise

    if args.output_json:
        # Import here to avoid circular at module level
        from code_snipe.seraph.report import to_json
        print(json.dumps(to_json(report), indent=2))
        return

    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = repo / ".seraph"

    # Save files
    from code_snipe.seraph.report import save_report
    file_sizes = save_report(report, output_dir)

    _print_file_summary(output_dir, file_sizes, args.quiet)
    _print_predictions(report.predictions, top_n=min(args.top, 10), quiet=args.quiet)
    _print_critical_anomalies(report.anomaly_report, quiet=args.quiet)

    if not args.quiet:
        _err("")


if __name__ == "__main__":
    main()
