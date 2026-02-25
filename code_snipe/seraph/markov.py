"""
Portable Seraph — Bug Probability from Git History

Given a GitAnalysis, compute per-file bug probability using a weighted
Markov-inspired model seeded entirely from git history.

No database. No external dependencies. Pure stdlib arithmetic.

Usage:
    from code_snipe.seraph.git_analyzer import analyze_git_history
    from code_snipe.seraph.markov import predict_bugs

    analysis = analyze_git_history('/path/to/repo', days=365)
    predictions = predict_bugs(analysis, top_n=20)
    for p in predictions:
        print(f'{p.path}: {p.probability:.3f}')
        for risk_factor in p.risk_factors:
            print(f'  - {risk_factor}')
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class BugPrediction:
    """Per-file bug probability prediction with human-readable risk factors."""

    path: str
    probability: float          # 0.0 – 1.0 weighted composite score
    risk_factors: list[str]     # Human-readable explanations
    bug_fix_count: int          # Raw bug-fix commit count for this file
    co_change_risk: float       # 0.0 – 1.0 normalized co-change-with-buggy-files score
    churn_risk: float           # 0.0 – 1.0 normalized commit frequency score


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_div(numerator: float, denominator: float) -> float:
    """Return numerator/denominator, or 0.0 if denominator is zero."""
    if denominator == 0.0:
        return 0.0
    return numerator / denominator


def _parse_iso_date(date_str: str) -> datetime | None:
    """
    Parse an ISO 8601 date string from git log output.

    Git produces strings like: "2025-03-14 12:34:56 +0000"
    or "2025-03-14T12:34:56+00:00". We handle both formats plus
    partial strings. Returns None on any parse failure.
    """
    if not date_str:
        return None

    # Normalise git's " +HHMM" offset to "+HH:MM" for fromisoformat
    # Example: "2025-03-14 12:34:56 +0000" -> "2025-03-14 12:34:56+00:00"
    import re

    date_str = date_str.strip()
    # Replace " +HHMM" or " -HHMM" at end with "+HH:MM"
    date_str = re.sub(
        r' ([+-])(\d{2})(\d{2})$',
        r'\1\2:\3',
        date_str,
    )
    # Replace space separator with T for fromisoformat compatibility
    date_str = date_str.replace(" ", "T", 1)

    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        pass

    # Fallback: try just the date portion
    try:
        return datetime.fromisoformat(date_str[:10])
    except ValueError:
        return None


def _days_since(date_str: str, now: datetime) -> float | None:
    """
    Return the number of days between `date_str` and `now`.

    Returns None if date_str cannot be parsed.
    """
    parsed = _parse_iso_date(date_str)
    if parsed is None:
        return None

    # Ensure both are offset-aware or both naive for subtraction
    if parsed.tzinfo is not None and now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    elif parsed.tzinfo is None and now.tzinfo is not None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    delta = now - parsed
    return max(0.0, delta.total_seconds() / 86400.0)


def _percentile_rank(value: float, all_values: list[float]) -> float:
    """
    Return the fraction of values strictly below `value` (0.0 – 1.0).

    Used to build "top X%" risk factor labels.
    """
    if not all_values:
        return 0.0
    below = sum(1 for v in all_values if v < value)
    return below / len(all_values)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

# Factor weights (must sum to 1.0)
_W_BUG_HISTORY = 0.4
_W_CHURN = 0.3
_W_CO_CHANGE = 0.2
_W_RECENCY = 0.1

# Only predict bugs for actual source code files — not docs, configs, or data.
_CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
        ".svelte", ".vue", ".go", ".rs", ".java", ".rb", ".cs",
        ".c", ".cpp", ".h", ".hpp", ".cc", ".cxx", ".sh",
    }
)


def _is_code_file(path: str) -> bool:
    """Return True if path has a source-code extension."""
    from pathlib import PurePosixPath
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in _CODE_EXTENSIONS


def predict_bugs(
    analysis: "GitAnalysis",  # noqa: F821  (forward ref — imported by callers)
    top_n: int = 20,
) -> list[BugPrediction]:
    """
    Compute per-file bug probability from a GitAnalysis and return the top N files.

    Probability formula (weighted sum, each factor 0.0 – 1.0):
        bug_history       (weight 0.4) = file_bug_fixes / max_bug_fixes
        churn_risk        (weight 0.3) = file_commits   / max_commits
        co_change_risk    (weight 0.2) = co-change exposure with bug-fix files, normalized
        recency           (weight 0.1) = exponential decay from days since last bug fix

    Args:
        analysis: Output of analyze_git_history().
        top_n:    Maximum number of predictions to return.

    Returns:
        List of BugPrediction, sorted by probability descending, length <= top_n.
    """
    if not analysis.file_churn:
        return []

    now = datetime.now(tz=timezone.utc)

    # Filter to code files only — skip .md, .yml, .json, .svg, etc.
    churn = {k: v for k, v in analysis.file_churn.items() if _is_code_file(k)}

    if not churn:
        return []

    # --- Pre-compute normalisation denominators ---
    all_bug_counts = [fc.bug_fix_count for fc in churn.values()]
    all_commit_counts = [fc.commit_count for fc in churn.values()]

    max_bug_fixes = max(all_bug_counts) if all_bug_counts else 1
    max_commits = max(all_commit_counts) if all_commit_counts else 1

    # --- Build: set of files touched by bug-fix commits ---
    bug_fix_files: set[str] = set()
    for commit in analysis.bug_fix_commits:
        bug_fix_files.update(commit.files_changed)

    # --- Build: co-change exposure scores for each file ---
    # For each file, sum up how many times it co-changed with any bug-fix file.
    # We look up (file_a, file_b) in co_change_matrix (canonical order: a < b).
    co_change_exposure: dict[str, float] = {}

    if bug_fix_files:
        for filepath in churn:
            exposure = 0.0
            for bf_file in bug_fix_files:
                if bf_file == filepath:
                    continue
                # Canonical key order
                key = (min(filepath, bf_file), max(filepath, bf_file))
                count = analysis.co_change_matrix.get(key, 0)
                exposure += count
            co_change_exposure[filepath] = exposure

        max_exposure = max(co_change_exposure.values()) if co_change_exposure else 1.0
    else:
        max_exposure = 1.0

    # --- Build: last bug-fix date per file ---
    # We need to find the most recent bug-fix commit that touched each file.
    # Index: file -> most recent bug-fix commit date string
    last_bug_fix_date: dict[str, str] = {}
    for commit in analysis.bug_fix_commits:
        for filepath in commit.files_changed:
            if filepath not in last_bug_fix_date:
                # Commits are newest-first from git log; first seen = most recent
                last_bug_fix_date[filepath] = commit.date

    # --- Compute per-file predictions ---
    predictions: list[BugPrediction] = []

    # Collect churn values for percentile labels
    all_churn_values = [fc.commit_count for fc in churn.values()]

    for filepath, fc in churn.items():
        # Factor 1: bug history
        bug_history_score = _safe_div(fc.bug_fix_count, max_bug_fixes)

        # Factor 2: churn risk
        churn_score = _safe_div(fc.commit_count, max_commits)

        # Factor 3: co-change infection
        raw_exposure = co_change_exposure.get(filepath, 0.0)
        co_change_score = _safe_div(raw_exposure, max_exposure)

        # Factor 4: recency (exponential decay, half-life ~30 days)
        recency_score = 0.0
        last_bf = last_bug_fix_date.get(filepath)
        if last_bf is not None:
            days_ago = _days_since(last_bf, now)
            if days_ago is not None:
                # Half-life of 30 days: score = exp(-ln(2)/30 * days_ago)
                # At 0 days: 1.0. At 30 days: 0.5. At 90 days: 0.125.
                import math
                recency_score = math.exp(-0.0231 * days_ago)  # ln(2)/30 ≈ 0.0231

        # Weighted composite
        probability = (
            _W_BUG_HISTORY * bug_history_score
            + _W_CHURN * churn_score
            + _W_CO_CHANGE * co_change_score
            + _W_RECENCY * recency_score
        )
        # Clamp to [0.0, 1.0] for floating-point safety
        probability = max(0.0, min(1.0, probability))

        # --- Build human-readable risk factors ---
        risk_factors: list[str] = []

        if fc.bug_fix_count > 0:
            risk_factors.append(
                f"{fc.bug_fix_count} bug fix{'es' if fc.bug_fix_count != 1 else ''} "
                f"in last {analysis.timeframe_days} days"
            )

        if fc.commit_count > 0:
            pct = _percentile_rank(fc.commit_count, all_churn_values)
            pct_label = f"top {int((1 - pct) * 100)}% churn" if pct >= 0.5 else f"bottom {int(pct * 100 + 1)}% churn"
            risk_factors.append(
                f"Changed in {fc.commit_count} commit{'s' if fc.commit_count != 1 else ''} ({pct_label})"
            )

        if raw_exposure > 0:
            # Count how many distinct bug-fix files this file co-changes with
            cochange_partners = sum(
                1 for bf_file in bug_fix_files
                if bf_file != filepath
                and analysis.co_change_matrix.get(
                    (min(filepath, bf_file), max(filepath, bf_file)), 0
                ) > 0
            )
            if cochange_partners > 0:
                risk_factors.append(
                    f"Co-changes with {cochange_partners} high-risk "
                    f"file{'s' if cochange_partners != 1 else ''}"
                )

        if last_bf is not None:
            days_ago = _days_since(last_bf, now)
            if days_ago is not None:
                days_int = int(days_ago)
                risk_factors.append(
                    f"Last bug fix was {days_int} day{'s' if days_int != 1 else ''} ago"
                )

        predictions.append(
            BugPrediction(
                path=filepath,
                probability=round(probability, 4),
                risk_factors=risk_factors,
                bug_fix_count=fc.bug_fix_count,
                co_change_risk=round(co_change_score, 4),
                churn_risk=round(churn_score, 4),
            )
        )

    # Sort descending by probability; tie-break by path for stable output
    predictions.sort(key=lambda p: (-p.probability, p.path))

    return predictions[:top_n]
