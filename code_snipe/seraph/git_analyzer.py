"""
Portable Seraph — Git History Analysis

Parse git history to build a co-change matrix and identify bug-fix commits.
No database. No config. Pure subprocess + stdlib.

Usage:
    from code_snipe.seraph.git_analyzer import analyze_git_history

    analysis = analyze_git_history('/path/to/repo', days=365)
    print(f'Bug-fix commits: {len(analysis.bug_fix_commits)}')
    print(f'Co-change pairs: {len(analysis.co_change_matrix)}')
"""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path


# ---------------------------------------------------------------------------
# Bug-fix keyword patterns (word-boundary matched, case-insensitive)
# ---------------------------------------------------------------------------

_BUG_FIX_PATTERNS = re.compile(
    r'\b(?:fix(?:es|ed)?|bug|hotfix|patch(?:ed)?|resolve[sd]?|issue|'
    r'error|crash(?:ed)?|broken|repair(?:ed)?|regression)\b',
    re.IGNORECASE,
)

# Test file patterns — commits that ONLY touch these are NOT bug fixes
_TEST_FILE_PATTERNS = re.compile(
    r'(?:^|/)(?:test[s_]|spec[s_]|__tests?__|conftest)'
    r'|[_-]test[s]?\.(?:py|ts|js|go|rs|java|rb|cs)$'
    r'|\.spec\.(?:ts|js)$'
    r'|/tests?/',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CommitInfo:
    """Metadata and file list for a single git commit."""

    hash: str
    subject: str
    author: str
    date: str
    files_changed: list[str]
    insertions: int
    deletions: int
    is_bug_fix: bool


@dataclass
class FileChurn:
    """Per-file change statistics derived from git history."""

    path: str
    commit_count: int
    total_insertions: int
    total_deletions: int
    bug_fix_count: int
    last_changed: str  # ISO date string of most recent commit touching this file
    authors: set[str] = field(default_factory=set)


@dataclass
class GitAnalysis:
    """Full result of a git history analysis run."""

    commits: list[CommitInfo]
    bug_fix_commits: list[CommitInfo]
    co_change_matrix: dict[tuple[str, str], int]  # (file_a, file_b) -> count
    file_churn: dict[str, FileChurn]              # path -> FileChurn
    total_commits: int
    timeframe_days: int


# ---------------------------------------------------------------------------
# Git log parsing
# ---------------------------------------------------------------------------


def _run_git(repo_path: str, args: list[str], timeout: int = 60) -> str:
    """
    Run a git command in repo_path and return stdout as text.

    Returns empty string on non-zero exit or any subprocess error.
    """
    cmd = ["git", "-C", repo_path] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def _is_bug_fix_subject(subject: str) -> bool:
    """Return True if the commit subject contains a bug-fix keyword."""
    return bool(_BUG_FIX_PATTERNS.search(subject))


def _all_test_files(files: list[str]) -> bool:
    """Return True if every file in the list matches a test-file pattern."""
    if not files:
        return False
    return all(_TEST_FILE_PATTERNS.search(f) for f in files)


def _parse_numstat_output(raw: str) -> dict[str, tuple[list[str], int, int]]:
    """
    Parse `git log --numstat --format="%H" --no-merges` output.

    Returns a dict mapping commit_hash -> (files_changed, total_insertions, total_deletions).

    The raw output interleaves commit hashes (single token lines) with numstat
    rows (three tab-separated columns: insertions, deletions, filename).

    Example raw block:
        abc123

        5\t2\tsome/file.py
        -\t-\tbinary_file.dat
        3\t0\tanother/file.py

        def456

        10\t1\tfoo.py
    """
    result: dict[str, tuple[list[str], int, int]] = {}
    current_hash: str | None = None
    current_files: list[str] = []
    current_ins: int = 0
    current_del: int = 0

    for line in raw.splitlines():
        line = line.rstrip()

        if not line:
            continue

        # Numstat line: "insertions\tdeletions\tfilename"
        if "\t" in line:
            parts = line.split("\t", 2)
            if len(parts) == 3 and current_hash is not None:
                ins_str, del_str, filepath = parts
                # Binary files show "-" for counts
                try:
                    ins = int(ins_str)
                except ValueError:
                    ins = 0
                try:
                    del_ = int(del_str)
                except ValueError:
                    del_ = 0
                current_files.append(filepath)
                current_ins += ins
                current_del += del_
        else:
            # Flush previous commit
            if current_hash is not None:
                result[current_hash] = (current_files, current_ins, current_del)

            # Start new commit
            current_hash = line.strip()
            current_files = []
            current_ins = 0
            current_del = 0

    # Flush final commit
    if current_hash is not None:
        result[current_hash] = (current_files, current_ins, current_del)

    return result


def _get_existing_files(repo_path: str) -> set[str]:
    """
    Return the set of files that currently exist in the repo.

    Uses `git ls-files` — only tracks committed files, not untracked.
    Falls back to an empty set if the command fails (safe — skips
    co-change filtering rather than crashing).
    """
    raw = _run_git(repo_path, ["ls-files"])
    if not raw:
        return set()
    return {line.strip() for line in raw.splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze_git_history(repo_path: str, days: int = 365) -> GitAnalysis:
    """
    Parse git history for repo_path over the past `days` days.

    Steps:
    1. Fetch commit metadata (hash, subject, author, date) via --format
    2. Fetch per-commit numstat (file insertions/deletions) in one pass
    3. Identify bug-fix commits via subject keyword matching
    4. Build co-change matrix (pairs of files changed together)
    5. Build per-file churn stats

    Args:
        repo_path: Absolute or relative path to the git repository root.
        days:      How far back to look (default: 365 days).

    Returns:
        GitAnalysis dataclass with all findings.
    """
    repo_path = str(Path(repo_path).resolve())
    since = f"{days} days ago"

    # --- Step 1: Commit metadata ---
    # Format: HASH|subject|author name|ISO date
    meta_raw = _run_git(
        repo_path,
        ["log", f"--since={since}", "--format=%H|%s|%an|%ai", "--no-merges"],
        timeout=90,
    )

    # Parse metadata lines
    commit_meta: dict[str, tuple[str, str, str]] = {}  # hash -> (subject, author, date)
    for line in meta_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        commit_hash, subject, author, date = parts
        commit_meta[commit_hash.strip()] = (subject.strip(), author.strip(), date.strip())

    # --- Step 2: Numstat (file change counts per commit) ---
    numstat_raw = _run_git(
        repo_path,
        ["log", f"--since={since}", "--numstat", "--format=%H", "--no-merges"],
        timeout=90,
    )
    numstat: dict[str, tuple[list[str], int, int]] = _parse_numstat_output(numstat_raw)

    # --- Step 3: Get files that still exist in the repo ---
    existing_files = _get_existing_files(repo_path)

    # --- Step 4: Build CommitInfo list ---
    commits: list[CommitInfo] = []

    for commit_hash, (subject, author, date) in commit_meta.items():
        files_raw, insertions, deletions = numstat.get(commit_hash, ([], 0, 0))

        # Filter to files that still exist (skip deleted files for co-change)
        files_existing = [f for f in files_raw if f in existing_files]

        is_bf = _is_bug_fix_subject(subject) and not _all_test_files(files_raw)

        commits.append(
            CommitInfo(
                hash=commit_hash,
                subject=subject,
                author=author,
                date=date,
                files_changed=files_existing,
                insertions=insertions,
                deletions=deletions,
                is_bug_fix=is_bf,
            )
        )

    bug_fix_commits = [c for c in commits if c.is_bug_fix]

    # --- Step 5: Co-change matrix ---
    # For each commit, every pair of files that changed together gets +1.
    co_change: dict[tuple[str, str], int] = defaultdict(int)

    for commit in commits:
        # Sort for canonical ordering (file_a < file_b always)
        present = sorted(commit.files_changed)
        for file_a, file_b in combinations(present, 2):
            co_change[(file_a, file_b)] += 1

    # --- Step 6: Per-file churn stats ---
    file_churn: dict[str, FileChurn] = {}

    for commit in commits:
        for filepath in commit.files_changed:
            if filepath not in file_churn:
                file_churn[filepath] = FileChurn(
                    path=filepath,
                    commit_count=0,
                    total_insertions=0,
                    total_deletions=0,
                    bug_fix_count=0,
                    last_changed=commit.date,
                    authors=set(),
                )

            churn = file_churn[filepath]
            churn.commit_count += 1
            churn.total_insertions += commit.insertions
            churn.total_deletions += commit.deletions
            churn.authors.add(commit.author)

            if commit.is_bug_fix:
                churn.bug_fix_count += 1

            # Keep the most recent date (commits are returned newest-first by git log)
            # We want the most recent, so take the first we see per file.
            # Because commits are newest-first, the first encounter is the latest date.
            # We set it on construction above — no update needed.

    return GitAnalysis(
        commits=commits,
        bug_fix_commits=bug_fix_commits,
        co_change_matrix=dict(co_change),
        file_churn=file_churn,
        total_commits=len(commits),
        timeframe_days=days,
    )
