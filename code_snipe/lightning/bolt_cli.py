"""
bolt_cli.py - The bolt that fires when you type hound.

Simplified CLI: 6 flags, smart argument order detection.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    """Lightning CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Lightning: AST-aware code search",
        epilog="Examples:\n"
        "  hound 'sendWhenReady' core/         # Fuzzy search in core/\n"
        "  hound 'def submit' auth/ -r         # Regex search\n"
        "  hound core/ 'db_query'              # Old arg order works too\n"
        "  hound --cooccur 'auth' core/        # Co-occurrence analysis\n"
        "  hound --stats 'websocket' core/     # Frequency stats\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("first", help="Search term or path")
    parser.add_argument("second", nargs="?", default=None, help="Path or search term")
    parser.add_argument("-r", "--regex", action="store_true", help="Raw regex mode")
    parser.add_argument("-g", "--glob", default=None, help="File pattern filter (e.g. '*.py')")
    parser.add_argument("-n", "--max-files", type=int, default=20, help="Max result files")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--cooccur", "-c", action="store_true", help="Co-occurrence analysis")
    parser.add_argument("--stats", action="store_true", help="Frequency stats only")

    args = parser.parse_args()

    # Smart argument order detection
    # If first arg is a directory, treat as: hound <path> <term> (old style)
    # Otherwise: hound <term> [path] (new style)
    first_is_dir = Path(args.first).is_dir()

    if first_is_dir and args.second:
        search_path = args.first
        term = args.second
    elif args.second and Path(args.second).is_dir():
        term = args.first
        search_path = args.second
    elif first_is_dir:
        # Only a directory, no term — error unless stats/cooccur mode
        if not (args.stats or args.cooccur):
            parser.error("Search term required")
        search_path = args.first
        term = args.second or ""
    else:
        term = args.first
        search_path = args.second or "."

    from .blitz_hunt import Lightning

    bolt = Lightning(search_path)

    # Co-occurrence mode
    if args.cooccur:
        try:
            from .extras.storm_cooccurrence import storm_markdown
        except ImportError:
            print("Co-occurrence analysis not available (extras not installed)", file=sys.stderr)
            sys.exit(1)
        output = storm_markdown(bolt, term, file_pattern=args.glob, max_files=args.max_files)
        print(output)
        return

    # Stats mode
    if args.stats:
        try:
            from .extras.stats import quick_stats
        except ImportError:
            print("Stats mode not available (extras not installed)", file=sys.stderr)
            sys.exit(1)
        stats = quick_stats(bolt, term)
        print(json.dumps(stats, indent=2))
        return

    # Default: hunt
    result = bolt.hunt(
        term,
        regex=args.regex,
        file_pattern=args.glob,
        max_files=args.max_files,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.to_markdown())


if __name__ == "__main__":
    main()
