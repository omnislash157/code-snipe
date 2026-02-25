"""
Portable Seraph — Language-agnostic codebase intelligence.

Phase 1: scanner.py + import_graph.py
  scanner.py      — Language detection + file discovery
  import_graph.py — Import graph builder (ast for Python, regex for TS/JS)

Usage:
    from code_snipe.seraph.scanner import scan_repo
    from code_snipe.seraph.import_graph import build_import_graph

    scan = scan_repo('/path/to/any/repo')
    graph = build_import_graph(scan)
"""
