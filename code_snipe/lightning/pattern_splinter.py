"""
pattern_splinter.py - Splits identifiers like lightning splits a tree.

Fuzzy pattern builder + tokenization. Turns getUserName into a regex
that matches get_user_name, GetUserName, get-user-name, get.user.name.
"""

import re


def tokenize(text: str) -> list[str]:
    """Split text into tokens (preserves whitespace for reconstruction)."""
    return re.findall(r"\S+|\s+", text)


def detokenize(tokens: list[str]) -> str:
    """Reconstruct text from tokens."""
    return "".join(tokens)


def token_count(text: str) -> int:
    """Count non-whitespace tokens."""
    return len([t for t in tokenize(text) if t.strip()])


def split_identifier(name: str) -> list[str]:
    """
    Split an identifier into component words.

    Handles:
    - camelCase: getUserName -> [get, User, Name]
    - PascalCase: GetUserName -> [Get, User, Name]
    - snake_case: get_user_name -> [get, user, name]
    - kebab-case: get-user-name -> [get, user, name]
    - dot.notation: user.name.get -> [user, name, get]
    - SCREAMING_SNAKE: GET_USER_NAME -> [GET, USER, NAME]
    """
    # Split on explicit separators
    parts = re.split(r"[-_.\s]+", name)

    # Split camelCase within each part
    result = []
    for part in parts:
        if not part:
            continue
        camel_parts = re.findall(
            r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+", part
        )
        if camel_parts:
            result.extend(camel_parts)
        else:
            result.append(part)

    return [p for p in result if p]


def build_code_pattern(term: str, case_insensitive: bool = True) -> re.Pattern:
    """
    Build regex that matches code identifier variations.

    "getUserName" matches: getUserName, get_user_name, GetUserName,
    get-user-name, get.user.name, GETUSERNAME, etc.
    """
    parts = split_identifier(term)

    if not parts:
        flags = re.IGNORECASE if case_insensitive else 0
        return re.compile(re.escape(term), flags)

    escaped_parts = [re.escape(p) for p in parts]
    separator = r"[-_.\s]?"
    pattern = separator.join(escaped_parts)

    flags = re.IGNORECASE if case_insensitive else 0
    return re.compile(pattern, flags)


def get_identifier_variations(term: str) -> list[str]:
    """Generate human-readable list of variations being matched."""
    parts = split_identifier(term)

    if not parts:
        return [term]

    lower_parts = [p.lower() for p in parts]

    return [
        "".join(lower_parts),                                          # getusername
        "_".join(lower_parts),                                         # get_user_name
        "-".join(lower_parts),                                         # get-user-name
        ".".join(lower_parts),                                         # get.user.name
        "".join(p.capitalize() for p in lower_parts),                  # GetUserName
        lower_parts[0] + "".join(p.capitalize() for p in lower_parts[1:]),  # getUserName
        "_".join(p.upper() for p in lower_parts),                      # GET_USER_NAME
    ]
