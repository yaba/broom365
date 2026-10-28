"""Scan-scope patterns: which inventoried objects should be scanned. Pure, no I/O.

Syntax (one pattern per line):
    win10-app-deployment*     '*' = any run of characters, '?' = exactly one character
    sales-emea                no wildcard = exact name
    !win10-app-deployment-t*  leading '!' excludes what the includes matched
    # comment                 ignored, as are blank lines
Matching is case-insensitive and applies to the display name. A scope with no include
pattern matches nothing (exclusions alone never widen a scope).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


def _to_regex(pattern: str) -> re.Pattern[str]:
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{body}$", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class ScopeMatcher:
    includes: tuple[re.Pattern[str], ...]
    excludes: tuple[re.Pattern[str], ...]

    def matches_any(self, names: "Iterable[str | None]") -> bool:
        """For objects with several names (a guest: display name, e-mail, company domain).

        Selected if ANY name matches an include pattern and NO name matches an exclude pattern.
        """
        found = [n for n in names if n]
        if not found or not self.includes:
            return False
        return any(p.match(n) for n in found for p in self.includes) and not any(p.match(n) for n in found for p in self.excludes)

    def matches(self, name: str | None) -> bool:
        """True if `name` matches an include pattern and no exclude pattern."""
        if not name or not self.includes:
            return False
        return any(p.match(name) for p in self.includes) and not any(p.match(name) for p in self.excludes)


def parse_patterns(text: str) -> ScopeMatcher:
    """Parse the multi-line pattern text into a matcher (see module docstring)."""
    includes: list[re.Pattern[str]] = []
    excludes: list[re.Pattern[str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            if len(line) > 1:
                excludes.append(_to_regex(line[1:].strip()))
        else:
            includes.append(_to_regex(line))
    return ScopeMatcher(tuple(includes), tuple(excludes))
