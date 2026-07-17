#!/usr/bin/env python
"""Stamp the CHANGELOG [Unreleased] section as a release.

Usage:
    release_changelog.py <version>   # [Unreleased] -> [version] - today
    release_changelog.py --check     # exit 1 if [Unreleased] is empty
"""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
REPO = "https://github.com/maartenq/cnert"
UNRELEASED = "## [Unreleased]"


def unreleased_body(text: str) -> str:
    """Return the text between [Unreleased] and the next release heading."""
    start = text.index(UNRELEASED) + len(UNRELEASED)
    match = re.search(r"\n## \[", text[start:])
    end = start + match.start() if match else len(text)
    return text[start:end].strip()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    text = CHANGELOG.read_text()
    if not unreleased_body(text):
        raise SystemExit(
            "CHANGELOG: nothing under [Unreleased]; add notes first"
        )
    if sys.argv[1] == "--check":
        return
    version = sys.argv[1]
    date = datetime.date.today().isoformat()
    text = text.replace(
        UNRELEASED,
        f"{UNRELEASED}\n\n## [{version}] - {date}",
        1,
    )
    text = re.sub(
        r"\[Unreleased\]: \S+",
        f"[Unreleased]: {REPO}/compare/{version}...HEAD\n"
        f"[{version}]: {REPO}/releases/tag/{version}",
        text,
        count=1,
    )
    CHANGELOG.write_text(text)


if __name__ == "__main__":
    main()
