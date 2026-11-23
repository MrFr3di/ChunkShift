#!/usr/bin/env python3
"""Print the published ChunkShift version a Patching consumer can run over.

CI runs the packed ChunkShift.Patching package once over the Core packed next
to it and once over a published Core, and requires identical evidence. The
packed Patching assembly references the Core assembly version of this commit
(X.Y.Z.0, from VersionPrefix), and .NET does not load a lower assembly version
than the one referenced. So only a published Core with the same X.Y.Z can
stand in for the packed one.

The script prints the highest nuget.org version of ChunkShift whose X.Y.Z
equals VersionPrefix of src/ChunkShift/ChunkShift.csproj, stable before any
pre-release. It prints nothing when there is none, for example in the release
PR that bumps VersionPrefix: that commit has no published counterpart yet.

The script uses only Python's standard library.

Usage:
  published_core_version.py [--project src/ChunkShift/ChunkShift.csproj]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

INDEX_URL = "https://api.nuget.org/v3-flatcontainer/chunkshift/index.json"


def version_prefix(project: Path) -> str:
    match = re.search(
        r"<VersionPrefix>\s*([0-9]+\.[0-9]+\.[0-9]+)\s*</VersionPrefix>",
        project.read_text(encoding="utf-8"),
    )
    if match is None:
        raise SystemExit(f"{project}: no X.Y.Z VersionPrefix")
    return match.group(1)


def precedence(version: str) -> tuple:
    core, _, pre = version.split("+", 1)[0].partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if not pre:
        return (numbers, 1, ())
    return (
        numbers,
        0,
        tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part)
            for part in pre.lower().split(".")
        ),
    )


def published_versions() -> list[str]:
    try:
        with urllib.request.urlopen(INDEX_URL, timeout=30) as response:
            return json.load(response)["versions"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return []
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--project",
        type=Path,
        default=Path("src/ChunkShift/ChunkShift.csproj"),
    )
    args = parser.parse_args()

    prefix = version_prefix(args.project)
    candidates = [
        version
        for version in published_versions()
        if version.split("+", 1)[0].partition("-")[0] == prefix
    ]
    if candidates:
        print(max(candidates, key=precedence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
