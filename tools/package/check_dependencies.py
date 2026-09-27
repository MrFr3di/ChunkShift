#!/usr/bin/env python3
"""Check the runtime dependency surface of a packed ChunkShift package.

The published package intentionally has exactly one runtime dependency,
Blake3, at a plain minimum version for every shipped target framework. Build
and analyzer packages such as Microsoft.CodeAnalysis.PublicApiAnalyzers stay
private to this repository. A new PackageReference would silently widen the
dependency contract consumers inherit, so this script makes the current
surface executable: it reads ChunkShift.nuspec from the .nupkg and fails on
any dependency, version range or framework reference that does not match.

The script uses only Python's standard library.

Usage:
  check_dependencies.py PACKAGE.nupkg [--packages-props Directory.Packages.props]
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

# The complete runtime dependency contract of the package: exactly these
# dependencies, at their plain minimum versions, in every shipped target
# framework group. Changing this set is a public dependency-contract change
# and needs an issue; this script is what keeps that decision executable.
EXPECTED_DEPENDENCIES = ("Blake3",)
EXPECTED_TARGET_FRAMEWORKS = ("net8.0", "net10.0")

# Build, analyzer and test packages must never appear in the nuspec. The
# "expected dependencies" rule would catch them anyway; matching them by name
# keeps the failure message actionable. Patterns match case-insensitively.
PRIVATE_DEPENDENCY_PATTERNS = (
    "microsoft.codeanalysis.*",
    "xunit*",
    "microsoft.net.test.sdk",
    "coverlet*",
    "benchmarkdotnet*",
)

NUSPEC_ENTRY = "ChunkShift.nuspec"

FRAMEWORK_REFERENCE_ELEMENTS = ("frameworkReferences", "frameworkAssemblies")

VERSION_RANGE_CHARACTERS = "[](),"


class CheckError(Exception):
    """The input cannot be checked at all (missing or malformed input)."""


def _local_name(tag: str) -> str:
    """Return the local name of an XML tag, ignoring any namespace."""
    return tag.rsplit("}", 1)[-1]


def _find_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _dependency_id(element: ET.Element) -> str:
    return element.get("id") or "(missing id)"


def _is_private_dependency(package_id: str) -> bool:
    lowered = package_id.lower()
    return any(
        fnmatch.fnmatchcase(lowered, pattern)
        for pattern in PRIVATE_DEPENDENCY_PATTERNS
    )


def read_metadata(package: Path) -> ET.Element:
    """Return the nuspec <metadata> element of the package."""
    try:
        with zipfile.ZipFile(package) as archive:
            try:
                raw = archive.read(NUSPEC_ENTRY)
            except KeyError:
                raise CheckError(
                    f"{package}: the package does not contain {NUSPEC_ENTRY}"
                ) from None
    except (OSError, zipfile.BadZipFile) as error:
        raise CheckError(f"{package}: cannot read package: {error}") from error

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise CheckError(
            f"{package}: {NUSPEC_ENTRY} is not well-formed XML: {error}"
        ) from error

    metadata = _find_child(root, "metadata")
    if metadata is None:
        raise CheckError(f"{package}: {NUSPEC_ENTRY} has no <metadata> element")
    return metadata


def expected_versions(packages_props: Path) -> dict[str, str]:
    """Return the plain minimum version for each expected dependency id."""
    if not packages_props.is_file():
        raise CheckError(f"{packages_props}: file not found")

    try:
        root = ET.parse(packages_props).getroot()
    except ET.ParseError as error:
        raise CheckError(f"{packages_props}: not well-formed XML: {error}") from error

    expected_ids = {dependency.lower() for dependency in EXPECTED_DEPENDENCIES}
    versions: dict[str, str] = {}

    for element in root.iter():
        if _local_name(element.tag) != "PackageVersion":
            continue
        include = element.get("Include") or element.get("Update") or ""
        package_id = include.lower()
        if package_id not in expected_ids:
            continue
        version = (element.get("Version") or "").strip()
        if not version:
            raise CheckError(
                f"{packages_props}: PackageVersion for {include} has no "
                "Version attribute"
            )
        if any(character in version for character in VERSION_RANGE_CHARACTERS):
            raise CheckError(
                f"{packages_props}: PackageVersion for {include} is the range "
                f"'{version}'; the package publishes a plain minimum version"
            )
        if package_id in versions and versions[package_id] != version:
            raise CheckError(
                f"{packages_props}: conflicting PackageVersion entries for "
                f"{include}: {versions[package_id]} and {version}"
            )
        versions[package_id] = version

    for dependency in EXPECTED_DEPENDENCIES:
        if dependency.lower() not in versions:
            raise CheckError(
                f"{packages_props}: no PackageVersion entry for {dependency}"
            )
    return versions


def _dependency_violations(
    element: ET.Element, versions: dict[str, str]
) -> list[str]:
    """Check one <dependency> element wherever it appears."""
    violations: list[str] = []
    package_id = element.get("id") or ""

    if _is_private_dependency(package_id):
        violations.append(
            f"build/test-only dependency '{package_id}' must not be part of "
            "the runtime dependency surface"
        )

    expected = versions.get(package_id.lower())
    if expected is None:
        return violations

    version = element.get("version")
    if version is None:
        violations.append(
            f"{package_id} dependency has no version attribute; "
            f"expected the plain minimum version '{expected}'"
        )
    elif version.strip() != expected or any(
        character in version for character in VERSION_RANGE_CHARACTERS
    ):
        violations.append(
            f"{package_id} dependency version '{version}' is not the plain "
            f"minimum version '{expected}'; the package publishes no version "
            "range or upper bound"
        )
    return violations


def _framework_reference_violations(metadata: ET.Element) -> list[str]:
    """Check for <frameworkReferences> or <frameworkAssemblies> entries."""
    violations: list[str] = []

    for element in metadata.iter():
        name = _local_name(element.tag)
        if name not in FRAMEWORK_REFERENCE_ELEMENTS:
            continue
        entries = [entry for entry in element.iter() if entry is not element]
        if not entries:
            continue
        names = sorted(
            {entry.get("name") for entry in entries if entry.get("name")}
        )
        detail = ", ".join(names) if names else f"{len(entries)} entries"
        violations.append(f"the nuspec declares <{name}>: {detail}")

    return violations


def collect_violations(
    metadata: ET.Element, versions: dict[str, str]
) -> list[str]:
    """Return every violation of the runtime dependency contract."""
    violations: list[str] = []
    expected_ids = {dependency.lower() for dependency in EXPECTED_DEPENDENCIES}

    dependencies = _find_child(metadata, "dependencies")
    groups: list[tuple[str, str, list[ET.Element]]] = []
    if dependencies is None:
        violations.append("the nuspec has no <dependencies> element")
    else:
        for child in dependencies:
            name = _local_name(child.tag)
            if name == "group":
                target = (child.get("targetFramework") or "").strip()
                label = target or "(missing targetFramework)"
                entries = [
                    entry
                    for entry in child
                    if _local_name(entry.tag) == "dependency"
                ]
                for entry in child:
                    if _local_name(entry.tag) != "dependency":
                        violations.append(
                            f"unexpected <{_local_name(entry.tag)}> element inside "
                            f"dependency group '{label}'"
                        )
                groups.append((target, target.lower(), entries))
            elif name == "dependency":
                violations.append(
                    f"dependency '{_dependency_id(child)}' is declared outside "
                    "a target-framework group"
                )
                violations.extend(_dependency_violations(child, versions))
            else:
                violations.append(
                    f"unexpected <{name}> element inside <dependencies>"
                )

    observed_targets = sorted(target for _, target, _ in groups)
    if observed_targets != sorted(EXPECTED_TARGET_FRAMEWORKS):
        violations.append(
            "dependency groups must be exactly "
            + ", ".join(EXPECTED_TARGET_FRAMEWORKS)
            + "; found "
            + (
                ", ".join(
                    raw or "(missing targetFramework)" for raw, _, _ in groups
                )
                or "none"
            )
        )

    for raw, target, entries in groups:
        label = raw or "(missing targetFramework)"
        for entry in entries:
            violations.extend(_dependency_violations(entry, versions))
        if len(entries) != 1:
            violations.append(
                f"dependency group '{label}' must contain exactly one "
                f"dependency, found {len(entries)}: "
                + (", ".join(_dependency_id(entry) for entry in entries) or "none")
            )
        elif _dependency_id(entries[0]).lower() not in expected_ids:
            violations.append(
                f"dependency group '{label}' must contain exactly one dependency "
                "with id " + " or ".join(EXPECTED_DEPENDENCIES) + ", found "
                f"'{_dependency_id(entries[0])}'"
            )

    violations.extend(_framework_reference_violations(metadata))
    return violations


def success_line(versions: dict[str, str]) -> str:
    dependencies = ", ".join(
        f"{dependency} >= {versions[dependency.lower()]}"
        for dependency in EXPECTED_DEPENDENCIES
    )
    return (
        "ChunkShift package runtime dependencies OK: "
        + ", ".join(EXPECTED_TARGET_FRAMEWORKS)
        + f" -> {dependencies}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the runtime dependency surface of a packed "
        "ChunkShift package."
    )
    parser.add_argument(
        "package",
        type=Path,
        help="Path to the ChunkShift .nupkg to check.",
    )
    parser.add_argument(
        "--packages-props",
        type=Path,
        default=Path("Directory.Packages.props"),
        help="Directory.Packages.props that owns the expected dependency "
        "versions.",
    )
    args = parser.parse_args()

    try:
        versions = expected_versions(args.packages_props)
        metadata = read_metadata(args.package)
    except CheckError as error:
        print(error, file=sys.stderr)
        return 2

    violations = collect_violations(metadata, versions)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        print(
            "ChunkShift package runtime dependency check FAILED: "
            f"{len(violations)} violation(s)",
            file=sys.stderr,
        )
        return 1

    print(success_line(versions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
