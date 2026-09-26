#!/usr/bin/env python3
"""Generate independent CSM v1 candidate SHA-256 vectors.

This tool intentionally does not call ChunkShift code. It uses only Python's
standard library and the byte layout documented in docs/architecture/CSM-V1.md.

Besides the four golden fixtures it emits positive, integrity-failure and
rejection vectors. Each vector is built from the byte layout directly, with
every unrelated offset and digest kept consistent, so it violates exactly the
rule its name describes. The expected verdict of every vector is written to
vectors.json from this file's definitions, never from any decoder.

--verify checks a directory against the generator and against the independent
decoder in decode.py (which does not import this module):

  1. every file in the directory is byte-identical to a fresh generation;
  2. vectors.json is identical to the generated expectations;
  3. decode.py reaches the expected verdict for every vector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

FORMAT_MAJOR = 1
PREAMBLE_SIZE = 32
TRAILER_SIZE = 64
REQUIRED = 1
MAX_CHUNKS_PER_BLOCK = 4096

HASH_SUITE_ID = b"chunkshift.sha256.v1"
PROFILE_ID = b"fixture.csm.synthetic.v1"
PROFILE_FINGERPRINT = hashlib.sha256(
    b"chunkshift.csm.fixture.profile.v1"
).digest()
MANIFEST_DOMAIN = b"chunkshift.manifest-id.v1\0"

Entries = list[tuple[bytes, int]]


def section_header(kind: bytes, flags: int, payload_length: int) -> bytes:
    if len(kind) != 4:
        raise ValueError("FourCC must be four bytes")
    return kind + struct.pack("<IQ", flags, payload_length)


def section(kind: bytes, flags: int, payload: bytes) -> bytes:
    return section_header(kind, flags, len(payload)) + payload


def crc32c(data: bytes) -> int:
    state = 0xFFFFFFFF
    polynomial = 0x82F63B78

    for value in data:
        state ^= value
        for _ in range(8):
            state = (state >> 1) ^ (polynomial if state & 1 else 0)

    return (~state) & 0xFFFFFFFF


def manifest_id(
    entries: Entries,
    hash_suite_id: bytes = HASH_SUITE_ID,
    profile_id: bytes = PROFILE_ID,
) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    digest.update(MANIFEST_DOMAIN)
    digest.update(struct.pack("<H", len(hash_suite_id)))
    digest.update(hash_suite_id)
    digest.update(struct.pack("<H", len(profile_id)))
    digest.update(profile_id)
    digest.update(PROFILE_FINGERPRINT)

    total_length = 0
    for chunk_id, length in entries:
        digest.update(chunk_id)
        digest.update(struct.pack("<I", length))
        total_length += length

    digest.update(struct.pack("<QQ", len(entries), total_length))
    return digest.digest(), total_length


def xor_byte(data: bytes, offset: int, mask: int = 0x01) -> bytes:
    mutable = bytearray(data)
    mutable[offset] ^= mask
    return bytes(mutable)


@dataclass
class Layout:
    """Knobs for building a CSM that deviates from v1 in one controlled way.

    The defaults produce a conforming representation. Offsets recorded in FOOT
    and TRAILER always describe the bytes actually emitted, and the FileDigest
    is always recomputed, unless a knob deliberately breaks that field.
    """

    magic: bytes = b"CSM1"
    format_major: int = FORMAT_MAJOR
    required_physical_features: int = 0
    optional_physical_features: int = 0
    preamble_reserved: int = 0

    hash_suite_id: bytes = HASH_SUITE_ID
    profile_id: bytes = PROFILE_ID
    required_semantic_features: int = 0
    optional_semantic_features: int = 0
    core_extension: bytes = b""
    core_payload_padding: bytes = b""

    include_block_index: bool = False
    block_index_flags: int = 0
    block_index_version: int = 1
    block_index_physical_delta: int = 0

    cblk_flags: int = REQUIRED
    cblk_reserved: int = 0
    cblk_first_index_delta: int = 0
    cblk_first_offset_delta: int = 0
    cblk_crc_xor: int = 0
    cblk_forced_payload_length: int | None = None

    cend_count_delta: int = 0
    cend_length_delta: int = 0
    cend_manifest_id_xor: bool = False
    omit_cend: bool = False

    foot_cend_offset_delta: int = 0
    foot_reserved: int = 0

    trailer_physical_length_delta: int = 0
    trailer_reserved: int = 0
    trailer_digest_xor: bool = False

    # Raw sections inserted at fixed points of the physical order.
    after_core: list[bytes] = field(default_factory=list)
    after_cend: list[bytes] = field(default_factory=list)
    after_bidx: list[bytes] = field(default_factory=list)
    after_foot: list[bytes] = field(default_factory=list)
    after_trailer: bytes = b""


def core_section(layout: Layout = Layout()) -> bytes:
    payload = bytearray(56)
    struct.pack_into(
        "<QQ",
        payload,
        0,
        layout.required_semantic_features,
        layout.optional_semantic_features,
    )
    payload[16:48] = PROFILE_FINGERPRINT
    struct.pack_into(
        "<HHI",
        payload,
        48,
        len(layout.hash_suite_id),
        len(layout.profile_id),
        len(layout.core_extension),
    )
    payload += layout.hash_suite_id
    payload += layout.profile_id
    payload += layout.core_extension
    payload += layout.core_payload_padding
    return section_header(b"CORE", REQUIRED, len(payload)) + payload


def chunk_block(
    entries: Entries,
    first_index: int,
    first_content_offset: int,
    layout: Layout = Layout(),
) -> bytes:
    count = len(entries)
    prefix = struct.pack(
        "<IIQQ",
        count,
        layout.cblk_reserved,
        first_index + layout.cblk_first_index_delta,
        first_content_offset + layout.cblk_first_offset_delta,
    )
    ids = b"".join(chunk_id for chunk_id, _ in entries)
    lengths = b"".join(
        struct.pack("<I", length)
        for _, length in entries
    )
    payload_length = 24 + count * 32 + count * 4 + 4
    if layout.cblk_forced_payload_length is not None:
        payload_length = layout.cblk_forced_payload_length
    header = section_header(b"CBLK", layout.cblk_flags, payload_length)
    without_crc = header + prefix + ids + lengths
    crc = crc32c(without_crc) ^ layout.cblk_crc_xor
    return without_crc + struct.pack("<I", crc)


def build(
    entries: Entries,
    include_block_index: bool,
    layout: Layout | None = None,
) -> tuple[bytes, dict[str, object]]:
    if layout is None:
        layout = Layout()
    layout.include_block_index = include_block_index

    output = bytearray(
        layout.magic
        + struct.pack(
            "<HHQQQ",
            layout.format_major,
            PREAMBLE_SIZE,
            layout.required_physical_features,
            layout.optional_physical_features,
            layout.preamble_reserved,
        )
    )

    core_offset = len(output)
    output += core_section(layout)
    for extra in layout.after_core:
        output += extra

    block_index: list[tuple[int, int]] = []
    chunk_index = 0
    content_offset = 0
    first_cblk_offset = 0

    for start in range(0, len(entries), MAX_CHUNKS_PER_BLOCK):
        block = entries[start : start + MAX_CHUNKS_PER_BLOCK]
        cblk_offset = len(output)

        if not block_index:
            first_cblk_offset = cblk_offset

        block_index.append((content_offset, cblk_offset))
        output += chunk_block(block, chunk_index, content_offset, layout)

        chunk_index += len(block)
        content_offset += sum(length for _, length in block)

    logical_id, total_length = manifest_id(
        entries,
        layout.hash_suite_id,
        layout.profile_id,
    )

    cend_offset = len(output)
    stored_id = xor_byte(logical_id, 0) if layout.cend_manifest_id_xor else logical_id
    cend_payload = (
        struct.pack(
            "<QQ",
            len(entries) + layout.cend_count_delta,
            total_length + layout.cend_length_delta,
        )
        + stored_id
    )
    if not layout.omit_cend:
        output += section(b"CEND", REQUIRED, cend_payload)
    for extra in layout.after_cend:
        output += extra

    bidx_offset = 0
    if include_block_index:
        bidx_offset = len(output)
        bidx_payload = struct.pack(
            "<II",
            layout.block_index_version,
            len(block_index),
        )
        bidx_payload += b"".join(
            struct.pack(
                "<QQ",
                content,
                physical + layout.block_index_physical_delta,
            )
            for content, physical in block_index
        )
        output += section(b"BIDX", layout.block_index_flags, bidx_payload)
    for extra in layout.after_bidx:
        output += extra

    foot_offset = len(output)
    foot_payload = struct.pack(
        "<QQQQQQ",
        core_offset,
        cend_offset + layout.foot_cend_offset_delta,
        bidx_offset,
        first_cblk_offset if entries else 0,
        len(block_index),
        layout.foot_reserved,
    )
    output += section(b"FOOT", REQUIRED, foot_payload)
    for extra in layout.after_foot:
        output += extra

    file_digest = hashlib.sha256(output).digest()
    stored_digest = xor_byte(file_digest, 0) if layout.trailer_digest_xor else file_digest
    physical_length = len(output) + TRAILER_SIZE
    output += (
        b"CSMT"
        + struct.pack(
            "<HHQQ",
            FORMAT_MAJOR,
            TRAILER_SIZE,
            foot_offset,
            physical_length + layout.trailer_physical_length_delta,
        )
        + stored_digest
        + struct.pack("<Q", layout.trailer_reserved)
    )
    output += layout.after_trailer

    metadata = {
        "manifestId": logical_id.hex(),
        "fileDigest": file_digest.hex(),
        "chunkCount": len(entries),
        "contentLength": total_length,
        "physicalLength": len(output),
        "cblkCount": len(block_index),
        "hasBidx": include_block_index,
    }
    return bytes(output), metadata


def one_entries() -> Entries:
    payload = b"hello chunkshift csm fixture"
    return [(hashlib.sha256(payload).digest(), len(payload))]


def multi_entries() -> Entries:
    return [
        (
            hashlib.sha256(f"chunk-{index}".encode("ascii")).digest(),
            (index % 4096) + 1,
        )
        for index in range(4097)
    ]


def small_entries() -> Entries:
    return [
        (hashlib.sha256(f"small-{index}".encode("ascii")).digest(), length)
        for index, length in enumerate((5, 7, 11))
    ]


VALID = {"outcome": "valid", "failures": []}


def integrity(*failures: str) -> dict[str, object]:
    return {"outcome": "integrity", "failures": sorted(failures)}


def reject(rule: str) -> dict[str, object]:
    return {"outcome": "reject", "failures": [], "rule": rule}


def unsupported(rule: str) -> dict[str, object]:
    return {"outcome": "unsupported", "failures": [], "rule": rule}


@dataclass
class Vector:
    data: bytes
    metadata: dict[str, object]
    expect: dict[str, object]


def golden(entries: Entries, bidx: bool) -> Vector:
    data, metadata = build(entries, bidx)
    return Vector(data, metadata, dict(VALID))


def variant(
    expect: dict[str, object],
    bidx: bool = False,
    entries: Entries | None = None,
    **knobs: object,
) -> Vector:
    data, metadata = build(
        small_entries() if entries is None else entries,
        bidx,
        Layout(**knobs),  # type: ignore[arg-type]
    )
    return Vector(data, metadata, expect)


def truncated(length_from_end: int | None, keep: int | None, rule: str) -> Vector:
    data, metadata = build(small_entries(), False)
    if length_from_end is not None:
        data = data[: len(data) - length_from_end]
    elif keep is not None:
        data = data[:keep]
    return Vector(data, metadata, reject(rule))


def small_cblk(first_index: int = 0, first_offset: int = 0) -> bytes:
    return chunk_block(small_entries()[:1], first_index, first_offset)


def fixtures() -> dict[str, Vector]:
    small = small_entries()
    small_total = sum(length for _, length in small)
    core_section_length = len(core_section())
    first_cblk_offset = PREAMBLE_SIZE + core_section_length

    vectors: dict[str, Vector] = {
        # Golden fixtures (unchanged since they were first published).
        "empty-sha256-no-bidx.csm": golden([], False),
        "one-entry-sha256-no-bidx.csm": golden(one_entries(), False),
        "multiblock-sha256-no-bidx.csm": golden(multi_entries(), False),
        "multiblock-sha256-bidx.csm": golden(multi_entries(), True),

        # Permitted physical differences: same ManifestId as the plain small
        # vector, different FileDigest.
        "valid-small-sha256-no-bidx.csm": variant(dict(VALID)),
        "valid-small-sha256-bidx.csm": variant(dict(VALID), bidx=True),
        "valid-aux0-optional-skipped.csm": variant(
            dict(VALID),
            bidx=True,
            after_cend=[section(b"AUX0", 0, b"aux payload")],
        ),
        "valid-unknown-optional-tail-section-skipped.csm": variant(
            dict(VALID),
            after_cend=[section(b"XTRA", 0, b"\x00" * 9)],
        ),
        "valid-optional-physical-feature-ignored.csm": variant(
            dict(VALID),
            optional_physical_features=1,
        ),

        # Integrity failures are verification results, not format errors.
        "integrity-bad-cblk-crc.csm": variant(
            integrity("BlockCrc"),
            cblk_crc_xor=0x00000001,
        ),
        "integrity-cend-chunk-count-mismatch.csm": variant(
            integrity("LogicalTotals"),
            cend_count_delta=1,
        ),
        "integrity-cend-content-length-mismatch.csm": variant(
            integrity("LogicalTotals"),
            cend_length_delta=1,
        ),
        "integrity-bad-stored-manifest-id.csm": variant(
            integrity("ManifestId"),
            cend_manifest_id_xor=True,
        ),
        "integrity-bad-file-digest.csm": variant(
            integrity("FileDigest"),
            trailer_digest_xor=True,
        ),

        # PREAMBLE (spec section 3).
        "reject-preamble-bad-magic.csm": variant(
            reject("3: magic"), magic=b"CSM2"),
        "reject-preamble-unsupported-format-major.csm": variant(
            reject("3: FormatMajor"), format_major=2),
        "reject-preamble-unknown-required-physical-feature.csm": variant(
            reject("1/3: unknown required physical feature"),
            required_physical_features=1),
        "reject-preamble-nonzero-reserved.csm": variant(
            reject("3: reserved must be zero"), preamble_reserved=1),

        # Section header (section 4).
        "reject-section-reserved-flag-bit.csm": variant(
            reject("4: reserved flag bits must be zero"),
            cblk_flags=REQUIRED | 2),
        "reject-section-overflowing-payload-length.csm": variant(
            reject("4/13: PayloadLength exceeds remaining bytes"),
            cblk_forced_payload_length=0xFFFFFFFFFFFFFFFF),

        # CORE (section 5).
        "reject-core-required-semantic-feature.csm": variant(
            reject("5: RequiredSemanticFeatures must be zero"),
            required_semantic_features=1),
        "reject-core-optional-semantic-feature.csm": variant(
            reject("5: OptionalSemanticFeatures must be zero"),
            optional_semantic_features=1),
        "reject-core-extension-bytes.csm": variant(
            reject("5: ExtensionBytes must be zero"),
            core_extension=b"\x00" * 4),
        "reject-core-payload-length-mismatch.csm": variant(
            reject("5: CORE PayloadLength must equal its fields"),
            core_payload_padding=b"\x00"),
        "reject-core-profile-id-grammar.csm": variant(
            reject("1/5: identifier grammar"),
            profile_id=b"Fixture.Upper"),
        "reject-core-profile-id-too-long.csm": variant(
            reject("1/5: identifier at most 128 bytes"),
            profile_id=b"p" * 129),

        # CBLK (section 6).
        "reject-cblk-nonzero-reserved.csm": variant(
            reject("6: reserved must be zero"), cblk_reserved=1),
        "reject-cblk-first-index-mismatch.csm": variant(
            reject("6: FirstChunkIndex"), cblk_first_index_delta=1),
        "reject-cblk-first-content-offset-mismatch.csm": variant(
            reject("6: FirstContentOffset"), cblk_first_offset_delta=1),
        "reject-cblk-zero-length-chunk.csm": variant(
            reject("6: chunk Length must be > 0"),
            entries=[(hashlib.sha256(b"zero").digest(), 0)]),

        # Section state machine (section 2.1).
        "reject-order-duplicate-core.csm": variant(
            reject("2.1: duplicate CORE"),
            after_core=[core_section()]),
        "reject-order-aux0-before-cend.csm": variant(
            reject("2.1: AUX before CEND"),
            after_core=[section(b"AUX0", 0, b"early")]),
        "reject-order-unknown-optional-before-cend.csm": variant(
            reject("2.1: unknown optional section outside the AUX phase"),
            after_core=[section(b"XTRA", 0, b"early")]),
        "reject-order-missing-cend.csm": variant(
            reject("2.1: missing CEND"), omit_cend=True),
        "reject-order-duplicate-cend.csm": variant(
            reject("2.1: duplicate CEND"),
            after_cend=[section(
                b"CEND",
                REQUIRED,
                struct.pack("<QQ", len(small), small_total)
                + manifest_id(small)[0])]),
        "reject-order-cblk-after-cend-required.csm": variant(
            reject("2.1: CBLK after CEND"),
            after_cend=[small_cblk(len(small), small_total)]),
        "reject-order-cblk-after-cend-optional-flag.csm": variant(
            reject("2.1: CBLK after CEND, independent of flags"),
            after_cend=[
                section_header(b"CBLK", 0, len(small_cblk()) - 16)
                + small_cblk()[16:]]),
        "reject-order-core-after-cend-optional-flag.csm": variant(
            reject("2.1: CORE after CEND, independent of flags"),
            after_cend=[
                section_header(b"CORE", 0, core_section_length - 16)
                + core_section()[16:]]),
        "reject-order-unknown-required-tail-section.csm": variant(
            reject("4: unknown REQUIRED section"),
            after_cend=[section(b"XTRA", REQUIRED, b"\x00" * 9)]),
        "reject-order-aux0-marked-required.csm": variant(
            reject("9: AUX0 is optional"),
            after_cend=[section(b"AUX0", REQUIRED, b"aux")]),
        "reject-order-duplicate-bidx.csm": variant(
            reject("2.1: duplicate BIDX"),
            bidx=True,
            after_bidx=[section(
                b"BIDX",
                0,
                struct.pack("<IIQQ", 1, 1, 0, first_cblk_offset))]),
        "reject-order-aux0-after-bidx.csm": variant(
            reject("2.1: AUX after BIDX"),
            bidx=True,
            after_bidx=[section(b"AUX0", 0, b"late")]),
        "reject-order-section-after-foot.csm": variant(
            reject("2.1: section after FOOT"),
            after_foot=[section(b"AUX0", 0, b"late")]),

        # BIDX (section 10).
        "reject-bidx-unknown-version.csm": variant(
            reject("10: IndexVersion = 1"),
            bidx=True, block_index_version=2),
        "reject-bidx-marked-required.csm": variant(
            reject("4/10: BIDX is optional and cannot be REQUIRED"),
            bidx=True, block_index_flags=REQUIRED),
        "reject-bidx-entry-does-not-match-cblk.csm": variant(
            reject("10: entries correspond one-to-one with CBLK"),
            bidx=True, block_index_physical_delta=1),

        # FOOT (section 11).
        "reject-foot-wrong-cend-offset.csm": variant(
            reject("11: CendSectionOffset"), foot_cend_offset_delta=1),
        "reject-foot-nonzero-reserved.csm": variant(
            reject("11: reserved must be zero"), foot_reserved=1),

        # TRAILER (section 12).
        "reject-trailer-wrong-physical-length.csm": variant(
            reject("12: PhysicalLength"), trailer_physical_length_delta=1),
        "reject-trailer-nonzero-reserved.csm": variant(
            reject("12: reserved must be zero"), trailer_reserved=1),
        "reject-trailer-bytes-after-trailer.csm": variant(
            reject("2.1: bytes after TRAILER"), after_trailer=b"\x00"),

        # Truncation (section 13: premature EOF is truncation).
        "reject-truncated-missing-trailer.csm": truncated(
            TRAILER_SIZE, None, "13: premature EOF"),
        "reject-truncated-inside-trailer.csm": truncated(
            1, None, "13: premature EOF"),
        "reject-truncated-inside-cblk-header.csm": truncated(
            None, first_cblk_offset + 8, "13: premature EOF"),
        "reject-truncated-inside-preamble.csm": truncated(
            None, 16, "13: premature EOF"),

        # Grammatically valid but unknown HashSuite: unsupported semantics,
        # which the .NET API reports as NotSupportedException.
        "unsupported-unknown-hash-suite.csm": variant(
            unsupported("5: unknown HashSuite"),
            hash_suite_id=b"chunkshift.sha512.v1"),

        # A ProfileId the .NET build registers, recorded with another profile's
        # fingerprint: manifest-only verification reports ProfileSemantics.
        # Every other check passes, because the fingerprint that enters ManifestId
        # is the recorded one.
        "integrity-profile-semantics-known-id-wrong-fingerprint.csm": variant(
            integrity("ProfileSemantics"),
            profile_id=b"fastcdc.gear.chunkshift.v1.64k"),

        # Well-formed CSM whose chunk Length does not fit the Int32
        # ChunkInfo.Length of the .NET API (section 13 implementation boundary).
        "unsupported-chunk-length-above-int32.csm": variant(
            unsupported("13: chunk Length above the .NET Int32 API range"),
            entries=[(hashlib.sha256(b"huge").digest(), 0x8000_0000)]),
    }

    return vectors


def generate(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    metadata: dict[str, object] = {
        "format": "CSM v1 candidate",
        "generator": "tools/conformance/csm/generate.py",
        "hashSuite": HASH_SUITE_ID.decode("ascii"),
        "profileId": PROFILE_ID.decode("ascii"),
        "profileFingerprint": PROFILE_FINGERPRINT.hex(),
        "vectors": {},
    }

    for name, vector in fixtures().items():
        (out / name).write_bytes(vector.data)
        entry = dict(vector.metadata)
        entry["expect"] = vector.expect
        if vector.expect["outcome"] != "valid":
            # Identities of a deliberately broken vector are not meaningful
            # expectations; only the verdict is.
            for key in ("manifestId", "fileDigest"):
                entry.pop(key)
        if vector.expect["outcome"] in ("reject", "unsupported"):
            for key in (
                "chunkCount",
                "contentLength",
                "cblkCount",
                "hasBidx",
            ):
                entry.pop(key)
            entry["physicalLength"] = len(vector.data)
        metadata["vectors"][name] = entry  # type: ignore[index]

    # Bytes, not text: LF on every platform, so --verify also holds on Windows.
    (out / "vectors.json").write_bytes(
        (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )


def verify(directory: Path) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import decode  # noqa: PLC0415 - independent module, imported on demand

    problems: list[str] = []

    with tempfile.TemporaryDirectory() as scratch:
        expected_dir = Path(scratch)
        generate(expected_dir)

        expected_files = {
            path.name for path in expected_dir.iterdir()
        }
        actual_files = {
            path.name
            for path in directory.iterdir()
            if path.suffix in (".csm", ".json")
        }

        for name in sorted(expected_files - actual_files):
            problems.append(f"{name}: missing from {directory}")
        for name in sorted(actual_files - expected_files):
            problems.append(f"{name}: not produced by the generator")

        for name in sorted(expected_files & actual_files):
            if (expected_dir / name).read_bytes() != (directory / name).read_bytes():
                problems.append(f"{name}: differs from a fresh generation")

    manifest = json.loads(
        (directory / "vectors.json").read_text(encoding="utf-8")
    )

    for name, entry in sorted(manifest["vectors"].items()):
        verdict = decode.decode((directory / name).read_bytes())
        expect = entry["expect"]

        if verdict["outcome"] != expect["outcome"]:
            problems.append(
                f"{name}: decoder outcome {verdict['outcome']!r} "
                f"({verdict.get('reason', '')}), expected {expect['outcome']!r}"
            )
            continue

        if verdict["failures"] != expect["failures"]:
            problems.append(
                f"{name}: decoder failures {verdict['failures']}, "
                f"expected {expect['failures']}"
            )

        for key in (
            "manifestId",
            "fileDigest",
            "chunkCount",
            "contentLength",
            "physicalLength",
            "cblkCount",
            "hasBidx",
        ):
            if key in entry and key in verdict and verdict[key] != entry[key]:
                problems.append(
                    f"{name}: decoder {key} {verdict[key]!r}, "
                    f"expected {entry[key]!r}"
                )

    for problem in problems:
        print(problem, file=sys.stderr)

    print(
        f"verified {len(manifest['vectors'])} vectors in {directory}: "
        f"{'FAILED' if problems else 'ok'}"
    )
    return 1 if problems else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--out",
        type=Path,
        help="Directory that receives .csm vectors and vectors.json.",
    )
    mode.add_argument(
        "--verify",
        type=Path,
        metavar="DIRECTORY",
        help=(
            "Check a vector directory against a fresh generation and the "
            "independent decoder."
        ),
    )
    args = parser.parse_args()

    if args.verify is not None:
        sys.exit(verify(args.verify))

    generate(args.out)


if __name__ == "__main__":
    main()
