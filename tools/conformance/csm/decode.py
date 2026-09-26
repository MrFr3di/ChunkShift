#!/usr/bin/env python3
"""Independent CSM v1 candidate decoder and verifier.

This is a second implementation of the *reading* side of
docs/architecture/CSM-V1.md. It exists so that rejection and
integrity verdicts are not checked only by the production C# reader.

Independence rules:

- it uses only Python's standard library;
- it does not import generate.py or any ChunkShift code;
- it is written from the specification, section by section, and keeps its
  own CRC-32C (table-driven, unlike the bitwise one in generate.py).

Verdict model (matches the public .NET contract):

- ``valid``        every check passed;
- ``integrity``    structurally valid, but one or more of BlockCrc,
                   LogicalTotals, ManifestId, FileDigest, ProfileSemantics
                   mismatched (the .NET API returns these as result flags);
- ``reject``       malformed or non-conforming representation
                   (the .NET API throws InvalidDataException);
- ``unsupported``  grammatically valid but unknown HashSuite, or a chunk
                   Length above Int32.MaxValue or a content length above
                   Int64.MaxValue, which the .NET API cannot represent
                   (the .NET API throws NotSupportedException).

Only the SHA-256 HashSuite is implemented, because BLAKE3 is not in the
standard library; the golden vectors deliberately use SHA-256.

Usage:
  decode.py FILE...             print one JSON verdict per file;
  decode.py --compare DIRECTORY compare .NET fuzz verdicts (verdicts-*.jsonl
                                written by CsmReaderFuzzTests) with this decoder.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

# Section 3 / 12.
PREAMBLE_MAGIC = b"CSM1"
TRAILER_MAGIC = b"CSMT"
SUPPORTED_MAJOR = 1
PREAMBLE_LENGTH = 32
TRAILER_LENGTH = 64

# Section 4.
HEADER_LENGTH = 16
FLAG_REQUIRED = 0x1

# Section 5.
CORE_FIXED = 56
ID_MAX_BYTES = 128
EXTENSION_CEILING = 65_536

# Section 6.
CBLK_FIXED = 24
CBLK_MAX_CHUNKS = 4096
ID_BYTES = 32

# Sections 7, 10, 11.
CEND_LENGTH = 48
BIDX_FIXED = 8
BIDX_ENTRY = 16
FOOT_LENGTH = 48

# Section 8.
MANIFEST_ID_DOMAIN = b"chunkshift.manifest-id.v1\x00"

# The two v1 HashSuites. Only SHA-256 can be computed here.
SHA256_SUITE = "chunkshift.sha256.v1"
BLAKE3_SUITE = "chunkshift.blake3-256.v1"

ID_FIRST = set(b"abcdefghijklmnopqrstuvwxyz0123456789")
ID_REST = ID_FIRST | set(b"._-")

U64_MAX = (1 << 64) - 1

# ProfileIds the .NET build registers, with the ProfileFingerprint of their
# semantics. This is a fact about the build under test, like its supported
# HashSuites, not part of the CSM format: manifest-only verification accepts an
# unknown ProfileId and reports ProfileSemantics for a known one whose recorded
# fingerprint differs. Core 0.1 registers exactly one production profile;
# pre-freeze calibration IDs are not registered.
REGISTERED_PROFILES = {
    b"fastcdc.gear.chunkshift.v1.64k": bytes.fromhex(
        "054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0"),
}

# Public .NET API range (ChunkInfo.Length is Int32; lengths and offsets are Int64).
I32_MAX = (1 << 31) - 1
I64_MAX = (1 << 63) - 1


def _crc32c_table() -> list[int]:
    reflected_polynomial = 0x82F63B78  # 0x1EDC6F41 reflected
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ reflected_polynomial if value & 1 else value >> 1
        table.append(value)
    return table


_CRC_TABLE = _crc32c_table()


def crc32c(data: bytes) -> int:
    state = 0xFFFFFFFF
    for value in data:
        state = _CRC_TABLE[(state ^ value) & 0xFF] ^ (state >> 8)
    return state ^ 0xFFFFFFFF


class Reject(Exception):
    """The representation violates the specification."""


class Unsupported(Exception):
    """The representation requires semantics this decoder does not know."""


class Cursor:
    """Bounds-checked forward reader over the complete representation."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, length: int, what: str) -> bytes:
        if length < 0 or length > self.remaining:
            raise Reject(f"premature EOF reading {what} at offset {self.offset}")
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]


def _check_identifier(raw: bytes, what: str) -> str:
    if not 1 <= len(raw) <= ID_MAX_BYTES:
        raise Reject(f"{what} must be 1..{ID_MAX_BYTES} bytes")
    if raw[0] not in ID_FIRST or any(value not in ID_REST for value in raw):
        raise Reject(f"{what} violates the ChunkShift identifier grammar")
    return raw.decode("ascii")


def _read_header(cursor: Cursor) -> tuple[int, bytes, int, int]:
    offset = cursor.offset
    kind, flags, payload_length = struct.unpack(
        "<4sIQ", cursor.take(HEADER_LENGTH, "section header")
    )
    if flags & ~FLAG_REQUIRED:
        raise Reject(f"reserved flag bits set on {kind!r}")
    # Section 13: the physical length is known, so a payload cannot exceed it.
    if payload_length > cursor.remaining:
        raise Reject(f"{kind!r} PayloadLength exceeds the remaining bytes")
    return offset, kind, flags, payload_length


def decode(data: bytes) -> dict[str, object]:
    """Return the verdict for one complete CSM representation."""

    try:
        return _decode(data)
    except Reject as error:
        return {"outcome": "reject", "failures": [], "reason": str(error)}
    except Unsupported as error:
        return {"outcome": "unsupported", "failures": [], "reason": str(error)}


def _decode(data: bytes) -> dict[str, object]:
    cursor = Cursor(data)
    failures: set[str] = set()

    # --- Section 3: PREAMBLE ------------------------------------------------
    magic, major, preamble_size, required_physical, _optional_physical, reserved = (
        struct.unpack("<4sHHQQQ", cursor.take(PREAMBLE_LENGTH, "PREAMBLE"))
    )
    if magic != PREAMBLE_MAGIC:
        raise Reject("PREAMBLE magic is not CSM1")
    if major != SUPPORTED_MAJOR:
        raise Reject(f"unsupported FormatMajor {major}")
    if preamble_size != PREAMBLE_LENGTH:
        raise Reject("PreambleSize must be 32")
    if required_physical != 0:
        # v1 defines no physical feature bits, so every required bit is unknown.
        raise Reject("unknown required physical feature")
    if reserved != 0:
        raise Reject("PREAMBLE reserved field must be zero")
    # OptionalPhysicalFeatures: unknown optional bits are ignored.

    # --- Section 5: CORE ----------------------------------------------------
    core_offset, kind, _flags, core_length = _read_header(cursor)
    if kind != b"CORE":
        raise Reject("CORE must immediately follow PREAMBLE")
    if core_length < CORE_FIXED:
        raise Reject("CORE payload shorter than its fixed prefix")
    core = cursor.take(core_length, "CORE payload")
    (
        required_semantic,
        optional_semantic,
        profile_fingerprint,
        suite_length,
        profile_length,
        extension_bytes,
    ) = struct.unpack_from("<QQ32sHHI", core, 0)

    if required_semantic != 0:
        raise Reject("RequiredSemanticFeatures must be zero in v1")
    if optional_semantic != 0:
        raise Reject("OptionalSemanticFeatures must be zero in v1")
    if extension_bytes > EXTENSION_CEILING:
        raise Reject("ExtensionBytes exceeds the hard ceiling")
    if suite_length > ID_MAX_BYTES or profile_length > ID_MAX_BYTES:
        raise Reject("identifier longer than 128 bytes")
    if core_length != CORE_FIXED + suite_length + profile_length + extension_bytes:
        raise Reject("CORE PayloadLength does not match its declared fields")
    if extension_bytes != 0:
        raise Reject("ExtensionBytes must be zero in v1")

    suite_raw = core[CORE_FIXED : CORE_FIXED + suite_length]
    profile_raw = core[CORE_FIXED + suite_length : CORE_FIXED + suite_length + profile_length]
    suite = _check_identifier(suite_raw, "HashSuiteId")
    _check_identifier(profile_raw, "ChunkingProfileId")

    if suite == BLAKE3_SUITE:
        raise Unsupported("BLAKE3 is not available in the Python standard library")
    if suite != SHA256_SUITE:
        raise Unsupported(f"unknown HashSuite {suite}")

    new_hash = hashlib.sha256

    identity = new_hash()
    identity.update(MANIFEST_ID_DOMAIN)
    identity.update(struct.pack("<H", suite_length))
    identity.update(suite_raw)
    identity.update(struct.pack("<H", profile_length))
    identity.update(profile_raw)
    identity.update(profile_fingerprint)

    # --- Section 6: CBLK* until CEND ---------------------------------------
    observed_count = 0
    observed_length = 0
    blocks: list[tuple[int, int]] = []  # (FirstContentOffset, section offset)

    while True:
        section_offset, kind, _flags, payload_length = _read_header(cursor)

        if kind == b"CEND":
            break
        if kind != b"CBLK":
            raise Reject(f"{kind!r} is not allowed between CORE and CEND")

        if payload_length < CBLK_FIXED + 4:
            raise Reject("CBLK payload shorter than its fixed prefix and CRC")
        payload = cursor.take(payload_length, "CBLK payload")
        count, block_reserved, first_index, first_offset = struct.unpack_from(
            "<IIQQ", payload, 0
        )
        if count == 0 or count > CBLK_MAX_CHUNKS:
            raise Reject("CBLK ChunkCount must be 1..4096")
        if block_reserved != 0:
            raise Reject("CBLK reserved field must be zero")
        if first_index != observed_count:
            raise Reject("CBLK FirstChunkIndex does not match preceding chunks")
        if first_offset != observed_length:
            raise Reject("CBLK FirstContentOffset does not match preceding lengths")
        if payload_length != CBLK_FIXED + count * (ID_BYTES + 4) + 4:
            raise Reject("CBLK PayloadLength does not match ChunkCount")

        ids_start = CBLK_FIXED
        lengths_start = ids_start + count * ID_BYTES
        crc_start = lengths_start + count * 4
        stored_crc = struct.unpack_from("<I", payload, crc_start)[0]
        header_bytes = data[section_offset : section_offset + HEADER_LENGTH]
        if crc32c(header_bytes + payload[:crc_start]) != stored_crc:
            failures.add("BlockCrc")

        block_length = 0
        for index in range(count):
            chunk_id = payload[ids_start + index * ID_BYTES : ids_start + (index + 1) * ID_BYTES]
            (length,) = struct.unpack_from("<I", payload, lengths_start + index * 4)
            if length == 0:
                raise Reject("CBLK chunk Length must be > 0")
            if length > I32_MAX:
                raise Unsupported("chunk Length exceeds the .NET Int32 API range")
            identity.update(chunk_id)
            identity.update(struct.pack("<I", length))
            block_length += length

        blocks.append((observed_length, section_offset))
        observed_count += count
        observed_length += block_length
        if observed_length > U64_MAX:
            raise Reject("content length overflows UInt64")
        if observed_length > I64_MAX:
            raise Unsupported("content length exceeds the .NET Int64 API range")

    # --- Section 7: CEND ----------------------------------------------------
    cend_offset = section_offset
    if payload_length != CEND_LENGTH:
        raise Reject("CEND payload must be 48 bytes")
    total_count, total_length, stored_manifest_id = struct.unpack(
        "<QQ32s", cursor.take(CEND_LENGTH, "CEND payload")
    )
    if (total_count, total_length) != (observed_count, observed_length):
        failures.add("LogicalTotals")

    # Section 8: totals come after the ordered records and are the observed ones.
    identity.update(struct.pack("<QQ", observed_count, observed_length))
    computed_manifest_id = identity.digest()
    if computed_manifest_id != stored_manifest_id:
        failures.add("ManifestId")

    # --- Sections 2.1, 9, 10: [AUX]* [BIDX] then FOOT ------------------------
    bidx_offset = 0
    seen_bidx = False

    while True:
        section_offset, kind, flags, payload_length = _read_header(cursor)

        if kind == b"FOOT":
            break

        if kind in (b"CORE", b"CBLK", b"CEND"):
            raise Reject(f"{kind!r} after CEND")

        if kind == b"BIDX":
            if seen_bidx:
                raise Reject("BIDX appears more than once")
            if flags & FLAG_REQUIRED:
                raise Reject("BIDX is optional and cannot be REQUIRED")
            if payload_length < BIDX_FIXED:
                raise Reject("BIDX payload shorter than its fixed prefix")
            payload = cursor.take(payload_length, "BIDX payload")
            version, block_count = struct.unpack_from("<II", payload, 0)
            if version != 1:
                raise Reject("BIDX IndexVersion must be 1")
            if payload_length != BIDX_FIXED + block_count * BIDX_ENTRY:
                raise Reject("BIDX PayloadLength does not match BlockCount")
            entries = [
                struct.unpack_from("<QQ", payload, BIDX_FIXED + index * BIDX_ENTRY)
                for index in range(block_count)
            ]
            if entries != blocks:
                raise Reject("BIDX entries do not correspond one-to-one with CBLK sections")
            bidx_offset = section_offset
            seen_bidx = True
            continue

        # AUX phase: only between CEND and BIDX/FOOT.
        if seen_bidx:
            raise Reject("only FOOT may follow BIDX")
        if kind == b"AUX0" and flags & FLAG_REQUIRED:
            raise Reject("AUX0 is optional and cannot be REQUIRED")
        if flags & FLAG_REQUIRED:
            raise Reject(f"unknown REQUIRED section {kind!r}")
        cursor.take(payload_length, f"optional {kind!r} payload")

    # --- Section 11: FOOT ---------------------------------------------------
    foot_offset = section_offset
    if payload_length != FOOT_LENGTH:
        raise Reject("FOOT payload must be 48 bytes")
    (
        foot_core,
        foot_cend,
        foot_bidx,
        foot_first_cblk,
        foot_cblk_count,
        foot_reserved,
    ) = struct.unpack("<QQQQQQ", cursor.take(FOOT_LENGTH, "FOOT payload"))
    expected_first_cblk = blocks[0][1] if blocks else 0
    if foot_core != core_offset:
        raise Reject("FOOT CoreSectionOffset does not identify CORE")
    if foot_cend != cend_offset:
        raise Reject("FOOT CendSectionOffset does not identify CEND")
    if foot_bidx != bidx_offset:
        raise Reject("FOOT BidxSectionOffset does not identify BIDX")
    if foot_first_cblk != expected_first_cblk:
        raise Reject("FOOT FirstCblkSectionOffset does not identify the first CBLK")
    if foot_cblk_count != len(blocks):
        raise Reject("FOOT CblkCount does not match the CBLK sections")
    if foot_reserved != 0:
        raise Reject("FOOT reserved field must be zero")

    # --- Section 12: TRAILER at physical EOF ---------------------------------
    digest_end = cursor.offset
    if cursor.remaining > TRAILER_LENGTH:
        raise Reject("bytes between FOOT and TRAILER, or after TRAILER")
    trailer = cursor.take(TRAILER_LENGTH, "TRAILER")
    (
        trailer_magic,
        trailer_major,
        trailer_size,
        trailer_foot,
        physical_length,
        stored_file_digest,
        trailer_reserved,
    ) = struct.unpack("<4sHHQQ32sQ", trailer)
    if trailer_magic != TRAILER_MAGIC:
        raise Reject("TRAILER magic is not CSMT")
    if trailer_major != SUPPORTED_MAJOR:
        raise Reject("TRAILER FormatMajor mismatch")
    if trailer_size != TRAILER_LENGTH:
        raise Reject("TrailerSize must be 64")
    if trailer_foot != foot_offset:
        raise Reject("TRAILER FootSectionOffset does not identify FOOT")
    if physical_length != len(data):
        raise Reject("TRAILER PhysicalLength does not match the representation")
    if trailer_reserved != 0:
        raise Reject("TRAILER reserved field must be zero")

    computed_file_digest = new_hash(data[:digest_end]).digest()
    if computed_file_digest != stored_file_digest:
        failures.add("FileDigest")

    # Profile semantics: only a registered ProfileId can be checked.
    registered = REGISTERED_PROFILES.get(profile_raw)
    if registered is not None and registered != profile_fingerprint:
        failures.add("ProfileSemantics")

    return {
        "outcome": "integrity" if failures else "valid",
        "failures": sorted(failures),
        "manifestId": stored_manifest_id.hex(),
        "computedManifestId": computed_manifest_id.hex(),
        "fileDigest": stored_file_digest.hex(),
        "chunkCount": observed_count,
        "contentLength": observed_length,
        "physicalLength": len(data),
        "cblkCount": len(blocks),
        "hasBidx": seen_bidx,
    }


def verdict_text(verdict: dict[str, object]) -> str:
    """Render a verdict the way the .NET fuzz harness does."""

    outcome = str(verdict["outcome"])
    if outcome == "integrity":
        return "integrity:" + ",".join(verdict["failures"])  # type: ignore[arg-type]
    return outcome


def compare(directory: Path) -> int:
    """Differential check of .NET fuzz verdicts against this decoder.

    Reads every verdicts-*.jsonl written by CsmReaderFuzzTests (one JSON object
    per line: {"file": ..., "verdict": ...}) and decodes each case.
    """

    checked = 0
    mismatches: list[str] = []

    for listing in sorted(directory.glob("verdicts-*.jsonl")):
        for line in listing.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            verdict = decode((directory / case["file"]).read_bytes())
            checked += 1
            if verdict_text(verdict) != case["verdict"]:
                mismatches.append(
                    f"{case['file']}: .NET {case['verdict']!r}, "
                    f"decoder {verdict_text(verdict)!r} ({verdict.get('reason', '')})"
                )

    for mismatch in mismatches[:50]:
        print(mismatch, file=sys.stderr)

    print(f"compared {checked} fuzz cases: {len(mismatches)} mismatches")
    if checked == 0:
        print("no fuzz cases found", file=sys.stderr)
        return 1
    return 1 if mismatches else 0


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    if paths[0] == "--compare":
        if len(paths) != 2:
            print("usage: decode.py --compare DIRECTORY", file=sys.stderr)
            return 2
        return compare(Path(paths[1]))
    for path in paths:
        verdict = decode(Path(path).read_bytes())
        print(json.dumps({"file": path, **verdict}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
