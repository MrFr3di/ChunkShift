#!/usr/bin/env python3
"""Independent CSP v1 decoder, verifier and applier.

This is a second implementation of docs/architecture/CSP-V1.md, so
that CSP verdicts are not checked only by the production C# code.

Independence rules:

- it uses only the Python standard library (3.14 or later, for the
  ``compression.zstd`` module that decodes payload encoding 1) and the
  pure-Python BLAKE3 of tools/conformance/csm/blake3_reference.py;
- it does not import generate.py or any ChunkShift code, and it was written
  from the specification, not from the C# implementation;
- the embedded target CSM and the base manifest are checked by
  tools/conformance/csm/decode.py, the independent CSM decoder;
- it keeps its own CRC-32C and its own zstd frame-envelope parser, because
  ``compression.zstd.decompress()`` accepts concatenated frames and skips
  skippable frames, which CSP must reject.

Verdicts:

- ``valid``         apply succeeds; ``outputSha256`` digests the reconstructed target;
- ``malformed``     the patch violates the format (.NET: InvalidDataException);
- ``unsupported``   well-formed, but needs semantics this decoder lacks
                    (.NET: NotSupportedException);
- ``verification``  an integrity failure; nothing may be published
                    (.NET: result flags); ``failures`` names the kinds;
- ``limit``         an operational limit of section 8 was exceeded.

Checks run in the verdict order of section 6:

A  structure: TRAILER, PREAMBLE, the section walk with every PAYL and PIDX
   CRC checked before its fields are interpreted, FOOT;
B  the embedded CSM;                              } accumulated, then
C  the patch FileDigest;                          } abort if any failed
D  payload entries against the target manifest (misplaced FirstTargetIndex is
   malformed; duplicates, entries not in the target and bad stored lengths are
   accumulated verification failures);
E  base binding;
F  every target record in order, stopping at the first failure;
G  the total length.

Both v1 HashSuites are implemented (the CSM decoder's table). BLAKE3 runs at
about 1 MB/s in pure Python, enough for the vectors and the test corpora.

Usage:
  decode.py PATCH [--base-manifest CSM --base CONTENT] [--max-payload-entries N]
  decode.py --compare DIRECTORY compare .NET fuzz verdicts (verdicts-*.jsonl
                                written by CspApplyFuzzTests) with this decoder.
  decode.py --compare-frames DIRECTORY
                                compare .NET verdicts on mutated zstd frames
                                (frames-*.jsonl written by ZstdFrameFuzzTests)
                                with this decoder's encoding-1 checks.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

try:
    from compression import zstd
except ImportError:  # pragma: no cover - environment check
    sys.exit("decode.py needs Python 3.14 or later with the compression.zstd module")

_CSM_DECODER_PATH = Path(__file__).resolve().parent.parent / "csm" / "decode.py"
_spec = importlib.util.spec_from_file_location("csm_fixtures_decode", _CSM_DECODER_PATH)
csm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = csm   # dataclasses resolve their module through sys.modules
_spec.loader.exec_module(csm)

# Section 4.2 / 4.9.
PREAMBLE_MAGIC = b"CSP1"
TRAILER_MAGIC = b"CSPT"
SUPPORTED_MAJOR = 1
PREAMBLE_LENGTH = 32
TRAILER_LENGTH = 64

# Section 4.3.
HEADER_LENGTH = 16
FLAG_REQUIRED = 0x1

# Sections 4.4 - 4.8.
BASE_LENGTH = 32
PAYL_PREFIX = 16
PAYL_ENTRY_HEADER = 40
ID_BYTES = 32
PAYL_MAX_ENTRIES = 4096
PIDX_PREFIX = 8
PIDX_ENTRY = 24
PIDX_VERSION = 1
FOOT_LENGTH = 56
CRC_LENGTH = 4

# Section 5.
ENCODING_RAW = 0
ENCODING_ZSTD = 1
MAX_DICTIONARY_CHUNKS = 4
MAX_DICTIONARY_BYTES = 1 << 20
MAX_WINDOW_BYTES = 1 << 20
ZSTD_DICTIONARY_MAGIC = b"\x37\xa4\x30\xec"
ZSTD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"

# Section 8 operational default.
DEFAULT_MAX_PAYLOAD_ENTRIES = 1_048_576

U64_MAX = (1 << 64) - 1


def _crc32c_table() -> list[int]:
    polynomial = 0x82F63B78  # Castagnoli, reflected
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ polynomial if value & 1 else value >> 1
        table.append(value)
    return table


_CRC_TABLE = _crc32c_table()


def crc32c(data: bytes) -> int:
    state = 0xFFFFFFFF
    for value in data:
        state = _CRC_TABLE[(state ^ value) & 0xFF] ^ (state >> 8)
    return state ^ 0xFFFFFFFF


class Malformed(Exception):
    def __init__(self, rule: int, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule


class Unsupported(Exception):
    def __init__(self, rule: int, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule


class Limit(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.rule = 26


class Verification(Exception):
    def __init__(self, failures: set[str], reason: str) -> None:
        super().__init__(reason)
        self.failures = failures


def _fourcc(kind: bytes) -> str:
    return kind.decode("latin-1")


# --- Section A: structure --------------------------------------------------------


class Entry:
    """One PAYL entry as parsed (section 4.6)."""

    def __init__(self, ordinal: int, record_offset: int, chunk_id: bytes, stored_length: int,
                 encoding: int, dictionary: list[bytes], stored: bytes) -> None:
        self.ordinal = ordinal
        self.record_offset = record_offset
        self.chunk_id = chunk_id
        self.stored_length = stored_length
        self.encoding = encoding
        self.dictionary = dictionary
        self.stored = stored
        self.first_target_index = -1


class Layout:
    def __init__(self) -> None:
        self.tcsm: tuple[int, int, int] | None = None   # section offset, payload offset, length
        self.base_offset = 0
        self.expected_base: bytes | None = None
        self.payl_offsets: list[int] = []
        self.entries: list[Entry] = []
        self.pidx_offset = 0
        self.foot_offset = 0


def _check_section_crc(data: bytes, offset: int, payload_length: int, what: str) -> None:
    crc_at = offset + HEADER_LENGTH + payload_length - CRC_LENGTH
    (stored,) = struct.unpack_from("<I", data, crc_at)
    if crc32c(data[offset:crc_at]) != stored:
        raise Malformed(9, f"{what} CRC-32C mismatch")


def _parse_payl(data: bytes, offset: int, payload_length: int, layout: Layout,
                max_entries: int) -> None:
    if payload_length < PAYL_PREFIX + CRC_LENGTH:
        raise Malformed(8, "PAYL payload shorter than its prefix and CRC")
    _check_section_crc(data, offset, payload_length, "PAYL")

    start = offset + HEADER_LENGTH
    end = start + payload_length - CRC_LENGTH
    count, reserved, first_ordinal = struct.unpack_from("<IIQ", data, start)
    if count == 0 or count > PAYL_MAX_ENTRIES:
        raise Malformed(8, "PAYL EntryCount must be 1..4096")
    if reserved != 0:
        raise Malformed(3, "PAYL reserved field must be zero")
    if first_ordinal != len(layout.entries):
        raise Malformed(8, "PAYL FirstEntryOrdinal does not match preceding entries")

    position = start + PAYL_PREFIX
    for _ in range(count):
        if len(layout.entries) >= max_entries:
            raise Limit("payload entry count exceeds the configured maximum")
        if end - position < PAYL_ENTRY_HEADER:
            raise Malformed(8, "PAYL entry header overruns the section")
        chunk_id = data[position:position + ID_BYTES]
        stored_length, encoding, dictionary_count, entry_reserved = struct.unpack_from(
            "<IBBH", data, position + ID_BYTES)
        if entry_reserved != 0:
            raise Malformed(3, "PAYL entry reserved field must be zero")
        if stored_length == 0:
            raise Malformed(8, "PAYL StoredLength must be > 0")
        if encoding == ENCODING_RAW and dictionary_count != 0:
            raise Malformed(27, "raw entry declares dictionary chunks")
        if encoding == ENCODING_ZSTD and dictionary_count > MAX_DICTIONARY_CHUNKS:
            raise Malformed(27, "encoding-1 entry declares more than 4 dictionary chunks")
        body = PAYL_ENTRY_HEADER + dictionary_count * ID_BYTES + stored_length
        if end - position < body:
            raise Malformed(8, "PAYL entry overruns the section")
        dictionary_start = position + PAYL_ENTRY_HEADER
        dictionary = [data[dictionary_start + i * ID_BYTES:dictionary_start + (i + 1) * ID_BYTES]
                      for i in range(dictionary_count)]
        stored_start = dictionary_start + dictionary_count * ID_BYTES
        if encoding not in (ENCODING_RAW, ENCODING_ZSTD):
            raise Unsupported(16, f"payload encoding {encoding} is not implemented")
        layout.entries.append(Entry(len(layout.entries), position, chunk_id, stored_length, encoding,
                                    dictionary, data[stored_start:stored_start + stored_length]))
        position += body
    if position != end:
        raise Malformed(8, "PAYL PayloadLength does not match its entries")


def _parse_pidx(data: bytes, offset: int, payload_length: int, layout: Layout,
                max_entries: int) -> None:
    if payload_length < PIDX_PREFIX + CRC_LENGTH:
        raise Malformed(10, "PIDX payload shorter than its prefix and CRC")
    _check_section_crc(data, offset, payload_length, "PIDX")

    start = offset + HEADER_LENGTH
    version, count = struct.unpack_from("<II", data, start)
    if version != PIDX_VERSION:
        raise Malformed(10, f"unknown PIDX IndexVersion {version}")
    if payload_length != PIDX_PREFIX + count * PIDX_ENTRY + CRC_LENGTH:
        raise Malformed(10, "PIDX PayloadLength does not match EntryCount")
    if count > max_entries:
        raise Limit("PIDX entry count exceeds the configured maximum")
    if count != len(layout.entries):
        raise Malformed(11, "PIDX and PAYL entry counts differ")

    previous = -1
    for index, entry in enumerate(layout.entries):
        first_target_index, payload_offset, stored_length, encoding, dictionary_count, reserved = (
            struct.unpack_from("<QQIBBH", data, start + PIDX_PREFIX + index * PIDX_ENTRY))
        if reserved != 0:
            raise Malformed(3, "PIDX entry reserved field must be zero")
        if (stored_length, encoding, dictionary_count) != (
                entry.stored_length, entry.encoding, len(entry.dictionary)):
            raise Malformed(11, "PIDX entry disagrees with its PAYL entry")
        if payload_offset != entry.record_offset:
            raise Malformed(12, "PIDX PayloadOffset does not point at its PAYL entry")
        if first_target_index <= previous:
            raise Malformed(12, "PIDX FirstTargetIndex values do not strictly increase")
        previous = first_target_index
        entry.first_target_index = first_target_index


def _parse_structure(data: bytes, max_entries: int) -> Layout:
    length = len(data)
    if length < PREAMBLE_LENGTH + TRAILER_LENGTH:
        raise Malformed(7, "shorter than PREAMBLE plus TRAILER")

    # TRAILER first (section 6 step 1).
    trailer_at = length - TRAILER_LENGTH
    magic, major, trailer_size, foot_offset, physical_length, _digest, reserved = struct.unpack_from(
        "<4sHHQQ32sQ", data, trailer_at)
    if magic != TRAILER_MAGIC or trailer_size != TRAILER_LENGTH:
        raise Malformed(5, "no CSP TRAILER at physical EOF")
    if major != SUPPORTED_MAJOR:
        raise Malformed(5, f"TRAILER FormatMajor {major}")
    if reserved != 0:
        raise Malformed(3, "TRAILER reserved field must be zero")
    if physical_length != length:
        raise Malformed(6, "PhysicalLength does not equal the artifact length")

    magic, major, preamble_size, required, _optional, reserved = struct.unpack_from(
        "<4sHHQQQ", data, 0)
    if magic != PREAMBLE_MAGIC or major != SUPPORTED_MAJOR or preamble_size != PREAMBLE_LENGTH:
        raise Malformed(1, "PREAMBLE magic, FormatMajor or PreambleSize is wrong")
    if reserved != 0:
        raise Malformed(1, "PREAMBLE reserved field must be zero")
    if required != 0:
        raise Unsupported(2, "unknown required physical feature")

    layout = Layout()
    phase = "start"          # start -> tcsm -> base -> payl -> optional -> pidx
    offset = PREAMBLE_LENGTH
    while True:
        if trailer_at - offset < HEADER_LENGTH:
            raise Malformed(5, "FOOT is missing before the TRAILER")
        kind, flags, payload_length = struct.unpack_from("<4sIQ", data, offset)
        if flags & ~FLAG_REQUIRED:
            raise Malformed(3, "reserved section flag bits are set")
        if payload_length > trailer_at - offset - HEADER_LENGTH:
            raise Malformed(7, f"{_fourcc(kind)} PayloadLength exceeds the remaining bytes")
        required = bool(flags & FLAG_REQUIRED)
        payload_at = offset + HEADER_LENGTH

        if phase == "start" and kind != b"TCSM":
            raise Malformed(5, "TCSM must be the first section")

        if kind == b"TCSM":
            if phase != "start":
                raise Malformed(5, "duplicate TCSM")
            layout.tcsm = (offset, payload_at, payload_length)
            phase = "tcsm"
        elif kind == b"BASE":
            if required:
                raise Malformed(4, "BASE is optional and must not be marked REQUIRED")
            if phase != "tcsm":
                raise Malformed(13, "BASE is duplicated or not directly after TCSM")
            if payload_length != BASE_LENGTH:
                raise Malformed(13, "BASE payload must be 32 bytes")
            layout.base_offset = offset
            layout.expected_base = data[payload_at:payload_at + BASE_LENGTH]
            phase = "base"
        elif kind == b"PAYL":
            if phase not in ("tcsm", "base", "payl"):
                raise Malformed(5, "PAYL outside the payload phase")
            _parse_payl(data, offset, payload_length, layout, max_entries)
            layout.payl_offsets.append(offset)
            phase = "payl"
        elif kind == b"PIDX":
            if phase == "pidx":
                raise Malformed(5, "duplicate PIDX")
            _parse_pidx(data, offset, payload_length, layout, max_entries)
            layout.pidx_offset = offset
            phase = "pidx"
        elif kind == b"FOOT":
            if phase != "pidx":
                raise Malformed(5, "FOOT without a preceding PIDX")
            if payload_length != FOOT_LENGTH:
                raise Malformed(15, "FOOT payload must be 56 bytes")
            if payload_at + FOOT_LENGTH != trailer_at:
                raise Malformed(5, "bytes between FOOT and the TRAILER")
            layout.foot_offset = offset
            _check_foot(data, payload_at, layout, foot_offset)
            return layout
        else:
            # AUX0 and unknown sections: optional phase only.
            if required:
                raise Malformed(4, f"{_fourcc(kind)} is optional or unknown and marked REQUIRED")
            if phase == "pidx":
                raise Malformed(5, f"{_fourcc(kind)} after PIDX")
            phase = "optional"
        offset = payload_at + payload_length


def _check_foot(data: bytes, at: int, layout: Layout, trailer_foot_offset: int) -> None:
    tcsm, base, pidx, first_payl, payl_count, entry_count, reserved = struct.unpack_from(
        "<QQQQQQQ", data, at)
    if reserved != 0:
        raise Malformed(3, "FOOT reserved field must be zero")
    expected = (layout.tcsm[0], layout.base_offset, layout.pidx_offset,
                layout.payl_offsets[0] if layout.payl_offsets else 0,
                len(layout.payl_offsets), len(layout.entries))
    if (tcsm, base, pidx, first_payl, payl_count, entry_count) != expected:
        raise Malformed(15, "FOOT fields disagree with the observed sections")
    if trailer_foot_offset != layout.foot_offset:
        raise Malformed(15, "TRAILER FootSectionOffset does not locate FOOT")


# --- Sections B-D: manifest, digest, payload against the target ----------------


def _read_manifest(data: bytes, what: str) -> tuple[dict, list[tuple[bytes, int]]]:
    records: list[tuple[bytes, int]] = []
    verdict = csm.decode(data, records)
    if verdict["outcome"] == "reject":
        raise Malformed(14 if what == "embedded" else 0, f"{what} CSM: {verdict['reason']}")
    if verdict["outcome"] == "unsupported":
        raise Unsupported(16, f"{what} CSM: {verdict['reason']}")
    return verdict, records


def _declared_hash_suite(data: bytes) -> str | None:
    """HashSuiteId from a CSM CORE section, or None when it cannot be read."""
    core = 32 + 16
    try:
        suite_length = struct.unpack_from("<H", data, core + 48)[0]
        return data[core + 56:core + 56 + suite_length].decode("ascii")
    except (struct.error, UnicodeDecodeError):
        return None


def _manifest_failures(verdict: dict) -> set[str]:
    kinds = set(verdict["failures"])
    failures = set()
    if kinds - {"ProfileSemantics"}:
        failures.add("EmbeddedManifest")
    if "ProfileSemantics" in kinds:
        failures.add("ProfileSemantics")
    return failures


# --- Section 5.2: zstd frame envelope ---------------------------------------


def _frame_envelope(stored: bytes, length: int) -> None:
    """Check RFC 8878 frame-header rules CSP adds (rules 29 and 30)."""

    if stored[:4] != ZSTD_FRAME_MAGIC:
        raise Malformed(29, "stored bytes do not start with a zstd frame")
    if len(stored) < 5:
        raise Malformed(29, "truncated zstd frame header")
    descriptor = stored[4]
    fcs_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    if descriptor & 0x08:
        raise Malformed(29, "zstd frame header reserved bit is set")
    dict_id_size = (0, 1, 2, 4)[descriptor & 0x03]
    position = 5
    window = None
    if not single_segment:
        if len(stored) < position + 1:
            raise Malformed(29, "truncated zstd frame header")
        window_descriptor = stored[position]
        position += 1
        window_log = 10 + (window_descriptor >> 3)
        window_base = 1 << window_log
        window = window_base + (window_base >> 3) * (window_descriptor & 0x07)
    if len(stored) < position + dict_id_size:
        raise Malformed(29, "truncated zstd frame header")
    dictionary_id = int.from_bytes(stored[position:position + dict_id_size], "little")
    position += dict_id_size
    fcs_size = ((1 if single_segment else 0), 2, 4, 8)[fcs_flag]
    if fcs_size == 0:
        raise Malformed(30, "zstd frame does not declare Frame_Content_Size")
    if len(stored) < position + fcs_size:
        raise Malformed(29, "truncated zstd frame header")
    content_size = int.from_bytes(stored[position:position + fcs_size], "little")
    if fcs_size == 2:
        content_size += 256
    if dictionary_id != 0:
        raise Malformed(30, "zstd frame declares a Dictionary_ID")
    if content_size != length:
        raise Malformed(30, "zstd Frame_Content_Size differs from the chunk Length")
    if (window if window is not None else content_size) > MAX_WINDOW_BYTES:
        raise Malformed(30, "zstd window exceeds 1 MiB")
    _check_sequence_headers(stored, position + fcs_size)


def _check_sequence_headers(stored: bytes, position: int) -> None:
    """Check the Sequences_Section of every compressed block (RFC 8878 3.1.1.3.2).

    Two rules that libzstd enforces only from 1.5.6 are checked here, so the
    verdict does not depend on the libzstd the interpreter links:

    - the reserved Symbol_Compression_Modes bits must be zero;
    - the sequence bitstream must be consumed exactly: decoding the declared
      number of sequences reads every bit below the padding marker, no more
      and no fewer. libzstd 1.5.5 accepts spare bits there.

    A section this check cannot follow (a truncated block, an invalid table
    description, a repeat mode without an earlier table, an invalid symbol) is
    left to libzstd, which rejects it in every version.
    """

    tables: dict[str, list[tuple[int, int, int]] | None] = {"ll": None, "of": None, "ml": None}
    while position + 3 <= len(stored):
        header = int.from_bytes(stored[position:position + 3], "little")
        last, block_type, block_size = header & 1, (header >> 1) & 3, header >> 3
        start = position + 3
        position = start + (1 if block_type == 1 else block_size)
        if block_type == 2 and position <= len(stored):
            block = stored[start:position]
            literals = _literals_section_size(block)
            if literals is not None and literals < len(block):
                count = block[literals]
                modes_at = literals + (1 if count < 128 else 2 if count < 255 else 3)
                if count != 0 and modes_at < len(block) and block[modes_at] & 0x03:
                    raise Malformed(29, "zstd Symbol_Compression_Modes reserved bits are set")
                if not _check_sequence_bitstream(block, literals, tables):
                    tables = {"ll": None, "of": None, "ml": None}
        if last:
            return


# RFC 8878 3.1.1.3.2.2: predefined distributions, their accuracy logs, the
# largest symbol of each code and the (baseline, extra bits) of every
# Literals_Length and Match_Length code.
_LL_DEFAULT = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
               -1, -1, -1, -1]
_ML_DEFAULT = [1, 4, 3, 2, 2, 2, 2, 2, 2] + [1] * 37 + [-1] * 7
_OF_DEFAULT = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]
_SEQUENCE_CODES = {  # kind: (predefined distribution, predefined accuracy log, largest symbol, largest accuracy log)
    "ll": (_LL_DEFAULT, 6, 35, 9),
    "of": (_OF_DEFAULT, 5, 31, 8),
    "ml": (_ML_DEFAULT, 6, 52, 9),
}
_LL_EXTRA = [0] * 16 + [1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
_ML_EXTRA = [0] * 32 + [1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]


def _fse_table(distribution: list[int], accuracy_log: int) -> list[tuple[int, int, int]]:
    """Build an FSE decoding table: (symbol, bits to read, baseline) per state (RFC 8878 4.1.1)."""

    size = 1 << accuracy_log
    high = size - 1
    symbols = [0] * size
    next_state = {}
    for symbol, probability in enumerate(distribution):
        if probability == -1:
            symbols[high] = symbol
            high -= 1
            next_state[symbol] = 1
        else:
            next_state[symbol] = probability
    step, mask, position = (size >> 1) + (size >> 3) + 3, size - 1, 0
    for symbol, probability in enumerate(distribution):
        for _ in range(max(probability, 0)):
            symbols[position] = symbol
            position = (position + step) & mask
            while position > high:
                position = (position + step) & mask
    table = []
    for state in range(size):
        symbol = symbols[state]
        value = next_state[symbol]
        next_state[symbol] += 1
        bits = accuracy_log - (value.bit_length() - 1)
        table.append((symbol, bits, (value << bits) - size))
    return table


def _fse_description(data: bytes, max_symbol: int, max_log: int) -> tuple[list[int], int, int] | None:
    """Read an FSE table description; return (distribution, accuracy log, bytes) or None if invalid."""

    value = int.from_bytes(data, "little")
    accuracy_log = (value & 0x0F) + 5
    if accuracy_log > max_log:
        return None
    bit = 4
    remaining = (1 << accuracy_log) + 1
    threshold = 1 << accuracy_log
    width = accuracy_log + 1
    distribution: list[int] = []
    while remaining > 1 and len(distribution) <= max_symbol:
        largest = (2 * threshold - 1) - remaining
        low = (value >> bit) & (threshold - 1)
        if low < largest:
            count, bit = low, bit + width - 1
        else:
            count = (value >> bit) & (2 * threshold - 1)
            if count >= threshold:
                count -= largest
            bit += width
        count -= 1
        remaining -= abs(count)
        distribution.append(count)
        if count == 0:
            while True:
                repeat = (value >> bit) & 3
                bit += 2
                distribution.extend([0] * repeat)
                if repeat != 3:
                    break
        while remaining < threshold:
            width -= 1
            threshold >>= 1
    size = (bit + 7) >> 3
    if remaining != 1 or len(distribution) > max_symbol + 1 or size > len(data):
        return None
    return distribution, accuracy_log, size


def _check_sequence_bitstream(block: bytes, literals: int,
                              tables: dict[str, list[tuple[int, int, int]] | None]) -> bool:
    """Decode one block's sequences and require the bitstream to be consumed exactly.

    Updates ``tables`` for later repeat modes. Returns False when the section
    cannot be followed (the caller then forgets the tables); raises Malformed
    when the bitstream has spare or missing bits.
    """

    at = literals
    first = block[at]
    if first == 0:
        return True
    if first < 128:
        count, at = first, at + 1
    elif first < 255:
        if at + 2 > len(block):
            return False
        count, at = ((first - 128) << 8) + block[at + 1], at + 2
    else:
        if at + 3 > len(block):
            return False
        count, at = block[at + 1] + (block[at + 2] << 8) + 0x7F00, at + 3
    if at >= len(block):
        return False
    modes = block[at]
    at += 1
    decoding = {}
    for kind, shift in (("ll", 6), ("of", 4), ("ml", 2)):
        distribution, predefined_log, max_symbol, max_log = _SEQUENCE_CODES[kind]
        mode = (modes >> shift) & 3
        if mode == 0:
            table = _fse_table(distribution, predefined_log)
        elif mode == 1:
            if at >= len(block) or block[at] > max_symbol:
                return False
            table = [(block[at], 0, 0)]
            at += 1
        elif mode == 2:
            description = _fse_description(block[at:], max_symbol, max_log)
            if description is None:
                return False
            table = _fse_table(description[0], description[1])
            at += description[2]
        else:
            table = tables[kind]
            if table is None:
                return False
        decoding[kind] = table
    tables.update(decoding)

    stream = block[at:]
    if not stream or stream[-1] == 0:
        return False
    value = int.from_bytes(stream, "little")
    available = value.bit_length() - 1
    position = available

    def read(bits: int) -> int:
        nonlocal position
        position -= bits
        if position < 0:
            return (value << -position) & ((1 << bits) - 1)
        return (value >> position) & ((1 << bits) - 1)

    ll, of, ml = decoding["ll"], decoding["of"], decoding["ml"]
    states = {"ll": read(len(ll).bit_length() - 1), "of": read(len(of).bit_length() - 1),
              "ml": read(len(ml).bit_length() - 1)}
    for remaining in range(count, 0, -1):
        of_code, ml_code, ll_code = of[states["of"]][0], ml[states["ml"]][0], ll[states["ll"]][0]
        if of_code > 31 or ml_code > 52 or ll_code > 35:
            return False
        read(of_code)
        read(_ML_EXTRA[ml_code])
        read(_LL_EXTRA[ll_code])
        if remaining > 1:
            for kind, table in (("ll", ll), ("ml", ml), ("of", of)):
                _, bits, baseline = table[states[kind]]
                states[kind] = baseline + read(bits)
    if position != 0:
        raise Malformed(29, "zstd sequence bitstream is not consumed exactly")
    return True


def _literals_section_size(block: bytes) -> int | None:
    """Return the byte length of a compressed block's Literals_Section."""

    if not block:
        return None
    literals_type, size_format = block[0] & 3, (block[0] >> 2) & 3
    if literals_type in (0, 1):  # raw or RLE
        header = (1, 2, 1, 3)[size_format]
        if len(block) < header:
            return None
        value = int.from_bytes(block[:header], "little")
        regenerated = value >> (3 if header == 1 else 4)
        return header + (regenerated if literals_type == 0 else 1)
    header = (3, 3, 4, 5)[size_format]  # compressed or treeless
    if len(block) < header:
        return None
    bits = (10, 10, 14, 18)[size_format]
    value = int.from_bytes(block[:header], "little") >> 4
    return header + ((value >> bits) & ((1 << bits) - 1))


def _decode_zstd(stored: bytes, length: int, dictionary: bytes) -> bytes:
    _frame_envelope(stored, length)
    options = {zstd.DecompressionParameter.window_log_max: 20}
    decompressor = zstd.ZstdDecompressor(
        zstd_dict=zstd.ZstdDict(dictionary, is_raw=True) if dictionary else None, options=options)
    try:
        decoded = decompressor.decompress(stored, max_length=length + 1)
    except zstd.ZstdError as error:
        rule = 30 if "checksum" in str(error).lower() else 29
        raise Malformed(rule, f"corrupt zstd frame: {error}") from None
    if not decompressor.eof:
        raise Malformed(29, "truncated zstd frame or output beyond the chunk Length")
    if decompressor.unused_data:
        raise Malformed(29, "bytes follow the zstd frame")
    if len(decoded) != length:
        raise Malformed(29, "zstd frame decodes to a different length")
    return decoded


# --- Apply --------------------------------------------------------------------------


def decode(patch: bytes, base_manifest: bytes | None = None, base_content: bytes | None = None,
           max_payload_entries: int = DEFAULT_MAX_PAYLOAD_ENTRIES) -> dict[str, object]:
    """Return the verdict of applying one CSP artifact."""

    try:
        return _apply(patch, base_manifest, base_content, max_payload_entries)
    except Malformed as error:
        return {"verdict": "malformed", "rule": error.rule, "reason": str(error)}
    except Unsupported as error:
        return {"verdict": "unsupported", "rule": error.rule, "reason": str(error)}
    except Limit as error:
        return {"verdict": "limit", "rule": error.rule, "reason": str(error)}
    except Verification as error:
        return {"verdict": "verification", "failures": sorted(error.failures), "reason": str(error)}


def _apply(patch: bytes, base_manifest: bytes | None, base_content: bytes | None,
           max_payload_entries: int) -> dict[str, object]:
    # A. Structure.
    layout = _parse_structure(patch, max_payload_entries)

    # B. Embedded CSM (section 4.5).
    _, tcsm_at, tcsm_length = layout.tcsm
    target, records = _read_manifest(patch[tcsm_at:tcsm_at + tcsm_length], "embedded")
    if target["physicalLength"] != tcsm_length:
        raise Malformed(14, "embedded CSM PhysicalLength differs from TCSM PayloadLength")
    failures = _manifest_failures(target)

    # C. Patch FileDigest (section 9.2), with the embedded HashSuite. The CSM
    # decoder has already rejected a suite it does not know as unsupported.
    new_hash = csm.HASH_SUITES[target["hashSuite"]]
    stored_digest = patch[-TRAILER_LENGTH + 24:-TRAILER_LENGTH + 56]
    if new_hash(patch[:-TRAILER_LENGTH]).digest() != stored_digest:
        failures.add("FileDigest")
    if failures:
        raise Verification(failures, "patch or embedded manifest integrity")

    # D. Payload entries against the target manifest.
    first_index: dict[bytes, int] = {}
    for index, (chunk_id, _) in enumerate(records):
        first_index.setdefault(chunk_id, index)
    seen: set[bytes] = set()
    unique: list[Entry] = []
    for entry in layout.entries:
        if entry.chunk_id in seen:
            failures.add("DuplicatePayload")
            continue
        seen.add(entry.chunk_id)
        if entry.chunk_id not in first_index:
            failures.add("PayloadNotInTarget")
            continue
        unique.append(entry)
    for entry in unique:
        if entry.first_target_index != first_index[entry.chunk_id]:
            raise Malformed(12, "FirstTargetIndex is not the first occurrence of its ChunkId")
    payload = {entry.chunk_id: entry for entry in unique}
    for entry in unique:
        target_length = records[entry.first_target_index][1]
        if entry.stored_length > target_length or (
                entry.encoding == ENCODING_RAW and entry.stored_length != target_length):
            failures.add("PayloadLength")
    if failures:
        raise Verification(failures, "payload entries disagree with the target manifest")

    # E. Base binding (section 3.3).
    depends_on_base = any(chunk_id not in payload for chunk_id, _ in records) or any(
        entry.dictionary for entry in layout.entries)
    if depends_on_base and layout.expected_base is None:
        raise Malformed(13, "the patch depends on a base but has no BASE section")
    base_locator: dict[bytes, tuple[int, int]] = {}
    if layout.expected_base is not None and (depends_on_base or base_manifest is not None):
        if base_manifest is None or base_content is None:
            raise Verification({"BaseMismatch"}, "the patch requires a base and none was supplied")
        # The HashSuite is compared first: ChunkIds of different suites are
        # not comparable, whatever the rest of the base manifest says.
        if _declared_hash_suite(base_manifest) not in (None, target["hashSuite"]):
            raise Verification({"BaseMismatch"}, "base and target HashSuites differ")
        base, base_records = _read_manifest(base_manifest, "base")
        if set(base["failures"]) - {"ProfileSemantics"}:
            # Section 3.4: the base profile is not an apply requirement.
            raise Verification({"BaseManifest"}, "the base manifest fails verification")
        if bytes.fromhex(base["manifestId"]) != layout.expected_base:
            raise Verification({"BaseMismatch"}, "base ManifestId differs from BASE")
        offset = 0
        for chunk_id, length in base_records:
            base_locator.setdefault(chunk_id, (offset, length))
            offset += length

    def base_chunk(chunk_id: bytes, expected_length: int | None, failure: str) -> bytes:
        located = base_locator.get(chunk_id)
        if located is None:
            raise Verification({failure}, "chunk is not in the base manifest")
        offset, length = located
        data = base_content[offset:offset + length]
        if len(data) != length or new_hash(data).digest() != chunk_id or (
                expected_length is not None and length != expected_length):
            raise Verification({failure}, "base chunk does not match its ChunkId and Length")
        return data

    # F. Resolve every target record in order.
    output = bytearray()
    resolved: dict[bytes, bytes] = {}
    for chunk_id, length in records:
        data = resolved.get(chunk_id)
        if data is None:
            entry = payload.get(chunk_id)
            if entry is not None:
                if entry.encoding == ENCODING_RAW:
                    data = entry.stored
                else:
                    dictionary = b"".join(base_chunk(d, None, "DictionaryChunk") for d in entry.dictionary)
                    if len(dictionary) > MAX_DICTIONARY_BYTES:
                        raise Verification({"DictionaryChunk"}, "dictionary exceeds 1 MiB")
                    if dictionary[:4] == ZSTD_DICTIONARY_MAGIC:
                        raise Verification({"DictionaryChunk"}, "dictionary starts with the zstd magic")
                    data = _decode_zstd(entry.stored, length, dictionary)
                if len(data) != length or new_hash(data).digest() != chunk_id:
                    raise Verification({"PayloadChunk"}, "payload bytes do not match their ChunkId")
            elif base_locator:
                if chunk_id not in base_locator:
                    raise Verification({"MissingPayload"}, "target chunk neither in base nor payload")
                data = base_chunk(chunk_id, length, "BaseChunk")
            else:
                raise Verification({"MissingPayload"}, "target chunk has no payload and no base")
            resolved[chunk_id] = data
        output += data

    # G. Total length.
    if len(output) != target["contentLength"]:
        raise Verification({"ContentLength"}, "reconstructed length differs from the manifest")

    return {"verdict": "valid", "outputSha256": hashlib.sha256(output).hexdigest(),
            "outputLength": len(output), "targetManifestId": target["manifestId"],
            "dependsOnBase": depends_on_base}


def verdict_text(verdict: dict[str, object]) -> str:
    """Render a verdict the way the .NET fuzz harness does."""

    outcome = str(verdict["verdict"])
    if outcome == "valid":
        return "valid:" + str(verdict["outputSha256"])
    if outcome == "verification":
        return "verification:" + ",".join(verdict["failures"])  # type: ignore[arg-type]
    return outcome


def compare(directory: Path) -> int:
    """Differential check of .NET fuzz verdicts against this decoder.

    Reads every verdicts-*.jsonl written by CspApplyFuzzTests (one JSON object
    per line: {"file": ..., "baseManifest": ... or null, "base": ... or null,
    "verdict": ...}) and applies each case with its base files.
    """

    checked = 0
    mismatches: list[str] = []

    for listing in sorted(directory.glob("verdicts-*.jsonl")):
        for line in listing.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            base_manifest = (
                (directory / case["baseManifest"]).read_bytes()
                if case.get("baseManifest") else None)
            base_content = (
                (directory / case["base"]).read_bytes()
                if case.get("base") else None)
            verdict = decode(
                (directory / case["file"]).read_bytes(), base_manifest, base_content)
            checked += 1
            text = verdict_text(verdict)
            if text != case["verdict"]:
                mismatches.append(
                    f"{case['file']}: .NET {case['verdict']!r}, "
                    f"decoder {text!r} ({verdict.get('reason', '')})"
                )

    for mismatch in mismatches[:50]:
        print(mismatch, file=sys.stderr)

    print(f"compared {checked} fuzz cases: {len(mismatches)} mismatches")
    if checked == 0:
        print("no fuzz cases found", file=sys.stderr)
        return 1
    return 1 if mismatches else 0


def compare_frames(directory: Path) -> int:
    """Differential check of encoding-1 frames: ZstdSharp against libzstd.

    Reads every frames-*.jsonl written by ZstdFrameFuzzTests (one JSON object
    per line: {"file": ..., "dictionary": ... or null, "length": ...,
    "verdict": "ok:<sha256>" or "malformed"}) and decodes each frame for that
    chunk length and dictionary with the checks of section 5.2.
    """

    checked = 0
    mismatches: list[str] = []
    dictionaries: dict[str, bytes] = {}

    for listing in sorted(directory.glob("frames-*.jsonl")):
        for line in listing.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            name = case.get("dictionary")
            if name and name not in dictionaries:
                dictionaries[name] = (directory / name).read_bytes()
            try:
                decoded = _decode_zstd(
                    (directory / case["file"]).read_bytes(), case["length"], dictionaries.get(name, b""))
                text = "ok:" + hashlib.sha256(decoded).hexdigest()
            except Malformed as error:
                text, reason = "malformed", str(error)
            else:
                reason = ""
            checked += 1
            if text != case["verdict"]:
                mismatches.append(f"{case['file']}: .NET {case['verdict']!r}, decoder {text!r} {reason}")

    for mismatch in mismatches[:50]:
        print(mismatch, file=sys.stderr)

    print(f"compared {checked} zstd frames: {len(mismatches)} mismatches")
    if checked == 0:
        print("no frame cases found", file=sys.stderr)
        return 1
    return 1 if mismatches else 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--compare-frames":
        if len(argv) != 2:
            print("usage: decode.py --compare-frames DIRECTORY", file=sys.stderr)
            return 2
        return compare_frames(Path(argv[1]))
    if argv and argv[0] == "--compare":
        if len(argv) != 2:
            print("usage: decode.py --compare DIRECTORY", file=sys.stderr)
            return 2
        return compare(Path(argv[1]))

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("patch", type=Path)
    parser.add_argument("--base-manifest", type=Path)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--max-payload-entries", type=int, default=DEFAULT_MAX_PAYLOAD_ENTRIES)
    args = parser.parse_args(argv)
    verdict = decode(args.patch.read_bytes(),
                     args.base_manifest.read_bytes() if args.base_manifest else None,
                     args.base.read_bytes() if args.base else None,
                     args.max_payload_entries)
    print(json.dumps({"file": str(args.patch), **verdict}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
