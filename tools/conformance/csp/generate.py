#!/usr/bin/env python3
"""Generate independent CSP v1 vectors.

This tool does not call ChunkShift code. It uses only the Python standard
library, the byte layout of docs/architecture/CSP-V1.md, and the CSM
builder of tools/conformance/csm/generate.py for the embedded target manifest and
the base manifests (with its pure-Python BLAKE3 for the BLAKE3 vectors).

Every vector is built from explicit field values with every unrelated offset,
CRC and digest kept consistent, so it violates exactly the rule its name
describes. Its expected verdict is written to vectors.json from this file's
definitions, never from a decoder. Each vector also records the stage that
reaches the verdict:

- ``structure``  the patch alone decides it: sections, CRCs, the embedded
                 manifest, the patch FileDigest, payload entries against the
                 target manifest, and a base-dependent patch without BASE;
- ``apply``      it needs the base or the reconstruction: base binding, base
                 and dictionary chunks, payload bytes, the final length.

A valid vector is ``apply`` and records the SHA-256 and length of the target
it must reconstruct.

--verify checks a directory against the generator and against the
independent decoder in decode.py (which does not import this module):

  1. every file in the directory is byte-identical to a fresh generation;
  2. vectors.json is identical to the generated expectations;
  3. decode.py reaches the expected verdict for every vector.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_CSM_GENERATOR = Path(__file__).resolve().parent.parent / "csm" / "generate.py"
_spec = importlib.util.spec_from_file_location("csm_fixtures_generate", _CSM_GENERATOR)
csmgen = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = csmgen   # dataclasses resolve their module through sys.modules
_spec.loader.exec_module(csmgen)

REQUIRED = 1
HASH_SUITE = csmgen.HASH_SUITE_ID.decode("ascii")
BLAKE3 = csmgen.BLAKE3_SUITE_ID
PROFILE = csmgen.PROFILE_ID.decode("ascii")
TRAILER_LENGTH = 64


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def digest(data: bytes, suite: bytes) -> bytes:
    """A digest under a HashSuite: ChunkIds, dictionary ChunkIds and the patch FileDigest."""
    return csmgen.suite_hash(suite)(data).digest()


def suite_of(layout) -> bytes:
    return layout.hash_suite_id if layout is not None else csmgen.HASH_SUITE_ID


def crc32c(data: bytes) -> int:
    state = 0xFFFFFFFF
    for value in data:
        state ^= value
        for _ in range(8):
            state = (state >> 1) ^ (0x82F63B78 if state & 1 else 0)
    return (~state) & 0xFFFFFFFF


def header(kind: bytes, flags: int, payload_length: int) -> bytes:
    return kind + struct.pack("<IQ", flags, payload_length)


def content(label: str, length: int) -> bytes:
    """Deterministic pseudo-random bytes: SHA-256 in counter mode over the label."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha256(label.encode("ascii") + struct.pack("<I", counter))
        counter += 1
    return bytes(out[:length])


def manifest(chunks: list[bytes], layout=None) -> tuple[bytes, dict]:
    """A CSM v1 (synthetic fixture profile) whose ChunkIds hash the chunks with its HashSuite."""
    suite = suite_of(layout)
    return csmgen.build([(digest(c, suite), len(c)) for c in chunks], False, layout)


# --- Content --------------------------------------------------------------------

BASE_A = [content(f"base-a-{i}", n) for i, n in enumerate((700, 900, 1200, 500, 800, 1000))]
NEW = [content(f"new-{i}", n) for i, n in enumerate((600, 750, 333, 1024, 64, 2000))]

# --- Encoding 1 (zstd, section 5.2) ----------------------------------------------------
#
# Compressed frames are pinned as hex, made once by libzstd 1.5.7 (CPython
# 3.14 compression.zstd, level 19, raw-content dictionary), so generation does
# not depend on the zstd version at hand; any RFC 8878 decoder must reproduce
# the chunk. Every other frame is assembled here from RFC 8878 fields with a
# single Raw_Block, which needs no compressor.

TEXT = (b"ChunkShift declarative patch payload, " * 40)[:900]
EDITED_A1 = BASE_A[1][:300] + b"CHUNKSHIFT" + BASE_A[1][310:]
SPLICED_A0_A3 = BASE_A[0][100:400] + BASE_A[2][0:500] + BASE_A[3][50:250]
MAGIC_CHUNK = bytes.fromhex("37a430ec") + content("magic", 596)   # starts with the zstd dictionary magic

FRAME_TEXT = bytes.fromhex(
    "28b52ffd6084027d010064024368756e6b5368696674206465636c61726174697665207061746368207061796c"
    "6f61642c200100de9a2af504")
FRAME_TEXT_CHECKSUM = bytes.fromhex(
    "28b52ffd6484027d010064024368756e6b5368696674206465636c61726174697665207061746368207061796c"
    "6f61642c200100de9a2af504915a6ee9")
FRAME_EDITED_A1 = bytes.fromhex("28b52ffd608402ad000050ee48554e4b534849465402004b40752987557105")   # dict: A1
FRAME_SPLICED = bytes.fromhex("28b52ffd60e802950000104eef0300c4723225f1d367155006a9c22b")          # dict: A0..A3

ZSTD_MAGIC = bytes.fromhex("28b52ffd")


RLE_CHUNK = b"A" * 750          # a target chunk an RLE frame encodes in a few bytes


def rle_frame(value: int, count: int, *, single_segment: bool = True, content_size: int | None = -1,
              window_descriptor: int = 0, dictionary_id: int | None = None, block_type: int = 1) -> bytes:
    """One zstd frame with one RLE_Block (RFC 8878 section 3.1.1): ``count`` copies of ``value``.

    content_size=-1 declares ``count``; None omits Frame_Content_Size.
    """
    declared = count if content_size == -1 else content_size
    if declared is None:
        fcs_flag, fcs = 0, b""
    elif single_segment and declared < 256:
        fcs_flag, fcs = 0, bytes([declared])
    elif 256 <= declared < 65792:
        fcs_flag, fcs = 1, struct.pack("<H", declared - 256)
    else:
        fcs_flag, fcs = 2, struct.pack("<I", declared)
    dict_flag, dict_field = (0, b"") if dictionary_id is None else (1, bytes([dictionary_id]))
    descriptor = (fcs_flag << 6) | (0x20 if single_segment else 0) | dict_flag
    head = ZSTD_MAGIC + bytes([descriptor])
    if not single_segment:
        head += bytes([window_descriptor])
    block_header = (count << 3) | (block_type << 1) | 1          # Last_Block
    return head + dict_field + fcs + block_header.to_bytes(3, "little") + bytes([value])


def rle(**knobs) -> bytes:
    return rle_frame(ord("A"), len(RLE_CHUNK), **knobs)


SKIPPABLE = struct.pack("<II", 0x184D2A50, 3) + b"abc"


@dataclass
class Base:
    chunks: list[bytes]
    layout: object = None
    content_override: bytes | None = None

    def files(self) -> tuple[bytes, bytes]:
        data, _ = manifest(self.chunks, self.layout)
        return data, self.content_override if self.content_override is not None else b"".join(self.chunks)

    def manifest_id(self) -> bytes:
        return bytes.fromhex(manifest(self.chunks, self.layout)[1]["manifestId"])


BASES = {
    "base-a": Base(BASE_A),
    "base-b": Base(BASE_A[:3] + [NEW[5]]),                 # a different, valid base
    "base-a-corrupt-content": Base(BASE_A, content_override=b"".join(
        BASE_A[:3] + [bytes([BASE_A[3][0] ^ 1]) + BASE_A[3][1:]] + BASE_A[4:])),
    "base-a-bad-manifest": Base(BASE_A, csmgen.Layout(trailer_digest_xor=True)),
    "base-a-blake3": Base(BASE_A, csmgen.Layout(hash_suite_id=BLAKE3)),
    "base-a-blake3-corrupt-content": Base(BASE_A, csmgen.Layout(hash_suite_id=BLAKE3), content_override=b"".join(
        BASE_A[:3] + [bytes([BASE_A[3][0] ^ 1]) + BASE_A[3][1:]] + BASE_A[4:])),
    "base-magic": Base(BASE_A[:2] + [MAGIC_CHUNK]),
    "base-a-corrupt-dictionary": Base(BASE_A, content_override=b"".join(
        BASE_A[:1] + [bytes([BASE_A[1][0] ^ 1]) + BASE_A[1][1:]] + BASE_A[2:])),
}


# --- Patch builder -------------------------------------------------------------------


@dataclass
class Entry:
    """A payload entry: target chunk bytes and how they are stored."""
    chunk: bytes
    encoding: int = 0
    dictionary: list[bytes] = field(default_factory=list)   # base chunk bytes
    stored: bytes | None = None                              # default: the raw chunk
    chunk_id: bytes | None = None                            # default: the chunk's digest
    reserved: int = 0
    declared_length: int | None = None                       # StoredLength field override

    def identity(self, suite: bytes) -> bytes:
        return self.chunk_id if self.chunk_id is not None else digest(self.chunk, suite)

    def stored_bytes(self) -> bytes:
        return self.stored if self.stored is not None else self.chunk


@dataclass
class Patch:
    """A CSP v1 representation; the defaults produce a conforming one.

    Offsets in PIDX, FOOT and TRAILER always describe the bytes actually
    emitted, CRCs and the FileDigest are recomputed, unless a knob
    deliberately breaks that field.
    """

    target: list[bytes]
    base: str | None = None                  # key of BASES whose ManifestId BASE binds
    base_section: bool | None = None         # default: emitted when base is set
    entries: list[Entry] | None = None       # default: distinct target chunks not in the base, raw
    first_target_index: dict[int, int] = field(default_factory=dict)   # entry ordinal -> override
    blocks: list[int] | None = None          # entries per PAYL; default one block per 4096

    target_layout: object = None             # csmgen.Layout for the embedded CSM
    tcsm_bytes: bytes | None = None          # raw TCSM payload override

    magic: bytes = b"CSP1"
    major: int = 1
    preamble_size: int = 32
    required_features: int = 0
    optional_features: int = 0
    preamble_reserved: int = 0

    tcsm_flags: int = REQUIRED
    base_flags: int = 0
    base_payload: bytes | None = None
    base_twice: bool = False
    base_after_payl: bool = False

    payl_reserved: int = 0
    payl_first_ordinal_delta: int = 0
    payl_count_override: int | None = None
    payl_padding: bytes = b""                # bytes after the entries, inside the CRC
    payl_crc_xor: int = 0
    between_payl: bytes = b""                # raw bytes after the first PAYL section

    pidx_version: int = 1
    pidx_crc_xor: int = 0
    pidx_drop_last: bool = False
    pidx_padding: bytes = b""                # bytes after the entries, inside the CRC
    pidx_entry: dict[int, dict[str, int]] = field(default_factory=dict)  # ordinal -> field overrides
    pidx_twice: bool = False

    after_tcsm: list[bytes] = field(default_factory=list)
    after_payl: list[bytes] = field(default_factory=list)
    after_pidx: list[bytes] = field(default_factory=list)
    omit_tcsm: bool = False
    omit_pidx: bool = False
    omit_foot: bool = False

    foot: dict[str, int] = field(default_factory=dict)     # field -> delta
    foot_reserved: int = 0

    trailer_magic: bytes = b"CSPT"
    trailer_major: int = 1
    trailer_foot_delta: int = 0
    trailer_length_delta: int = 0
    trailer_digest_xor: bool = False
    trailer_reserved: int = 0
    after_trailer: bytes = b""

    @property
    def suite(self) -> bytes:
        """The HashSuite of the embedded target manifest, which the whole patch uses."""
        return suite_of(self.target_layout)

    def payload_entries(self) -> list[Entry]:
        if self.entries is not None:
            return self.entries
        base_ids = {digest(c, self.suite) for c in BASES[self.base].chunks} if self.base else set()
        seen, entries = set(), []
        for chunk in self.target:
            chunk_id = digest(chunk, self.suite)
            if chunk_id not in base_ids and chunk_id not in seen:
                seen.add(chunk_id)
                entries.append(Entry(chunk))
        return entries

    def build(self) -> bytes:
        entries = self.payload_entries()
        first_index = {}
        for index, chunk in enumerate(self.target):
            first_index.setdefault(digest(chunk, self.suite), index)

        out = bytearray(self.magic + struct.pack(
            "<HHQQQ", self.major, self.preamble_size, self.required_features,
            self.optional_features, self.preamble_reserved))

        tcsm_offset = len(out)
        tcsm = self.tcsm_bytes if self.tcsm_bytes is not None else manifest(self.target, self.target_layout)[0]
        if not self.omit_tcsm:
            out += header(b"TCSM", self.tcsm_flags, len(tcsm)) + tcsm
        for extra in self.after_tcsm:
            out += extra

        emit_base = self.base_section if self.base_section is not None else self.base is not None
        base_offset = 0

        def base_section() -> bytes:
            payload = self.base_payload if self.base_payload is not None else BASES[self.base].manifest_id()
            return header(b"BASE", self.base_flags, len(payload)) + payload

        if emit_base and not self.base_after_payl:
            base_offset = len(out)
            out += base_section()
            if self.base_twice:
                out += base_section()

        blocks = self.blocks
        if blocks is None:
            blocks = [min(4096, len(entries) - s) for s in range(0, len(entries), 4096)]
        pidx_rows = []
        payl_offsets = []
        ordinal = 0
        for block_index, count in enumerate(blocks):
            block = entries[ordinal:ordinal + count]
            section_offset = len(out)
            payl_offsets.append(section_offset)
            body = bytearray(struct.pack(
                "<IIQ", count if self.payl_count_override is None else self.payl_count_override,
                self.payl_reserved, ordinal + (self.payl_first_ordinal_delta if block_index == 0 else 0)))
            for entry in block:
                record_offset = section_offset + 16 + len(body)
                stored = entry.stored_bytes()
                declared = len(stored) if entry.declared_length is None else entry.declared_length
                body += entry.identity(self.suite) + struct.pack(
                    "<IBBH", declared, entry.encoding, len(entry.dictionary), entry.reserved)
                body += b"".join(digest(d, self.suite) for d in entry.dictionary) + stored
                fti = self.first_target_index.get(ordinal, first_index.get(entry.identity(self.suite), 0))
                pidx_rows.append([fti, record_offset, declared, entry.encoding, len(entry.dictionary), 0])
                ordinal += 1
            body += self.payl_padding
            head = header(b"PAYL", REQUIRED, len(body) + 4)
            out += head + body + struct.pack("<I", crc32c(head + body) ^ self.payl_crc_xor)
            if block_index == 0:
                out += self.between_payl

        if emit_base and self.base_after_payl:
            base_offset = len(out)
            out += base_section()
        for extra in self.after_payl:
            out += extra

        for ordinal_key, overrides in self.pidx_entry.items():
            row = pidx_rows[ordinal_key]
            for name, value in overrides.items():
                row[("fti", "offset", "stored", "encoding", "dictionary", "reserved").index(name)] = value
        if self.pidx_drop_last:
            pidx_rows = pidx_rows[:-1]

        def pidx_section() -> bytes:
            body = struct.pack("<II", self.pidx_version, len(pidx_rows))
            body += b"".join(struct.pack("<QQIBBH", *row) for row in pidx_rows) + self.pidx_padding
            head = header(b"PIDX", REQUIRED, len(body) + 4)
            return head + body + struct.pack("<I", crc32c(head + body) ^ self.pidx_crc_xor)

        pidx_offset = len(out)
        if not self.omit_pidx:
            out += pidx_section()
            if self.pidx_twice:
                out += pidx_section()
        for extra in self.after_pidx:
            out += extra

        foot_offset = len(out)
        values = {
            "tcsm": tcsm_offset, "base": base_offset, "pidx": pidx_offset,
            "first_payl": payl_offsets[0] if payl_offsets else 0,
            "payl_count": len(payl_offsets), "entries": ordinal,
        }
        for name, delta in self.foot.items():
            values[name] += delta
        if not self.omit_foot:
            out += header(b"FOOT", REQUIRED, 56) + struct.pack(
                "<QQQQQQQ", values["tcsm"], values["base"], values["pidx"], values["first_payl"],
                values["payl_count"], values["entries"], self.foot_reserved)

        file_digest = digest(bytes(out), self.suite)
        if self.trailer_digest_xor:
            file_digest = bytes([file_digest[0] ^ 1]) + file_digest[1:]
        out += self.trailer_magic + struct.pack(
            "<HHQQ", self.trailer_major, 64, foot_offset + self.trailer_foot_delta,
            len(out) + TRAILER_LENGTH + self.trailer_length_delta) + file_digest + struct.pack(
            "<Q", self.trailer_reserved)
        return bytes(out + self.after_trailer)


# --- Vectors ---------------------------------------------------------------------------


@dataclass
class Vector:
    patch: Patch | bytes
    expect: dict
    stage: str
    base: str | None = None                  # base files supplied to apply
    max_payload_entries: int | None = None


def valid(target: list[bytes], depends_on_base: bool) -> dict:
    return {"verdict": "valid", "outputSha256": hashlib.sha256(b"".join(target)).hexdigest(),
            "outputLength": sum(map(len, target)), "dependsOnBase": depends_on_base}


def malformed(rule: int) -> dict:
    return {"verdict": "malformed", "rule": rule}


def unsupported(rule: int) -> dict:
    return {"verdict": "unsupported", "rule": rule}


def verification(*failures: str) -> dict:
    return {"verdict": "verification", "failures": sorted(failures)}


def limit() -> dict:
    return {"verdict": "limit", "rule": 26}


A = BASE_A
N = NEW
# Target of the base-dependent family: reused chunks, a repeated missing chunk
# (one entry, three uses) and a repeated base chunk.
MIXED = [A[0], N[0], A[1], N[1], N[0], A[3], N[2], A[0], N[0]]
SELF = [N[3], N[4], N[3], N[5]]


def mixed(**knobs) -> Patch:
    return Patch(MIXED, base="base-a", **knobs)


def self_contained(**knobs) -> Patch:
    return Patch(SELF, **knobs)


def section(kind: bytes, flags: int, payload: bytes) -> bytes:
    return header(kind, flags, len(payload)) + payload


def truncations() -> dict[str, Vector]:
    """Cut the base-dependent patch at every structural boundary."""
    data = mixed().build()
    boundaries = {"preamble": 32}
    offset = 32
    names = iter(["tcsm", "base", "payl", "pidx", "foot"])
    while offset < len(data) - TRAILER_LENGTH:
        length = struct.unpack_from("<Q", data, offset + 8)[0]
        name = next(names)
        boundaries[f"{name}-header"] = offset + 8
        boundaries[f"{name}-end"] = offset + 16 + length
        offset += 16 + length
    boundaries["trailer-half"] = len(data) - 32
    vectors = {}
    for name, cut in boundaries.items():
        # A cut artifact has no TRAILER at physical EOF (rule 5), or is too
        # short to hold PREAMBLE and TRAILER at all (rule 7).
        vectors[f"truncated-{name}.csp"] = Vector(
            data[:cut], malformed(7 if cut < 32 + TRAILER_LENGTH else 5), "structure", "base-a")
    return vectors


def fixtures() -> dict[str, Vector]:
    v: dict[str, Vector] = {}
    dep = verification

    # Valid.
    v["valid-base-dependent.csp"] = Vector(mixed(), valid(MIXED, True), "apply", "base-a")
    v["valid-no-payload.csp"] = Vector(Patch([A[2], A[0], A[2], A[5]], base="base-a"),
                                       valid([A[2], A[0], A[2], A[5]], True), "apply", "base-a")
    v["valid-one-chunk.csp"] = Vector(Patch([N[1]]), valid([N[1]], False), "apply")
    v["valid-self-contained.csp"] = Vector(self_contained(), valid(SELF, False), "apply")
    v["valid-self-contained-with-base.csp"] = Vector(
        Patch(SELF, base="base-a"), valid(SELF, False), "apply", "base-a")
    v["valid-self-contained-with-base-unsupplied.csp"] = Vector(
        Patch(SELF, base="base-a"), valid(SELF, False), "apply")
    v["valid-multiple-payl.csp"] = Vector(mixed(blocks=[1, 1, 1]), valid(MIXED, True), "apply", "base-a")
    many = [i.to_bytes(3, "little") for i in range(4097)]   # distinct by construction
    v["valid-4097-entries.csp"] = Vector(Patch(many), valid(many, False), "apply")
    v["valid-aux-and-unknown-optional.csp"] = Vector(
        mixed(after_payl=[section(b"AUX0", 0, b"aux"), section(b"XTRA", 0, b"")]),
        valid(MIXED, True), "apply", "base-a")
    v["valid-optional-feature-bit.csp"] = Vector(mixed(optional_features=1), valid(MIXED, True),
                                                 "apply", "base-a")

    # Rule 1: PREAMBLE.
    v["preamble-magic.csp"] = Vector(mixed(magic=b"CSQ1"), malformed(1), "structure", "base-a")
    v["preamble-major.csp"] = Vector(mixed(major=2), malformed(1), "structure", "base-a")
    v["preamble-size.csp"] = Vector(mixed(preamble_size=40), malformed(1), "structure", "base-a")
    v["preamble-reserved.csp"] = Vector(mixed(preamble_reserved=1), malformed(1), "structure", "base-a")
    # Rule 2.
    v["required-feature.csp"] = Vector(mixed(required_features=1), unsupported(2), "structure", "base-a")
    # Rule 3: reserved fields.
    v["section-flag-reserved.csp"] = Vector(mixed(tcsm_flags=REQUIRED | 2), malformed(3), "structure", "base-a")
    v["payl-reserved.csp"] = Vector(mixed(payl_reserved=1), malformed(3), "structure", "base-a")
    v["payl-entry-reserved.csp"] = Vector(
        mixed(entries=[Entry(N[0], reserved=1), Entry(N[1]), Entry(N[2])]), malformed(3), "structure", "base-a")
    v["pidx-entry-reserved.csp"] = Vector(mixed(pidx_entry={0: {"reserved": 1}}), malformed(3),
                                          "structure", "base-a")
    v["foot-reserved.csp"] = Vector(mixed(foot_reserved=1), malformed(3), "structure", "base-a")
    v["trailer-reserved.csp"] = Vector(mixed(trailer_reserved=1), malformed(3), "structure", "base-a")
    # Rule 4.
    v["base-required.csp"] = Vector(mixed(base_flags=REQUIRED), malformed(4), "structure", "base-a")
    v["aux-required.csp"] = Vector(mixed(after_payl=[section(b"AUX0", REQUIRED, b"")]), malformed(4),
                                   "structure", "base-a")
    v["unknown-required.csp"] = Vector(mixed(after_payl=[section(b"XTRA", REQUIRED, b"")]), malformed(4),
                                       "structure", "base-a")
    # Rule 5: state machine and TRAILER placement.
    v["missing-tcsm.csp"] = Vector(mixed(omit_tcsm=True), malformed(5), "structure", "base-a")
    v["duplicate-tcsm.csp"] = Vector(
        mixed(after_tcsm=[section(b"TCSM", REQUIRED, manifest(MIXED)[0])]), malformed(5), "structure", "base-a")
    v["payl-after-aux.csp"] = Vector(mixed(blocks=[2, 1], between_payl=section(b"AUX0", 0, b"x")),
                                     malformed(5), "structure", "base-a")
    v["aux-after-pidx.csp"] = Vector(mixed(after_pidx=[section(b"AUX0", 0, b"")]), malformed(5),
                                     "structure", "base-a")
    v["duplicate-pidx.csp"] = Vector(mixed(pidx_twice=True), malformed(5), "structure", "base-a")
    v["missing-pidx.csp"] = Vector(mixed(omit_pidx=True), malformed(5), "structure", "base-a")
    v["missing-foot.csp"] = Vector(mixed(omit_foot=True), malformed(5), "structure", "base-a")
    v["bytes-after-trailer.csp"] = Vector(mixed(after_trailer=b"\x00"), malformed(5), "structure", "base-a")
    v["trailer-magic.csp"] = Vector(mixed(trailer_magic=b"CSPX"), malformed(5), "structure", "base-a")
    v["trailer-major.csp"] = Vector(mixed(trailer_major=2), malformed(5), "structure", "base-a")
    # Rule 6.
    v["physical-length.csp"] = Vector(mixed(trailer_length_delta=1), malformed(6), "structure", "base-a")
    # Rule 7.
    v["section-length-overflow.csp"] = Vector(
        mixed(after_pidx=[header(b"XTRA", 0, (1 << 64) - 1)]), malformed(7), "structure", "base-a")
    # Rule 8: PAYL.
    v["payl-entry-count-zero.csp"] = Vector(mixed(payl_count_override=0), malformed(8), "structure", "base-a")
    v["payl-first-ordinal.csp"] = Vector(mixed(payl_first_ordinal_delta=1), malformed(8), "structure", "base-a")
    v["payl-length-mismatch.csp"] = Vector(mixed(payl_padding=b"\x00"), malformed(8), "structure", "base-a")
    v["payl-entry-overrun.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1]), Entry(N[2], declared_length=len(N[2]) + 1)]),
        malformed(8), "structure", "base-a")
    v["payl-stored-zero.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1]), Entry(N[2], stored=b"")]), malformed(8), "structure", "base-a")
    # Rule 9.
    v["payl-crc.csp"] = Vector(mixed(payl_crc_xor=1), malformed(9), "structure", "base-a")
    v["pidx-crc.csp"] = Vector(mixed(pidx_crc_xor=1), malformed(9), "structure", "base-a")
    # Rule 10.
    v["pidx-version.csp"] = Vector(mixed(pidx_version=2), malformed(10), "structure", "base-a")
    v["pidx-length.csp"] = Vector(mixed(pidx_padding=bytes(24)), malformed(10), "structure", "base-a")
    # Rule 11.
    v["pidx-count-mismatch.csp"] = Vector(mixed(pidx_drop_last=True), malformed(11), "structure", "base-a")
    v["pidx-stored-length.csp"] = Vector(mixed(pidx_entry={1: {"stored": len(N[1]) - 1}}), malformed(11),
                                         "structure", "base-a")
    v["pidx-encoding.csp"] = Vector(mixed(pidx_entry={1: {"encoding": 1}}), malformed(11), "structure", "base-a")
    # Rule 12.
    v["pidx-offset.csp"] = Vector(mixed(pidx_entry={1: {"offset": 0}}), malformed(12), "structure", "base-a")
    v["pidx-order.csp"] = Vector(mixed(first_target_index={1: 0}), malformed(12), "structure", "base-a")
    later = [N[1], N[0], A[0], N[0]]
    v["first-index-later-occurrence.csp"] = Vector(Patch(later, base="base-a", first_target_index={1: 3}),
                                                   malformed(12), "structure", "base-a")
    v["first-index-out-of-range.csp"] = Vector(mixed(first_target_index={2: 99}), malformed(12),
                                               "structure", "base-a")
    # Rule 13.
    v["base-twice.csp"] = Vector(mixed(base_twice=True), malformed(13), "structure", "base-a")
    v["base-after-payl.csp"] = Vector(mixed(base_after_payl=True), malformed(13), "structure", "base-a")
    v["base-length.csp"] = Vector(mixed(base_payload=bytes(33)), malformed(13), "structure", "base-a")
    v["base-missing-dependent.csp"] = Vector(mixed(base_section=False), malformed(13), "structure", "base-a")
    # Rule 14.
    v["tcsm-malformed.csp"] = Vector(mixed(target_layout=csmgen.Layout(magic=b"XSM1")), malformed(14),
                                     "structure", "base-a")
    # Rule 15.
    v["foot-tcsm-offset.csp"] = Vector(mixed(foot={"tcsm": 1}), malformed(15), "structure", "base-a")
    v["foot-base-offset.csp"] = Vector(mixed(foot={"base": 1}), malformed(15), "structure", "base-a")
    v["foot-entry-count.csp"] = Vector(mixed(foot={"entries": 1}), malformed(15), "structure", "base-a")
    v["foot-payl-count.csp"] = Vector(mixed(foot={"payl_count": 1}), malformed(15), "structure", "base-a")
    v["trailer-foot-offset.csp"] = Vector(mixed(trailer_foot_delta=16), malformed(15), "structure", "base-a")
    # Rule 16.
    v["unknown-hash-suite.csp"] = Vector(
        mixed(target_layout=csmgen.Layout(hash_suite_id=b"chunkshift.unknown.v1")), unsupported(16),
        "structure", "base-a")
    v["unknown-encoding.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], encoding=2), Entry(N[2])]), unsupported(16), "structure", "base-a")
    # Rule 17.
    v["duplicate-payload.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1]), Entry(N[1]), Entry(N[2])], first_target_index={2: 5}),
        dep("DuplicatePayload"), "structure", "base-a")
    v["payload-not-in-target.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1]), Entry(N[2]), Entry(N[5])], first_target_index={3: 8}),
        dep("PayloadNotInTarget"), "structure", "base-a")
    # Rule 18.
    v["raw-length-mismatch.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], stored=N[1][:-1]), Entry(N[2])]),
        dep("PayloadLength"), "structure", "base-a")
    v["stored-longer-than-chunk.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], encoding=1, stored=N[1] + b"\x00"), Entry(N[2])]),
        dep("PayloadLength"), "structure", "base-a")
    # Rule 19.
    v["payload-hash.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], stored=bytes([N[1][0] ^ 1]) + N[1][1:]), Entry(N[2])]),
        dep("PayloadChunk"), "apply", "base-a")
    # Rule 20.
    v["base-not-supplied.csp"] = Vector(mixed(), dep("BaseMismatch"), "apply")
    v["base-other-manifest.csp"] = Vector(mixed(), dep("BaseMismatch"), "apply", "base-b")
    v["base-hash-suite.csp"] = Vector(mixed(), dep("BaseMismatch"), "apply", "base-a-blake3")
    v["base-manifest-integrity.csp"] = Vector(
        Patch(MIXED, base="base-a-bad-manifest"), dep("BaseManifest"), "apply", "base-a-bad-manifest")
    v["self-contained-base-other.csp"] = Vector(Patch(SELF, base="base-a"), dep("BaseMismatch"), "apply", "base-b")
    # Rule 21.
    v["base-chunk-corrupt.csp"] = Vector(
        Patch(MIXED, base="base-a"), dep("BaseChunk"), "apply", "base-a-corrupt-content")
    # Rule 22.
    v["missing-payload.csp"] = Vector(mixed(entries=[Entry(N[0]), Entry(N[1])]), dep("MissingPayload"),
                                      "apply", "base-a")
    # Rule 25.
    v["tcsm-integrity.csp"] = Vector(mixed(target_layout=csmgen.Layout(trailer_digest_xor=True)),
                                     dep("EmbeddedManifest"), "structure", "base-a")
    v["patch-file-digest.csp"] = Vector(mixed(trailer_digest_xor=True), dep("FileDigest"), "structure", "base-a")
    v["profile-semantics.csp"] = Vector(
        mixed(target_layout=csmgen.Layout(profile_id=b"fastcdc.gear.chunkshift.v1.64k")),
        dep("ProfileSemantics"), "structure", "base-a")
    # Rule 26.
    v["payload-entry-limit.csp"] = Vector(mixed(), limit(), "structure", "base-a", max_payload_entries=2)
    # Rule 27.
    v["raw-with-dictionary.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], dictionary=[A[1]]), Entry(N[2])]), malformed(27),
        "structure", "base-a")
    v["zstd-five-dictionary-chunks.csp"] = Vector(
        mixed(entries=[Entry(N[0]), Entry(N[1], encoding=1, dictionary=A[:5]), Entry(N[2])]), malformed(27),
        "structure", "base-a")

    # Encoding 1: valid frames.
    z = 1
    v["zstd-no-dictionary.csp"] = Vector(
        Patch([TEXT], entries=[Entry(TEXT, z, stored=FRAME_TEXT)]), valid([TEXT], False), "apply")
    v["zstd-content-checksum.csp"] = Vector(
        Patch([TEXT], entries=[Entry(TEXT, z, stored=FRAME_TEXT_CHECKSUM)]), valid([TEXT], False), "apply")
    one = [A[0], EDITED_A1, A[2]]
    v["zstd-one-dictionary-chunk.csp"] = Vector(
        Patch(one, base="base-a", entries=[Entry(EDITED_A1, z, [A[1]], FRAME_EDITED_A1)]),
        valid(one, True), "apply", "base-a")
    v["zstd-four-dictionary-chunks.csp"] = Vector(
        Patch([SPLICED_A0_A3], base="base-a", entries=[Entry(SPLICED_A0_A3, z, A[:4], FRAME_SPLICED)]),
        valid([SPLICED_A0_A3], True), "apply", "base-a")
    v["zstd-rle-with-dictionary.csp"] = Vector(
        Patch([RLE_CHUNK], base="base-a", entries=[Entry(RLE_CHUNK, z, [A[1]], rle())]),
        valid([RLE_CHUNK], True), "apply", "base-a")
    v["zstd-window-descriptor.csp"] = Vector(
        Patch([RLE_CHUNK], entries=[Entry(RLE_CHUNK, z, stored=rle(single_segment=False,
                                                                  window_descriptor=10 << 3))]),
        valid([RLE_CHUNK], False), "apply")

    # Encoding 1: rule 28 (dictionary chunks).
    v["zstd-dictionary-not-in-base.csp"] = Vector(
        Patch([RLE_CHUNK], base="base-a", entries=[Entry(RLE_CHUNK, z, [N[5]], rle())]),
        dep("DictionaryChunk"), "apply", "base-a")
    v["zstd-dictionary-magic.csp"] = Vector(
        Patch([RLE_CHUNK], base="base-magic", entries=[Entry(RLE_CHUNK, z, [MAGIC_CHUNK], rle())]),
        dep("DictionaryChunk"), "apply", "base-magic")
    v["zstd-dictionary-chunk-corrupt.csp"] = Vector(
        Patch(one, base="base-a", entries=[Entry(EDITED_A1, z, [A[1]], FRAME_EDITED_A1)]),
        dep("DictionaryChunk"), "apply", "base-a-corrupt-dictionary")

    # Encoding 1: rules 29 and 30 (frame envelope).
    def frame_vector(stored: bytes, expect: dict) -> Vector:
        return Vector(Patch([RLE_CHUNK], entries=[Entry(RLE_CHUNK, z, stored=stored)]), expect, "apply")

    v["zstd-no-content-size.csp"] = frame_vector(
        rle(single_segment=False, content_size=None, window_descriptor=0), malformed(30))
    v["zstd-wrong-content-size.csp"] = frame_vector(rle(content_size=len(RLE_CHUNK) - 1), malformed(30))
    v["zstd-dictionary-id.csp"] = frame_vector(rle(dictionary_id=7), malformed(30))
    v["zstd-window-over-1mib.csp"] = frame_vector(
        rle(single_segment=False, window_descriptor=11 << 3), malformed(30))
    v["zstd-second-frame.csp"] = frame_vector(rle() + rle_frame(ord("A"), 1), malformed(29))
    v["zstd-leading-skippable-frame.csp"] = frame_vector(SKIPPABLE + rle(), malformed(29))
    v["zstd-trailing-skippable-frame.csp"] = frame_vector(rle() + SKIPPABLE, malformed(29))
    v["zstd-trailing-bytes.csp"] = frame_vector(rle() + b"\x00\x01", malformed(29))
    v["zstd-reserved-block-type.csp"] = frame_vector(rle(block_type=3), malformed(29))
    v["zstd-truncated-frame.csp"] = frame_vector(rle()[:-1], malformed(29))
    v["zstd-not-a-frame.csp"] = frame_vector(bytes(16), malformed(29))
    checksum_broken = FRAME_TEXT_CHECKSUM[:-1] + bytes([FRAME_TEXT_CHECKSUM[-1] ^ 1])
    v["zstd-bad-content-checksum.csp"] = Vector(
        Patch([TEXT], entries=[Entry(TEXT, z, stored=checksum_broken)]), malformed(30), "apply")
    v["zstd-decodes-other-bytes.csp"] = frame_vector(rle_frame(ord("B"), len(RLE_CHUNK)), dep("PayloadChunk"))

    # The BLAKE3 HashSuite: ChunkIds, dictionary ChunkIds, the embedded and base
    # manifests and the patch FileDigest are BLAKE3 digests.
    b3 = csmgen.Layout(hash_suite_id=BLAKE3)

    def blake3_mixed(**knobs) -> Patch:
        return Patch(MIXED, base="base-a-blake3", target_layout=knobs.pop("target_layout", b3), **knobs)

    v["valid-blake3-base-dependent.csp"] = Vector(blake3_mixed(), valid(MIXED, True), "apply", "base-a-blake3")
    v["valid-blake3-self-contained.csp"] = Vector(
        Patch(SELF, target_layout=b3), valid(SELF, False), "apply")
    v["valid-blake3-zstd-dictionary.csp"] = Vector(
        Patch(one, base="base-a-blake3", target_layout=b3,
              entries=[Entry(EDITED_A1, z, [A[1]], FRAME_EDITED_A1)]),
        valid(one, True), "apply", "base-a-blake3")
    v["blake3-tcsm-integrity.csp"] = Vector(
        blake3_mixed(target_layout=csmgen.Layout(hash_suite_id=BLAKE3, trailer_digest_xor=True)),
        dep("EmbeddedManifest"), "structure", "base-a-blake3")
    v["blake3-patch-file-digest.csp"] = Vector(
        blake3_mixed(trailer_digest_xor=True), dep("FileDigest"), "structure", "base-a-blake3")
    v["blake3-payload-hash.csp"] = Vector(
        blake3_mixed(entries=[Entry(N[0]), Entry(N[1], stored=bytes([N[1][0] ^ 1]) + N[1][1:]), Entry(N[2])]),
        dep("PayloadChunk"), "apply", "base-a-blake3")
    v["blake3-base-chunk-corrupt.csp"] = Vector(
        blake3_mixed(), dep("BaseChunk"), "apply", "base-a-blake3-corrupt-content")
    v["blake3-base-sha256.csp"] = Vector(blake3_mixed(), dep("BaseMismatch"), "apply", "base-a")
    # A consistent BLAKE3 manifest whose ChunkIds are SHA-256 digests: a reader
    # that hashed payloads with SHA-256 whatever the suite would accept it.
    sha256_ids = [(sha256(c), len(c)) for c in SELF]
    v["blake3-sha256-chunk-ids.csp"] = Vector(
        Patch(SELF, target_layout=b3, tcsm_bytes=csmgen.build(sha256_ids, False, b3)[0],
              entries=[Entry(c, chunk_id=sha256(c)) for c in (N[3], N[4], N[5])],
              first_target_index={1: 1, 2: 3}),
        dep("PayloadChunk"), "apply")

    v.update(truncations())
    return v


# --- Output and verification ------------------------------------------------------


def generate(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    metadata: dict[str, object] = {
        "format": "CSP v1",
        "generator": "tools/conformance/csp/generate.py",
        "hashSuite": HASH_SUITE,
        "profileId": PROFILE,
        "bases": {},
        "vectors": {},
    }
    used_bases = set()
    for name, vector in fixtures().items():
        data = vector.patch if isinstance(vector.patch, bytes) else vector.patch.build()
        (out / name).write_bytes(data)
        entry: dict[str, object] = {"stage": vector.stage, "expect": vector.expect}
        if vector.base is not None:
            entry["base"] = vector.base
            used_bases.add(vector.base)
        if vector.max_payload_entries is not None:
            entry["maxPayloadEntries"] = vector.max_payload_entries
        metadata["vectors"][name] = entry  # type: ignore[index]
    for key in sorted(used_bases):
        manifest_bytes, content_bytes = BASES[key].files()
        (out / f"{key}.csm").write_bytes(manifest_bytes)
        (out / f"{key}.bin").write_bytes(content_bytes)
        metadata["bases"][key] = {"manifest": f"{key}.csm", "content": f"{key}.bin"}  # type: ignore[index]
    # Bytes, not text: LF on every platform, so --verify also holds on Windows.
    (out / "vectors.json").write_bytes((json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def verify(directory: Path) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import decode  # noqa: PLC0415 - independent module, imported on demand

    problems: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        expected_dir = Path(scratch)
        generate(expected_dir)
        expected = {p.name for p in expected_dir.iterdir()}
        actual = {p.name for p in directory.iterdir() if p.suffix in (".csp", ".csm", ".bin", ".json")}
        problems += [f"{n}: missing from {directory}" for n in sorted(expected - actual)]
        problems += [f"{n}: not produced by the generator" for n in sorted(actual - expected)]
        problems += [f"{n}: differs from a fresh generation" for n in sorted(expected & actual)
                     if (expected_dir / n).read_bytes() != (directory / n).read_bytes()]

    metadata = json.loads((directory / "vectors.json").read_text(encoding="utf-8"))
    for name, entry in sorted(metadata["vectors"].items()):
        base = metadata["bases"].get(entry.get("base")) if entry.get("base") else None
        verdict = decode.decode(
            (directory / name).read_bytes(),
            (directory / base["manifest"]).read_bytes() if base else None,
            (directory / base["content"]).read_bytes() if base else None,
            entry.get("maxPayloadEntries", decode.DEFAULT_MAX_PAYLOAD_ENTRIES))
        expect = entry["expect"]
        for key, value in expect.items():
            if verdict.get(key) != value:
                problems.append(f"{name}: decoder {key} {verdict.get(key)!r} ({verdict.get('reason', '')}), "
                                f"expected {value!r}")
                break

    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"verified {len(metadata['vectors'])} vectors in {directory}: {'FAILED' if problems else 'ok'}")
    return 1 if problems else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path, help="Directory that receives the vectors and vectors.json.")
    mode.add_argument("--verify", type=Path, metavar="DIRECTORY",
                      help="Check a vector directory against a fresh generation and the independent decoder.")
    args = parser.parse_args()
    if args.verify is not None:
        sys.exit(verify(args.verify))
    generate(args.out)


if __name__ == "__main__":
    main()
