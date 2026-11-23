#!/usr/bin/env python3
"""Forward-only CSP v1 apply: a conformance check of section 6.

Section 6 allows an applier to read the patch once, front to back, and decide
the verdict after its end. This tool checks that the v1 byte layout admits it: can an applier that reads the patch once, front to back, reach the
verdict of decode.py for every input, without buffering payload bytes?

The patch is read through ``ForwardSource``, which cannot seek and holds back
only the last 64 bytes (the TRAILER) so that it can tell where the sections
end. What the pass retains:

- PREAMBLE, the TCSM bytes and the section headers, CRCs and offsets;
- per PAYL entry its ChunkId, lengths, encoding and dictionary ChunkIds, never
  its stored bytes: those are decoded when they are read, in target order, and
  written to the output (standing in for the temporary file of section 6 step 8);
- the PIDX entries (24 bytes each, as a materializing reader holds them) and
  the running FileDigest state.

Repeated target chunks are replayed from the output, reused chunks read from
the random-access base. No verdict is reached before EOF: the checks of
decode.py run afterwards, in its order, over what was retained, and the result
of the lockstep reconstruction counts only when every earlier stage passed.
Nothing is published before that, which section 6 step 8 already requires.

This is test tooling, not a second applier: it reuses decode.py's constants,
exceptions and zstd checks and differs from it only in how the patch is read.

Usage:
  forward_apply.py --vectors DIRECTORY   every vector of vectors.json: the same
                                         verdict, rule, failures and output as decode.py;
  forward_apply.py --compare DIRECTORY   every fuzz case (verdicts-*.jsonl, as for
                                         decode.py --compare): the same verdict as decode.py.
"""

from __future__ import annotations

import importlib.util
import json
import random
import struct
import sys
from pathlib import Path

_DECODER_PATH = Path(__file__).resolve().parent / "decode.py"
_spec = importlib.util.spec_from_file_location("csp_fixtures_decode", _DECODER_PATH)
dec = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = dec
_spec.loader.exec_module(dec)

Malformed, Unsupported, Limit, Verification = dec.Malformed, dec.Unsupported, dec.Limit, dec.Verification
HEADER, TRAILER, CRC = dec.HEADER_LENGTH, dec.TRAILER_LENGTH, dec.CRC_LENGTH


class ForwardSource:
    """Sequential reads over a patch, in pieces of random size, never seeking.

    ``read`` returns only bytes that are followed by at least 64 more, so the
    TRAILER is never handed to the section walk; ``tail`` gives it after EOF.
    """

    def __init__(self, data: bytes, seed: int) -> None:
        self._data = data            # reached only through _pull, front to back
        self._next = 0
        self._random = random.Random(seed)
        self._window = bytearray()   # pulled, not yet returned
        self.position = 0            # logical bytes returned so far
        self.eof = False
        self.observers: list = []    # called with every returned piece

    def _pull(self) -> bool:
        if self._next >= len(self._data):
            self.eof = True
            return False
        size = self._random.choice((1, 7, 64, 4096, 65536))
        self._window += self._data[self._next:self._next + size]
        self._next += size
        return True

    def read(self, count: int) -> bytes:
        """Up to ``count`` logical bytes; fewer only at the logical end."""
        while len(self._window) < count + TRAILER and self._pull():
            pass
        take = max(0, min(count, len(self._window) - TRAILER))
        piece = bytes(self._window[:take])
        del self._window[:take]
        self.position += take
        for observer in self.observers:
            observer(piece)
        return piece

    def skip(self, count: int) -> int:
        skipped = 0
        while skipped < count:
            piece = self.read(min(65536, count - skipped))
            if not piece:
                break
            skipped += len(piece)
        return skipped

    def at_end(self) -> bool:
        while len(self._window) < TRAILER + 1 and self._pull():
            pass
        return len(self._window) <= TRAILER

    def drain(self) -> None:
        while self.skip(1 << 20):
            pass

    def tail(self) -> tuple[int, bytes]:
        """Physical length and the held-back bytes (the TRAILER), after EOF."""
        self.drain()
        return self.position + len(self._window), bytes(self._window)


class EntryMeta:
    """What a forward pass keeps of one PAYL entry."""

    def __init__(self, record_offset, chunk_id, stored_length, encoding, dictionary) -> None:
        self.record_offset = record_offset
        self.chunk_id = chunk_id
        self.stored_length = stored_length
        self.encoding = encoding
        self.dictionary = dictionary
        self.first_target_index = -1


class Pass:
    def __init__(self, patch: bytes, base_manifest: bytes | None, base_content: bytes | None,
                 max_entries: int, seed: int) -> None:
        self.source = ForwardSource(patch, seed)
        self.base_manifest = base_manifest
        self.base_content = base_content
        self.max_entries = max_entries
        self.walk_failure: Exception | None = None
        self.preamble = b""
        self.tcsm: tuple[int, bytes] | None = None       # section offset, payload
        self.base_offset = 0
        self.expected_base: bytes | None = None
        self.payl_offsets: list[int] = []
        self.entries: list[EntryMeta] = []
        self.pidx_offset = 0
        self.foot: tuple[int, bytes] | None = None       # section offset, payload
        self.foot_reached = False
        self.digest = None
        self.prefix = bytearray()                        # bytes before the suite is known
        # Lockstep reconstruction.
        self.records: list[tuple[bytes, int]] | None = None
        self.first_index: dict[bytes, int] = {}
        self.new_hash = None
        self.base_locator: dict[bytes, tuple[int, int]] = {}
        self.output = bytearray()
        self.resolved: dict[bytes, tuple[int, int]] = {}
        self.payload_ids: set[bytes] = set()
        self.next_record = 0
        self.lockstep_failure: Exception | None = None
        self.lockstep = False

    # --- FileDigest over the logical bytes -------------------------------------

    def _observe(self, piece: bytes) -> None:
        if self.digest is None:
            self.prefix += piece
        else:
            self.digest.update(piece)

    # --- Section walk: decode.py's _parse_structure, in stream order ---------------

    def walk(self) -> None:
        source = self.source
        source.observers.append(self._observe)
        self.preamble = source.read(dec.PREAMBLE_LENGTH)
        if len(self.preamble) < dec.PREAMBLE_LENGTH:
            return                     # decided after EOF (rules 7, 5)
        magic, major, preamble_size, required, _optional, reserved = struct.unpack(
            "<4sHHQQQ", self.preamble)
        if (magic != dec.PREAMBLE_MAGIC or major != dec.SUPPORTED_MAJOR
                or preamble_size != dec.PREAMBLE_LENGTH or reserved != 0 or required != 0):
            return                     # PREAMBLE rules are evaluated after EOF

        phase = "start"
        while True:
            offset = source.position
            header = source.read(HEADER)
            if len(header) < HEADER:
                raise Malformed(5, "FOOT is missing before the TRAILER")
            kind, flags, payload_length = struct.unpack("<4sIQ", header)
            if flags & ~dec.FLAG_REQUIRED:
                raise Malformed(3, "reserved section flag bits are set")
            required = bool(flags & dec.FLAG_REQUIRED)

            # Checks that need only the header, in decode.py's order; they are
            # raised after the payload is known to fit (rule 7 comes first).
            pending: Exception | None = None
            if phase == "start" and kind != b"TCSM":
                pending = Malformed(5, "TCSM must be the first section")
            elif kind == b"TCSM":
                if phase != "start":
                    pending = Malformed(5, "duplicate TCSM")
            elif kind == b"BASE":
                if required:
                    pending = Malformed(4, "BASE is optional and must not be marked REQUIRED")
                elif phase != "tcsm":
                    pending = Malformed(13, "BASE is duplicated or not directly after TCSM")
                elif payload_length != dec.BASE_LENGTH:
                    pending = Malformed(13, "BASE payload must be 32 bytes")
            elif kind == b"PAYL":
                if phase not in ("tcsm", "base", "payl"):
                    pending = Malformed(5, "PAYL outside the payload phase")
            elif kind == b"PIDX":
                if phase == "pidx":
                    pending = Malformed(5, "duplicate PIDX")
            elif kind == b"FOOT":
                if phase != "pidx":
                    pending = Malformed(5, "FOOT without a preceding PIDX")
                elif payload_length != dec.FOOT_LENGTH:
                    pending = Malformed(15, "FOOT payload must be 56 bytes")
            elif required:
                pending = Malformed(4, f"{dec._fourcc(kind)} is optional or unknown and marked REQUIRED")
            elif phase == "pidx":
                pending = Malformed(5, f"{dec._fourcc(kind)} after PIDX")

            if pending is not None or kind not in (b"TCSM", b"BASE", b"PAYL", b"PIDX", b"FOOT"):
                if source.skip(payload_length) < payload_length:
                    raise Malformed(7, f"{dec._fourcc(kind)} PayloadLength exceeds the remaining bytes")
                if pending is not None:
                    raise pending
                phase = "optional"
                continue

            if kind == b"PAYL":
                self._payl(offset, header, payload_length)
                self.payl_offsets.append(offset)
                phase = "payl"
                continue

            # TCSM, BASE, PIDX and FOOT are retained whole: the embedded CSM is
            # bounded by the CSM reader's limits, PIDX by 24 bytes per entry.
            payload = source.read(payload_length)
            if len(payload) < payload_length:
                raise Malformed(7, f"{dec._fourcc(kind)} PayloadLength exceeds the remaining bytes")
            if kind == b"TCSM":
                self.tcsm = (offset, payload)
                self._start_lockstep(payload)
                phase = "tcsm"
            elif kind == b"BASE":
                self.base_offset = offset
                self.expected_base = payload
                self._load_base()
                phase = "base"
            elif kind == b"PIDX":
                self._pidx(offset, header, payload)
                self.pidx_offset = offset
                phase = "pidx"
            else:
                if not source.at_end():
                    raise Malformed(5, "bytes between FOOT and the TRAILER")
                self.foot = (offset, payload)
                self.foot_reached = True
                return

    def _payl(self, offset: int, header: bytes, payload_length: int) -> None:
        """Stream one PAYL section: entries are decoded as they are read."""
        source = self.source
        if payload_length < dec.PAYL_PREFIX + CRC:
            if source.skip(payload_length) < payload_length:
                raise Malformed(7, "PAYL PayloadLength exceeds the remaining bytes")
            raise Malformed(8, "PAYL payload shorter than its prefix and CRC")

        crc_state = [header]
        body_length = payload_length - CRC
        consumed = 0
        finding: Exception | None = None      # first field failure, raised after rule 7 and the CRC

        def take(count: int) -> bytes:
            nonlocal consumed
            piece = source.read(count)
            consumed += len(piece)
            crc_state.append(piece)
            if len(piece) < count:
                raise Malformed(7, "PAYL PayloadLength exceeds the remaining bytes")
            return piece

        count, reserved, first_ordinal = struct.unpack("<IIQ", take(dec.PAYL_PREFIX))
        if count == 0 or count > dec.PAYL_MAX_ENTRIES:
            finding = Malformed(8, "PAYL EntryCount must be 1..4096")
        elif reserved != 0:
            finding = Malformed(3, "PAYL reserved field must be zero")
        elif first_ordinal != len(self.entries):
            finding = Malformed(8, "PAYL FirstEntryOrdinal does not match preceding entries")

        index = 0
        while finding is None and index < count:
            if len(self.entries) >= self.max_entries:
                finding = Limit("payload entry count exceeds the configured maximum")
                break
            record_offset = offset + HEADER + consumed
            if body_length - consumed < dec.PAYL_ENTRY_HEADER:
                finding = Malformed(8, "PAYL entry header overruns the section")
                break
            entry_header = take(dec.PAYL_ENTRY_HEADER)
            chunk_id = entry_header[:dec.ID_BYTES]
            stored_length, encoding, dictionary_count, entry_reserved = struct.unpack_from(
                "<IBBH", entry_header, dec.ID_BYTES)
            if entry_reserved != 0:
                finding = Malformed(3, "PAYL entry reserved field must be zero")
            elif stored_length == 0:
                finding = Malformed(8, "PAYL StoredLength must be > 0")
            elif encoding == dec.ENCODING_RAW and dictionary_count != 0:
                finding = Malformed(27, "raw entry declares dictionary chunks")
            elif encoding == dec.ENCODING_ZSTD and dictionary_count > dec.MAX_DICTIONARY_CHUNKS:
                finding = Malformed(27, "encoding-1 entry declares more than 4 dictionary chunks")
            elif body_length - consumed < dictionary_count * dec.ID_BYTES + stored_length:
                finding = Malformed(8, "PAYL entry overruns the section")
            if finding is not None:
                break
            dictionary_bytes = take(dictionary_count * dec.ID_BYTES)
            dictionary = [dictionary_bytes[i * dec.ID_BYTES:(i + 1) * dec.ID_BYTES]
                          for i in range(dictionary_count)]
            if encoding not in (dec.ENCODING_RAW, dec.ENCODING_ZSTD):
                finding = Unsupported(16, f"payload encoding {encoding} is not implemented")
                break
            meta = EntryMeta(record_offset, chunk_id, stored_length, encoding, dictionary)
            self.entries.append(meta)
            self._lockstep_entry(meta, lambda: take(stored_length))
            index += 1

        if finding is None and consumed != body_length:
            finding = Malformed(8, "PAYL PayloadLength does not match its entries")

        # Rule 7 first: the rest of the section must exist.
        remaining = body_length - consumed
        skipped = 0
        while skipped < remaining:
            piece = source.read(min(65536, remaining - skipped))
            if not piece:
                break
            crc_state.append(piece)
            skipped += len(piece)
        stored_crc = source.read(CRC)
        if skipped < remaining or len(stored_crc) < CRC:
            raise Malformed(7, "PAYL PayloadLength exceeds the remaining bytes")
        if dec.crc32c(b"".join(crc_state)) != struct.unpack("<I", stored_crc)[0]:
            raise Malformed(9, "PAYL CRC-32C mismatch")
        if finding is not None:
            raise finding

    def _pidx(self, offset: int, header: bytes, payload: bytes) -> None:
        data = header + payload
        payload_length = len(payload)
        if payload_length < dec.PIDX_PREFIX + CRC:
            raise Malformed(10, "PIDX payload shorter than its prefix and CRC")
        stored = struct.unpack_from("<I", data, len(data) - CRC)[0]
        if dec.crc32c(data[:-CRC]) != stored:
            raise Malformed(9, "PIDX CRC-32C mismatch")
        version, count = struct.unpack_from("<II", data, HEADER)
        if version != dec.PIDX_VERSION:
            raise Malformed(10, f"unknown PIDX IndexVersion {version}")
        if payload_length != dec.PIDX_PREFIX + count * dec.PIDX_ENTRY + CRC:
            raise Malformed(10, "PIDX PayloadLength does not match EntryCount")
        if count > self.max_entries:
            raise Limit("PIDX entry count exceeds the configured maximum")
        if count != len(self.entries):
            raise Malformed(11, "PIDX and PAYL entry counts differ")
        previous = -1
        for index, entry in enumerate(self.entries):
            first_target_index, payload_offset, stored_length, encoding, dictionary_count, reserved = (
                struct.unpack_from("<QQIBBH", data, HEADER + dec.PIDX_PREFIX + index * dec.PIDX_ENTRY))
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

    # --- Lockstep reconstruction (speculative until the verdict) -------------------

    def _start_lockstep(self, tcsm: bytes) -> None:
        records: list[tuple[bytes, int]] = []
        verdict = dec.csm.decode(tcsm, records)
        suite = verdict.get("hashSuite")
        if verdict["outcome"] in ("reject", "unsupported") or suite not in dec.csm.HASH_SUITES:
            return                     # stage B decides after EOF
        self.new_hash = dec.csm.HASH_SUITES[suite]
        self.digest = self.new_hash()
        self.digest.update(bytes(self.prefix))
        self.records = records
        for index, (chunk_id, _) in enumerate(records):
            self.first_index.setdefault(chunk_id, index)
        self.lockstep = True

    def _load_base(self) -> None:
        if not self.lockstep or self.base_manifest is None or self.base_content is None:
            return
        records: list[tuple[bytes, int]] = []
        verdict = dec.csm.decode(self.base_manifest, records)
        if verdict["outcome"] not in ("valid", "integrity"):
            return                     # stage E decides after EOF
        offset = 0
        for chunk_id, length in records:
            self.base_locator.setdefault(chunk_id, (offset, length))
            offset += length

    def _base_chunk(self, chunk_id: bytes, expected_length: int | None, failure: str) -> bytes:
        located = self.base_locator.get(chunk_id)
        if located is None:
            raise Verification({failure}, "chunk is not in the base manifest")
        offset, length = located
        data = self.base_content[offset:offset + length]
        if len(data) != length or self.new_hash(data).digest() != chunk_id or (
                expected_length is not None and length != expected_length):
            raise Verification({failure}, "base chunk does not match its ChunkId and Length")
        return data

    def _emit(self, chunk_id: bytes, data: bytes) -> None:
        self.resolved.setdefault(chunk_id, (len(self.output), len(data)))
        self.output += data

    def _resolve_without_entry(self, until: int) -> None:
        """Target records before ``until`` that no pending entry supplies."""
        while self.lockstep_failure is None and self.next_record < until:
            chunk_id, length = self.records[self.next_record]
            try:
                replay = self.resolved.get(chunk_id)
                if replay is not None:
                    data = bytes(self.output[replay[0]:replay[0] + replay[1]])
                elif self.base_locator:
                    if chunk_id not in self.base_locator:
                        raise Verification({"MissingPayload"}, "target chunk neither in base nor payload")
                    data = self._base_chunk(chunk_id, length, "BaseChunk")
                else:
                    raise Verification({"MissingPayload"}, "target chunk has no payload and no base")
                self._emit(chunk_id, data)
            except (Malformed, Verification) as error:
                self.lockstep_failure = error
            self.next_record += 1

    def _lockstep_entry(self, meta: EntryMeta, read_stored) -> None:
        index = self.first_index.get(meta.chunk_id) if self.lockstep else None
        if (self.lockstep_failure is not None or index is None or meta.chunk_id in self.payload_ids
                or index < self.next_record or meta.stored_length > self.records[index][1]):
            # Not a well-placed, first entry of a target chunk: a later stage
            # (duplicate, not in target, order, length) decides, so the stored
            # bytes are only consumed.
            read_stored()
            return
        self.payload_ids.add(meta.chunk_id)
        self._resolve_without_entry(index)
        stored = read_stored()           # at most the target chunk Length
        if self.lockstep_failure is not None:
            return
        length = self.records[index][1]
        try:
            if meta.encoding == dec.ENCODING_RAW:
                data = stored
            else:
                dictionary = b"".join(self._base_chunk(d, None, "DictionaryChunk") for d in meta.dictionary)
                if len(dictionary) > dec.MAX_DICTIONARY_BYTES:
                    raise Verification({"DictionaryChunk"}, "dictionary exceeds 1 MiB")
                if dictionary[:4] == dec.ZSTD_DICTIONARY_MAGIC:
                    raise Verification({"DictionaryChunk"}, "dictionary starts with the zstd magic")
                data = dec._decode_zstd(stored, length, dictionary)
            if len(data) != length or self.new_hash(data).digest() != meta.chunk_id:
                raise Verification({"PayloadChunk"}, "payload bytes do not match their ChunkId")
            self._emit(meta.chunk_id, data)
        except (Malformed, Verification) as error:
            self.lockstep_failure = error
        self.next_record = index + 1

    # --- Verdict after EOF: decode.py's order over what the pass retained ---------

    def verdict(self) -> dict[str, object]:
        try:
            try:
                self.walk()
            except (Malformed, Unsupported, Limit) as error:
                self.walk_failure = error
            length, trailer = self.source.tail()
            return self._decide(length, trailer)
        except Malformed as error:
            return {"verdict": "malformed", "rule": error.rule, "reason": str(error)}
        except Unsupported as error:
            return {"verdict": "unsupported", "rule": error.rule, "reason": str(error)}
        except Limit as error:
            return {"verdict": "limit", "rule": error.rule, "reason": str(error)}
        except Verification as error:
            return {"verdict": "verification", "failures": sorted(error.failures), "reason": str(error)}

    def _decide(self, length: int, trailer: bytes) -> dict[str, object]:
        # A: TRAILER and PREAMBLE, then the section walk.
        if length < dec.PREAMBLE_LENGTH + TRAILER:
            raise Malformed(7, "shorter than PREAMBLE plus TRAILER")
        magic, major, trailer_size, foot_offset, physical_length, stored_digest, reserved = struct.unpack(
            "<4sHHQQ32sQ", trailer)
        if magic != dec.TRAILER_MAGIC or trailer_size != TRAILER:
            raise Malformed(5, "no CSP TRAILER at physical EOF")
        if major != dec.SUPPORTED_MAJOR:
            raise Malformed(5, f"TRAILER FormatMajor {major}")
        if reserved != 0:
            raise Malformed(3, "TRAILER reserved field must be zero")
        if physical_length != length:
            raise Malformed(6, "PhysicalLength does not equal the artifact length")
        magic, major, preamble_size, required, _optional, reserved = struct.unpack("<4sHHQQQ", self.preamble)
        if magic != dec.PREAMBLE_MAGIC or major != dec.SUPPORTED_MAJOR or preamble_size != dec.PREAMBLE_LENGTH:
            raise Malformed(1, "PREAMBLE magic, FormatMajor or PreambleSize is wrong")
        if reserved != 0:
            raise Malformed(1, "PREAMBLE reserved field must be zero")
        if required != 0:
            raise Unsupported(2, "unknown required physical feature")
        if self.walk_failure is not None:
            raise self.walk_failure
        foot_at, foot = self.foot
        tcsm, base, pidx, first_payl, payl_count, entry_count, reserved = struct.unpack("<QQQQQQQ", foot)
        if reserved != 0:
            raise Malformed(3, "FOOT reserved field must be zero")
        if (tcsm, base, pidx, first_payl, payl_count, entry_count) != (
                self.tcsm[0], self.base_offset, self.pidx_offset,
                self.payl_offsets[0] if self.payl_offsets else 0, len(self.payl_offsets), len(self.entries)):
            raise Malformed(15, "FOOT fields disagree with the observed sections")
        if foot_offset != foot_at:
            raise Malformed(15, "TRAILER FootSectionOffset does not locate FOOT")

        # B, C: embedded CSM, then the FileDigest the pass computed.
        tcsm_bytes = self.tcsm[1]
        target, records = dec._read_manifest(tcsm_bytes, "embedded")
        if target["physicalLength"] != len(tcsm_bytes):
            raise Malformed(14, "embedded CSM PhysicalLength differs from TCSM PayloadLength")
        failures = dec._manifest_failures(target)
        if self.digest.digest() != stored_digest:
            failures.add("FileDigest")
        if failures:
            raise Verification(failures, "patch or embedded manifest integrity")

        # D: payload entries against the target manifest (retained metadata).
        first_index = self.first_index
        seen: set[bytes] = set()
        unique: list[EntryMeta] = []
        for entry in self.entries:
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
        payload = {entry.chunk_id for entry in unique}
        for entry in unique:
            target_length = records[entry.first_target_index][1]
            if entry.stored_length > target_length or (
                    entry.encoding == dec.ENCODING_RAW and entry.stored_length != target_length):
                failures.add("PayloadLength")
        if failures:
            raise Verification(failures, "payload entries disagree with the target manifest")

        # E: base binding, as decode.py decides it.
        depends_on_base = any(chunk_id not in payload for chunk_id, _ in records) or any(
            entry.dictionary for entry in self.entries)
        if depends_on_base and self.expected_base is None:
            raise Malformed(13, "the patch depends on a base but has no BASE section")
        if self.expected_base is not None and (depends_on_base or self.base_manifest is not None):
            if self.base_manifest is None or self.base_content is None:
                raise Verification({"BaseMismatch"}, "the patch requires a base and none was supplied")
            if dec._declared_hash_suite(self.base_manifest) not in (None, target["hashSuite"]):
                raise Verification({"BaseMismatch"}, "base and target HashSuites differ")
            base, _ = dec._read_manifest(self.base_manifest, "base")
            if set(base["failures"]) - {"ProfileSemantics"}:
                raise Verification({"BaseManifest"}, "the base manifest fails verification")
            if bytes.fromhex(base["manifestId"]) != self.expected_base:
                raise Verification({"BaseMismatch"}, "base ManifestId differs from BASE")

        # F: the lockstep reconstruction, finished over the records after the last entry.
        self._resolve_without_entry(len(records))
        if self.lockstep_failure is not None:
            raise self.lockstep_failure

        # G: total length.
        if len(self.output) != target["contentLength"]:
            raise Verification({"ContentLength"}, "reconstructed length differs from the manifest")
        return {"verdict": "valid", "outputSha256": dec.hashlib.sha256(self.output).hexdigest(),
                "outputLength": len(self.output), "targetManifestId": target["manifestId"],
                "dependsOnBase": depends_on_base}


def apply(patch: bytes, base_manifest: bytes | None = None, base_content: bytes | None = None,
          max_payload_entries: int = dec.DEFAULT_MAX_PAYLOAD_ENTRIES, seed: int = 0) -> dict[str, object]:
    return Pass(patch, base_manifest, base_content, max_payload_entries, seed).verdict()


def _same(left: dict, right: dict, keys: tuple[str, ...]) -> bool:
    return all(left.get(key) == right.get(key) for key in keys)


def check_vectors(directory: Path) -> int:
    metadata = json.loads((directory / "vectors.json").read_text(encoding="utf-8"))
    keys = ("verdict", "rule", "failures", "outputSha256", "outputLength", "dependsOnBase")
    problems = []
    for name, entry in sorted(metadata["vectors"].items()):
        base = metadata["bases"].get(entry.get("base")) if entry.get("base") else None
        inputs = ((directory / name).read_bytes(),
                  (directory / base["manifest"]).read_bytes() if base else None,
                  (directory / base["content"]).read_bytes() if base else None,
                  entry.get("maxPayloadEntries", dec.DEFAULT_MAX_PAYLOAD_ENTRIES))
        expected = dec.decode(*inputs)
        for seed in range(3):
            actual = apply(*inputs, seed=seed)
            if not _same(actual, expected, keys):
                problems.append(f"{name} (seed {seed}): forward {actual}, decode.py {expected}")
                break
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"forward-only apply: {len(metadata['vectors'])} vectors, {len(problems)} differ from decode.py")
    return 1 if problems else 0


def compare(directory: Path) -> int:
    checked, mismatches = 0, []
    for listing in sorted(directory.glob("verdicts-*.jsonl")):
        for line in listing.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            inputs = ((directory / case["file"]).read_bytes(),
                      (directory / case["baseManifest"]).read_bytes() if case.get("baseManifest") else None,
                      (directory / case["base"]).read_bytes() if case.get("base") else None)
            expected = dec.verdict_text(dec.decode(*inputs))
            actual = dec.verdict_text(apply(*inputs, seed=checked))
            checked += 1
            if actual != expected:
                mismatches.append(f"{case['file']}: forward {actual!r}, decode.py {expected!r}")
    for mismatch in mismatches[:50]:
        print(mismatch, file=sys.stderr)
    print(f"forward-only apply: {checked} fuzz cases, {len(mismatches)} differ from decode.py")
    return 1 if mismatches or checked == 0 else 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--vectors":
        return check_vectors(Path(argv[1]))
    if len(argv) == 2 and argv[0] == "--compare":
        return compare(Path(argv[1]))
    print(__doc__[__doc__.index("Usage:"):].rstrip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
