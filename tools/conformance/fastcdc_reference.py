#!/usr/bin/env python3
"""Independent scalar verifier for ChunkShift FastCDC v1 semantics (docs/architecture/FASTCDC-V1.md)."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import struct
import sys

EXPECTED_GEAR_SHA256 = "91a3061015ae351cd3701852712bcd6aa4a1ce26c8a231d3969432b00f028f88"
MASKS = {
    5: 0x0000000001804110,
    6: 0x0000000001803110,
    7: 0x0000000018035100,
    8: 0x0000001800035300,
    9: 0x0000019000353000,
    10: 0x0000590003530000,
    11: 0x0000D90003530000,
    12: 0x0000D90103530000,
    13: 0x0000D90303530000,
    14: 0x0000D90313530000,
    15: 0x0000D90F03530000,
    16: 0x0000D90303537000,
    17: 0x0000D90703537000,
    18: 0x0000D90707537000,
    19: 0x0000D91707537000,
    20: 0x0000D91747537000,
    21: 0x0000D91767537000,
    22: 0x0000D93767537000,
    23: 0x0000D93777537000,
    24: 0x0000D93777577000,
    25: 0x0000DB3777577000,
}
EXPECTED_RANDOM_1M_64K = [
    (0, 100081),
    (100081, 33106),
    (133187, 69903),
    (203090, 49442),
    (252532, 103705),
    (356237, 144977),
    (501214, 214287),
    (715501, 145480),
    (860981, 50981),
    (911962, 37677),
    (949639, 79457),
    (1029096, 19480),
]


def load_gear(root: pathlib.Path) -> list[int]:
    path = root / "docs" / "architecture" / "FASTCDC-GEAR-V1.txt"
    values: list[int] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\d{3}\s+0x([0-9a-fA-F]{16})", line)
        if match:
            values.append(int(match.group(1), 16))

    if len(values) != 256:
        raise ValueError(f"expected 256 GEAR values, got {len(values)}")

    serialized = b"".join(struct.pack("<Q", value) for value in values)
    actual = hashlib.sha256(serialized).hexdigest()
    if actual != EXPECTED_GEAR_SHA256:
        raise ValueError(f"GEAR digest mismatch: {actual}")

    return values


def xorshift_bytes(length: int, seed: int) -> bytes:
    state = seed & 0xFFFFFFFF
    output = bytearray(length)

    for index in range(length):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        output[index] = state & 0xFF

    return bytes(output)


def find_cut(source: memoryview, minimum: int, target: int, maximum: int, gear: list[int]) -> int:
    remaining = min(len(source), maximum)
    if remaining <= minimum:
        return remaining

    bits = target.bit_length() - 1
    strict = MASKS[bits + 1]
    relaxed = MASKS[bits - 1]
    center = min(target, remaining)
    rolling = 0

    for index in range(minimum, center):
        rolling = ((rolling << 1) + gear[source[index]]) & 0xFFFFFFFFFFFFFFFF
        if rolling & strict == 0:
            return index

    for index in range(center, remaining):
        rolling = ((rolling << 1) + gear[source[index]]) & 0xFFFFFFFFFFFFFFFF
        if rolling & relaxed == 0:
            return index

    return remaining


def chunk(source: bytes, minimum: int, target: int, maximum: int, gear: list[int]) -> list[tuple[int, int]]:
    view = memoryview(source)
    output: list[tuple[int, int]] = []
    offset = 0

    while offset < len(source):
        length = find_cut(view[offset:], minimum, target, maximum, gear)
        if length <= 0:
            raise ValueError("non-positive FastCDC cut")
        output.append((offset, length))
        offset += length

    return output


PRESETS = [
    (16 * 1024, 64 * 1024, 256 * 1024),
    (32 * 1024, 128 * 1024, 512 * 1024),
    (64 * 1024, 256 * 1024, 1024 * 1024),
]

# Pre-freeze fixtures over the calibration presets, cross-checked byte-for-byte
# against fastcdc-rs 5.0.0 (v2016 cut convention). Each entry is the FNV-1a 64
# digest of the ordered cut list, serialized as UInt64LE(offset) || UInt64LE(length)
# per chunk, for (fixture, minimum, target, maximum).
EXPECTED_FIXTURE_DIGESTS: dict[tuple[str, int], str] = {
    ("xorshift-1m", 65536): "259bdfaf8c068fd9",
    ("xorshift-1m-minus-1", 65536): "27978d2329d4f2ee",
    ("zero-1m", 65536): "d9d0423596bbe425",
    ("pattern7-1m", 65536): "d9d0423596bbe425",
    ("low-entropy-1m", 65536): "06efcccd64876221",
    ("alternating-1m", 65536): "916a6a99875bf022",
    ("odd-eof-transient", 65536): "5746b5ee65e8c544",
    ("edge-minimum-1", 65536): "b03cf1b9a107f86b",
    ("edge-minimum+0", 65536): "dcbf024dd5f41b25",
    ("edge-minimum+1", 65536): "bdc43b44cb04d104",
    ("edge-target-1", 65536): "5b9e0f252c1341ab",
    ("edge-target+0", 65536): "ab89bb86730d9e2c",
    ("edge-target+1", 65536): "45bbbce34401e07d",
    ("edge-maximum-1", 65536): "060282e0655707de",
    ("edge-maximum+0", 65536): "b21353787c45bca7",
    ("edge-maximum+1", 65536): "da0f4034bef199f4",
    ("xorshift-1m", 131072): "464e3d6d6c352f84",
    ("xorshift-1m-minus-1", 131072): "1db1daf2c9ad0169",
    ("zero-1m", 131072): "32693adb0e3f9add",
    ("pattern7-1m", 131072): "32693adb0e3f9add",
    ("low-entropy-1m", 131072): "aa16dedf79d7c399",
    ("alternating-1m", 131072): "adde3c7d1be636c9",
    ("odd-eof-transient", 131072): "527c042df6f9f7c6",
    ("edge-minimum-1", 131072): "04dbd44e15fcaf2b",
    ("edge-minimum+0", 131072): "dee25a907715f6e5",
    ("edge-minimum+1", 131072): "12631dd93ff987c4",
    ("edge-target-1", 131072): "7f07aaf23e217b72",
    ("edge-target+0", 131072): "414ce81f3ce2f0d7",
    ("edge-target+1", 131072): "2252211631f3a6b6",
    ("edge-maximum-1", 131072): "23efad2d3a67c40f",
    ("edge-maximum+0", 131072): "6fef63033c4d69fa",
    ("edge-maximum+1", 131072): "217e9ab2d20fff1d",
    ("xorshift-1m", 262144): "9fb1e2b02eb07bf5",
    ("xorshift-1m-minus-1", 262144): "1ac9cf7ca50b8510",
    ("zero-1m", 262144): "518662e8401bc7f5",
    ("pattern7-1m", 262144): "518662e8401bc7f5",
    ("low-entropy-1m", 262144): "760461a5dc0b7709",
    ("alternating-1m", 262144): "e9b3b311b10f70f2",
    ("odd-eof-transient", 262144): "527c042df6f9f7c6",
    ("edge-minimum-1", 262144): "5b9e0f252c1341ab",
    ("edge-minimum+0", 262144): "ab89bb86730d9e2c",
    ("edge-minimum+1", 262144): "45bbbce34401e07d",
    ("edge-target-1", 262144): "c5dae28c623def00",
    ("edge-target+0", 262144): "15c68eeda9384b81",
    ("edge-target+1", 262144): "f6cbc7e49e490160",
    ("edge-maximum-1", 262144): "911de9cb6670a0e6",
    ("edge-maximum+0", 262144): "f6c86c436bfdaab5",
    ("edge-maximum+1", 262144): "e2f2233039eccf80",
}


def fnv1a64(cuts: list[tuple[int, int]]) -> str:
    value = 0xCBF29CE484222325
    for offset, length in cuts:
        for byte in struct.pack("<QQ", offset, length):
            value ^= byte
            value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def fixtures(minimum: int, target: int, maximum: int) -> list[tuple[str, bytes]]:
    random_1m = xorshift_bytes(1024 * 1024, 0x12345678)
    pattern = random_1m[:7]
    alternating = bytearray(1024 * 1024)
    for block in range(0, len(alternating), 128 * 1024):
        alternating[block:block + 64 * 1024] = random_1m[block:block + 64 * 1024]
    output = [
        ("xorshift-1m", random_1m),
        ("xorshift-1m-minus-1", random_1m[:-1]),
        ("zero-1m", bytes(1024 * 1024)),
        ("pattern7-1m", bytes(pattern[i % 7] for i in range(1024 * 1024))),
        ("low-entropy-1m", bytes(b & 0x03 for b in random_1m)),
        ("alternating-1m", bytes(alternating)),
        ("odd-eof-transient", bytes(16 * 1024) + bytes([2, 255, 65])),
    ]
    random_edges = xorshift_bytes(maximum + 1, 0x9E3779B9)
    for name, size in (("minimum", minimum), ("target", target), ("maximum", maximum)):
        for delta in (-1, 0, 1):
            output.append((f"edge-{name}{delta:+d}", random_edges[: size + delta]))
    return output


def fixture_digests(gear: list[int]) -> dict[tuple[str, int], str]:
    digests: dict[tuple[str, int], str] = {}
    for minimum, target, maximum in PRESETS:
        for name, data in fixtures(minimum, target, maximum):
            digests[(name, target)] = fnv1a64(chunk(data, minimum, target, maximum, gear))
    return digests


def verify(root: pathlib.Path) -> None:
    gear = load_gear(root)
    source = xorshift_bytes(1024 * 1024, 0x12345678)
    actual = chunk(source, 16 * 1024, 64 * 1024, 256 * 1024, gear)

    if actual != EXPECTED_RANDOM_1M_64K:
        raise ValueError(f"golden vector mismatch:\nexpected={EXPECTED_RANDOM_1M_64K}\nactual={actual}")

    print(f"FastCDC independent vector OK: {len(actual)} chunks; gear={EXPECTED_GEAR_SHA256}")

    # The v2016 cut convention on an odd final window: the last
    # position is tested, so the chunk before EOF can end one byte early.
    odd = chunk(bytes(16 * 1024) + bytes([2, 255, 65]), 16 * 1024, 64 * 1024, 256 * 1024, gear)
    if odd != [(0, 16386), (16386, 1)]:
        raise ValueError(f"odd-EOF vector mismatch: {odd}")

    actual_digests = fixture_digests(gear)
    if actual_digests != EXPECTED_FIXTURE_DIGESTS:
        raise ValueError(f"fixture digest mismatch:\n{actual_digests}")

    print(f"FastCDC pre-freeze fixtures OK: {len(actual_digests)} (fixture, preset) digests")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--print-fixture-digests", action="store_true")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[2]

    if args.verify:
        verify(root)
        return 0

    gear = load_gear(root)

    if args.print_fixture_digests:
        for (name, target), digest in fixture_digests(gear).items():
            print(f'    ("{name}", {target}): "{digest}",')
        return 0

    source = xorshift_bytes(1024 * 1024, 0x12345678)
    print(chunk(source, 16 * 1024, 64 * 1024, 256 * 1024, gear))
    return 0


if __name__ == "__main__":
    sys.exit(main())
