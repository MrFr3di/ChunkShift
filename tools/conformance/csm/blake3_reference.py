#!/usr/bin/env python3
"""BLAKE3 in pure Python, for the independent CSM and CSP decoders.

The ``chunkshift.blake3-256.v1`` HashSuite is the 32-byte default-mode BLAKE3
hash. Python's standard library has no BLAKE3, so the independent decoders
use this module instead of a third-party package. It is written from the
BLAKE3 specification (https://github.com/BLAKE3-team/BLAKE3-specs) and shares
no code with the .NET ``Blake3`` package that production uses.

Only the unkeyed hash with a 32-byte output is implemented: ChunkShift uses no
keyed, derive-key or extended-output mode.

Run it directly to check it against the official BLAKE3 test vectors:

  blake3_reference.py
"""

from __future__ import annotations

import struct
import sys

OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _schedules() -> tuple[tuple[int, ...], ...]:
    # The message word order of each of the seven rounds: round r reads the
    # block's words through the permutation applied r times.
    order = tuple(range(16))
    rounds = []
    for _ in range(7):
        rounds.append(order)
        order = tuple(order[index] for index in MSG_PERMUTATION)
    return tuple(rounds)


_SCHEDULES = _schedules()
_M32 = 0xFFFFFFFF


def _compress(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    """The BLAKE3 compression function; returns all 16 output words."""

    v0, v1, v2, v3, v4, v5, v6, v7 = chaining_value
    v8, v9, v10, v11 = IV[0], IV[1], IV[2], IV[3]
    v12 = counter & _M32
    v13 = (counter >> 32) & _M32
    v14 = block_len
    v15 = flags
    m = block_words

    for s in _SCHEDULES:
        # Columns.
        v0 = (v0 + v4 + m[s[0]]) & _M32; v12 ^= v0; v12 = ((v12 >> 16) | (v12 << 16)) & _M32
        v8 = (v8 + v12) & _M32; v4 ^= v8; v4 = ((v4 >> 12) | (v4 << 20)) & _M32
        v0 = (v0 + v4 + m[s[1]]) & _M32; v12 ^= v0; v12 = ((v12 >> 8) | (v12 << 24)) & _M32
        v8 = (v8 + v12) & _M32; v4 ^= v8; v4 = ((v4 >> 7) | (v4 << 25)) & _M32

        v1 = (v1 + v5 + m[s[2]]) & _M32; v13 ^= v1; v13 = ((v13 >> 16) | (v13 << 16)) & _M32
        v9 = (v9 + v13) & _M32; v5 ^= v9; v5 = ((v5 >> 12) | (v5 << 20)) & _M32
        v1 = (v1 + v5 + m[s[3]]) & _M32; v13 ^= v1; v13 = ((v13 >> 8) | (v13 << 24)) & _M32
        v9 = (v9 + v13) & _M32; v5 ^= v9; v5 = ((v5 >> 7) | (v5 << 25)) & _M32

        v2 = (v2 + v6 + m[s[4]]) & _M32; v14 ^= v2; v14 = ((v14 >> 16) | (v14 << 16)) & _M32
        v10 = (v10 + v14) & _M32; v6 ^= v10; v6 = ((v6 >> 12) | (v6 << 20)) & _M32
        v2 = (v2 + v6 + m[s[5]]) & _M32; v14 ^= v2; v14 = ((v14 >> 8) | (v14 << 24)) & _M32
        v10 = (v10 + v14) & _M32; v6 ^= v10; v6 = ((v6 >> 7) | (v6 << 25)) & _M32

        v3 = (v3 + v7 + m[s[6]]) & _M32; v15 ^= v3; v15 = ((v15 >> 16) | (v15 << 16)) & _M32
        v11 = (v11 + v15) & _M32; v7 ^= v11; v7 = ((v7 >> 12) | (v7 << 20)) & _M32
        v3 = (v3 + v7 + m[s[7]]) & _M32; v15 ^= v3; v15 = ((v15 >> 8) | (v15 << 24)) & _M32
        v11 = (v11 + v15) & _M32; v7 ^= v11; v7 = ((v7 >> 7) | (v7 << 25)) & _M32

        # Diagonals.
        v0 = (v0 + v5 + m[s[8]]) & _M32; v15 ^= v0; v15 = ((v15 >> 16) | (v15 << 16)) & _M32
        v10 = (v10 + v15) & _M32; v5 ^= v10; v5 = ((v5 >> 12) | (v5 << 20)) & _M32
        v0 = (v0 + v5 + m[s[9]]) & _M32; v15 ^= v0; v15 = ((v15 >> 8) | (v15 << 24)) & _M32
        v10 = (v10 + v15) & _M32; v5 ^= v10; v5 = ((v5 >> 7) | (v5 << 25)) & _M32

        v1 = (v1 + v6 + m[s[10]]) & _M32; v12 ^= v1; v12 = ((v12 >> 16) | (v12 << 16)) & _M32
        v11 = (v11 + v12) & _M32; v6 ^= v11; v6 = ((v6 >> 12) | (v6 << 20)) & _M32
        v1 = (v1 + v6 + m[s[11]]) & _M32; v12 ^= v1; v12 = ((v12 >> 8) | (v12 << 24)) & _M32
        v11 = (v11 + v12) & _M32; v6 ^= v11; v6 = ((v6 >> 7) | (v6 << 25)) & _M32

        v2 = (v2 + v7 + m[s[12]]) & _M32; v13 ^= v2; v13 = ((v13 >> 16) | (v13 << 16)) & _M32
        v8 = (v8 + v13) & _M32; v7 ^= v8; v7 = ((v7 >> 12) | (v7 << 20)) & _M32
        v2 = (v2 + v7 + m[s[13]]) & _M32; v13 ^= v2; v13 = ((v13 >> 8) | (v13 << 24)) & _M32
        v8 = (v8 + v13) & _M32; v7 ^= v8; v7 = ((v7 >> 7) | (v7 << 25)) & _M32

        v3 = (v3 + v4 + m[s[14]]) & _M32; v14 ^= v3; v14 = ((v14 >> 16) | (v14 << 16)) & _M32
        v9 = (v9 + v14) & _M32; v4 ^= v9; v4 = ((v4 >> 12) | (v4 << 20)) & _M32
        v3 = (v3 + v4 + m[s[15]]) & _M32; v14 ^= v3; v14 = ((v14 >> 8) | (v14 << 24)) & _M32
        v9 = (v9 + v14) & _M32; v4 ^= v9; v4 = ((v4 >> 7) | (v4 << 25)) & _M32

    h = chaining_value
    return [
        v0 ^ v8, v1 ^ v9, v2 ^ v10, v3 ^ v11,
        v4 ^ v12, v5 ^ v13, v6 ^ v14, v7 ^ v15,
        v8 ^ h[0], v9 ^ h[1], v10 ^ h[2], v11 ^ h[3],
        v12 ^ h[4], v13 ^ h[5], v14 ^ h[6], v15 ^ h[7],
    ]


_BLOCK_WORDS = struct.Struct("<16I")


def _words(block: bytes) -> tuple[int, ...]:
    if len(block) < BLOCK_LEN:
        block = block + bytes(BLOCK_LEN - len(block))
    return _BLOCK_WORDS.unpack(block)


class _Output:
    """The inputs of the last compression of a node, before its flags are final."""

    __slots__ = ("chaining_value", "block_words", "counter", "block_len", "flags")

    def __init__(self, chaining_value, block_words, counter, block_len, flags):
        self.chaining_value = chaining_value
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value_of_node(self) -> tuple[int, ...]:
        return tuple(_compress(
            self.chaining_value, self.block_words, self.counter, self.block_len, self.flags)[:8])

    def root_digest(self) -> bytes:
        # A 32-byte output is the first eight words of output block 0.
        words = _compress(self.chaining_value, self.block_words, 0, self.block_len, self.flags | ROOT)
        return struct.pack("<8I", *words[:8])


def _parent_output(left: tuple[int, ...], right: tuple[int, ...]) -> _Output:
    return _Output(IV, tuple(left) + tuple(right), 0, BLOCK_LEN, PARENT)


class blake3:
    """Incremental BLAKE3 hash with the hashlib ``update``/``digest`` interface."""

    digest_size = OUT_LEN
    block_size = BLOCK_LEN
    name = "blake3"

    def __init__(self, data: bytes = b"") -> None:
        self._chunk_counter = 0
        self._chunk_cv: tuple[int, ...] = IV
        self._chunk_blocks = 0          # full blocks already compressed in this chunk
        self._buffer = bytearray()      # at most one block; never compressed early
        self._stack: list[tuple[int, ...]] = []
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        view = memoryview(data)
        while len(view):
            # The last block of a chunk carries CHUNK_END, so a full buffer is
            # compressed only once more input shows it is not the last one.
            if len(self._buffer) == BLOCK_LEN:
                if self._chunk_blocks == CHUNK_LEN // BLOCK_LEN - 1:
                    self._finish_chunk()
                else:
                    self._compress_buffer()
                continue
            take = min(BLOCK_LEN - len(self._buffer), len(view))
            self._buffer += view[:take]
            view = view[take:]

    def _compress_buffer(self) -> None:
        flags = CHUNK_START if self._chunk_blocks == 0 else 0
        self._chunk_cv = tuple(_compress(
            self._chunk_cv, _BLOCK_WORDS.unpack(self._buffer), self._chunk_counter,
            BLOCK_LEN, flags)[:8])
        self._chunk_blocks += 1
        self._buffer.clear()

    def _chunk_output(self) -> _Output:
        flags = CHUNK_END | (CHUNK_START if self._chunk_blocks == 0 else 0)
        return _Output(
            self._chunk_cv, _words(bytes(self._buffer)), self._chunk_counter,
            len(self._buffer), flags)

    def _finish_chunk(self) -> None:
        cv = self._chunk_output().chaining_value_of_node()
        # Merge completed subtrees: one merge per trailing one bit of the
        # number of chunks completed so far.
        total = self._chunk_counter + 1
        while total & 1 == 0:
            cv = _parent_output(self._stack.pop(), cv).chaining_value_of_node()
            total >>= 1
        self._stack.append(cv)
        self._chunk_counter += 1
        self._chunk_cv = IV
        self._chunk_blocks = 0
        self._buffer.clear()

    def digest(self) -> bytes:
        output = self._chunk_output()
        for index in range(len(self._stack) - 1, -1, -1):
            output = _parent_output(self._stack[index], output.chaining_value_of_node())
        return output.root_digest()

    def hexdigest(self) -> str:
        return self.digest().hex()


# The official BLAKE3 regular-hash vectors: the first 64 hex characters of the
# "hash" field of
# https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
# over input[i] = i % 251. tests/ChunkShift.Tests/Hashing/HashVectors.cs holds
# the same values for the .NET implementation.
OFFICIAL_VECTORS = (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
    (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"),
    (6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"),
    (7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"),
    (8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
    (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
    (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
    (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
    (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
    (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"),
)

# ChunkShift's own pins at the stable profile's target and maximum chunk sizes,
# computed with the official Rust implementation (HashVectors.cs).
CHUNKSHIFT_SCALE_VECTORS = (
    (65536, "68d647e619a930e7b1082f74f334b0c65a315725569bdc123f0ee11881717bfe"),
    (262144, "d57dc906e20d3fd326ffaa85535500486f46a0979f5a323f028dcabfd381fd4a"),
)


def self_test() -> list[str]:
    """Return the failures of the vector check; empty when every vector matches."""

    failures = []
    for length, expected in OFFICIAL_VECTORS + CHUNKSHIFT_SCALE_VECTORS:
        data = bytes(index % 251 for index in range(length))
        one_shot = blake3(data).hexdigest()
        # The same input fed in uneven pieces must give the same digest.
        incremental = blake3()
        for start in range(0, length, 1000):
            incremental.update(data[start : start + 1000])
        for name, actual in (("one-shot", one_shot), ("incremental", incremental.hexdigest())):
            if actual != expected:
                failures.append(f"length {length} ({name}): {actual} != {expected}")
    return failures


def main() -> int:
    failures = self_test()
    for failure in failures:
        print(failure, file=sys.stderr)
    count = len(OFFICIAL_VECTORS) + len(CHUNKSHIFT_SCALE_VECTORS)
    print(f"BLAKE3 reference: {count} vectors, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
