using System.Buffers.Binary;
using System.Numerics;

namespace ChunkShift.Manifest;

internal static class Crc32C
{
    // Reflected Castagnoli polynomial corresponding to normal-form 0x1EDC6F41.
    // BitOperations.Crc32C implements exactly this reflected CRC step (SSE4.2
    // or ARMv8 CRC32 instructions when present, a table fallback otherwise);
    // the initial value and final inversion stay here.
    private const uint InitialState = 0xFFFFFFFFu;

    internal static uint Compute(ReadOnlySpan<byte> data)
    {
        uint state = Append(InitialState, data);
        return Finalize(state);
    }

    internal static uint Start() => InitialState;

    internal static uint Append(uint state, ReadOnlySpan<byte> data)
    {
        // A reflected CRC consumes a little-endian word lowest byte first, so
        // eight bytes per step give the same state as eight one-byte steps.
        while (data.Length >= sizeof(ulong))
        {
            state = BitOperations.Crc32C(state, BinaryPrimitives.ReadUInt64LittleEndian(data));
            data = data[sizeof(ulong)..];
        }

        foreach (byte value in data)
        {
            state = BitOperations.Crc32C(state, value);
        }

        return state;
    }

    internal static uint Finalize(uint state) => ~state;
}
