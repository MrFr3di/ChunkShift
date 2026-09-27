using System;
using System.Runtime.CompilerServices;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Primitives;

public class Hash256Tests
{
    private static readonly byte[] SequenceBytes = Enumerable.Range(0, 32).Select(static i => (byte)i).ToArray();

    [Theory]
    [MemberData(nameof(ValidBitPatterns))]
    public void FromBytes_AcceptsEveryRepresentativeBitPattern(byte[] bytes)
    {
        Hash256 value = Hash256.FromBytes(bytes);

        Span<byte> roundTrip = stackalloc byte[32];
        value.CopyTo(roundTrip);

        Assert.Equal(bytes, roundTrip.ToArray());
    }

    public static TheoryData<byte[]> ValidBitPatterns => new()
    {
        new byte[32],
        Enumerable.Repeat((byte)0xFF, 32).ToArray(),
        SequenceBytes,
        Enumerable.Range(0, 32).Select(static i => (byte)(i % 2 == 0 ? 0x00 : 0xFF)).ToArray(),
        new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        new byte[32] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    };

    [Fact]
    public void Default_IsValidAllZeroDigest()
    {
        Hash256 value = default;

        Assert.Equal(new string('0', 64), value.ToHexLower());

        Span<byte> bytes = stackalloc byte[32];
        Assert.True(value.TryCopyTo(bytes));
        Assert.True(bytes.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void FromBytes_RequiresExactly32Bytes()
    {
        Assert.Throws<ArgumentException>(() => Hash256.FromBytes(new byte[31]));
        Assert.Throws<ArgumentException>(() => Hash256.FromBytes(new byte[33]));
    }

    [Fact]
    public void LowerHex_AllZeroRoundTrips()
    {
        string hex = new('0', 64);

        Assert.True(Hash256.TryParseHexLower(hex, out Hash256 value));
        Assert.Equal(default, value);
        Assert.Equal(hex, value.ToHexLower());
    }

    [Fact]
    public void LowerHex_NonZeroRoundTrips()
    {
        Hash256 original = Hash256.FromBytes(SequenceBytes);
        string hex = original.ToHexLower();

        Assert.True(Hash256.TryParseHexLower(hex, out Hash256 parsed));
        Assert.Equal(original, parsed);
        Assert.Matches("^[0-9a-f]{64}$", hex);
    }

    [Fact]
    public void TryParseHexLower_RejectsUppercaseInvalidAndWrongLength()
    {
        Assert.False(Hash256.TryParseHexLower(Convert.ToHexString(SequenceBytes), out _));
        Assert.False(Hash256.TryParseHexLower(new string('g', 64), out _));
        Assert.False(Hash256.TryParseHexLower(new string('a', 63), out _));
    }

    [Fact]
    public void CopyTo_RequiresEnoughSpace()
    {
        Hash256 value = Hash256.FromBytes(SequenceBytes);

        Assert.Throws<ArgumentException>(() => value.CopyTo(new byte[31]));
        Assert.False(value.TryCopyTo(new byte[31]));
    }

    [Fact]
    public void TryFormatHexLower_FormatsZeroAndNonZero()
    {
        Span<char> zero = stackalloc char[64];
        Span<char> nonZero = stackalloc char[64];

        Assert.True(default(Hash256).TryFormatHexLower(zero));
        Assert.True(Hash256.FromBytes(SequenceBytes).TryFormatHexLower(nonZero));
        Assert.Equal(new string('0', 64), new string(zero));
        Assert.Equal(Hash256.FromBytes(SequenceBytes).ToHexLower(), new string(nonZero));
    }

    [Fact]
    public void TryFormatHexLower_RejectsSmallDestination()
    {
        Span<char> destination = stackalloc char[63];
        Assert.False(default(Hash256).TryFormatHexLower(destination));
    }

    [Fact]
    public void EqualityAndFixedTimeEquality_WorkForAllZeroAndNonZeroValues()
    {
        Hash256 zeroA = default;
        Hash256 zeroB = Hash256.FromBytes(new byte[32]);
        Hash256 valueA = Hash256.FromBytes(SequenceBytes);
        Hash256 valueB = Hash256.FromBytes(SequenceBytes);

        Assert.Equal(zeroA, zeroB);
        Assert.True(zeroA.FixedTimeEquals(zeroB));
        Assert.Equal(valueA, valueB);
        Assert.True(valueA.FixedTimeEquals(valueB));
        Assert.NotEqual(zeroA, valueA);
        Assert.False(zeroA.FixedTimeEquals(valueA));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(31)]
    public void FixedTimeEquals_DetectsASingleBitDifferenceInEveryWord(int byteIndex)
    {
        byte[] changed = (byte[])SequenceBytes.Clone();
        changed[byteIndex] ^= 0x80;

        Hash256 value = Hash256.FromBytes(SequenceBytes);
        Hash256 other = Hash256.FromBytes(changed);

        Assert.False(value.FixedTimeEquals(other));
        Assert.False(other.FixedTimeEquals(value));
        Assert.Equal(value.Equals(other), value.FixedTimeEquals(other));
    }

    [Theory]
    [MemberData(nameof(AllBitIndices))]
    public void FixedTimeEquals_DetectsEverySingleBitDifference(int bitIndex)
    {
        byte[] changed = (byte[])SequenceBytes.Clone();
        changed[bitIndex / 8] ^= (byte)(1 << (bitIndex % 8));

        Hash256 value = Hash256.FromBytes(SequenceBytes);
        Hash256 other = Hash256.FromBytes(changed);

        Assert.False(value.Equals(other));
        Assert.False(value.FixedTimeEquals(other));
        Assert.False(other.FixedTimeEquals(value));
        Assert.True(value.FixedTimeEquals(Hash256.FromBytes((byte[])SequenceBytes.Clone())));
    }

    public static TheoryData<int> AllBitIndices()
    {
        var indices = new TheoryData<int>();

        for (int bit = 0; bit < 256; bit++)
        {
            indices.Add(bit);
        }

        return indices;
    }

    [Fact]
    public void FixedTimeEquals_DoesNotAllocate()
    {
        Hash256 value = Hash256.FromBytes(SequenceBytes);
        Hash256 other = Hash256.FromBytes(SequenceBytes);

        // The first measured run absorbs one-time runtime work (tier-up/OSR of
        // the loop), which CI observed at 2,688 bytes on ubuntu-24.04 net10.0.
        // The minimum of the following runs is what
        // the comparison itself costs: an allocation per call would add at
        // least 240 KB to every run, so it cannot hide behind the minimum.
        _ = MeasureFixedTimeEqualsAllocations(value, other);

        long allocated = long.MaxValue;
        for (int run = 0; run < 3; run++)
        {
            allocated = Math.Min(allocated, MeasureFixedTimeEqualsAllocations(value, other));
        }

        Assert.True(allocated <= 1024, $"FixedTimeEquals allocated {allocated} bytes across 10,000 calls.");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static long MeasureFixedTimeEqualsAllocations(Hash256 value, Hash256 other)
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        bool all = true;

        for (int iteration = 0; iteration < 10_000; iteration++)
        {
            all &= value.FixedTimeEquals(other);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(all);
        return allocated;
    }
}
