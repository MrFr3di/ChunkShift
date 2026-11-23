using ChunkShift.Patching.IO;
using ChunkShift.Patching.Tests.Format;

namespace ChunkShift.Patching.Tests.IO;

/// <summary>
/// Views that let the reconstruction and the overlapped re-chunk check read
/// one patch stream concurrently.
/// </summary>
public sealed class SharedStreamViewTests
{
    [Fact]
    public void Views_KeepTheirOwnPositions()
    {
        byte[] bytes = CspBytes.CreateXorShiftBytes(4096, 0x5EED8001u);
        using var inner = new MemoryStream(bytes, writable: false);
        using var gate = new SemaphoreSlim(1, 1);
        using var first = new SharedStreamView(inner, gate, 0);
        using var second = new SharedStreamView(inner, gate, 1000);

        byte[] a = new byte[100];
        byte[] b = new byte[100];

        first.ReadExactly(a);
        second.ReadExactly(b);
        first.ReadExactly(a);

        Assert.Equal(bytes.AsSpan(100, 100).ToArray(), a);
        Assert.Equal(bytes.AsSpan(1000, 100).ToArray(), b);
        Assert.Equal(200, first.Position);
        Assert.Equal(1100, second.Position);
        Assert.Equal(bytes.Length, first.Length);

        second.Seek(-10, SeekOrigin.End);
        Assert.Equal(10, second.Read(b));
        Assert.Equal(bytes.AsSpan(bytes.Length - 10).ToArray(), b.AsSpan(0, 10).ToArray());
        Assert.Equal(0, second.Read(b));
    }

    [Fact]
    public async Task ConcurrentReaders_EachReadTheirOwnRange()
    {
        byte[] bytes = CspBytes.CreateXorShiftBytes(1024 * 1024, 0x5EED8002u);
        using var inner = new MemoryStream(bytes, writable: false);
        using var gate = new SemaphoreSlim(1, 1);
        using var low = new SharedStreamView(inner, gate, 0);
        using var high = new SharedStreamView(inner, gate, bytes.Length / 2);

        Task<byte[]> ReadAsync(Stream view) => Task.Run(async () =>
        {
            byte[] result = new byte[bytes.Length / 2];
            int offset = 0;

            // Small reads interleave the two views as much as possible.
            while (offset < result.Length)
            {
                int read = await view.ReadAsync(result.AsMemory(offset, Math.Min(97, result.Length - offset)));
                Assert.NotEqual(0, read);
                offset += read;
            }

            return result;
        });

        byte[][] results = await Task.WhenAll(ReadAsync(low), ReadAsync(high));

        Assert.Equal(bytes.AsSpan(0, bytes.Length / 2).ToArray(), results[0]);
        Assert.Equal(bytes.AsSpan(bytes.Length / 2).ToArray(), results[1]);
    }

    [Fact]
    public void View_IsReadOnlyAndRejectsAnUnseekableInner()
    {
        using var gate = new SemaphoreSlim(1, 1);
        using var view = new SharedStreamView(new MemoryStream(new byte[8]), gate, 0);

        Assert.False(view.CanWrite);
        Assert.Throws<NotSupportedException>(() => view.Write(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => view.SetLength(1));
        Assert.Throws<ArgumentOutOfRangeException>(() => view.Seek(-1, SeekOrigin.Begin));
        Assert.Throws<ArgumentException>(() => new SharedStreamView(
            new ShortReadStream(new byte[8], 1, seekable: false),
            gate,
            0));
    }
}
