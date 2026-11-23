using ChunkShift.Patching.IO;

namespace ChunkShift.Patching.Tests.IO;

public sealed class PendingFileTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("chunkshift-pending-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task Commit_ReplacesTheDestinationAndLeavesNoTemporaryFile()
    {
        string destination = Path.Combine(_directory, "target.bin");
        File.WriteAllBytes(destination, [1, 2, 3]);

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.Stream.WriteAsync(new byte[] { 9, 8 });
            await pending.CommitAsync(CancellationToken.None);
        }

        Assert.Equal([9, 8], File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task DisposeWithoutCommit_DeletesTheTemporaryFileAndKeepsTheDestination()
    {
        string destination = Path.Combine(_directory, "target.bin");
        File.WriteAllBytes(destination, [1, 2, 3]);

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.Stream.WriteAsync(new byte[] { 9, 8 });
            Assert.True(File.Exists(pending.TemporaryPath));
        }

        Assert.Equal([1, 2, 3], File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task FlushToDisk_PublishesNothingUntilCommit()
    {
        string destination = Path.Combine(_directory, "target.bin");
        File.WriteAllBytes(destination, [1, 2, 3]);

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.Stream.WriteAsync(new byte[] { 9, 8 });
            await pending.FlushToDiskAsync(CancellationToken.None);

            Assert.Equal([1, 2, 3], File.ReadAllBytes(destination));
            Assert.Equal(2, new FileInfo(pending.TemporaryPath).Length);

            await pending.CommitAsync(CancellationToken.None);
        }

        Assert.Equal([9, 8], File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task FlushToDiskWithoutCommit_DeletesTheTemporaryFile()
    {
        string destination = Path.Combine(_directory, "target.bin");
        File.WriteAllBytes(destination, [1, 2, 3]);

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.Stream.WriteAsync(new byte[] { 9, 8 });
            await pending.FlushToDiskAsync(CancellationToken.None);
        }

        Assert.Equal([1, 2, 3], File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task CancelledCommit_KeepsTheDestination()
    {
        string destination = Path.Combine(_directory, "target.bin");
        File.WriteAllBytes(destination, [1, 2, 3]);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.Stream.WriteAsync(new byte[] { 9, 8 });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => pending.CommitAsync(cancellation.Token));
        }

        Assert.Equal([1, 2, 3], File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task LongDestinationName_GetsAValidTemporaryName()
    {
        string destination = Path.Combine(_directory, new string('a', 250));

        await using (PendingFile pending = PendingFile.Create(destination))
        {
            await pending.CommitAsync(CancellationToken.None);
        }

        Assert.True(File.Exists(destination));
    }
}
