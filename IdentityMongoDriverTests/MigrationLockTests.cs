using AspNetCoreIdentity.MongoDriver.Mongo;
using MongoDB.Bson;
using MongoDB.Driver;
using Mongo2Go;

namespace IdentityMongoDriverTests;

/// <summary>
/// Tests for the leased distributed migration lock: mutual exclusion between holders,
/// release semantics, and stale-lease takeover after a holder dies without releasing.
/// </summary>
public class MigrationLockTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();
    private readonly IMongoCollection<BsonDocument> _lock;

    public MigrationLockTests()
    {
        MongoClient client = new(_runner.ConnectionString);
        _lock = client.GetDatabase("LockTest").GetCollection<BsonDocument>("test_lock");
    }

    public void Dispose()
    {
        _runner.Dispose();
    }

    [Fact]
    public async Task Acquire_WhileHeldByAnother_Blocks()
    {
        await MongoMigrationLock.AcquireAsync(_lock, "owner-a", TestContext.Current.CancellationToken);

        // A second owner cannot take a freshly held lock; AcquireAsync polls until its
        // token is cancelled rather than returning, proving it is blocked.
        using CancellationTokenSource cts = new(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MongoMigrationLock.AcquireAsync(_lock, "owner-b", cts.Token));

        // The original owner still holds exactly one lock.
        BsonDocument held = await _lock.Find(FilterDefinition<BsonDocument>.Empty)
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("owner-a", held["owner"].AsString);
    }

    [Fact]
    public async Task Release_AllowsAnotherOwnerToAcquire()
    {
        await MongoMigrationLock.AcquireAsync(_lock, "owner-a", TestContext.Current.CancellationToken);
        await MongoMigrationLock.ReleaseAsync(_lock, "owner-a");

        // With the lock released the next caller acquires immediately.
        await MongoMigrationLock.AcquireAsync(_lock, "owner-b", TestContext.Current.CancellationToken);

        BsonDocument held = await _lock.Find(FilterDefinition<BsonDocument>.Empty)
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("owner-b", held["owner"].AsString);
    }

    [Fact]
    public async Task Release_ByNonOwner_DoesNotReleaseTheLock()
    {
        await MongoMigrationLock.AcquireAsync(_lock, "owner-a", TestContext.Current.CancellationToken);

        // A release call that does not name the current owner must be a no-op.
        await MongoMigrationLock.ReleaseAsync(_lock, "intruder");

        long count = await _lock.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(1, count);

        // And the lock is still genuinely held: a different owner remains blocked.
        using CancellationTokenSource cts = new(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MongoMigrationLock.AcquireAsync(_lock, "owner-b", cts.Token));
    }

    [Fact]
    public async Task Acquire_TakesOverAStaleLease()
    {
        await MongoMigrationLock.AcquireAsync(_lock, "dead-owner", TestContext.Current.CancellationToken);

        // Simulate a holder that crashed long ago by back-dating its lease beyond the
        // staleness window (5 minutes).
        await _lock.UpdateOneAsync(
            FilterDefinition<BsonDocument>.Empty,
            Builders<BsonDocument>.Update.Set("acquiredAt", DateTime.UtcNow.AddMinutes(-10)),
            cancellationToken: TestContext.Current.CancellationToken);

        // A new owner overrides the abandoned lease without waiting.
        await MongoMigrationLock.AcquireAsync(_lock, "new-owner", TestContext.Current.CancellationToken);

        BsonDocument held = await _lock.Find(FilterDefinition<BsonDocument>.Empty)
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("new-owner", held["owner"].AsString);
    }
}
