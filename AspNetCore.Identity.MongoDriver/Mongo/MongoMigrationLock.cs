using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Mongo;

/// <summary>
/// A leased distributed lock that prevents multiple application instances from applying
/// migrations concurrently. A holder that dies without releasing is overridden once its
/// lease goes stale.
/// </summary>
internal static class MongoMigrationLock
{
    private const string LockId = "identity-migration-lock";
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan AcquireTimeout = TimeSpan.FromMinutes(10);

    public static async Task AcquireAsync(IMongoCollection<BsonDocument> lockCollection, string owner, CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + AcquireTimeout;
        while (!await TryAcquireAsync(lockCollection, owner, cancellationToken).ConfigureAwait(false))
        {
            if (DateTime.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"Timed out waiting for the identity migration lock. A lock abandoned by a crashed process expires after {StaleAfter}.");
            }

            await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    public static Task ReleaseAsync(IMongoCollection<BsonDocument> lockCollection, string owner)
    {
        FilterDefinition<BsonDocument> ownLock = Builders<BsonDocument>.Filter.Eq("_id", LockId)
            & Builders<BsonDocument>.Filter.Eq("owner", owner);
        return lockCollection.DeleteOneAsync(ownLock);
    }

    private static async Task<bool> TryAcquireAsync(IMongoCollection<BsonDocument> lockCollection, string owner, CancellationToken cancellationToken)
    {
        DateTime now = DateTime.UtcNow;

        // Upsert against "lock exists but is stale": if no lock document exists the upsert
        // inserts one (we win); if a stale lock exists the filter matches and we take it over;
        // if a fresh lock exists the filter matches nothing and the insert attempt hits the
        // _id unique constraint (someone else holds it).
        FilterDefinition<BsonDocument> staleLock = Builders<BsonDocument>.Filter.Eq("_id", LockId)
            & Builders<BsonDocument>.Filter.Lt("acquiredAt", now - StaleAfter);
        UpdateDefinition<BsonDocument> takeOwnership = Builders<BsonDocument>.Update
            .Set("acquiredAt", now)
            .Set("owner", owner);

        try
        {
            await lockCollection.UpdateOneAsync(staleLock, takeOwnership, new UpdateOptions { IsUpsert = true }, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return false;
        }
    }
}
