using AspNetCoreIdentity.MongoDriver.Migrations;
using AspNetCoreIdentity.MongoDriver.Models;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Mongo;

internal static class MongoIndexNames
{
    public const string NormalizedUserName = "identity_normalized_user_name";
    public const string NormalizedEmail = "identity_normalized_email";
    public const string LoginProviderKey = "identity_login_provider_key";
    public const string NormalizedRoleName = "identity_normalized_role_name";
}

internal static class MongoIdentityInitialization
{
    public static async Task InitializeAsync<TUser, TRole, TKey>(
        MongoIdentityOptions options,
        IMongoCollection<MigrationHistory> migrationCollection,
        IMongoCollection<MigrationMongoUser<TKey>> migrationUserCollection,
        IMongoCollection<TUser> userCollection,
        IMongoCollection<TRole> roleCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        if (!options.DisableAutoMigrations)
        {
            await MigrateAsync<TRole, TKey>(options, migrationCollection, migrationUserCollection, roleCollection, cancellationToken).ConfigureAwait(false);
        }

        if (!options.DisableIndexCreation)
        {
            await EnsureIndexesAsync<TUser, TRole, TKey>(userCollection, roleCollection, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task MigrateAsync<TRole, TKey>(
        MongoIdentityOptions options,
        IMongoCollection<MigrationHistory> migrationCollection,
        IMongoCollection<MigrationMongoUser<TKey>> migrationUserCollection,
        IMongoCollection<TRole> roleCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TRole : MongoRole<TKey>
    {
        int version = await migrationCollection
            .Find(h => true)
            .SortByDescending(h => h.DatabaseVersion)
            .Project(h => h.DatabaseVersion)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        if (BaseMigration.Migrations.All(m => m.Version < version))
        {
            // Already up to date - skip the lock round-trips entirely.
            return;
        }

        IMongoCollection<BsonDocument> lockCollection =
            migrationCollection.Database.GetCollection<BsonDocument>(options.MigrationCollection + "_lock");
        string owner = Guid.NewGuid().ToString("N");
        await MongoMigrationLock.AcquireAsync(lockCollection, owner, cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-reads the version inside the lock, so an instance that waited while another
            // instance migrated finds nothing left to do.
            await Migrator.ApplyAsync<MigrationMongoUser<TKey>, TRole, TKey>(
                migrationCollection, migrationUserCollection, roleCollection, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await MongoMigrationLock.ReleaseAsync(lockCollection, owner).ConfigureAwait(false);
        }
    }

    private static async Task EnsureIndexesAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> userCollection,
        IMongoCollection<TRole> roleCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        CreateIndexModel<TUser>[] userIndexes =
        [
            new(Builders<TUser>.IndexKeys.Ascending(u => u.NormalizedUserName),
                new CreateIndexOptions<TUser>
                {
                    Name = MongoIndexNames.NormalizedUserName,
                    Unique = true,
                    PartialFilterExpression = Builders<TUser>.Filter.Type(u => u.NormalizedUserName, BsonType.String)
                }),
            new(Builders<TUser>.IndexKeys.Ascending(u => u.NormalizedEmail),
                new CreateIndexOptions { Name = MongoIndexNames.NormalizedEmail }),
            new(Builders<TUser>.IndexKeys.Ascending("Logins.LoginProvider").Ascending("Logins.ProviderKey"),
                new CreateIndexOptions { Name = MongoIndexNames.LoginProviderKey })
        ];
        foreach (CreateIndexModel<TUser> model in userIndexes)
        {
            await CreateIndexAsync(userCollection, model, cancellationToken).ConfigureAwait(false);
        }

        CreateIndexModel<TRole> roleIndex = new(
            Builders<TRole>.IndexKeys.Ascending(r => r.NormalizedName),
            new CreateIndexOptions<TRole>
            {
                Name = MongoIndexNames.NormalizedRoleName,
                Unique = true,
                PartialFilterExpression = Builders<TRole>.Filter.Type(r => r.NormalizedName, BsonType.String)
            });
        await CreateIndexAsync(roleCollection, roleIndex, cancellationToken).ConfigureAwait(false);
    }

    private static async Task CreateIndexAsync<TDocument>(
        IMongoCollection<TDocument> collection,
        CreateIndexModel<TDocument> model,
        CancellationToken cancellationToken)
    {
        try
        {
            await collection.Indexes.CreateOneAsync(model, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (MongoCommandException ex) when (ex.Code is 85 or 86)
        {
            // IndexOptionsConflict / IndexKeySpecsConflict: an index with a different
            // definition already covers these keys - leave the existing index in place.
        }
    }
}
