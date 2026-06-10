using AspNetCoreIdentity.MongoDriver.Models;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Migrations;

internal abstract class BaseMigration
{
    private static readonly Lazy<List<BaseMigration>> LazyMigrations = new(BuildMigrations);

    public static List<BaseMigration> Migrations => LazyMigrations.Value;

    private static List<BaseMigration> BuildMigrations()
    {
        List<BaseMigration> migrations = typeof(BaseMigration)
            .Assembly
            .GetTypes()
            .Where(t => typeof(BaseMigration).IsAssignableFrom(t))
            .Select(t => t.GetConstructor(Type.EmptyTypes)?.Invoke(Array.Empty<object>()))
            .Where(o => o != null)
            .Cast<BaseMigration>()
            .OrderBy(m => m.Version)
            .ToList();
        if (migrations.Count != migrations.Select(m => m.Version).Distinct().Count())
        {
            throw new InvalidOperationException("Migration versions must be unique, please check versions");
        }

        return migrations;
    }

    public abstract int Version { get; }

    public async Task<MigrationHistory> ApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TUser : MigrationMongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        await DoApplyAsync<TUser, TRole, TKey>(usersCollection, rolesCollection, cancellationToken).ConfigureAwait(false);
        return new MigrationHistory
        {
            Id = ObjectId.GenerateNewId(),
            InstalledOn = DateTime.UtcNow,
            DatabaseVersion = Version + 1
        };
    }

    protected abstract Task DoApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TUser : MigrationMongoUser<TKey>
        where TRole : MongoRole<TKey>;
}
