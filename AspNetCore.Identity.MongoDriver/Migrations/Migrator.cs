using AspNetCoreIdentity.MongoDriver.Models;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Migrations;

internal static class Migrator
{
    public static async Task ApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<MigrationHistory> migrationCollection,
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
        where TKey : IEquatable<TKey>
        where TUser : MigrationMongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        int version = await migrationCollection
            .Find(h => true)
            .SortByDescending(h => h.DatabaseVersion)
            .Project(h => h.DatabaseVersion)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (BaseMigration migration in BaseMigration.Migrations.Where(m => m.Version >= version))
        {
            MigrationHistory history = await migration
                .ApplyAsync<TUser, TRole, TKey>(usersCollection, rolesCollection, cancellationToken)
                .ConfigureAwait(false);
            // Record each migration as soon as it completes so a failure part way through
            // the chain does not re-run the migrations that already succeeded.
            await migrationCollection.InsertOneAsync(history, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }
}
