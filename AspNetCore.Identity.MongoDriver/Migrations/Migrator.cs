using System.Runtime.CompilerServices;
using AspNetCore.Identity.MongoDriver.Models;
using MongoDB.Driver;

[assembly: InternalsVisibleTo("Tests")]

namespace AspNetCore.Identity.MongoDriver.Migrations;

internal static class Migrator
{
    //Starting from 4 in case we want to implement migrations for previous versions
    public static int CurrentVersion = 6;

    public static void Apply<TUser, TRole, TKey>(IMongoCollection<MigrationHistory> migrationCollection,
        IMongoCollection<TUser> usersCollection, IMongoCollection<TRole> rolesCollection)
        where TKey : IEquatable<TKey>
        where TUser : MigrationMongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        int version = migrationCollection
            .Find(h => true)
            .SortByDescending(h => h.DatabaseVersion)
            .Project(h => h.DatabaseVersion)
            .FirstOrDefault();

        List<MigrationHistory> appliedMigrations = BaseMigration.Migrations
            .Where(m => m.Version >= version)
            .Select(migration => migration.Apply<TUser, TRole, TKey>(usersCollection, rolesCollection))
            .ToList();

        if (appliedMigrations.Count > 0)
        {
            migrationCollection.InsertMany(appliedMigrations);
        }
    }
}