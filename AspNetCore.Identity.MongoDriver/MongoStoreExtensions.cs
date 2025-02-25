using AspNetCore.Identity.MongoDriver.Migrations;
using AspNetCore.Identity.MongoDriver.Models;
using AspNetCore.Identity.MongoDriver.Mongo;
using AspNetCore.Identity.MongoDriver.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCore.Identity.MongoDriver;

public static class MongoStoreExtensions
{
    public static IdentityBuilder AddMongoDbStores<TUser>(this IdentityBuilder builder,
        Action<MongoIdentityOptions> setupDatabaseAction,
        IdentityErrorDescriber? identityErrorDescriber = null)
        where TUser : MongoUser
    {
        return AddMongoDbStores<TUser, MongoRole, ObjectId>(builder, setupDatabaseAction, identityErrorDescriber);
    }

    public static IdentityBuilder AddMongoDbStores<TUser, TRole, TKey>(this IdentityBuilder builder,
        Action<MongoIdentityOptions> setupDatabaseAction,
        IdentityErrorDescriber? identityErrorDescriber = null)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        MongoIdentityOptions dbOptions = new();
        setupDatabaseAction(dbOptions);

        IMongoCollection<MigrationHistory> migrationCollection =
            MongoUtil.FromConnectionString<MigrationHistory>(dbOptions, dbOptions.MigrationCollection);
        IMongoCollection<MigrationMongoUser<TKey>> migrationUserCollection =
            MongoUtil.FromConnectionString<MigrationMongoUser<TKey>>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TUser> userCollection = MongoUtil.FromConnectionString<TUser>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TRole> roleCollection = MongoUtil.FromConnectionString<TRole>(dbOptions, dbOptions.RolesCollection);

        if (!dbOptions.DisableAutoMigrations)
        {
            Migrator.Apply<MigrationMongoUser<TKey>, TRole, TKey>(
                migrationCollection, migrationUserCollection, roleCollection);
        }

        builder.Services.AddSingleton(_ => userCollection);
        builder.Services.AddSingleton(_ => roleCollection);

        // register custom ObjectId TypeConverter
        if (typeof(TKey) == typeof(ObjectId))
        {
            TypeConverterResolver.RegisterTypeConverter<ObjectId, ObjectIdConverter>();
        }

        // Identity Services
        builder.Services.AddTransient<IRoleStore<TRole>>(_ =>
            new RoleStore<TRole, TKey>(roleCollection, identityErrorDescriber));
        builder.Services.AddTransient<IUserStore<TUser>>(_ =>
            new UserStore<TUser, TRole, TKey>(userCollection, roleCollection, identityErrorDescriber));

        return builder;
    }
}