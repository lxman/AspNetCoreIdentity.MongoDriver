using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using AspNetCoreIdentity.MongoDriver.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver;

public static class MongoStoreExtensions
{
    public static IdentityBuilder AddMongoDbStores<TUser>(this IdentityBuilder builder,
        Action<MongoIdentityOptions> setupDatabaseAction,
        IdentityErrorDescriber? identityErrorDescriber = null)
        where TUser : MongoUser
    {
        return builder.AddMongoDbStores<TUser, MongoRole, ObjectId>(setupDatabaseAction, identityErrorDescriber);
    }

    public static IdentityBuilder AddMongoDbStores<TUser, TRole, TKey>(this IdentityBuilder builder,
        Action<MongoIdentityOptions> setupDatabaseAction,
        IdentityErrorDescriber? identityErrorDescriber = null)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(setupDatabaseAction);
        MongoIdentityOptions dbOptions = new();
        setupDatabaseAction(dbOptions);

        AddStores<TUser, TRole, TKey>(builder.Services, dbOptions, identityErrorDescriber);

        return builder;
    }

    internal static void AddStores<TUser, TRole, TKey>(IServiceCollection services,
        MongoIdentityOptions dbOptions,
        IdentityErrorDescriber? identityErrorDescriber)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        IMongoCollection<MigrationHistory> migrationCollection =
            MongoUtil.FromConnectionString<MigrationHistory>(dbOptions, dbOptions.MigrationCollection);
        IMongoCollection<MigrationMongoUser<TKey>> migrationUserCollection =
            MongoUtil.FromConnectionString<MigrationMongoUser<TKey>>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TUser> userCollection = MongoUtil.FromConnectionString<TUser>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TRole> roleCollection = MongoUtil.FromConnectionString<TRole>(dbOptions, dbOptions.RolesCollection);

        // register custom ObjectId TypeConverter
        if (typeof(TKey) == typeof(ObjectId))
        {
            TypeConverterResolver.RegisterTypeConverter<ObjectId, ObjectIdConverter>();
        }

        // Migrations and index creation run lazily on first store use (one instance at a
        // time, guarded by a distributed lock) instead of blocking service registration.
        MongoIdentityInitializer initializer = new(cancellationToken =>
            MongoIdentityInitialization.InitializeAsync<TUser, TRole, TKey>(
                dbOptions, migrationCollection, migrationUserCollection, userCollection, roleCollection, cancellationToken));

        services.AddSingleton(_ => userCollection);
        services.AddSingleton(_ => roleCollection);
        services.AddSingleton(initializer);

        // Identity Services
        services.AddTransient<IRoleStore<TRole>>(_ =>
            new RoleStore<TRole, TKey>(roleCollection, identityErrorDescriber, initializer));
        services.AddTransient<IUserStore<TUser>>(_ =>
            new UserStore<TUser, TRole, TKey>(userCollection, roleCollection, identityErrorDescriber, initializer));
    }
}
