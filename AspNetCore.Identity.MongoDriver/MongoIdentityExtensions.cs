﻿using AspNetCoreIdentity.MongoDriver.Migrations;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using AspNetCoreIdentity.MongoDriver.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver;

public static class MongoIdentityExtensions
{
    public static IdentityBuilder AddIdentityMongoDbProvider<TUser>(this IServiceCollection services)
        where TUser : MongoUser
    {
        return AddIdentityMongoDbProvider<TUser, MongoRole, ObjectId>(services, _ => { });
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser, TKey>(this IServiceCollection services)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
    {
        return AddIdentityMongoDbProvider<TUser, MongoRole<TKey>, TKey>(services, _ => { });
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser>(this IServiceCollection services,
        Action<MongoIdentityOptions> setupDatabaseAction)
        where TUser : MongoUser
    {
        return AddIdentityMongoDbProvider<TUser, MongoRole, ObjectId>(services, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser, TKey>(this IServiceCollection services,
        Action<MongoIdentityOptions> setupDatabaseAction)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
    {
        return AddIdentityMongoDbProvider<TUser, MongoRole<TKey>, TKey>(services, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser, TRole>(this IServiceCollection services,
        Action<IdentityOptions> setupIdentityAction, Action<MongoIdentityOptions> setupDatabaseAction)
        where TUser : MongoUser
        where TRole : MongoRole
    {
        return AddIdentityMongoDbProvider<TUser, TRole, ObjectId>(services, setupIdentityAction, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser, TRole, TKey>(this IServiceCollection services,
        Action<MongoIdentityOptions> setupDatabaseAction)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        return AddIdentityMongoDbProvider<TUser, TRole, TKey>(services, _ => { }, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider(this IServiceCollection services,
        Action<IdentityOptions> setupIdentityAction, Action<MongoIdentityOptions> setupDatabaseAction)
    {
        return AddIdentityMongoDbProvider<MongoUser, MongoRole, ObjectId>(services, setupIdentityAction, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser>(this IServiceCollection services,
        Action<IdentityOptions> setupIdentityAction, Action<MongoIdentityOptions> setupDatabaseAction) where TUser : MongoUser
    {
        return AddIdentityMongoDbProvider<TUser, MongoRole, ObjectId>(services, setupIdentityAction, setupDatabaseAction);
    }

    public static IdentityBuilder AddIdentityMongoDbProvider<TUser, TRole, TKey>(this IServiceCollection services,
        Action<IdentityOptions> setupIdentityAction, Action<MongoIdentityOptions> setupDatabaseAction, IdentityErrorDescriber identityErrorDescriber = null!)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        MongoIdentityOptions dbOptions = new();
        setupDatabaseAction(dbOptions);

        IMongoCollection<MigrationHistory> migrationCollection = MongoUtil.FromConnectionString<MigrationHistory>(dbOptions, dbOptions.MigrationCollection);
        IMongoCollection<MigrationMongoUser<TKey>> migrationUserCollection = MongoUtil.FromConnectionString<MigrationMongoUser<TKey>>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TUser> userCollection = MongoUtil.FromConnectionString<TUser>(dbOptions, dbOptions.UsersCollection);
        IMongoCollection<TRole> roleCollection = MongoUtil.FromConnectionString<TRole>(dbOptions, dbOptions.RolesCollection);

        // apply migrations before identity services resolved
        if (!dbOptions.DisableAutoMigrations)
        {
            Migrator.Apply<MigrationMongoUser<TKey>, TRole, TKey>(
                migrationCollection, migrationUserCollection, roleCollection);
        }

        IdentityBuilder? builder = services.AddIdentity<TUser, TRole>(setupIdentityAction);

        builder.AddRoleStore<RoleStore<TRole, TKey>>()
            .AddUserStore<UserStore<TUser, TRole, TKey>>()
            .AddUserManager<UserManager<TUser>>()
            .AddRoleManager<RoleManager<TRole>>()
            .AddDefaultTokenProviders();

        services.AddSingleton(_ => userCollection);
        services.AddSingleton(_ => roleCollection);

        // register custom ObjectId TypeConverter
        if (typeof(TKey) == typeof(ObjectId))
        {
            TypeConverterResolver.RegisterTypeConverter<ObjectId, ObjectIdConverter>();
        }

        // Identity Services
        services.AddTransient<IRoleStore<TRole>>(_ => new RoleStore<TRole, TKey>(roleCollection, identityErrorDescriber));
        services.AddTransient<IUserStore<TUser>>(_ => new UserStore<TUser, TRole, TKey>(userCollection, roleCollection, identityErrorDescriber));

        return builder;
    }
}