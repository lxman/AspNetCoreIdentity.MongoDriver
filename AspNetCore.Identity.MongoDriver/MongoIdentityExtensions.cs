using AspNetCoreIdentity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;

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
        Action<IdentityOptions> setupIdentityAction, Action<MongoIdentityOptions> setupDatabaseAction, IdentityErrorDescriber? identityErrorDescriber = null)
        where TKey : IEquatable<TKey>
        where TUser : MongoUser<TKey>
        where TRole : MongoRole<TKey>
    {
        ArgumentNullException.ThrowIfNull(setupDatabaseAction);
        MongoIdentityOptions dbOptions = new();
        setupDatabaseAction(dbOptions);

        // AddIdentity already registers UserManager, RoleManager, SignInManager and the
        // related options; only the stores and token providers are added on top of it.
        IdentityBuilder builder = services.AddIdentity<TUser, TRole>(setupIdentityAction)
            .AddDefaultTokenProviders();

        MongoStoreExtensions.AddStores<TUser, TRole, TKey>(services, dbOptions, identityErrorDescriber);

        return builder;
    }
}
