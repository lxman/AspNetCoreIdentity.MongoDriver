using System.Collections.Concurrent;
using MongoDB.Driver;
using MongoDB.Driver.Core.Configuration;

// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace AspNetCoreIdentity.MongoDriver.Mongo;

public static class MongoUtil
{
    // Keyed on the connection string plus the settings that influence client construction,
    // so two registrations with the same connection string but different SSL settings or
    // cluster configurators do not silently share a client built from the first one seen.
    private static readonly ConcurrentDictionary<ClientKey, MongoClient> Clients = new();

    private readonly record struct ClientKey(
        string ConnectionString,
        SslSettings? SslSettings,
        Action<ClusterBuilder>? ClusterConfigurator);

    public static IMongoCollection<TItem> FromConnectionString<TItem>(MongoIdentityOptions options, string collectionName)
    {
        string connectionString = options.ConnectionString ?? "mongodb://localhost/default";
        MongoUrl url = new(connectionString);
        string databaseName = url.DatabaseName ?? "default";

        MongoClient client = Clients.GetOrAdd(new ClientKey(connectionString, options.SslSettings, options.ClusterConfigurator), key =>
        {
            MongoClientSettings settings = MongoClientSettings.FromUrl(new MongoUrl(key.ConnectionString));
            settings.SslSettings = key.SslSettings;
            settings.ClusterConfigurator = key.ClusterConfigurator;
            return new MongoClient(settings);
        });

        return client.GetDatabase(databaseName).GetCollection<TItem>(collectionName);
    }
}
