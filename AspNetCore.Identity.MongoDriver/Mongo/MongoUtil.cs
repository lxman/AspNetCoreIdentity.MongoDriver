using System.Collections.Concurrent;
using MongoDB.Driver;

// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace AspNetCoreIdentity.MongoDriver.Mongo;

public static class MongoUtil
{
    private static readonly ConcurrentDictionary<string, MongoClient> Clients = new();

    public static IMongoCollection<TItem> FromConnectionString<TItem>(MongoIdentityOptions options, string collectionName)
    {
        string connectionString = options.ConnectionString ?? "mongodb://localhost/default";
        MongoUrl url = new(connectionString);
        string databaseName = url.DatabaseName ?? "default";

        MongoClient client = Clients.GetOrAdd(connectionString, _ =>
        {
            MongoClientSettings settings = MongoClientSettings.FromUrl(url);
            settings.SslSettings = options.SslSettings;
            settings.ClusterConfigurator = options.ClusterConfigurator;
            return new MongoClient(settings);
        });

        return client.GetDatabase(databaseName).GetCollection<TItem>(collectionName);
    }
}