using MongoDB.Driver;

// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace AspNetCore.Identity.MongoDriver.Mongo;

public static class MongoUtil
{
    public static IMongoCollection<TItem> FromConnectionString<TItem>(MongoIdentityOptions options, string collectionName)
    {
        IMongoCollection<TItem> collection;

        if (options.ConnectionString is not null)
        {
            MongoUrl url = new(options.ConnectionString);
            MongoClientSettings? settings = MongoClientSettings.FromUrl(url);

            settings.SslSettings = options.SslSettings;
            settings.ClusterConfigurator = options.ClusterConfigurator;

            MongoClient client = new(settings);
            collection = client.GetDatabase(url.DatabaseName ?? "default")
                .GetCollection<TItem>(collectionName);
        }
        else
        {
            MongoClientSettings settings = new()
            {
                SslSettings = options.SslSettings,
                ClusterConfigurator = options.ClusterConfigurator
            };

            collection = new MongoClient(settings).GetDatabase("default")
                .GetCollection<TItem>(collectionName);
        }

        return collection;
    }
}