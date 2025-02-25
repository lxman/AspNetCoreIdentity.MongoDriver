using MongoDB.Driver;

namespace AspNetCore.Identity.MongoDriver.Mongo;

public static class MongoUtil
{
    public static IMongoCollection<TItem> FromConnectionString<TItem>(MongoIdentityOptions options, string collectionName)
    {
        IMongoCollection<TItem> collection;

        Type type = typeof(TItem);


        if (options.ConnectionString is not null)
        {
            var url = new MongoUrl(options.ConnectionString);
            MongoClientSettings? settings = MongoClientSettings.FromUrl(url);

            settings.SslSettings = options.SslSettings;
            settings.ClusterConfigurator = options.ClusterConfigurator;

            var client = new MongoClient(settings);
            collection = client.GetDatabase(url.DatabaseName ?? "default")
                .GetCollection<TItem>(collectionName);
        }
        else
        {
            var settings = new MongoClientSettings
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