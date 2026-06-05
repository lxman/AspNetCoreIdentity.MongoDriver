using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using MongoDB.Driver;
using Mongo2Go;
using Xunit;

namespace IdentityMongoDriverTests;

public class MultiTenancyTests : IDisposable
{
    private readonly MongoDbRunner _runner1 = MongoDbRunner.Start();
    private readonly MongoDbRunner _runner2 = MongoDbRunner.Start();

    public void Dispose()
    {
        _runner1.Dispose();
        _runner2.Dispose();
    }

    [Fact]
    public void FromConnectionString_ShouldReuseClientsForSameConnectionString()
    {
        MongoIdentityOptions options1 = new() { ConnectionString = _runner1.ConnectionString };
        MongoIdentityOptions options2 = new() { ConnectionString = _runner1.ConnectionString };

        IMongoCollection<MongoUser>? collection1 = MongoUtil.FromConnectionString<MongoUser>(options1, "Users");
        IMongoCollection<MongoUser>? collection2 = MongoUtil.FromConnectionString<MongoUser>(options2, "Users");

        Assert.Same(collection1.Database.Client, collection2.Database.Client);
    }

    [Fact]
    public void FromConnectionString_ShouldCreateDifferentClientsForDifferentConnectionStrings()
    {
        MongoIdentityOptions options1 = new() { ConnectionString = _runner1.ConnectionString };
        MongoIdentityOptions options2 = new() { ConnectionString = _runner2.ConnectionString };

        IMongoCollection<MongoUser>? collection1 = MongoUtil.FromConnectionString<MongoUser>(options1, "Users");
        IMongoCollection<MongoUser>? collection2 = MongoUtil.FromConnectionString<MongoUser>(options2, "Users");

        Assert.NotSame(collection1.Database.Client, collection2.Database.Client);
    }

    [Fact]
    public void FromConnectionString_ShouldHandleDatabaseNameInConnectionString()
    {
        string connStr = _runner1.ConnectionString.TrimEnd('/') + "/CustomDbName";
        MongoIdentityOptions options = new() { ConnectionString = connStr };

        IMongoCollection<MongoUser>? collection = MongoUtil.FromConnectionString<MongoUser>(options, "Users");

        Assert.Equal("CustomDbName", collection.Database.DatabaseNamespace.DatabaseName);
    }
}
