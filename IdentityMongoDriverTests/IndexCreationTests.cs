using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Driver;
using Mongo2Go;

namespace IdentityMongoDriverTests;

/// <summary>
/// Tests for the indexes created on first use: the unique partial index on normalized user
/// name, the non-unique normalized email index, the login provider/key compound index, the
/// unique partial index on normalized role name, and idempotent re-creation.
/// </summary>
public class IndexCreationTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();
    private readonly IMongoDatabase _db;

    public IndexCreationTests()
    {
        try
        {
            BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));
        }
        catch (BsonSerializationException)
        {
            // Already registered
        }

        _db = new MongoClient(_runner.ConnectionString).GetDatabase("IndexTest");
    }

    public void Dispose()
    {
        _runner.Dispose();
    }

    private Task InitializeAsync(CancellationToken cancellationToken) =>
        MongoIdentityInitialization.InitializeAsync<MongoUser<Guid>, MongoRole<Guid>, Guid>(
            new MongoIdentityOptions { DisableAutoMigrations = true },
            _db.GetCollection<MigrationHistory>("_Migrations"),
            _db.GetCollection<MigrationMongoUser<Guid>>("Users"),
            _db.GetCollection<MongoUser<Guid>>("Users"),
            _db.GetCollection<MongoRole<Guid>>("Roles"),
            cancellationToken);

    private async Task<List<BsonDocument>> IndexesAsync(string collection)
    {
        return await _db.GetCollection<BsonDocument>(collection).Indexes
            .List(TestContext.Current.CancellationToken)
            .ToListAsync(TestContext.Current.CancellationToken);
    }

    private static BsonDocument ByName(IEnumerable<BsonDocument> indexes, string name)
    {
        BsonDocument? match = indexes.SingleOrDefault(i => i["name"].AsString == name);
        Assert.NotNull(match);
        return match;
    }

    [Fact]
    public async Task Initialize_CreatesUniquePartialUserNameIndex()
    {
        await InitializeAsync(TestContext.Current.CancellationToken);

        BsonDocument index = ByName(await IndexesAsync("Users"), MongoIndexNames.NormalizedUserName);
        Assert.True(index.GetValue("unique", false).ToBoolean());
        Assert.True(index.Contains("partialFilterExpression"));
    }

    [Fact]
    public async Task Initialize_CreatesNonUniqueEmailIndex()
    {
        await InitializeAsync(TestContext.Current.CancellationToken);

        BsonDocument index = ByName(await IndexesAsync("Users"), MongoIndexNames.NormalizedEmail);
        Assert.False(index.GetValue("unique", false).ToBoolean());
    }

    [Fact]
    public async Task Initialize_CreatesLoginProviderKeyIndex()
    {
        await InitializeAsync(TestContext.Current.CancellationToken);

        // Present by name and keyed on both login fields.
        BsonDocument index = ByName(await IndexesAsync("Users"), MongoIndexNames.LoginProviderKey);
        BsonDocument key = index["key"].AsBsonDocument;
        Assert.True(key.Contains("Logins.LoginProvider"));
        Assert.True(key.Contains("Logins.ProviderKey"));
    }

    [Fact]
    public async Task Initialize_CreatesUniquePartialRoleNameIndex()
    {
        await InitializeAsync(TestContext.Current.CancellationToken);

        BsonDocument index = ByName(await IndexesAsync("Roles"), MongoIndexNames.NormalizedRoleName);
        Assert.True(index.GetValue("unique", false).ToBoolean());
        Assert.True(index.Contains("partialFilterExpression"));
    }

    [Fact]
    public async Task Initialize_Twice_DoesNotThrow()
    {
        await InitializeAsync(TestContext.Current.CancellationToken);
        // A second initialization re-issues the same index creations; conflicting/duplicate
        // definitions must be swallowed rather than surfaced.
        await InitializeAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(ByName(await IndexesAsync("Users"), MongoIndexNames.NormalizedUserName));
    }
}
