using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Driver;
using Mongo2Go;

namespace IdentityMongoDriverTests;

/// <summary>
/// End-to-end tests for the lazily-triggered store initialization wired up by
/// <c>AddIdentityMongoDbProvider</c>: auto-migration on first use, the option toggles that
/// disable migrations or index creation, and honoring a custom migration collection name.
/// </summary>
public class AutoInitializationTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();

    public AutoInitializationTests()
    {
        try
        {
            BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));
        }
        catch (BsonSerializationException)
        {
            // Already registered
        }
    }

    public void Dispose()
    {
        _runner.Dispose();
    }

    private IMongoDatabase Database(string dbName) =>
        new MongoClient(_runner.ConnectionString).GetDatabase(dbName);

    private ServiceProvider BuildProvider(string dbName, Action<MongoIdentityOptions> configure)
    {
        // A database name in the connection string keeps the store and the test's own seed
        // writes in the same database.
        string connectionString = _runner.ConnectionString.TrimEnd('/') + "/" + dbName;

        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(_ => { }, mongo =>
        {
            mongo.ConnectionString = connectionString;
            configure(mongo);
        });
        return services.BuildServiceProvider();
    }

    private async Task SeedLegacyUserAsync(string dbName, Guid userId, string authenticatorKey)
    {
        await Database(dbName).GetCollection<BsonDocument>("Users").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(userId, GuidRepresentation.Standard) },
            { "UserName", "legacy" },
            { "AuthenticatorKey", authenticatorKey }
        }, cancellationToken: TestContext.Current.CancellationToken);
    }

    private async Task<MigrationMongoUser<Guid>?> ReadUserAsync(string dbName, Guid userId)
    {
        return await Database(dbName).GetCollection<MigrationMongoUser<Guid>>("Users")
            .Find(u => u.Id == userId)
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task EnsureInitialized_RunsMigrationsLazilyOnFirstCall()
    {
        const string dbName = "AutoInit_Default";
        Guid userId = Guid.NewGuid();
        await SeedLegacyUserAsync(dbName, userId, "OLD_KEY");

        ServiceProvider provider = BuildProvider(dbName, _ => { });
        MongoIdentityInitializer initializer = provider.GetRequiredService<MongoIdentityInitializer>();
        IMongoCollection<MigrationHistory> history = Database(dbName).GetCollection<MigrationHistory>("_Migrations");

        // Nothing runs at registration time: the history is empty until initialization fires.
        Assert.Equal(0, await history.CountDocumentsAsync(FilterDefinition<MigrationHistory>.Empty,
            cancellationToken: TestContext.Current.CancellationToken));

        await initializer.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        Assert.Equal(3, await history.CountDocumentsAsync(FilterDefinition<MigrationHistory>.Empty,
            cancellationToken: TestContext.Current.CancellationToken));
        MigrationMongoUser<Guid>? migrated = await ReadUserAsync(dbName, userId);
        Assert.NotNull(migrated);
        Assert.Null(migrated.AuthenticatorKey);
        Assert.Contains(migrated.Tokens, t => t.Name == "AuthenticatorKey" && t.Value == "OLD_KEY");
    }

    [Fact]
    public async Task StoreOperation_TriggersInitialization()
    {
        const string dbName = "AutoInit_StoreTrigger";
        Guid userId = Guid.NewGuid();
        await SeedLegacyUserAsync(dbName, userId, "OLD_KEY");

        ServiceProvider provider = BuildProvider(dbName, _ => { });
        UserManager<MongoUser<Guid>> userManager = provider.GetRequiredService<UserManager<MongoUser<Guid>>>();

        // A plain store read is enough to drive the one-time migration.
        await userManager.FindByIdAsync(userId.ToString());

        MigrationMongoUser<Guid>? migrated = await ReadUserAsync(dbName, userId);
        Assert.NotNull(migrated);
        Assert.Null(migrated.AuthenticatorKey);
        Assert.Contains(migrated.Tokens, t => t.Name == "AuthenticatorKey" && t.Value == "OLD_KEY");
    }

    [Fact]
    public async Task DisableAutoMigrations_LeavesLegacyDataUntouched()
    {
        const string dbName = "AutoInit_NoMigrations";
        Guid userId = Guid.NewGuid();
        await SeedLegacyUserAsync(dbName, userId, "OLD_KEY");

        ServiceProvider provider = BuildProvider(dbName, mongo => mongo.DisableAutoMigrations = true);
        MongoIdentityInitializer initializer = provider.GetRequiredService<MongoIdentityInitializer>();

        await initializer.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        // No migration ran: the legacy field is still present and no history was recorded.
        MigrationMongoUser<Guid>? user = await ReadUserAsync(dbName, userId);
        Assert.NotNull(user);
        Assert.Equal("OLD_KEY", user.AuthenticatorKey);
        Assert.Equal(0, await Database(dbName).GetCollection<MigrationHistory>("_Migrations")
            .CountDocumentsAsync(FilterDefinition<MigrationHistory>.Empty,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DisableIndexCreation_CreatesNoIdentityIndexes()
    {
        const string dbName = "AutoInit_NoIndexes";
        Guid userId = Guid.NewGuid();
        await SeedLegacyUserAsync(dbName, userId, "OLD_KEY");

        ServiceProvider provider = BuildProvider(dbName, mongo => mongo.DisableIndexCreation = true);
        MongoIdentityInitializer initializer = provider.GetRequiredService<MongoIdentityInitializer>();

        await initializer.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        List<BsonDocument> indexes = await Database(dbName).GetCollection<BsonDocument>("Users").Indexes
            .List(TestContext.Current.CancellationToken)
            .ToListAsync(TestContext.Current.CancellationToken);
        List<string> names = indexes.Select(i => i["name"].AsString).ToList();
        Assert.DoesNotContain(MongoIndexNames.NormalizedUserName, names);
        Assert.DoesNotContain(MongoIndexNames.NormalizedEmail, names);
        Assert.DoesNotContain(MongoIndexNames.LoginProviderKey, names);
    }

    [Fact]
    public async Task CustomMigrationCollection_IsHonored()
    {
        const string dbName = "AutoInit_CustomCollection";
        Guid userId = Guid.NewGuid();
        await SeedLegacyUserAsync(dbName, userId, "OLD_KEY");

        ServiceProvider provider = BuildProvider(dbName, mongo => mongo.MigrationCollection = "custom_migrations");
        MongoIdentityInitializer initializer = provider.GetRequiredService<MongoIdentityInitializer>();

        await initializer.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        // History lands in the configured collection, not the default one.
        Assert.Equal(3, await Database(dbName).GetCollection<MigrationHistory>("custom_migrations")
            .CountDocumentsAsync(FilterDefinition<MigrationHistory>.Empty,
                cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, await Database(dbName).GetCollection<MigrationHistory>("_Migrations")
            .CountDocumentsAsync(FilterDefinition<MigrationHistory>.Empty,
                cancellationToken: TestContext.Current.CancellationToken));
    }
}
