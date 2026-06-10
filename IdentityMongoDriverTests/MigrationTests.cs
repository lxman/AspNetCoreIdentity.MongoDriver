using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Migrations;
using MongoDB.Driver;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using Mongo2Go;

namespace IdentityMongoDriverTests;

public class MigrationTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();

    public MigrationTests()
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

    [Fact]
    public async Task Schema4Migration_ShouldMoveAuthenticatorKeyToTokens()
    {
        MongoClient client = new(_runner.ConnectionString);
        IMongoDatabase db = client.GetDatabase("MigrationTest");
        IMongoCollection<MigrationMongoUser<Guid>> usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>> rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid userId = Guid.NewGuid();
        MigrationMongoUser<Guid> user = new()
        {
            Id = userId,
            UserName = "test",
            AuthenticatorKey = "OLD_KEY"
        };
        await usersCollection.InsertOneAsync(user);

        Schema4Migration migration = new();
        await migration.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection, CancellationToken.None);

        MigrationMongoUser<Guid>? updatedUser = await usersCollection.Find(u => u.Id == userId).FirstOrDefaultAsync();
        Assert.NotNull(updatedUser);
        Assert.Null(updatedUser.AuthenticatorKey);
        Assert.Contains(updatedUser.Tokens, t => t.Name == "AuthenticatorKey" && t.Value == "OLD_KEY" && t.LoginProvider == "[AspNetUserStore]");
    }

    [Fact]
    public async Task Schema5Migration_ShouldUnsetLegacyProperties()
    {
        MongoClient client = new(_runner.ConnectionString);
        IMongoDatabase db = client.GetDatabase("MigrationTest5");
        IMongoCollection<MigrationMongoUser<Guid>> usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>> rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid userId = Guid.NewGuid();
        // We use BsonDocument to insert properties that might be removed from the C# model or to ensure they exist in DB
        await db.GetCollection<BsonDocument>("Users").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(userId, GuidRepresentation.Standard) },
            { "UserName", "test5" },
            { "AuthenticatorKey", "SOME_KEY" },
            { "RecoveryCodes", new BsonArray { new BsonDocument { { "Code", "123" }, { "Redeemed", false } } } }
        });

        Schema5Migration migration = new();
        await migration.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection, CancellationToken.None);

        BsonDocument? doc = await db.GetCollection<BsonDocument>("Users")
            .Find(Builders<BsonDocument>.Filter.Eq("_id", userId))
            .FirstOrDefaultAsync();
        Assert.NotNull(doc);
        Assert.False(doc.Contains("AuthenticatorKey"));
        Assert.False(doc.Contains("RecoveryCodes"));
    }

    [Fact]
    public async Task Schema6Migration_ShouldConvertLegacyRoleNamesToRoleIds()
    {
        MongoClient client = new(_runner.ConnectionString);
        IMongoDatabase db = client.GetDatabase("MigrationTest6");
        IMongoCollection<MigrationMongoUser<Guid>> usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>> rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid roleId = Guid.NewGuid();
        await db.GetCollection<BsonDocument>("Roles").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(roleId, GuidRepresentation.Standard) },
            { "Name", "Administrator" },
            { "NormalizedName", "ADMINISTRATOR" }
        });

        // A legacy (pre-id-based) user document: role membership stored as name strings,
        // including one referencing a role that no longer exists.
        Guid userId = Guid.NewGuid();
        await db.GetCollection<BsonDocument>("Users").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(userId, GuidRepresentation.Standard) },
            { "UserName", "test6" },
            { "Roles", new BsonArray { "ADMINISTRATOR", "GHOST_ROLE" } }
        });

        Schema6Migration migration = new();
        await migration.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection, CancellationToken.None);

        // The migrated document must deserialize into the current model with the role id.
        MongoUser<Guid>? migratedUser = await db.GetCollection<MongoUser<Guid>>("Users")
            .Find(u => u.Id == userId)
            .FirstOrDefaultAsync();
        Assert.NotNull(migratedUser);
        Guid convertedRoleId = Assert.Single(migratedUser.Roles);
        Assert.Equal(roleId, convertedRoleId);
    }

    [Fact]
    public async Task Schema6Migration_ShouldLeaveIdBasedDocumentsUntouched()
    {
        MongoClient client = new(_runner.ConnectionString);
        IMongoDatabase db = client.GetDatabase("MigrationTest6b");
        IMongoCollection<MigrationMongoUser<Guid>> usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>> rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid roleId = Guid.NewGuid();
        await db.GetCollection<BsonDocument>("Roles").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(roleId, GuidRepresentation.Standard) },
            { "Name", "Administrator" },
            { "NormalizedName", "ADMINISTRATOR" }
        });

        Guid userId = Guid.NewGuid();
        await db.GetCollection<BsonDocument>("Users").InsertOneAsync(new BsonDocument
        {
            { "_id", new BsonBinaryData(userId, GuidRepresentation.Standard) },
            { "UserName", "test6b" },
            { "Roles", new BsonArray { new BsonBinaryData(roleId, GuidRepresentation.Standard) } }
        });

        Schema6Migration migration = new();
        await migration.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection, CancellationToken.None);

        MongoUser<Guid>? migratedUser = await db.GetCollection<MongoUser<Guid>>("Users")
            .Find(u => u.Id == userId)
            .FirstOrDefaultAsync();
        Assert.NotNull(migratedUser);
        Guid keptRoleId = Assert.Single(migratedUser.Roles);
        Assert.Equal(roleId, keptRoleId);
    }
}
