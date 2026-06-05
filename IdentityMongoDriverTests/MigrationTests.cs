using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Migrations;
using MongoDB.Driver;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using Mongo2Go;
using Xunit;
using Microsoft.AspNetCore.Identity;

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
    public void Schema4Migration_ShouldMoveAuthenticatorKeyToTokens()
    {
        MongoClient? client = new MongoClient(_runner.ConnectionString);
        IMongoDatabase? db = client.GetDatabase("MigrationTest");
        IMongoCollection<MigrationMongoUser<Guid>>? usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>>? rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid userId = Guid.NewGuid();
        MigrationMongoUser<Guid> user = new()
        {
            Id = userId,
            UserName = "test",
            AuthenticatorKey = "OLD_KEY"
        };
        usersCollection.InsertOne(user);

        Schema4Migration? migration = new Schema4Migration();
        migration.Apply<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection);

        MigrationMongoUser<Guid>? updatedUser = usersCollection.Find(u => u.Id == userId).FirstOrDefault();
        Assert.NotNull(updatedUser);
        Assert.Null(updatedUser.AuthenticatorKey);
        Assert.Contains(updatedUser.Tokens, t => t.Name == "AuthenticatorKey" && t.Value == "OLD_KEY" && t.LoginProvider == "[AspNetUserStore]");
    }

    [Fact]
    public void Schema5Migration_ShouldUnsetLegacyProperties()
    {
        MongoClient? client = new MongoClient(_runner.ConnectionString);
        IMongoDatabase? db = client.GetDatabase("MigrationTest5");
        IMongoCollection<MigrationMongoUser<Guid>>? usersCollection = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        IMongoCollection<MongoRole<Guid>>? rolesCollection = db.GetCollection<MongoRole<Guid>>("Roles");

        Guid userId = Guid.NewGuid();
        // We use BsonDocument to insert properties that might be removed from the C# model or to ensure they exist in DB
        usersCollection.Database.GetCollection<MongoDB.Bson.BsonDocument>("Users").InsertOne(new MongoDB.Bson.BsonDocument
        {
            { "_id", new BsonBinaryData(userId, GuidRepresentation.Standard) },
            { "UserName", "test5" },
            { "AuthenticatorKey", "SOME_KEY" },
            { "RecoveryCodes", new MongoDB.Bson.BsonArray { new MongoDB.Bson.BsonDocument { { "Code", "123" }, { "Redeemed", false } } } }
        });

        Schema5Migration? migration = new Schema5Migration();
        migration.Apply<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(usersCollection, rolesCollection);

        MongoDB.Bson.BsonDocument? doc = usersCollection.Database.GetCollection<MongoDB.Bson.BsonDocument>("Users").Find(Builders<MongoDB.Bson.BsonDocument>.Filter.Eq("_id", userId)).FirstOrDefault();
        Assert.NotNull(doc);
        Assert.False(doc.Contains("AuthenticatorKey"));
        Assert.False(doc.Contains("RecoveryCodes"));
    }
}
