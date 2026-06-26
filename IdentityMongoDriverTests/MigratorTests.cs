using AspNetCoreIdentity.MongoDriver.Migrations;
using AspNetCoreIdentity.MongoDriver.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Driver;
using Mongo2Go;

namespace IdentityMongoDriverTests;

/// <summary>
/// Tests for the migration orchestrator: it runs the outstanding migration chain, records
/// each step in the history as it completes, is idempotent on a current database, and
/// resumes from a partially migrated database without re-running earlier steps.
/// </summary>
public class MigratorTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();
    private readonly IMongoCollection<MigrationHistory> _history;
    private readonly IMongoCollection<MigrationMongoUser<Guid>> _users;
    private readonly IMongoCollection<MongoRole<Guid>> _roles;

    public MigratorTests()
    {
        try
        {
            BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));
        }
        catch (BsonSerializationException)
        {
            // Already registered
        }

        IMongoDatabase db = new MongoClient(_runner.ConnectionString).GetDatabase("MigratorTest");
        _history = db.GetCollection<MigrationHistory>("_Migrations");
        _users = db.GetCollection<MigrationMongoUser<Guid>>("Users");
        _roles = db.GetCollection<MongoRole<Guid>>("Roles");
    }

    public void Dispose()
    {
        _runner.Dispose();
    }

    private async Task<List<int>> RecordedVersionsAsync()
    {
        List<MigrationHistory> history = await _history.Find(_ => true)
            .ToListAsync(TestContext.Current.CancellationToken);
        return history.Select(h => h.DatabaseVersion).OrderBy(v => v).ToList();
    }

    [Fact]
    public async Task Apply_OnFreshDatabase_RunsWholeChainAndRecordsEachStep()
    {
        await Migrator.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(
            _history, _users, _roles, TestContext.Current.CancellationToken);

        // One history record per migration (Schema4/5/6), each stamped with Version + 1.
        Assert.Equal(new[] { 5, 6, 7 }, await RecordedVersionsAsync());
    }

    [Fact]
    public async Task Apply_Twice_IsIdempotent()
    {
        await Migrator.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(
            _history, _users, _roles, TestContext.Current.CancellationToken);
        await Migrator.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(
            _history, _users, _roles, TestContext.Current.CancellationToken);

        // The second run finds the database already current and adds nothing.
        Assert.Equal(new[] { 5, 6, 7 }, await RecordedVersionsAsync());
    }

    [Fact]
    public async Task Apply_MigratesLegacyData()
    {
        Guid userId = Guid.NewGuid();
        MigrationMongoUser<Guid> user = new()
        {
            Id = userId,
            UserName = "legacy",
            AuthenticatorKey = "OLD_KEY"
        };
        await _users.InsertOneAsync(user, cancellationToken: TestContext.Current.CancellationToken);

        await Migrator.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(
            _history, _users, _roles, TestContext.Current.CancellationToken);

        // Schema4's effect: the authenticator key is moved out of its own field into a token.
        MigrationMongoUser<Guid>? migrated = await _users.Find(u => u.Id == userId)
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(migrated);
        Assert.Null(migrated.AuthenticatorKey);
        Assert.Contains(migrated.Tokens,
            t => t.Name == "AuthenticatorKey" && t.Value == "OLD_KEY" && t.LoginProvider == "[AspNetUserStore]");
        Assert.Equal(new[] { 5, 6, 7 }, await RecordedVersionsAsync());
    }

    [Fact]
    public async Task Apply_OnPartiallyMigratedDatabase_RunsOnlyRemainingSteps()
    {
        // Schema4 already recorded (DatabaseVersion 5): the chain should resume from Schema5.
        await _history.InsertOneAsync(
            new MigrationHistory { Id = ObjectId.GenerateNewId(), InstalledOn = DateTime.UtcNow, DatabaseVersion = 5 },
            cancellationToken: TestContext.Current.CancellationToken);

        await Migrator.ApplyAsync<MigrationMongoUser<Guid>, MongoRole<Guid>, Guid>(
            _history, _users, _roles, TestContext.Current.CancellationToken);

        // Only Schema5 (-> 6) and Schema6 (-> 7) are appended; Schema4 is not re-run.
        Assert.Equal(new[] { 5, 6, 7 }, await RecordedVersionsAsync());
    }
}
