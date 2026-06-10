using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using Mongo2Go;
using Xunit;

namespace IdentityMongoDriverTests;

public class TKeyTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();

    public TKeyTests()
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
    public async Task ObjectId_Key_Tests()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser, MongoRole, ObjectId>(options => { }, mongo =>
        {
            mongo.ConnectionString = _runner.ConnectionString;
        });

        ServiceProvider serviceProvider = services.BuildServiceProvider();
        UserManager<MongoUser> userManager = serviceProvider.GetRequiredService<UserManager<MongoUser>>();
        RoleManager<MongoRole> roleManager = serviceProvider.GetRequiredService<RoleManager<MongoRole>>();

        MongoUser user = new("objectid@test.com");
        IdentityResult result = await userManager.CreateAsync(user);
        Assert.True(result.Succeeded);
        Assert.NotEqual(ObjectId.Empty, user.Id);

        MongoUser? found = await userManager.FindByIdAsync(user.Id.ToString());
        Assert.NotNull(found);
        Assert.Equal(user.Id, found.Id);

        // A malformed id is "not found", not an exception.
        MongoUser? notFound = await userManager.FindByIdAsync("definitely-not-an-objectid");
        Assert.Null(notFound);
    }

    [Fact]
    public async Task String_Key_Tests()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser<string>, MongoRole<string>, string>(options => { }, mongo =>
        {
            mongo.ConnectionString = _runner.ConnectionString;
        });

        ServiceProvider serviceProvider = services.BuildServiceProvider();
        UserManager<MongoUser<string>> userManager = serviceProvider.GetRequiredService<UserManager<MongoUser<string>>>();

        string userId = Guid.NewGuid().ToString();
        MongoUser<string> user = new("string@test.com") { Id = userId };
        IdentityResult result = await userManager.CreateAsync(user);
        Assert.True(result.Succeeded);
        Assert.Equal(userId, user.Id);

        MongoUser<string>? found = await userManager.FindByIdAsync(userId);
        Assert.NotNull(found);
        Assert.Equal(userId, found.Id);

        // Users created without an explicit string Id get a generated one; previously the
        // second such insert failed on a duplicate null _id.
        MongoUser<string> firstGenerated = new("autoid1@test.com");
        result = await userManager.CreateAsync(firstGenerated);
        Assert.True(result.Succeeded);
        Assert.False(string.IsNullOrEmpty(firstGenerated.Id));

        MongoUser<string> secondGenerated = new("autoid2@test.com");
        result = await userManager.CreateAsync(secondGenerated);
        Assert.True(result.Succeeded);
        Assert.False(string.IsNullOrEmpty(secondGenerated.Id));
        Assert.NotEqual(firstGenerated.Id, secondGenerated.Id);
    }

    [Fact]
    public async Task Guid_Key_Tests()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(options => { }, mongo =>
        {
            mongo.ConnectionString = _runner.ConnectionString;
        });

        ServiceProvider serviceProvider = services.BuildServiceProvider();
        UserManager<MongoUser<Guid>> userManager = serviceProvider.GetRequiredService<UserManager<MongoUser<Guid>>>();

        Guid userId = Guid.NewGuid();
        MongoUser<Guid> user = new("guid@test.com") { Id = userId };
        IdentityResult result = await userManager.CreateAsync(user);
        Assert.True(result.Succeeded);
        Assert.Equal(userId, user.Id);

        MongoUser<Guid>? found = await userManager.FindByIdAsync(userId.ToString());
        Assert.NotNull(found);
        Assert.Equal(userId, found.Id);
    }
}
