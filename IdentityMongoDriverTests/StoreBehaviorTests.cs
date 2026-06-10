using AspNetCoreIdentity.MongoDriver;
using AspNetCoreIdentity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using Mongo2Go;

namespace IdentityMongoDriverTests;

/// <summary>
/// Regression tests for store-level update semantics, optimistic concurrency,
/// and index-backed uniqueness.
/// </summary>
public class StoreBehaviorTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();

    public StoreBehaviorTests()
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

    private ServiceProvider BuildServices()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(options => { }, mongo =>
        {
            mongo.ConnectionString = _runner.ConnectionString;
        });
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Update_WithNoChanges_Succeeds()
    {
        ServiceProvider provider = BuildServices();
        UserManager<MongoUser<Guid>> userManager = provider.GetRequiredService<UserManager<MongoUser<Guid>>>();

        MongoUser<Guid> user = new("noop@test.com");
        IdentityResult created = await userManager.CreateAsync(user);
        Assert.True(created.Succeeded);

        // Previously a no-op update replaced the document with an identical one,
        // MongoDB reported ModifiedCount 0, and the store returned a failure.
        IdentityResult first = await userManager.UpdateAsync(user);
        Assert.True(first.Succeeded);
        IdentityResult second = await userManager.UpdateAsync(user);
        Assert.True(second.Succeeded);
    }

    [Fact]
    public async Task Update_WithStaleInstance_FailsWithConcurrencyError()
    {
        ServiceProvider provider = BuildServices();
        UserManager<MongoUser<Guid>> userManager = provider.GetRequiredService<UserManager<MongoUser<Guid>>>();

        MongoUser<Guid> user = new("stale@test.com");
        Assert.True((await userManager.CreateAsync(user)).Succeeded);

        MongoUser<Guid> copyA = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        MongoUser<Guid> copyB = (await userManager.FindByIdAsync(user.Id.ToString()))!;

        copyA.PhoneNumber = "111-111-1111";
        Assert.True((await userManager.UpdateAsync(copyA)).Succeeded);

        copyB.PhoneNumber = "222-222-2222";
        IdentityResult staleResult = await userManager.UpdateAsync(copyB);
        Assert.False(staleResult.Succeeded);
        string concurrencyCode = new IdentityErrorDescriber().ConcurrencyFailure().Code;
        Assert.Contains(staleResult.Errors, e => e.Code == concurrencyCode);

        // The first writer's value won; the stale write did not clobber it.
        MongoUser<Guid> persisted = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        Assert.Equal("111-111-1111", persisted.PhoneNumber);
    }

    [Fact]
    public async Task Create_WithDuplicateUserName_FailsWithDuplicateUserNameError()
    {
        ServiceProvider provider = BuildServices();
        IUserStore<MongoUser<Guid>> store = provider.GetRequiredService<IUserStore<MongoUser<Guid>>>();

        // Going through the store directly bypasses the UserManager's pre-insert lookup,
        // so this exercises the unique index and the duplicate-key error mapping.
        MongoUser<Guid> first = new("dup@test.com");
        IdentityResult firstResult = await store.CreateAsync(first, CancellationToken.None);
        Assert.True(firstResult.Succeeded);

        MongoUser<Guid> second = new("dup@test.com");
        IdentityResult secondResult = await store.CreateAsync(second, CancellationToken.None);
        Assert.False(secondResult.Succeeded);
        string duplicateCode = new IdentityErrorDescriber().DuplicateUserName("dup@test.com").Code;
        Assert.Contains(secondResult.Errors, e => e.Code == duplicateCode);
    }

    [Fact]
    public async Task FindById_WithMalformedId_ReturnsNull()
    {
        ServiceProvider provider = BuildServices();
        UserManager<MongoUser<Guid>> userManager = provider.GetRequiredService<UserManager<MongoUser<Guid>>>();

        MongoUser<Guid>? found = await userManager.FindByIdAsync("definitely-not-a-guid");
        Assert.Null(found);
    }

    [Fact]
    public async Task RoleUpdate_WithStaleInstance_FailsWithConcurrencyError()
    {
        ServiceProvider provider = BuildServices();
        RoleManager<MongoRole<Guid>> roleManager = provider.GetRequiredService<RoleManager<MongoRole<Guid>>>();

        MongoRole<Guid> role = new("Editors");
        Assert.True((await roleManager.CreateAsync(role)).Succeeded);

        MongoRole<Guid> copyA = (await roleManager.FindByIdAsync(role.Id.ToString()))!;
        MongoRole<Guid> copyB = (await roleManager.FindByIdAsync(role.Id.ToString()))!;

        copyA.Name = "EditorsA";
        Assert.True((await roleManager.UpdateAsync(copyA)).Succeeded);

        copyB.Name = "EditorsB";
        IdentityResult staleResult = await roleManager.UpdateAsync(copyB);
        Assert.False(staleResult.Succeeded);
        string concurrencyCode = new IdentityErrorDescriber().ConcurrencyFailure().Code;
        Assert.Contains(staleResult.Errors, e => e.Code == concurrencyCode);
    }
}
