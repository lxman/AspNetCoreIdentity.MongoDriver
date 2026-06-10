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

public class SecurityTests : IDisposable
{
    private readonly MongoDbRunner _runner = MongoDbRunner.Start();

    public SecurityTests()
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

    private UserManager<MongoUser<Guid>> GetUserManager()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(options =>
        {
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            options.Lockout.MaxFailedAccessAttempts = 3;
            options.Lockout.AllowedForNewUsers = true;
        }, mongo =>
        {
            mongo.ConnectionString = _runner.ConnectionString;
        });

        ServiceProvider serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<UserManager<MongoUser<Guid>>>();
    }

    [Fact]
    public async Task UserLockout_Tests()
    {
        UserManager<MongoUser<Guid>>? userManager = GetUserManager();
        MongoUser<Guid> user = new("lockout@test.com");
        await userManager.CreateAsync(user, "Password123!");

        Assert.True(await userManager.GetLockoutEnabledAsync(user));

        // Fail 3 times
        await userManager.AccessFailedAsync(user);
        await userManager.AccessFailedAsync(user);
        await userManager.AccessFailedAsync(user);

        // We need to refresh the user object from the database to see the updated lockout state
        user = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        Assert.NotNull(user);

        Assert.True(await userManager.IsLockedOutAsync(user));
        
        DateTimeOffset? lockoutEnd = await userManager.GetLockoutEndDateAsync(user);
        Assert.NotNull(lockoutEnd);
        Assert.True(lockoutEnd > DateTimeOffset.UtcNow);

        await userManager.ResetAccessFailedCountAsync(user);
        
        // Refresh again
        user = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        Assert.NotNull(user);
        Assert.Equal(0, await userManager.GetAccessFailedCountAsync(user));

        // Manually clear lockout end for testing ResetAccessFailedCount behavior expectations
        await userManager.SetLockoutEndDateAsync(user, null);
        Assert.False(await userManager.IsLockedOutAsync(user));
    }

    [Fact]
    public async Task TwoFactor_Tests()
    {
        UserManager<MongoUser<Guid>>? userManager = GetUserManager();
        MongoUser<Guid> user = new("2fa@test.com");
        await userManager.CreateAsync(user, "Password123!");

        Assert.False(await userManager.GetTwoFactorEnabledAsync(user));
        await userManager.SetTwoFactorEnabledAsync(user, true);
        Assert.True(await userManager.GetTwoFactorEnabledAsync(user));

        string? key = await userManager.GetAuthenticatorKeyAsync(user);
        if (key == null)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);
        }
        Assert.NotNull(key);

        IEnumerable<string>? codes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);
        Assert.NotNull(codes);
        Assert.Equal(5, codes.Count());
        
        // Refresh to see tokens in memory if they were persisted only to DB
        user = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        Assert.NotNull(user);

        int count = await userManager.CountRecoveryCodesAsync(user);
        Assert.Equal(5, count);

        string firstCode = codes.First();
        IdentityResult? redeemResult = await userManager.RedeemTwoFactorRecoveryCodeAsync(user, firstCode);
        Assert.True(redeemResult.Succeeded);

        // Refresh after redemption
        user = (await userManager.FindByIdAsync(user.Id.ToString()))!;
        Assert.NotNull(user);

        count = await userManager.CountRecoveryCodesAsync(user);
        Assert.Equal(4, count);
    }
}
