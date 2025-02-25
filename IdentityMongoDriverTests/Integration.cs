using System.Security.Claims;
using AspNetCoreIdentity.MongoDriver.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MongoDB.Driver.Linq;

namespace IdentityMongoDriverTests;

[Collection("Global Collection")]
public class Integration(GlobalFixture fixture)
{
    private readonly UserManager<MongoUser<Guid>> _userManager = fixture.UserManager;
    private readonly RoleManager<MongoRole<Guid>> _roleManager = fixture.RoleManager;

    [Fact]
    public async Task UserManager_Tests()
    {
        string passwordHash = _userManager.PasswordHasher.HashPassword(null!, "password");
        MongoUser<Guid>? user = new("test@example.com")
        {
            Email = "test@example.com",
            NormalizedEmail = "test@example.com".ToUpperInvariant(),
            NormalizedUserName = "test@example.com".ToUpperInvariant(),
            EmailConfirmed = true,
            PasswordHash = passwordHash
        };
        IdentityResult result = await _userManager.CreateAsync(user);
        Assert.True(result.Succeeded);
        MongoRole<Guid> role = new("Administrator");
        result = await _roleManager.CreateAsync(role);
        Assert.True(result.Succeeded);
        result = await _userManager.AddToRoleAsync(user, "Administrator");
        Assert.True(result.Succeeded);
        bool inRole = await _userManager.IsInRoleAsync(user, "Administrator");
        Assert.True(inRole);
        IList<MongoUser<Guid>> users = await _userManager.GetUsersInRoleAsync("Administrator");
        Assert.Single(users);
        user = await _userManager.FindByNameAsync("test@example.com");
        Assert.NotNull(user);
        result = await _userManager.RemoveFromRoleAsync(user, "Administrator");
        Assert.True(result.Succeeded);
        users = await _userManager.GetUsersInRoleAsync("Administrator");
        Assert.Empty(users);
        string id = await _userManager.GetUserIdAsync(user);
        Assert.DoesNotMatch(Guid.Empty.ToString(), id);
        string? name = await _userManager.GetUserNameAsync(user);
        Assert.NotNull(name);
        Assert.NotEqual(string.Empty, name);
        result = await _userManager.SetUserNameAsync(user, "joe@nowhere.com");
        Assert.True(result.Succeeded);
        name = await _userManager.GetUserNameAsync(user);
        Assert.NotNull(name);
        Assert.Equal("joe@nowhere.com", name);
        bool emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
        Assert.True(emailConfirmed);
        user.EmailConfirmed = false;
        result = await _userManager.UpdateAsync(user);
        Assert.True(result.Succeeded);
        emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
        Assert.False(emailConfirmed);
        user = await _userManager.FindByIdAsync(user.Id.ToString());
        Assert.NotNull(user);
        Claim claim = new("test", "value");
        result = await _userManager.AddClaimAsync(user, claim);
        Assert.True(result.Succeeded);
        IList<Claim> claims = await _userManager.GetClaimsAsync(user);
        Assert.Single(claims);
        claims.Add(new Claim("type1", "value1"));
        claims.Add(new Claim("type2", "value2"));
        claims.Add(new Claim("type3", "value3"));
        claims.RemoveAt(0);
        result = await _userManager.AddClaimsAsync(user, claims);
        Assert.True(result.Succeeded);
        claims = await _userManager.GetClaimsAsync(user);
        Assert.Equal(4, claims.Count);
        Claim claim2 = new("type4", "value4");
        result = await _userManager.ReplaceClaimAsync(user, new Claim("type2", "value2"), claim2);
        Assert.True(result.Succeeded);
        claims = await _userManager.GetClaimsAsync(user);
        Assert.Single(claims, c => c.Type == claim2.Type && c.Value == claim2.Value);
        IList<MongoUser<Guid>> usersWithClaim = await _userManager.GetUsersForClaimAsync(claims[0]);
        Assert.Single(usersWithClaim);
        result = await _userManager.RemoveClaimsAsync(user, claims);
        Assert.True(result.Succeeded);
        claims = await _userManager.GetClaimsAsync(user);
        Assert.Empty(claims);
        UserLoginInfo login = new("provider", "key", "name");
        result = await _userManager.AddLoginAsync(user, login);
        Assert.True(result.Succeeded);
        user = await _userManager.FindByLoginAsync(login.LoginProvider, login.ProviderKey);
        Assert.NotNull(user);
        IList<UserLoginInfo> logins = await _userManager.GetLoginsAsync(user);
        Assert.Single(logins);
        result = await _userManager.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
        Assert.True(result.Succeeded);
        bool hasPassword = await _userManager.HasPasswordAsync(user);
        Assert.True(hasPassword);
        result = await _userManager.RemovePasswordAsync(user);
        Assert.True(result.Succeeded);
        hasPassword = await _userManager.HasPasswordAsync(user);
        Assert.False(hasPassword);
        result = await _userManager.AddPasswordAsync(user, "password");
        Assert.False(result.Succeeded);
        hasPassword = await _userManager.HasPasswordAsync(user);
        Assert.False(hasPassword);
        result = await _userManager.AddPasswordAsync(user, "Password1!");
        Assert.True(result.Succeeded);
        result = await _userManager.ChangePasswordAsync(user, "Password1!", "Password2!");
        Assert.True(result.Succeeded);
        bool passwordOk = await _userManager.CheckPasswordAsync(user, "Password");
        Assert.False(passwordOk);
        passwordOk = await _userManager.CheckPasswordAsync(user, "Password2!");
        Assert.True(passwordOk);
        string resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        Assert.NotNull(resetToken);
        Assert.NotEqual(string.Empty, resetToken);
        result = await _userManager.ResetPasswordAsync(user, resetToken, "Password3!");
        Assert.True(result.Succeeded);
        result = await _userManager.UpdateSecurityStampAsync(user);
        Assert.True(result.Succeeded);
        string stamp = await _userManager.GetSecurityStampAsync(user);
        Assert.NotNull(stamp);
        Assert.NotEmpty(stamp);
        string? email = await _userManager.GetEmailAsync(user);
        Assert.NotNull(email);
        Assert.NotEqual(string.Empty, email);
        user = await _userManager.FindByEmailAsync(email);
        Assert.NotNull(user);
        string emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        Assert.NotNull(emailToken);
        Assert.NotEqual(string.Empty, emailToken);
        result = await _userManager.ConfirmEmailAsync(user, emailToken);
        Assert.True(result.Succeeded);
        emailToken = await _userManager.GenerateChangeEmailTokenAsync(user, "my.new.email@nowhere.com");
        Assert.NotNull(emailToken);
        Assert.NotEqual(string.Empty, emailToken);
        result = await _userManager.ChangeEmailAsync(user, "my.new.email@nowhere.com", emailToken);
        Assert.True(result.Succeeded);
        emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
        Assert.True(emailConfirmed);
        string? normalizedEmail = _userManager.NormalizeEmail(user.Email);
        Assert.NotNull(normalizedEmail);
        Assert.Equal(user.Email?.ToUpperInvariant(), normalizedEmail);
        result = await _userManager.SetEmailAsync(user, "yet.another.email@yahoo.com");
        Assert.True(result.Succeeded);
        await _userManager.UpdateNormalizedEmailAsync(user);
        Assert.Equal("yet.another.email@yahoo.com".ToUpperInvariant(), user.NormalizedEmail);
        string? phoneNumber = await _userManager.GetPhoneNumberAsync(user);
        Assert.Null(phoneNumber);
        result = await _userManager.SetPhoneNumberAsync(user, "123-456-7890");
        Assert.True(result.Succeeded);
        phoneNumber = await _userManager.GetPhoneNumberAsync(user);
        Assert.NotNull(phoneNumber);
        Assert.Equal("123-456-7890", phoneNumber);
        string phoneToken = await _userManager.GenerateChangePhoneNumberTokenAsync(user, "098-765-4321");
        Assert.NotEqual(string.Empty, phoneToken);
        bool tokenOk = await _userManager.VerifyChangePhoneNumberTokenAsync(user, phoneToken, "098-765-4321");
        Assert.True(tokenOk);
        result = await _userManager.ChangePhoneNumberAsync(user, "098-765-4321", phoneToken);
        Assert.True(result.Succeeded);
        bool phoneConfirmed = await _userManager.IsPhoneNumberConfirmedAsync(user);
        Assert.True(phoneConfirmed);
        bool twoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        Assert.False(twoFactorEnabled);
        result = await _userManager.SetTwoFactorEnabledAsync(user, true);
        Assert.True(result.Succeeded);
        twoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        Assert.True(twoFactorEnabled);
        List<string> codes = (await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 12))!.ToList();
        Assert.Equal(12, codes.Count);
        IList<string> validProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
        Assert.NotEmpty(validProviders);
        string twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, validProviders[0]);
        Assert.NotNull(twoFactorToken);
        Assert.NotEmpty(twoFactorToken);
        bool tokenVerified = await _userManager.VerifyTwoFactorTokenAsync(user, validProviders[0], twoFactorToken);
        Assert.True(tokenVerified);
        result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, codes[0]);
        Assert.True(result.Succeeded);
        result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, codes[0]);
        Assert.False(result.Succeeded);
        result = await _userManager.SetLockoutEnabledAsync(user, false);
        Assert.True(result.Succeeded);
        bool lockoutEnabled = await _userManager.GetLockoutEnabledAsync(user);
        Assert.False(lockoutEnabled);
        result = await _userManager.SetLockoutEnabledAsync(user, true);
        Assert.True(result.Succeeded);
        result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.True(result.Succeeded);
        bool lockedOut = await _userManager.IsLockedOutAsync(user);
        Assert.True(lockedOut);
        _ = await _userManager.SetLockoutEndDateAsync(user, null);
        lockedOut = await _userManager.IsLockedOutAsync(user);
        Assert.False(lockedOut);
        DateTimeOffset? lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        Assert.Null(lockoutEnd);
        int failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
        Assert.Equal(0, failedAttempts);
        result = await _userManager.AccessFailedAsync(user);
        Assert.True(result.Succeeded);
        failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
        Assert.Equal(1, failedAttempts);
        result = await _userManager.ResetAccessFailedCountAsync(user);
        Assert.True(result.Succeeded);
        failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
        Assert.Equal(0, failedAttempts);
        string authenticatorKey = _userManager.GenerateNewAuthenticatorKey();
        Assert.NotEqual(0, authenticatorKey.Length);
        string? key = await _userManager.GetAuthenticatorKeyAsync(user);
        Assert.Null(key);
        result = await _userManager.ResetAuthenticatorKeyAsync(user);
        Assert.True(result.Succeeded);
        _userManager.RegisterTokenProvider("secret-provider", new DataProtectorTokenProvider<MongoUser<Guid>>(new EphemeralDataProtectionProvider(), new OptionsWrapper<DataProtectionTokenProviderOptions>(new DataProtectionTokenProviderOptions())));
        string authenticationToken = await _userManager.GenerateUserTokenAsync(user, "secret-provider", "authentication");
        Assert.NotNull(authenticationToken);
        bool verified = await _userManager.VerifyUserTokenAsync(user, "secret-provider", "authentication", authenticationToken);
        Assert.True(verified);
        result = await _userManager.RemoveAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey");
        Assert.True(result.Succeeded);
        result = await _userManager.DeleteAsync(user);
        Assert.True(result.Succeeded);
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await _userManager.CreateAsync(null!));
    }

    [Fact]
    public async Task RoleManager_Tests()
    {
        List<MongoRole<Guid>>? roles = await _roleManager.Roles.ToListAsync();
        roles.ForEach(r => _roleManager.DeleteAsync(r));

        // Create a new role
        MongoRole<Guid> role = new("Administrator");
        IdentityResult result = await _roleManager.CreateAsync(role);
        Assert.True(result.Succeeded);

        // Find role by name
        MongoRole<Guid>? foundRole = await _roleManager.FindByNameAsync("Administrator");
        Assert.NotNull(foundRole);
        Assert.Equal(role.Name, foundRole.Name);

        // Find role by ID
        foundRole = await _roleManager.FindByIdAsync(role.Id.ToString());
        Assert.NotNull(foundRole);
        Assert.Equal(role.Id, foundRole.Id);

        // Update role
        role.Name = "Admin";
        result = await _roleManager.UpdateAsync(role);
        Assert.True(result.Succeeded);
        foundRole = await _roleManager.FindByIdAsync(role.Id.ToString());
        Assert.Equal("Admin", foundRole?.Name);

        // Add claim to role
        Claim claim = new("Permission", "Edit");
        result = await _roleManager.AddClaimAsync(role, claim);
        Assert.True(result.Succeeded);
        IList<Claim> claims = await _roleManager.GetClaimsAsync(role);
        Assert.Single(claims);
        Assert.Equal(claim.Type, claims[0].Type);
        Assert.Equal(claim.Value, claims[0].Value);

        // Remove claim from role
        result = await _roleManager.RemoveClaimAsync(role, claim);
        Assert.True(result.Succeeded);
        claims = await _roleManager.GetClaimsAsync(role);
        Assert.Empty(claims);

        // Delete role
        result = await _roleManager.DeleteAsync(role);
        Assert.True(result.Succeeded);
        foundRole = await _roleManager.FindByIdAsync(role.Id.ToString());
        Assert.Null(foundRole);

        // Role exists
        bool roleExists = await _roleManager.RoleExistsAsync("Admin");
        Assert.False(roleExists);

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await _roleManager.CreateAsync(null!));
    }
}