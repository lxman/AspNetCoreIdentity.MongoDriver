using System.ComponentModel;
using System.Security.Claims;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Linq;


namespace AspNetCoreIdentity.MongoDriver.Stores;

public class UserStore<TUser, TRole, TKey> :
    IUserClaimStore<TUser>,
    IUserLoginStore<TUser>,
    IUserRoleStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserEmailStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IQueryableUserStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserLockoutStore<TUser>,
    IUserAuthenticatorKeyStore<TUser>,
    IUserAuthenticationTokenStore<TUser>,
    IUserTwoFactorRecoveryCodeStore<TUser>
    where TUser : MongoUser<TKey>
    where TRole : MongoRole<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>
    /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
    /// </summary>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <summary>
    /// A navigation property for the users that the store contains.
    /// </summary>
    public IQueryable<TUser> Users => _userCollection.AsQueryable();

    public IQueryable<TRole> Roles => _roleCollection.AsQueryable();

    private readonly IMongoCollection<TUser> _userCollection;
    private readonly IMongoCollection<TRole> _roleCollection;
    private readonly MongoIdentityInitializer? _initializer;

    private const string InternalLoginProvider = "[AspNetUserStore]";
    private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
    private const string RecoveryCodeTokenName = "RecoveryCodes";

    private bool _disposed;

    /// <summary>
    /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TKey}"/>.
    /// </summary>
    /// <param name="userCollection">The user mongo collection.</param>
    /// <param name="roleCollection">The role mongo collection.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public UserStore(
        IMongoCollection<TUser> userCollection,
        IMongoCollection<TRole> roleCollection,
        IdentityErrorDescriber? describer)
        : this(userCollection, roleCollection, describer, null)
    {
    }

    internal UserStore(
        IMongoCollection<TUser> userCollection,
        IMongoCollection<TRole> roleCollection,
        IdentityErrorDescriber? describer,
        MongoIdentityInitializer? initializer)
    {
        _userCollection = userCollection;
        _roleCollection = roleCollection;
        _initializer = initializer;
        ErrorDescriber = describer ?? new IdentityErrorDescriber();
    }

    public async Task<string> GetUserIdAsync(TUser? user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.Id.ToString() ?? string.Empty;
    }

    public async Task<string?> GetUserNameAsync(TUser? user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.UserName;
    }

    public async Task SetUserNameAsync(TUser user, string? userName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.UserName = userName;
    }

    public async Task<string?> GetNormalizedUserNameAsync(TUser? user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.NormalizedUserName;
    }

    public async Task SetNormalizedUserNameAsync(TUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.NormalizedUserName = normalizedName;
    }

    public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        if (typeof(TKey) == typeof(string))
        {
            // The driver has no default id generator for string keys, so without this a
            // second user created without an explicit Id fails on the duplicate null _id.
            object? rawId = user.Id;
            if (rawId is null || (rawId is string stringId && stringId.Length == 0))
            {
                user.Id = (TKey)(object)ObjectId.GenerateNewId().ToString();
            }
        }
        try
        {
            await _userCollection.InsertOneAsync(user, new InsertOneOptions(), cancellationToken).ConfigureAwait(false);
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return IdentityResult.Failed(ex.WriteError.Message.Contains(MongoIndexNames.NormalizedEmail, StringComparison.Ordinal)
                ? ErrorDescriber.DuplicateEmail(user.Email ?? string.Empty)
                : ErrorDescriber.DuplicateUserName(user.UserName ?? string.Empty));
        }
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        // Optimistic concurrency: replace the document only if nobody else updated it since
        // this instance was loaded, and rotate the stamp so concurrent holders of the old
        // document fail instead of silently overwriting this update.
        string? expectedStamp = user.ConcurrencyStamp;
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        FilterDefinition<TUser> filter = Builders<TUser>.Filter.Eq(u => u.Id, user.Id)
            & Builders<TUser>.Filter.Eq(u => u.ConcurrencyStamp, expectedStamp);
        ReplaceOneResult result = await _userCollection.ReplaceOneAsync(filter, user, new ReplaceOptions(), cancellationToken).ConfigureAwait(false);
        if (!result.IsAcknowledged || result.MatchedCount != 1)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        FilterDefinition<TUser> filter = Builders<TUser>.Filter.Eq(u => u.Id, user.Id)
            & Builders<TUser>.Filter.Eq(u => u.ConcurrencyStamp, user.ConcurrencyStamp);
        DeleteResult result = await _userCollection.DeleteOneAsync(filter, cancellationToken).ConfigureAwait(false);
        if (!result.IsAcknowledged || result.DeletedCount != 1)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    public async Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        if (!TryConvertIdFromString(userId, out TKey id))
        {
            return null;
        }
        return await _userCollection.Find(u => u.Id.Equals(id)).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await _userCollection.Find(u => u.NormalizedUserName == normalizedUserName).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.Claims.Select(c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty)).ToList();
    }

    public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        foreach (Claim claim in claims)
        {
            IdentityUserClaim<string> newClaim = new()
            {
                UserId = user.Id.ToString()!
            };
            newClaim.InitializeFromClaim(claim);
            user.Claims.Add(newClaim);
        }
    }

    public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        // Update every matching claim in place, mirroring the EF store's semantics.
        foreach (IdentityUserClaim<string> matchedClaim in
                 user.Claims.Where(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value))
        {
            matchedClaim.ClaimType = newClaim.Type;
            matchedClaim.ClaimValue = newClaim.Value;
        }
    }

    public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        foreach (Claim claim in claims)
        {
            user.Claims.RemoveAll(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value);
        }
    }

    public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await _userCollection
            .AsQueryable()
            .Where(u => u.Claims.Any(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.Logins.Add(new IdentityUserLogin<string> { LoginProvider = login.LoginProvider, ProviderDisplayName = login.ProviderDisplayName, ProviderKey = login.ProviderKey, UserId = user.Id.ToString()! });
    }

    public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.Logins.RemoveAll(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
    }

    public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.Logins
            .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
            .ToList();
    }

    public async Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await _userCollection.Find(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        TRole? role = await _roleCollection.Find(r => r.NormalizedName == normalizedRoleName)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        if (role is null)
        {
            throw new InvalidOperationException($"Role {normalizedRoleName} not found.");
        }
        user.Roles.Add(role.Id);
    }

    public async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        TRole? role = await _roleCollection.Find(r => r.NormalizedName == normalizedRoleName)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        if (role is null)
        {
            throw new InvalidOperationException($"Role {normalizedRoleName} not found.");
        }

        user.Roles.Remove(role.Id);
    }

    public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        if (user.Roles.Count == 0)
        {
            return new List<string>();
        }
        FilterDefinition<TRole> filter = Builders<TRole>.Filter.In(r => r.Id, user.Roles);
        List<string?> roleNames = await _roleCollection.Find(filter)
            .Project(r => r.Name)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return roleNames.OfType<string>().ToList();
    }

    public async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        TRole? role = await _roleCollection.Find(r => r.NormalizedName == normalizedRoleName)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        return role != null && user.Roles.Contains(role.Id);
    }

    public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        TRole? role = await _roleCollection.Find(r => r.NormalizedName == normalizedRoleName)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (role == null)
        {
            return new List<TUser>();
        }

        return await _userCollection.Find(u => u.Roles.Contains(role.Id))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task SetPasswordHashAsync(TUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.PasswordHash = passwordHash;
    }

    public async Task<string?> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.PasswordHash;
    }

    public async Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.PasswordHash is not null;
    }

    public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.SecurityStamp = stamp;
    }

    public async Task<string?> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.SecurityStamp;
    }

    public async Task SetEmailAsync(TUser user, string? email, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.Email = email;
    }

    public async Task<string?> GetEmailAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.Email;
    }

    public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.EmailConfirmed;
    }

    public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.EmailConfirmed = confirmed;
    }

    public async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        return await _userCollection.Find(u => u.NormalizedEmail == normalizedEmail).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.NormalizedEmail;
    }

    public async Task SetNormalizedEmailAsync(TUser user, string? normalizedEmail, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.NormalizedEmail = normalizedEmail;
    }

    public async Task SetPhoneNumberAsync(TUser user, string? phoneNumber, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.PhoneNumber = phoneNumber;
    }

    public async Task<string?> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.PhoneNumber;
    }

    public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.PhoneNumberConfirmed;
    }

    public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.PhoneNumberConfirmed = confirmed;
    }

    public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.TwoFactorEnabled = enabled;
    }

    public async Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.TwoFactorEnabled;
    }

    public async Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.LockoutEnd;
    }

    public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.LockoutEnd = lockoutEnd;
    }

    public async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.AccessFailedCount++;
        return user.AccessFailedCount;
    }

    public async Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.AccessFailedCount = 0;
    }

    public async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.AccessFailedCount;
    }

    public async Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return user.LockoutEnabled;
    }

    public async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        user.LockoutEnabled = enabled;
    }

    public async Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        await SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        return await GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken).ConfigureAwait(false);
    }

    public async Task SetTokenAsync(TUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        IdentityUserToken<string>? existingToken = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);
        if (existingToken is null)
        {
            user.Tokens.Add(new IdentityUserToken<string>
            {
                UserId = user.Id.ToString()!,
                LoginProvider = loginProvider,
                Name = name,
                Value = value
            });
        }
        else
        {
            existingToken.Value = value;
        }
    }

    public async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        IdentityUserToken<string>? token = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);
        if (token is null)
        {
            return;
        }
        user.Tokens.Remove(token);
    }

    public async Task<string?> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        IdentityUserToken<string>? token = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);
        return token?.Value;
    }

    public async Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        string mergedCodes = string.Join(";", recoveryCodes);
        await SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, mergedCodes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(code);
        string? mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken).ConfigureAwait(false);
        if (mergedCodes is null)
        {
            return false;
        }
        string[] individualCodes = mergedCodes.Split(';', StringSplitOptions.RemoveEmptyEntries);
        if (!individualCodes.Contains(code))
        {
            return false;
        }
        List<string> updatedCodes = new(individualCodes.Where(s => s != code));
        await ReplaceCodesAsync(user, updatedCodes, cancellationToken).ConfigureAwait(false);

        return true;
    }

    public async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(user);
        string? mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(mergedCodes))
        {
            return 0;
        }
        return mergedCodes.Split(';', StringSplitOptions.RemoveEmptyEntries).Length;
    }

    /// <summary>
    /// Throws if this class has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (!_disposed) return;
        throw new ObjectDisposedException(GetType().Name);
    }

    /// <summary>
    /// Dispose the store
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private Task PreambleAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Runs the lazy one-time initialization (migrations and indexes) before an operation
    /// that touches the database. Purely in-memory operations skip this so they keep working
    /// while the database is unreachable.
    /// </summary>
    private Task EnsureInitializedAsync(CancellationToken token)
    {
        return _initializer?.EnsureInitializedAsync(token) ?? Task.CompletedTask;
    }

    private static bool TryConvertIdFromString(string? id, out TKey key)
    {
        key = default!;
        if (string.IsNullOrEmpty(id))
        {
            return false;
        }
        try
        {
            object? converted = TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
            if (converted is null)
            {
                return false;
            }
            key = (TKey)converted;
            return true;
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or NotSupportedException or ArgumentException)
        {
            // A malformed id means "no such user", not an exceptional condition.
            return false;
        }
    }
}
