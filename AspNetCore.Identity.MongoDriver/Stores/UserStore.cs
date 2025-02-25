using System.Security.Claims;
using AspNetCore.Identity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
#pragma warning disable CA1862

namespace AspNetCore.Identity.MongoDriver.Stores
{
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
        IUserTwoFactorRecoveryCodeStore<TUser>,
        IProtectedUserStore<TUser>
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
        public IQueryable<TUser> Users => _userCollection.AsQueryable()!;

        public IQueryable<TRole> Roles => _roleCollection.AsQueryable()!;

        private readonly IMongoCollection<TUser> _userCollection;
        private readonly IMongoCollection<TRole> _roleCollection;

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
        {
            _userCollection = userCollection;
            _roleCollection = roleCollection;
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
            await _userCollection.InsertOneAsync(user, new InsertOneOptions(), cancellationToken);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            ReplaceOneResult? result = await _userCollection.ReplaceOneAsync(u => u.Id.Equals(user.Id), user, new ReplaceOptions(), cancellationToken);
            if (result.IsAcknowledged && result is { IsModifiedCountAvailable: true, ModifiedCount: 1 })
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed();
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            FilterDefinition<TUser> filter = Builders<TUser>.Filter.Eq(u => u.Id, user.Id);
            DeleteResult? deleteResult = await _userCollection.DeleteOneAsync(filter, cancellationToken);
            if ((deleteResult?.IsAcknowledged ?? false) && deleteResult.DeletedCount == 1)
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed();
        }

        public async Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            List<TUser> users = await Users.ToListAsync(cancellationToken);
            return users.FirstOrDefault(u => u.Id.ToString() == userId);
        }

        public async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            return Users.FirstOrDefault(u => u.NormalizedUserName == normalizedUserName);
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
                var newClaim = new IdentityUserClaim<string>
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
            IdentityUserClaim<string>? existing =
                user.Claims.FirstOrDefault(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value);
            if (existing is not null)
            {
                user.Claims.Remove(existing);
            }

            var toInsert = new IdentityUserClaim<string>
            {
                UserId = user.Id.ToString()!,
                Id = existing?.Id ?? 0
            };
            toInsert.InitializeFromClaim(newClaim);
            user.Claims.Add(toInsert);
        }

        public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            foreach (Claim claim in claims)
            {
                IdentityUserClaim<string>? matching =
                    user.Claims.FirstOrDefault(c => c.ClaimValue == claim.Value && c.ClaimType == claim.Type);
                if (matching is not null)
                {
                    user.Claims.Remove(matching);
                }
            }
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
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
            return (await Users.FirstOrDefaultAsync(cancellationToken))?.Logins
                .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
                .ToList() ?? [];
        }

        public async Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            foreach (TUser user in Users)
            {
                if (user.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
                {
                    return user;
                }
            }

            return null;
        }

        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            TRole? role = Roles.FirstOrDefault(r => r.NormalizedName != null && r.NormalizedName == roleName.ToUpperInvariant());
            if (role is null)
            {
                throw new InvalidOperationException($"Role {roleName} not found.");
            }
            user.Roles.Add(role.Id);
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            TRole? role = Roles.FirstOrDefault(r => r.NormalizedName != null && r.NormalizedName == roleName.ToUpperInvariant());
            if (role is null)
            {
                throw new InvalidOperationException($"Role {roleName} not found.");
            }

            user.Roles.Remove(role.Id);
        }

        public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            return user.Roles.Select(r => Roles.FirstOrDefault(role => role.Id.Equals(r))?.Name ?? string.Empty).ToList();
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            return user.Roles.Any(r => Roles.FirstOrDefault(role => role.NormalizedName != null && role.NormalizedName == roleName.ToUpperInvariant())?.Id.Equals(r) ?? false);
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            List<TRole> roles = await Roles.Where(r => r.NormalizedName != null && r.NormalizedName == roleName.ToUpperInvariant()).ToListAsync(cancellationToken);
            return Users.Where(u => u.Roles.Any(r => r.Equals(roles[0].Id))).ToList();
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
            return Users.FirstOrDefault(u => u.NormalizedEmail == normalizedEmail);
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
            await SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);
        }

        public async Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            return await GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);
        }

        public async Task SetTokenAsync(TUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            IdentityUserToken<string>? existingToken = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);
            if (existingToken is null)
            {
                var newToken = new IdentityUserToken<string>
                {
                    UserId = user.Id.ToString()!,
                    LoginProvider = loginProvider,
                    Name = name,
                    Value = value
                };
                user.Tokens.Add(newToken);
            }
            else
            {
                existingToken.Value = value;
                int idx = user.Tokens.FindIndex(t => t.LoginProvider == loginProvider && t.Name == name);
                user.Tokens[idx] = existingToken;
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
            await SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, mergedCodes, cancellationToken);
        }

        public async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(code);
            string? mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken);
            if (mergedCodes is null)
            {
                return false;
            }
            string[] individualCodes = mergedCodes.Split(';', StringSplitOptions.RemoveEmptyEntries);
            if (!individualCodes.Contains(code))
            {
                return false;
            }
            var updatedCodes = new List<string>(individualCodes.Where(s => s != code));
            await ReplaceCodesAsync(user, updatedCodes, cancellationToken);

            return true;
        }

        public async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(user);
            return user.Tokens.Count(t => t is { Name: RecoveryCodeTokenName, LoginProvider: InternalLoginProvider });
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
    }
}