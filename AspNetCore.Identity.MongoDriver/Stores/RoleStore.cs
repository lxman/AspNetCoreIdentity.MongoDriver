using System.Security.Claims;
using AspNetCore.Identity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;

namespace AspNetCore.Identity.MongoDriver.Stores
{
    public class RoleStore<TRole, TKey> :
        IRoleClaimStore<TRole>,
        IQueryableRoleStore<TRole>
        where TKey : IEquatable<TKey>
        where TRole : MongoRole<TKey>
    {
        /// <summary>
        /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        /// <summary>
        /// A navigation property for the roles the store contains.
        /// </summary>
        public IQueryable<TRole> Roles => _collection.AsQueryable();

        private readonly IMongoCollection<TRole> _collection;

        private bool _disposed;

        /// <summary>
        /// Constructs a new instance of <see cref="RoleStore{TRole, TKey}"/>.
        /// </summary>
        /// <param name="collection">The role mongo collection.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public RoleStore(IMongoCollection<TRole> collection, IdentityErrorDescriber? describer)
        {
            _collection = collection;
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);

            await _collection.InsertOneAsync(role, cancellationToken: cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            FilterDefinition<TRole>? filter = Builders<TRole>.Filter.Eq(r => r.Id, role.Id);
            UpdateDefinition<TRole>? update = Builders<TRole>.Update.Set(r => r, role)
                .Set(r => r.NormalizedName, role.NormalizedName);
            UpdateResult? updateResult = await _collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (updateResult.IsAcknowledged && updateResult.ModifiedCount == 1)
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed();
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            DeleteResult deleteResult = await _collection
                .DeleteOneAsync(Builders<TRole>.Filter.Eq(r => r.Id, role.Id), cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (deleteResult.IsAcknowledged && deleteResult.DeletedCount == 1)
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed();
        }

        public async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            return role.Id.ToString() ?? string.Empty;
        }

        public async Task<string?> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            return role.Name;
        }

        public async Task SetRoleNameAsync(TRole role, string? roleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            role.Name = roleName;
        }

        public async Task<string?> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            return role.NormalizedName;
        }

        public async Task SetNormalizedRoleNameAsync(TRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            role.NormalizedName = normalizedName;
        }

        public async Task<TRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            FilterDefinition<TRole>? filter = Builders<TRole>.Filter.Eq(r => r.Id.ToString(), roleId);
            return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<TRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            await PreambleAsync(cancellationToken);
            FilterDefinition<TRole>? filter = Builders<TRole>.Filter.Eq(r => r.NormalizedName, normalizedRoleName);
            return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            IEnumerable<Claim> claims = role.Claims.Select(c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty));
            return claims.ToList();
        }

        public async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            ArgumentNullException.ThrowIfNull(claim);
            var userClaim = new IdentityRoleClaim<TKey>();
            userClaim.InitializeFromClaim(claim);
            role.Claims.Add(userClaim);
        }

        public async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            await PreambleAsync(cancellationToken);
            ArgumentNullException.ThrowIfNull(role);
            ArgumentNullException.ThrowIfNull(claim);
            var roleClaim = new IdentityRoleClaim<TKey>();
            roleClaim.InitializeFromClaim(claim);
            role.Claims.Remove(roleClaim);
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
        /// Dispose the stores
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