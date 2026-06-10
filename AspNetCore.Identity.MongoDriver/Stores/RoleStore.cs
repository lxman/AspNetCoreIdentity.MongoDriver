using System.ComponentModel;
using System.Security.Claims;
using AspNetCoreIdentity.MongoDriver.Models;
using AspNetCoreIdentity.MongoDriver.Mongo;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Stores;

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
    private readonly MongoIdentityInitializer? _initializer;

    private bool _disposed;

    /// <summary>
    /// Constructs a new instance of <see cref="RoleStore{TRole, TKey}"/>.
    /// </summary>
    /// <param name="collection">The role mongo collection.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public RoleStore(IMongoCollection<TRole> collection, IdentityErrorDescriber? describer)
        : this(collection, describer, null)
    {
    }

    internal RoleStore(IMongoCollection<TRole> collection, IdentityErrorDescriber? describer, MongoIdentityInitializer? initializer)
    {
        _collection = collection;
        _initializer = initializer;
        ErrorDescriber = describer ?? new IdentityErrorDescriber();
    }

    public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        if (typeof(TKey) == typeof(string))
        {
            // The driver has no default id generator for string keys, so without this a
            // second role created without an explicit Id fails on the duplicate null _id.
            object? rawId = role.Id;
            if (rawId is null || (rawId is string stringId && stringId.Length == 0))
            {
                role.Id = (TKey)(object)ObjectId.GenerateNewId().ToString();
            }
        }

        try
        {
            await _collection.InsertOneAsync(role, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name ?? string.Empty));
        }

        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        // Optimistic concurrency: replace the document only if nobody else updated it since
        // this instance was loaded, and rotate the stamp so concurrent holders of the old
        // document fail instead of silently overwriting this update.
        string? expectedStamp = role.ConcurrencyStamp;
        role.ConcurrencyStamp = Guid.NewGuid().ToString();
        FilterDefinition<TRole> filter = Builders<TRole>.Filter.Eq(r => r.Id, role.Id)
            & Builders<TRole>.Filter.Eq(r => r.ConcurrencyStamp, expectedStamp);
        ReplaceOneResult result = await _collection.ReplaceOneAsync(filter, role, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (!result.IsAcknowledged || result.MatchedCount != 1)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        FilterDefinition<TRole> filter = Builders<TRole>.Filter.Eq(r => r.Id, role.Id)
            & Builders<TRole>.Filter.Eq(r => r.ConcurrencyStamp, role.ConcurrencyStamp);
        DeleteResult result = await _collection.DeleteOneAsync(filter, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (!result.IsAcknowledged || result.DeletedCount != 1)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
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
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        if (!TryConvertIdFromString(roleId, out TKey id))
        {
            return null;
        }
        return await _collection.Find(r => r.Id.Equals(id)).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<TRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        await PreambleAsync(cancellationToken);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        FilterDefinition<TRole>? filter = Builders<TRole>.Filter.Eq(r => r.NormalizedName, normalizedRoleName);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = new())
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        IEnumerable<Claim> claims = role.Claims.Select(c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty));
        return claims.ToList();
    }

    public async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new())
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);
        IdentityRoleClaim<TKey> userClaim = new();
        userClaim.InitializeFromClaim(claim);
        role.Claims.Add(userClaim);
    }

    public async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new())
    {
        await PreambleAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);
        IdentityRoleClaim<TKey>? roleClaim = role.Claims.FirstOrDefault(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value);
        if (roleClaim is null)
        {
            return;
        }
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
            // A malformed id means "no such role", not an exceptional condition.
            return false;
        }
    }
}
