using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Migrations;

internal class Schema4Migration : BaseMigration
{
    public override int Version => 4;

    protected override async Task DoApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
    {
        List<TUser> users = await usersCollection
            .Find(x => !string.IsNullOrEmpty(x.AuthenticatorKey))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (TUser user in users)
        {
            List<IdentityUserToken<string>> tokens = user.Tokens;
            if (user.AuthenticatorKey != null)
            {
                tokens.Add(new IdentityUserToken<string>
                {
                    UserId = user.Id.ToString() ?? string.Empty,
                    Value = user.AuthenticatorKey,
                    LoginProvider = "[AspNetUserStore]",
                    Name = "AuthenticatorKey"
                });
            }
            await usersCollection.UpdateOneAsync(x => x.Id.Equals(user.Id),
                Builders<TUser>.Update.Set(x => x.Tokens, tokens)
                    .Set(x => x.AuthenticatorKey, (string?)null),
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }
}
