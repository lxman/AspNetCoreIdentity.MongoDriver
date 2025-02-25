using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;

namespace AspNetCore.Identity.MongoDriver.Migrations;

internal class Schema4Migration : BaseMigration
{
    public override int Version { get; } = 4;

    protected override void DoApply<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection)
    {
        List<TUser>? users = usersCollection.Find(x => !string.IsNullOrEmpty(x.AuthenticatorKey)).ToList();
        foreach (TUser? user in users)
        {
            List<IdentityUserToken<string>> tokens = user.Tokens;
            tokens.Add(new IdentityUserToken<string>()
            {
                UserId = user.Id.ToString(),
                Value = user.AuthenticatorKey,
                LoginProvider = "[AspNetUserStore]",
                Name = "AuthenticatorKey"
            });
            usersCollection.UpdateOne(x => x.Id.Equals(user.Id),
                Builders<TUser>.Update.Set(x => x.Tokens, tokens)
                    .Set(x => x.AuthenticatorKey, null));

        }
    }
}