using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Migrations;

internal class Schema5Migration : BaseMigration
{
    public override int Version => 5;

    protected override async Task DoApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
    {
        await usersCollection.UpdateManyAsync(x => true,
            Builders<TUser>.Update.Unset(x => x.AuthenticatorKey)
                .Unset(x => x.RecoveryCodes),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
