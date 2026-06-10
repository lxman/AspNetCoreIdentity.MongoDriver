# AspNetCoreIdentity.MongoDriver
A provisioner for AspNetCore Identity using MongoDB as the backing store.

## Features
This implements all of the interfaces required by the AspNetCore Identity system.

It also includes a `UserStore` and `RoleStore` implementation that can be used with the `UserManager` and `RoleManager` classes.

A typical connection string for local development would be `mongodb://localhost:27017/Identity`.

This would create a database called `Identity` and store the collections in there.

## Usage

Register the provider in `Program.cs`:

```csharp
builder.Services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(identity =>
{
    identity.User.RequireUniqueEmail = true;
}, mongo =>
{
    mongo.ConnectionString = builder.Configuration.GetConnectionString("MongoDb")!;
});
```

Then take `UserManager<MongoUser<Guid>>` and `RoleManager<MongoRole<Guid>>` as constructor or
handler parameters wherever you need them; they are registered as scoped services and the
container manages their lifetime. Do not call `BuildServiceProvider()` yourself or cache the
managers in long-lived objects.

```csharp
public class AccountController(UserManager<MongoUser<Guid>> userManager) : Controller
{
    // ...
}
```

>[!NOTE]
> The `MongoUser` and `MongoRole` classes are provided by the library and are generic. This allows you to use any type for the key, not just a `Guid`.
>
> If you want to use a `Guid` as the key, you need to insert the line `BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));` somewhere above this.
>
> If you use `string` keys and do not assign an `Id` yourself, the store generates an ObjectId-style string on create.

## Initialization, indexes, and migrations

On the first store operation (not during service registration) the library:

- applies any pending schema migrations, guarded by a distributed lock so multiple
  application instances starting at once apply them exactly once, and
- creates its indexes: a unique index on `NormalizedUserName`, an index on `NormalizedEmail`,
  a compound index on `Logins.LoginProvider`/`Logins.ProviderKey`, and a unique index on the
  role `NormalizedName`.

Because the unique index on `NormalizedUserName` enforces real uniqueness, index creation will
fail if existing data already contains duplicate user names — clean those up before upgrading.
Set `mongo.DisableIndexCreation = true` if you manage indexes yourself, and
`mongo.DisableAutoMigrations = true` if you manage schema upgrades yourself. You can also warm
up eagerly at startup by resolving `MongoIdentityInitializer` from the container and awaiting
`EnsureInitializedAsync()`.

## Concurrency

Updates and deletes use optimistic concurrency via the Identity `ConcurrencyStamp`. If the
document changed since your copy was loaded, the operation fails with a
`ConcurrencyFailure` error instead of silently overwriting the other write — reload the
user/role and retry.

## Limitations

`options.Stores.ProtectPersonalData` is not supported: the store does not encrypt personal
data at rest, and enabling that option will throw at runtime by design rather than silently
storing data unprotected.
