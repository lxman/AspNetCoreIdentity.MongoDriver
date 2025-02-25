# AspNetCoreIdentity.MongoDriver
A provisioner for AspNetCore Identity using MongoDB as the backing store.

## Features
This implements all of the interfaces required by the AspNetCore Identity system.

It also includes a `UserStore` and `RoleStore` implementation that can be used with the `UserManager` and `RoleManager` classes.

A typical connection string for local development would be `mongodb://localhost:27017/Identity`.

This would create a database called `Identity` and store the collections in there.

## Usage

```
        builder.services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(identity =>
        {
            identity.User.RequireUniqueEmail = true;
        }, mongo =>
        {
            mongo.ConnectionString = builder.Configuration.GetConnectionString("MongoDb")!;
            mongo.DisableAutoMigrations = true;
        });
        IServiceProvider serviceProvider = builder.services.BuildServiceProvider();
        IServiceScope scope = serviceProvider.CreateScope();
        UserManager = scope.ServiceProvider.GetService<UserManager<MongoUser<Guid>>>()!;
        RoleManager = scope.ServiceProvider.GetService<RoleManager<MongoRole<Guid>>>()!;
```

>[!NOTE]
> The `MongoUser` and `MongoRole` classes are provided by the library and are generic. This allows you to use any type for the key, not just a `Guid`.
>
> If you want to use a `Guid` as the key, you need to insert the line `BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));` somewhere above this.

>[!NOTE]
> `UserManager` and `RoleManager` are `IDisposable` and should be disposed of when they are no longer needed.