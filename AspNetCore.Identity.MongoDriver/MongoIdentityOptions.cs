﻿using MongoDB.Driver;
using MongoDB.Driver.Core.Configuration;

namespace AspNetCoreIdentity.MongoDriver;

public class MongoIdentityOptions
{
    public string ConnectionString { get; set; } = "mongodb://localhost/default";

    public string UsersCollection { get; set; } = "Users";

    public string UserClaimsCollection { get; set; } = "UserClaims";

    public string RolesCollection { get; set; } = "Roles";

    public string MigrationCollection { get; set; } = "_Migrations";

    public SslSettings SslSettings { get; set; }

    public Action<ClusterBuilder> ClusterConfigurator { get; set; }

    public bool DisableAutoMigrations { get; set; }
}