using MongoDB.Driver;
using MongoDB.Driver.Core.Configuration;

namespace AspNetCoreIdentity.MongoDriver;

public class MongoIdentityOptions
{
    public string ConnectionString { get; set; } = "mongodb://localhost/default";

    public string UsersCollection { get; set; } = "Users";

    public string RolesCollection { get; set; } = "Roles";

    public string MigrationCollection { get; set; } = "_Migrations";

    public SslSettings? SslSettings { get; set; }

    public Action<ClusterBuilder>? ClusterConfigurator { get; set; }

    public bool DisableAutoMigrations { get; set; }

    /// <summary>
    /// When true, the library does not create its indexes (unique normalized user name,
    /// normalized email, login provider/key, unique normalized role name) on first use.
    /// </summary>
    public bool DisableIndexCreation { get; set; }
}