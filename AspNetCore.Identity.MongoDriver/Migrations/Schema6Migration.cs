using MongoDB.Bson;
using MongoDB.Driver;

namespace AspNetCoreIdentity.MongoDriver.Migrations;

/// <summary>
/// Converts the legacy <c>Roles</c> schema, which stored role names as strings, to the
/// current schema, which stores role ids typed as <c>TKey</c>. Works on raw BSON because a
/// database can contain a mixture of both shapes, which neither typed model can deserialize.
/// </summary>
internal class Schema6Migration : BaseMigration
{
    public override int Version => 6;

    protected override async Task DoApplyAsync<TUser, TRole, TKey>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRole> rolesCollection,
        CancellationToken cancellationToken)
    {
        IMongoCollection<BsonDocument> rawUsers = usersCollection.Database
            .GetCollection<BsonDocument>(usersCollection.CollectionNamespace.CollectionName);
        IMongoCollection<BsonDocument> rawRoles = rolesCollection.Database
            .GetCollection<BsonDocument>(rolesCollection.CollectionNamespace.CollectionName);

        List<BsonDocument> roles = await rawRoles
            .Find(FilterDefinition<BsonDocument>.Empty)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        Dictionary<string, BsonValue> roleIdsByName = new(StringComparer.Ordinal);
        HashSet<BsonValue> knownRoleIds = [];
        foreach (BsonDocument role in roles)
        {
            BsonValue roleId = role["_id"];
            knownRoleIds.Add(roleId);
            if (role.TryGetValue("NormalizedName", out BsonValue normalizedName) && normalizedName.IsString)
            {
                roleIdsByName.TryAdd(normalizedName.AsString, roleId);
            }
            if (role.TryGetValue("Name", out BsonValue name) && name.IsString)
            {
                roleIdsByName.TryAdd(name.AsString, roleId);
            }
        }

        // For string keys an entry can be either a legacy name or a current id, so an entry
        // is only treated as a name when it is not a known role id. For all other key types
        // any string entry is legacy data.
        bool keyIsString = typeof(TKey) == typeof(string);

        FilterDefinition<BsonDocument> hasStringRoleEntry =
            new BsonDocument("Roles", new BsonDocument("$elemMatch", new BsonDocument("$type", "string")));
        using IAsyncCursor<BsonDocument> cursor = await rawUsers
            .Find(hasStringRoleEntry)
            .ToCursorAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await cursor.MoveNextAsync(cancellationToken).ConfigureAwait(false))
        {
            foreach (BsonDocument userDocument in cursor.Current)
            {
                BsonArray currentRoles = userDocument["Roles"].AsBsonArray;
                BsonArray convertedRoles = [];
                bool changed = false;
                foreach (BsonValue entry in currentRoles)
                {
                    if (!entry.IsString)
                    {
                        convertedRoles.Add(entry);
                        continue;
                    }
                    if (keyIsString && knownRoleIds.Contains(entry))
                    {
                        convertedRoles.Add(entry);
                        continue;
                    }
                    if (roleIdsByName.TryGetValue(entry.AsString, out BsonValue? roleId))
                    {
                        if (!convertedRoles.Contains(roleId))
                        {
                            convertedRoles.Add(roleId);
                        }
                        changed = true;
                        continue;
                    }
                    if (keyIsString)
                    {
                        // Unknown string for a string-keyed schema: keep it, it may be the id
                        // of a role that was deleted.
                        convertedRoles.Add(entry);
                    }
                    else
                    {
                        // A name that matches no role cannot be represented as TKey; keeping
                        // it would make the whole user document undeserializable.
                        changed = true;
                    }
                }

                if (!changed)
                {
                    continue;
                }

                await rawUsers.UpdateOneAsync(
                    new BsonDocument("_id", userDocument["_id"]),
                    new BsonDocument("$set", new BsonDocument("Roles", convertedRoles)),
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
