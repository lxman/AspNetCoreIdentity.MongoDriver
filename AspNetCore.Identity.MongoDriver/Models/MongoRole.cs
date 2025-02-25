using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AspNetCoreIdentity.MongoDriver.Models;

[BsonIgnoreExtraElements]
public class MongoRole : MongoRole<ObjectId>
{
    public MongoRole() : base()
    {
    }

    public MongoRole(string name) : base(name)
    {
    }
}

[BsonIgnoreExtraElements]
public class MongoRole<TKey>() : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    public MongoRole(string name) : this()
    {
        Name = name;
        NormalizedName = name.ToUpperInvariant();
    }

    public override string ToString()
    {
        return Name;
    }

    public List<IdentityRoleClaim<TKey>> Claims { get; set; } = [];
}