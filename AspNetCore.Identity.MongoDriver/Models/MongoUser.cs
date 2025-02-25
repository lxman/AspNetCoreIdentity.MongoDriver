using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AspNetCore.Identity.MongoDriver.Models;

[BsonIgnoreExtraElements]
public class MongoUser : MongoUser<ObjectId>
{
    public MongoUser() { }

    public MongoUser(string userName) : base(userName) { }
}

[BsonIgnoreExtraElements]
public class MongoUser<TKey>() : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{
    public MongoUser(string userName) : this()
    {
        UserName = userName;
        NormalizedUserName = userName.ToUpperInvariant();
    }

    public List<TKey> Roles { get; set; } = [];

    public List<IdentityUserClaim<string>> Claims { get; set; } = [];

    public List<IdentityUserLogin<string>> Logins { get; set; } = [];

    public List<IdentityUserToken<string>> Tokens { get; set; } = [];
}