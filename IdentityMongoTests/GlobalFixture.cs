using AspNetCore.Identity.MongoDriver;
using AspNetCore.Identity.MongoDriver.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Mongo2Go;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;

namespace IdentityMongoTests
{
    public class GlobalFixture : IDisposable
    {
        public UserManager<MongoUser<Guid>> UserManager { get; }

        public RoleManager<MongoRole<Guid>> RoleManager { get; }

        private readonly MongoDbRunner _runner = MongoDbRunner.Start();

        public GlobalFixture()
        {
            BsonSerializer.RegisterSerializer(new GuidSerializer(GuidRepresentation.Standard));
            IServiceCollection services = new ServiceCollection();
            services.AddLogging();
            services.AddIdentityMongoDbProvider<MongoUser<Guid>, MongoRole<Guid>, Guid>(identity =>
            {
                identity.User.RequireUniqueEmail = true;
            }, mongo =>
            {
                mongo.ConnectionString = _runner.ConnectionString;
                mongo.DisableAutoMigrations = true;
            });
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            IServiceScope scope = serviceProvider.CreateScope();
            UserManager = scope.ServiceProvider.GetService<UserManager<MongoUser<Guid>>>()!;
            RoleManager = scope.ServiceProvider.GetService<RoleManager<MongoRole<Guid>>>()!;
        }

        public void Dispose()
        {
            UserManager.Dispose();
            RoleManager.Dispose();
            _runner.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}