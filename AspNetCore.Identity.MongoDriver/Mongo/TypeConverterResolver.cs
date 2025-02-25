using System.ComponentModel;

namespace AspNetCore.Identity.MongoDriver.Mongo;

internal static class TypeConverterResolver
{
    internal static void RegisterTypeConverter<T, TC>() where TC : TypeConverter
    {
        var attr = new Attribute[1];
        var vConv = new TypeConverterAttribute(typeof(TC));
        attr[0] = vConv;
        TypeDescriptor.AddAttributes(typeof(T), attr);
    }
}