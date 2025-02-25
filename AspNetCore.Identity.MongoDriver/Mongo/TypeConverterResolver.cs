using System.ComponentModel;

namespace AspNetCore.Identity.MongoDriver.Mongo;

internal static class TypeConverterResolver
{
    internal static void RegisterTypeConverter<T, TC>() where TC : TypeConverter
    {
        Attribute[] attr = new Attribute[1];
        TypeConverterAttribute vConv = new(typeof(TC));
        attr[0] = vConv;
        TypeDescriptor.AddAttributes(typeof(T), attr);
    }
}