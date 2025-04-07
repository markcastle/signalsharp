using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for creating JSON serializers.
    /// </summary>
    public interface IJsonSerializerFactory
    {
        /// <summary>
        /// Creates a new JSON serializer instance.
        /// </summary>
        /// <returns>A new JSON serializer instance.</returns>
        IJsonSerializer CreateSerializer();

        /// <summary>
        /// Creates a new JSON serializer instance with the specified options.
        /// </summary>
        /// <param name="options">The options to use for the serializer.</param>
        /// <returns>A new JSON serializer instance.</returns>
        IJsonSerializer CreateSerializer(IJsonSerializerOptions options);

        /// <summary>
        /// Asynchronously creates a new JSON serializer instance.
        /// </summary>
        /// <returns>A new JSON serializer instance.</returns>
        Task<IJsonSerializer> CreateSerializerAsync();

        /// <summary>
        /// Asynchronously creates a new JSON serializer instance with the specified options.
        /// </summary>
        /// <param name="options">The options to use for the serializer.</param>
        /// <returns>A new JSON serializer instance.</returns>
        Task<IJsonSerializer> CreateSerializerAsync(IJsonSerializerOptions options);
    }
} 