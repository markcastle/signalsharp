using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for JSON serialization operations.
    /// </summary>
    public interface IJsonSerializer
    {
        /// <summary>
        /// Deserializes a JSON string to an object of type T.
        /// </summary>
        /// <typeparam name="T">The type to deserialize to.</typeparam>
        /// <param name="json">The JSON string to deserialize.</param>
        /// <returns>The deserialized object.</returns>
        T Deserialize<T>(string json) where T : class;

        /// <summary>
        /// Serializes an object to a JSON string.
        /// </summary>
        /// <typeparam name="T">The type of object to serialize.</typeparam>
        /// <param name="value">The object to serialize.</param>
        /// <returns>The JSON string.</returns>
        string Serialize<T>(T value) where T : class;

        /// <summary>
        /// Asynchronously deserializes a JSON string to an object of type T.
        /// </summary>
        /// <typeparam name="T">The type to deserialize to.</typeparam>
        /// <param name="json">The JSON string to deserialize.</param>
        /// <returns>The deserialized object.</returns>
        Task<T> DeserializeAsync<T>(string json) where T : class;

        /// <summary>
        /// Asynchronously serializes an object to a JSON string.
        /// </summary>
        /// <typeparam name="T">The type of object to serialize.</typeparam>
        /// <param name="value">The object to serialize.</param>
        /// <returns>The JSON string.</returns>
        Task<string> SerializeAsync<T>(T value) where T : class;
    }
} 