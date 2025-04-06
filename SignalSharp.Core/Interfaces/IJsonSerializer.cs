using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides JSON serialization and deserialization capabilities.
    /// </summary>
    public interface IJsonSerializer
    {
        /// <summary>
        /// Serializes an object to a JSON string.
        /// </summary>
        /// <typeparam name="T">The type of the object to serialize.</typeparam>
        /// <param name="value">The object to serialize.</param>
        /// <returns>A JSON string representation of the object.</returns>
        /// <exception cref="ArgumentNullException">Thrown when value is null.</exception>
        string Serialize<T>(T value);

        /// <summary>
        /// Asynchronously serializes an object to a JSON string.
        /// </summary>
        /// <typeparam name="T">The type of the object to serialize.</typeparam>
        /// <param name="value">The object to serialize.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the JSON string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when value is null.</exception>
        Task<string> SerializeAsync<T>(T value);

        /// <summary>
        /// Deserializes a JSON string to an object.
        /// </summary>
        /// <typeparam name="T">The type of the object to deserialize to.</typeparam>
        /// <param name="json">The JSON string to deserialize.</param>
        /// <returns>The deserialized object.</returns>
        /// <exception cref="ArgumentNullException">Thrown when json is null or empty.</exception>
        T? Deserialize<T>(string json);

        /// <summary>
        /// Asynchronously deserializes a JSON string to an object.
        /// </summary>
        /// <typeparam name="T">The type of the object to deserialize to.</typeparam>
        /// <param name="json">The JSON string to deserialize.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the deserialized object.</returns>
        /// <exception cref="ArgumentNullException">Thrown when json is null or empty.</exception>
        Task<T?> DeserializeAsync<T>(string json);
    }
} 