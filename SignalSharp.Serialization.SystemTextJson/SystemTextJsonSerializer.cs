using System;
using System.Text.Json;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Serialization.SystemTextJson
{
    /// <summary>
    /// Implementation of IJsonSerializer using System.Text.Json.
    /// </summary>
    public class SystemTextJsonSerializer : IJsonSerializer
    {
        private readonly JsonSerializerOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="SystemTextJsonSerializer"/> class.
        /// </summary>
        /// <param name="options">Optional JSON serialization options.</param>
        public SystemTextJsonSerializer(JsonSerializerOptions? options = null)
        {
            _options = options ?? new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        /// <inheritdoc/>
        public string Serialize<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return JsonSerializer.Serialize(value, _options);
        }

        /// <inheritdoc/>
        public Task<string> SerializeAsync<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return Task.FromResult(JsonSerializer.Serialize(value, _options));
        }

        /// <inheritdoc/>
        public T Deserialize<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            T? result = JsonSerializer.Deserialize<T>(json, _options);
            if (result == null)
                throw new InvalidOperationException($"Failed to deserialize JSON to type {typeof(T).Name}");

            return result;
        }

        /// <inheritdoc/>
        public Task<T> DeserializeAsync<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            T? result = JsonSerializer.Deserialize<T>(json, _options);
            if (result == null)
                throw new InvalidOperationException($"Failed to deserialize JSON to type {typeof(T).Name}");

            return Task.FromResult(result);
        }
    }
} 