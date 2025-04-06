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
        public string Serialize<T>(T value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return JsonSerializer.Serialize(value, _options);
        }

        /// <inheritdoc/>
        public Task<string> SerializeAsync<T>(T value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return Task.FromResult(JsonSerializer.Serialize(value, _options));
        }

        /// <inheritdoc/>
        public T? Deserialize<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return JsonSerializer.Deserialize<T>(json, _options);
        }

        /// <inheritdoc/>
        public Task<T?> DeserializeAsync<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return Task.FromResult(JsonSerializer.Deserialize<T>(json, _options));
        }
    }
} 