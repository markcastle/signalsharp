using System;
using System.Text.Json;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Core.Services
{
    /// <summary>
    /// JSON serializer implementation using System.Text.Json.
    /// </summary>
    public class SystemTextJsonSerializer : IJsonSerializer
    {
        private readonly JsonSerializerOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="SystemTextJsonSerializer"/> class.
        /// </summary>
        public SystemTextJsonSerializer()
        {
            _options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };
        }

        /// <inheritdoc/>
        public T Deserialize<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return JsonSerializer.Deserialize<T>(json, _options)
                ?? throw new InvalidOperationException($"Failed to deserialize {typeof(T).Name}");
        }

        /// <inheritdoc/>
        public string Serialize<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return JsonSerializer.Serialize(value, _options);
        }

        /// <inheritdoc/>
        public async Task<T> DeserializeAsync<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            using var stream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(json));
            var result = await JsonSerializer.DeserializeAsync<T>(stream, _options);
            return result ?? throw new InvalidOperationException($"Failed to deserialize {typeof(T).Name}");
        }

        /// <inheritdoc/>
        public async Task<string> SerializeAsync<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            using var stream = new System.IO.MemoryStream();
            await JsonSerializer.SerializeAsync(stream, value, _options);
            stream.Position = 0;
            using var reader = new System.IO.StreamReader(stream);
            return await reader.ReadToEndAsync();
        }
    }
} 