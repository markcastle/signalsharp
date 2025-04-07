using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Core.Services
{
    /// <summary>
    /// JSON serializer implementation using Newtonsoft.Json.
    /// </summary>
    public class NewtonsoftJsonSerializer : IJsonSerializer
    {
        private readonly JsonSerializerSettings _settings;

        /// <summary>
        /// Initializes a new instance of the <see cref="NewtonsoftJsonSerializer"/> class.
        /// </summary>
        public NewtonsoftJsonSerializer()
        {
            _settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        /// <inheritdoc/>
        public T Deserialize<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return JsonConvert.DeserializeObject<T>(json, _settings)
                ?? throw new InvalidOperationException($"Failed to deserialize {typeof(T).Name}");
        }

        /// <inheritdoc/>
        public string Serialize<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return JsonConvert.SerializeObject(value, _settings);
        }

        /// <inheritdoc/>
        public Task<T> DeserializeAsync<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return Task.FromResult(Deserialize<T>(json));
        }

        /// <inheritdoc/>
        public Task<string> SerializeAsync<T>(T value) where T : class
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return Task.FromResult(Serialize(value));
        }
    }
} 