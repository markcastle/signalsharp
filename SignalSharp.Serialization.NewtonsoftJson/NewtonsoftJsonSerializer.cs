using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Serialization.NewtonsoftJson
{
    /// <summary>
    /// Implementation of IJsonSerializer using Newtonsoft.Json.
    /// </summary>
    public class NewtonsoftJsonSerializer : IJsonSerializer
    {
        private readonly JsonSerializerSettings _settings;

        /// <summary>
        /// Initializes a new instance of the <see cref="NewtonsoftJsonSerializer"/> class.
        /// </summary>
        /// <param name="settings">Optional JSON serialization settings.</param>
        public NewtonsoftJsonSerializer(JsonSerializerSettings? settings = null)
        {
            _settings = settings ?? new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver()
            };
        }

        /// <inheritdoc/>
        public string Serialize<T>(T value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return JsonConvert.SerializeObject(value, _settings);
        }

        /// <inheritdoc/>
        public Task<string> SerializeAsync<T>(T value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            return Task.FromResult(JsonConvert.SerializeObject(value, _settings));
        }

        /// <inheritdoc/>
        public T? Deserialize<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return JsonConvert.DeserializeObject<T>(json, _settings);
        }

        /// <inheritdoc/>
        public Task<T?> DeserializeAsync<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            return Task.FromResult(JsonConvert.DeserializeObject<T>(json, _settings));
        }
    }
} 