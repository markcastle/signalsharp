using System;
using System.Text.Json;
using SignalSharp.Core.Interfaces;
using Newtonsoft.Json;

namespace SignalSharp.Core.Options
{
    /// <summary>
    /// Options for configuring SignalSharp services.
    /// </summary>
    public class SignalSharpOptions
    {
        /// <summary>
        /// Gets or sets the base directory for storing data.
        /// </summary>
        public string BaseDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the key store options.
        /// </summary>
        public KeyStoreOptions KeyStore { get; set; } = new();

        /// <summary>
        /// Gets or sets the JSON serializer options.
        /// </summary>
        public JsonSerializerConfiguration JsonSerializer { get; set; } = new();

        /// <summary>
        /// Gets or sets the session manager options.
        /// </summary>
        public SessionManagerOptions SessionManager { get; set; } = new();
    }

    /// <summary>
    /// Options for configuring the key store.
    /// </summary>
    public class KeyStoreOptions
    {
        /// <summary>
        /// Gets or sets the path to the key store.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of key store to use.
        /// </summary>
        public KeyStoreType Type { get; set; } = KeyStoreType.File;

        /// <summary>
        /// Gets or sets the factory for creating key store instances.
        /// </summary>
        public Func<IServiceProvider, IKeyStore>? KeyStoreFactory { get; set; }
    }

    /// <summary>
    /// Options for configuring the JSON serializer.
    /// </summary>
    public class JsonSerializerConfiguration
    {
        /// <summary>
        /// Gets or sets the type of JSON serializer to use.
        /// </summary>
        public JsonSerializerType Type { get; set; } = JsonSerializerType.SystemTextJson;

        /// <summary>
        /// Gets or sets the factory for creating JSON serializer instances.
        /// </summary>
        public Func<IServiceProvider, IJsonSerializer>? JsonSerializerFactory { get; set; }

        /// <summary>
        /// Gets or sets the System.Text.Json serializer options.
        /// </summary>
        public System.Text.Json.JsonSerializerOptions? SystemTextJsonOptions { get; set; }

        /// <summary>
        /// Gets or sets the Newtonsoft.Json serializer settings.
        /// </summary>
        public Newtonsoft.Json.JsonSerializerSettings? NewtonsoftJsonSettings { get; set; }
    }

    /// <summary>
    /// Options for configuring the session manager.
    /// </summary>
    public class SessionManagerOptions
    {
        /// <summary>
        /// Gets or sets the path to the session manager.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of session manager to use.
        /// </summary>
        public SessionManagerType Type { get; set; } = SessionManagerType.File;

        /// <summary>
        /// Gets or sets the factory for creating session manager instances.
        /// </summary>
        public Func<IServiceProvider, ISessionManager>? SessionManagerFactory { get; set; }
    }

    /// <summary>
    /// Specifies the type of key store to use.
    /// </summary>
    public enum KeyStoreType
    {
        /// <summary>
        /// Use a file-based key store.
        /// </summary>
        File,

        /// <summary>
        /// Use a custom key store implementation.
        /// </summary>
        Custom
    }

    /// <summary>
    /// Specifies the type of JSON serializer to use.
    /// </summary>
    public enum JsonSerializerType
    {
        /// <summary>
        /// Use System.Text.Json serializer.
        /// </summary>
        SystemTextJson,

        /// <summary>
        /// Use Newtonsoft.Json serializer.
        /// </summary>
        NewtonsoftJson,

        /// <summary>
        /// Use a custom JSON serializer implementation.
        /// </summary>
        Custom
    }

    /// <summary>
    /// Specifies the type of session manager to use.
    /// </summary>
    public enum SessionManagerType
    {
        /// <summary>
        /// Use a file-based session manager.
        /// </summary>
        File,

        /// <summary>
        /// Use a custom session manager implementation.
        /// </summary>
        Custom
    }
} 