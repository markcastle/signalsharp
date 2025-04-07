using System;
using SignalSharp.Core;
using SignalSharp.Security;
using SignalSharp.Storage;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Options;

namespace SignalSharp.DependencyInjection
{
    /// <summary>
    /// Configuration options for SignalSharp.
    /// </summary>
    public class SignalSharpOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignalSharpOptions"/> class.
        /// </summary>
        public SignalSharpOptions()
        {
            KeyStoreOptions = new KeyStoreOptions();
            JsonSerializerOptions = new JsonSerializerOptions();
            SessionManagerOptions = new SessionManagerOptions();
        }

        /// <summary>
        /// Gets the key store options.
        /// </summary>
        public KeyStoreOptions KeyStoreOptions { get; }

        /// <summary>
        /// Gets the JSON serializer options.
        /// </summary>
        public JsonSerializerOptions JsonSerializerOptions { get; }

        /// <summary>
        /// Gets the session manager options.
        /// </summary>
        public SessionManagerOptions SessionManagerOptions { get; }
    }

    /// <summary>
    /// Configuration options for the key store.
    /// </summary>
    public class KeyStoreOptions
    {
        /// <summary>
        /// Gets or sets the type of key store to use.
        /// </summary>
        public KeyStoreType Type { get; set; }

        /// <summary>
        /// Gets or sets the path where keys will be stored.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the factory for creating the key store.
        /// </summary>
        public Func<IServiceProvider, IKeyStore> KeyStoreFactory { get; set; } = null!;
    }

    /// <summary>
    /// Configuration options for the JSON serializer.
    /// </summary>
    public class JsonSerializerOptions
    {
        /// <summary>
        /// Gets or sets the type of JSON serializer to use.
        /// </summary>
        public JsonSerializerType Type { get; set; }

        /// <summary>
        /// Gets or sets the factory for creating the JSON serializer.
        /// </summary>
        public Func<IServiceProvider, IJsonSerializer> JsonSerializerFactory { get; set; } = null!;

        /// <summary>
        /// Gets or sets the JSON serializer options.
        /// </summary>
        public IJsonSerializerOptions Options { get; set; } = new Core.Options.JsonSerializerOptions();
    }

    /// <summary>
    /// Configuration options for the session manager.
    /// </summary>
    public class SessionManagerOptions
    {
        /// <summary>
        /// Gets or sets the type of session manager to use.
        /// </summary>
        public SessionManagerType Type { get; set; }

        /// <summary>
        /// Gets or sets the path where session states will be stored.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the factory for creating the session manager.
        /// </summary>
        public Func<IServiceProvider, ISessionManager> SessionManagerFactory { get; set; } = null!;
    }

    /// <summary>
    /// The type of JSON serializer to use.
    /// </summary>
    public enum JsonSerializerType
    {
        /// <summary>
        /// Use the default JSON serializer.
        /// </summary>
        Default,

        /// <summary>
        /// Use a custom JSON serializer.
        /// </summary>
        Custom
    }

    /// <summary>
    /// The type of key store to use.
    /// </summary>
    public enum KeyStoreType
    {
        /// <summary>
        /// Use file-based key store.
        /// </summary>
        File,

        /// <summary>
        /// Use a custom key store.
        /// </summary>
        Custom
    }

    /// <summary>
    /// The type of session manager to use.
    /// </summary>
    public enum SessionManagerType
    {
        /// <summary>
        /// Use file-based session manager.
        /// </summary>
        File,

        /// <summary>
        /// Use a custom session manager.
        /// </summary>
        Custom
    }
} 