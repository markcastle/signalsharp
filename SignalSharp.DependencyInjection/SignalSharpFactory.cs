using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SignalSharp.Core;
using SignalSharp.Security;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;
using SignalSharp.Core.Services;
using SignalSharp.Core.Options;
using SignalSharp.Storage.Services;
using SignalSharp.Serialization.SystemTextJson;
using SignalSharp.Serialization.NewtonsoftJson;

namespace SignalSharp.DependencyInjection
{
    /// <summary>
    /// Factory for creating SignalSharp services.
    /// </summary>
    public class SignalSharpFactory : ISignalSharpFactory
    {
        private readonly IKeyStore _keyStore;
        private readonly IJsonSerializer _jsonSerializer;
        private readonly ISessionManager _sessionManager;
        private readonly IEcKeyExchangeService _ecKeyExchangeService;
        private readonly IEncryptionService _encryptionService;
        private readonly IHashService _hashService;
        private readonly IDoubleRatchetService _doubleRatchetService;
        private readonly IX3DHKeyAgreementService _x3DHKeyAgreementService;
        private readonly SignalSharpOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="SignalSharpFactory"/> class.
        /// </summary>
        /// <param name="serviceProvider">The service provider.</param>
        /// <param name="options">The SignalSharp options.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="serviceProvider"/> or <paramref name="options"/> is null.</exception>
        public SignalSharpFactory(IServiceProvider serviceProvider, IOptions<SignalSharpOptions> options)
        {
            if (serviceProvider == null)
                throw new ArgumentNullException(nameof(serviceProvider));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            _options = options.Value;
            _keyStore = serviceProvider.GetRequiredService<IKeyStore>();
            _jsonSerializer = serviceProvider.GetRequiredService<IJsonSerializer>();
            _sessionManager = serviceProvider.GetRequiredService<ISessionManager>();
            _ecKeyExchangeService = serviceProvider.GetRequiredService<IEcKeyExchangeService>();
            _encryptionService = serviceProvider.GetRequiredService<IEncryptionService>();
            _hashService = serviceProvider.GetRequiredService<IHashService>();
            _doubleRatchetService = serviceProvider.GetRequiredService<IDoubleRatchetService>();
            _x3DHKeyAgreementService = serviceProvider.GetRequiredService<IX3DHKeyAgreementService>();
        }

        /// <summary>
        /// Creates a new instance of the <see cref="SignalSharpFactory"/> class with default options.
        /// </summary>
        /// <param name="baseDirectory">The base directory for storing data.</param>
        /// <returns>A new instance of the <see cref="SignalSharpFactory"/> class.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="baseDirectory"/> is null or empty.</exception>
        public static SignalSharpFactory CreateDefault(string baseDirectory)
        {
            if (string.IsNullOrEmpty(baseDirectory))
                throw new ArgumentException("Base directory cannot be null or empty.", nameof(baseDirectory));

            var services = new ServiceCollection();

            // Configure options
            var options = new Core.Options.SignalSharpOptions
            {
                BaseDirectory = baseDirectory,
                KeyStore = new Core.Options.KeyStoreOptions
                {
                    Path = Path.Combine(baseDirectory, "keys"),
                    Type = Core.Options.KeyStoreType.File
                },
                JsonSerializer = new Core.Options.JsonSerializerConfiguration
                {
                    Type = Core.Options.JsonSerializerType.Default,
                    Options = new Core.Options.JsonSerializerOptions()
                },
                SessionManager = new Core.Options.SessionManagerOptions
                {
                    Path = Path.Combine(baseDirectory, "sessions"),
                    Type = Core.Options.SessionManagerType.File
                }
            };

            services.Configure<Core.Options.SignalSharpOptions>(o => 
            {
                o.BaseDirectory = options.BaseDirectory;
                o.KeyStore = options.KeyStore;
                o.JsonSerializer = options.JsonSerializer;
                o.SessionManager = options.SessionManager;
            });

            // Register services
            services.AddSingleton<IKeyStore, FileKeyStore>();
            services.AddSingleton<IJsonSerializer, Serialization.SystemTextJson.SystemTextJsonSerializer>();
            services.AddSingleton<ISessionManager, FileSessionManager>();
            services.AddSingleton<IEcKeyExchangeService, EcKeyExchangeService>();
            services.AddSingleton<IEncryptionService, AesEncryptionService>();
            services.AddSingleton<IHashService, HashService>();
            services.AddSingleton<IDoubleRatchetService, DoubleRatchetService>();
            services.AddSingleton<IX3DHKeyAgreementService, X3DHKeyAgreementService>();
            services.AddSingleton<ISignalSharpFactory, SignalSharpFactory>();

            var serviceProvider = services.BuildServiceProvider();
            return (SignalSharpFactory)serviceProvider.GetRequiredService<ISignalSharpFactory>();
        }

        /// <inheritdoc/>
        public async Task<KeyPair> CreateIdentityKeyPairAsync()
        {
            var (publicKey, privateKey) = await _ecKeyExchangeService.GenerateKeyPairAsync();
            await _keyStore.StoreKeyAsync("identity", privateKey);
            return new KeyPair(publicKey, privateKey);
        }

        /// <inheritdoc/>
        public async Task<SessionState> CreateSessionAsync(string recipientId, KeyPair identityKeyPair)
        {
            if (string.IsNullOrEmpty(recipientId))
                throw new ArgumentNullException(nameof(recipientId));
            if (identityKeyPair == null)
                throw new ArgumentNullException(nameof(identityKeyPair));

            // Generate remote keys (in a real implementation, these would come from the recipient)
            var (remotePublicKey, _) = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var (remoteSignedPreKey, _) = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var (remoteOneTimePreKey, _) = await _ecKeyExchangeService.GenerateKeyPairAsync();

            // Create the session
            await _sessionManager.CreateSessionAsync(recipientId, remotePublicKey, remoteSignedPreKey, remoteOneTimePreKey);
            return await _sessionManager.GetSessionStateAsync(recipientId);
        }

        /// <inheritdoc/>
        public async Task<byte[]> EncryptMessageAsync(string recipientId, byte[] message)
        {
            if (string.IsNullOrEmpty(recipientId))
                throw new ArgumentNullException(nameof(recipientId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            return await _sessionManager.EncryptMessageAsync(recipientId, message);
        }

        /// <inheritdoc/>
        public async Task<byte[]> DecryptMessageAsync(string senderId, byte[] message)
        {
            if (string.IsNullOrEmpty(senderId))
                throw new ArgumentNullException(nameof(senderId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            return await _sessionManager.ProcessIncomingMessageAsync(senderId, message);
        }

        /// <inheritdoc/>
        public async Task<KeyPair> CreateSignedPreKeyPairAsync()
        {
            var keys = await _ecKeyExchangeService.GenerateKeyPairAsync();
            return new KeyPair(keys.PublicKey, keys.PrivateKey);
        }

        /// <inheritdoc/>
        public async Task<KeyPair> CreateOneTimePreKeyPairAsync()
        {
            var keys = await _ecKeyExchangeService.GenerateKeyPairAsync();
            return new KeyPair(keys.PublicKey, keys.PrivateKey);
        }

        /// <inheritdoc/>
        public async Task<SessionState> CreateSessionStateAsync(string sessionId, KeyPair identityKeyPair, KeyPair signedPreKeyPair)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (identityKeyPair == null)
                throw new ArgumentNullException(nameof(identityKeyPair));
            if (signedPreKeyPair == null)
                throw new ArgumentNullException(nameof(signedPreKeyPair));

            var rootKey = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var sendingChainKey = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var receivingChainKey = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var sendingRatchetKey = await _ecKeyExchangeService.GenerateKeyPairAsync();
            var receivingRatchetKey = await _ecKeyExchangeService.GenerateKeyPairAsync();

            var sessionState = new SessionState(
                sessionId,
                identityKeyPair.PublicKey,
                identityKeyPair.PrivateKey,
                rootKey.PublicKey,
                sendingChainKey.PublicKey,
                receivingChainKey.PublicKey,
                sendingRatchetKey.PublicKey,
                receivingRatchetKey.PublicKey);

            await _sessionManager.SaveSessionStateAsync(sessionState);
            return sessionState;
        }

        /// <inheritdoc/>
        public async Task<EncryptedMessage> EncryptMessageAsync(string sessionId, string message)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException(nameof(message));

            var sessionState = await _sessionManager.GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new InvalidOperationException($"Session {sessionId} not found.");

            var messageBytes = Encoding.UTF8.GetBytes(message);
            var iv = await _encryptionService.GenerateIvAsync();
            var encryptedData = await _encryptionService.EncryptAsync(messageBytes, sessionState.LocalIdentityKey);
            var mac = await _hashService.ComputeMacAsync(encryptedData, sessionState.LocalIdentityKey);
            var ephemeralKey = await _ecKeyExchangeService.GenerateKeyPairAsync();

            return new EncryptedMessage(
                encryptedData,
                mac,
                iv,
                sessionState.LocalIdentityKey,
                ephemeralKey.PublicKey);
        }

        /// <inheritdoc/>
        public async Task<DecryptedMessage> DecryptMessageAsync(string sessionId, EncryptedMessage encryptedMessage)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            var sessionState = await _sessionManager.GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new InvalidOperationException($"Session {sessionId} not found.");

            var decryptedData = await _encryptionService.DecryptAsync(
                encryptedMessage.Ciphertext,
                sessionState.LocalIdentityKey);

            return new DecryptedMessage(decryptedData, encryptedMessage.SenderIdentityKey);
        }

        /// <inheritdoc/>
        public Task<ISessionManager> CreateSessionManagerAsync()
        {
            return Task.FromResult(_sessionManager);
        }

        /// <inheritdoc/>
        public Task<IKeyStore> CreateKeyStoreAsync()
        {
            return Task.FromResult(_keyStore);
        }

        /// <inheritdoc/>
        public Task<IEncryptionService> CreateEncryptionServiceAsync()
        {
            return Task.FromResult(_encryptionService);
        }

        /// <inheritdoc/>
        public Task<IEcKeyExchangeService> CreateKeyExchangeServiceAsync()
        {
            return Task.FromResult(_ecKeyExchangeService);
        }

        /// <inheritdoc/>
        public Task<IHashService> CreateHashServiceAsync()
        {
            return Task.FromResult(_hashService);
        }

        /// <inheritdoc/>
        public Task<IDoubleRatchetService> CreateDoubleRatchetServiceAsync()
        {
            return Task.FromResult(_doubleRatchetService);
        }

        /// <inheritdoc/>
        public Task<IX3DHKeyAgreementService> CreateX3DHKeyAgreementServiceAsync()
        {
            return Task.FromResult(_x3DHKeyAgreementService);
        }

        /// <inheritdoc/>
        public Task<IJsonSerializer> CreateJsonSerializerAsync()
        {
            return Task.FromResult(_jsonSerializer);
        }
    }
} 