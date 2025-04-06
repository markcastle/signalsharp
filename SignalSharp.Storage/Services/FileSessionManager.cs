using System;
using System.IO;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Storage.Services
{
    /// <summary>
    /// Implementation of ISessionManager that stores session states in files.
    /// </summary>
    public class FileSessionManager : ISessionManager
    {
        private readonly string _storageDirectory;
        private readonly IKeyStore _keyStore;
        private readonly IEncryptionService _encryptionService;
        private readonly IJsonSerializer _jsonSerializer;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileSessionManager"/> class.
        /// </summary>
        /// <param name="storageDirectory">The directory where session states will be stored.</param>
        /// <param name="keyStore">The key store to use for key storage.</param>
        /// <param name="encryptionService">The encryption service to use for message encryption/decryption.</param>
        /// <param name="jsonSerializer">The JSON serializer to use for session state serialization.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public FileSessionManager(
            string storageDirectory,
            IKeyStore keyStore,
            IEncryptionService encryptionService,
            IJsonSerializer jsonSerializer)
        {
            if (string.IsNullOrEmpty(storageDirectory))
                throw new ArgumentNullException(nameof(storageDirectory));
            _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _jsonSerializer = jsonSerializer ?? throw new ArgumentNullException(nameof(jsonSerializer));

            _storageDirectory = storageDirectory;
            Directory.CreateDirectory(_storageDirectory);
        }

        /// <inheritdoc/>
        public async Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey, byte[] remotePreKeySignature)
        {
            if (remoteIdentityKey == null)
                throw new ArgumentNullException(nameof(remoteIdentityKey));
            if (remotePreKey == null)
                throw new ArgumentNullException(nameof(remotePreKey));
            if (remotePreKeySignature == null)
                throw new ArgumentNullException(nameof(remotePreKeySignature));

            var sessionId = Guid.NewGuid().ToString();
            var localIdentityKey = await _keyStore.GetKeyAsync("local_identity_key");
            var rootKey = await _keyStore.GetKeyAsync("root_key");
            var sendingChainKey = await _keyStore.GetKeyAsync("sending_chain_key");
            var receivingChainKey = await _keyStore.GetKeyAsync("receiving_chain_key");
            var sendingRatchetKey = await _keyStore.GetKeyAsync("sending_ratchet_key");
            var receivingRatchetKey = await _keyStore.GetKeyAsync("receiving_ratchet_key");

            if (localIdentityKey == null || rootKey == null || sendingChainKey == null ||
                receivingChainKey == null || sendingRatchetKey == null || receivingRatchetKey == null)
            {
                throw new InvalidOperationException("Required keys not found");
            }

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            await SaveSessionStateAsync(sessionState);
            return sessionId;
        }

        /// <inheritdoc/>
        public async Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            var sessionState = await LoadSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new InvalidOperationException($"Session {sessionId} not found");

            var localIdentityKey = await _keyStore.GetKeyAsync("local_identity_key");
            var rootKey = await _keyStore.GetKeyAsync("root_key");
            var sendingChainKey = await _keyStore.GetKeyAsync("sending_chain_key");
            var receivingChainKey = await _keyStore.GetKeyAsync("receiving_chain_key");
            var sendingRatchetKey = await _keyStore.GetKeyAsync("sending_ratchet_key");
            var receivingRatchetKey = await _keyStore.GetKeyAsync("receiving_ratchet_key");

            if (localIdentityKey == null || rootKey == null || sendingChainKey == null ||
                receivingChainKey == null || sendingRatchetKey == null || receivingRatchetKey == null)
            {
                throw new InvalidOperationException("Required keys not found");
            }

            var decryptedMessage = await _encryptionService.DecryptAsync(message, receivingChainKey);
            sessionState.LastUsedAt = DateTime.UtcNow;
            await SaveSessionStateAsync(sessionState);

            return decryptedMessage;
        }

        /// <inheritdoc/>
        public async Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            var sessionState = await LoadSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new InvalidOperationException($"Session {sessionId} not found");

            var localIdentityKey = await _keyStore.GetKeyAsync("local_identity_key");
            var rootKey = await _keyStore.GetKeyAsync("root_key");
            var sendingChainKey = await _keyStore.GetKeyAsync("sending_chain_key");
            var receivingChainKey = await _keyStore.GetKeyAsync("receiving_chain_key");
            var sendingRatchetKey = await _keyStore.GetKeyAsync("sending_ratchet_key");
            var receivingRatchetKey = await _keyStore.GetKeyAsync("receiving_ratchet_key");

            if (localIdentityKey == null || rootKey == null || sendingChainKey == null ||
                receivingChainKey == null || sendingRatchetKey == null || receivingRatchetKey == null)
            {
                throw new InvalidOperationException("Required keys not found");
            }

            var encryptedMessage = await _encryptionService.EncryptAsync(message, sendingChainKey);
            sessionState.LastUsedAt = DateTime.UtcNow;
            await SaveSessionStateAsync(sessionState);

            return encryptedMessage;
        }

        /// <inheritdoc/>
        public async Task DeleteSessionAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            var filePath = Path.Combine(_storageDirectory, $"{sessionId}.json");
            if (File.Exists(filePath))
            {
                await Task.Run(() => File.Delete(filePath));
            }
        }

        private async Task<SessionState?> LoadSessionStateAsync(string sessionId)
        {
            var filePath = Path.Combine(_storageDirectory, $"{sessionId}.json");
            if (!File.Exists(filePath))
                return null;

            var json = await File.ReadAllTextAsync(filePath);
            return _jsonSerializer.Deserialize<SessionState>(json);
        }

        private async Task SaveSessionStateAsync(SessionState sessionState)
        {
            var filePath = Path.Combine(_storageDirectory, $"{sessionState.SessionId}.json");
            var json = _jsonSerializer.Serialize(sessionState);
            await File.WriteAllTextAsync(filePath, json);
        }
    }
} 