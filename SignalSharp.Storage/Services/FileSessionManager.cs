using System;
using System.IO;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Exceptions;

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
        public async Task CreateSessionAsync(string sessionId, byte[] remoteIdentityKey, byte[] remoteSignedPreKey, byte[] remoteOneTimePreKey)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (remoteIdentityKey == null)
                throw new ArgumentNullException(nameof(remoteIdentityKey));
            if (remoteSignedPreKey == null)
                throw new ArgumentNullException(nameof(remoteSignedPreKey));
            if (remoteOneTimePreKey == null)
                throw new ArgumentNullException(nameof(remoteOneTimePreKey));

            string? localIdentityKey = await _keyStore.GetAsync("local_identity_key");
            string? rootKey = await _keyStore.GetAsync("root_key");
            string? sendingChainKey = await _keyStore.GetAsync("sending_chain_key");
            string? receivingChainKey = await _keyStore.GetAsync("receiving_chain_key");
            string? sendingRatchetKey = await _keyStore.GetAsync("sending_ratchet_key");
            string? receivingRatchetKey = await _keyStore.GetAsync("receiving_ratchet_key");

            if (string.IsNullOrEmpty(localIdentityKey) || string.IsNullOrEmpty(rootKey) || 
                string.IsNullOrEmpty(sendingChainKey) || string.IsNullOrEmpty(receivingChainKey) || 
                string.IsNullOrEmpty(sendingRatchetKey) || string.IsNullOrEmpty(receivingRatchetKey))
            {
                throw new InvalidOperationException("Required keys not found");
            }

            SessionState sessionState = new SessionState(
                sessionId,
                Convert.FromBase64String(localIdentityKey),
                remoteIdentityKey,
                Convert.FromBase64String(rootKey),
                Convert.FromBase64String(sendingChainKey),
                Convert.FromBase64String(receivingChainKey),
                Convert.FromBase64String(sendingRatchetKey),
                Convert.FromBase64String(receivingRatchetKey));

            await SaveSessionStateAsync(sessionState);
        }

        /// <inheritdoc/>
        public async Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            SessionState? sessionState = await GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new SessionNotFoundException($"Session {sessionId} not found", sessionId);

            byte[]? decryptedMessage = await _encryptionService.DecryptAsync(message, sessionState.ReceivingChainKey);
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

            SessionState? sessionState = await GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new SessionNotFoundException($"Session {sessionId} not found", sessionId);

            byte[]? encryptedMessage = await _encryptionService.EncryptAsync(message, sessionState.SendingChainKey);
            sessionState.LastUsedAt = DateTime.UtcNow;
            await SaveSessionStateAsync(sessionState);

            return encryptedMessage;
        }

        /// <inheritdoc/>
        public async Task DeleteSessionAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            string? filePath = Path.Combine(_storageDirectory, $"{sessionId}.json");
            if (File.Exists(filePath))
            {
                await Task.Run(() => File.Delete(filePath));
            }
        }

        /// <inheritdoc/>
        public async Task<SessionState?> GetSessionStateAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            string? filePath = Path.Combine(_storageDirectory, $"{sessionId}.json");
            if (!File.Exists(filePath))
                return null;

            string? json = await File.ReadAllTextAsync(filePath);
            return _jsonSerializer.Deserialize<SessionState>(json);
        }

        /// <inheritdoc/>
        public async Task SaveSessionStateAsync(SessionState sessionState)
        {
            if (sessionState == null)
                throw new ArgumentNullException(nameof(sessionState));

            string? filePath = Path.Combine(_storageDirectory, $"{sessionState.SessionId}.json");
            string? json = _jsonSerializer.Serialize(sessionState);
            await File.WriteAllTextAsync(filePath, json);
        }
    }
} 