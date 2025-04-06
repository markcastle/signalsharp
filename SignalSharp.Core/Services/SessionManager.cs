using System;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Services
{
    /// <summary>
    /// Provides implementation for managing Signal protocol sessions.
    /// </summary>
    public class SessionManager : ISessionManager
    {
        private readonly IKeyStore _keyStore;
        private readonly IEncryptionService _encryptionService;
        private readonly IKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;
        private readonly IDoubleRatchetService _doubleRatchetService;

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionManager"/> class.
        /// </summary>
        /// <param name="keyStore">The key store for storing and retrieving keys.</param>
        /// <param name="encryptionService">The encryption service for encrypting and decrypting messages.</param>
        /// <param name="keyExchangeService">The key exchange service for establishing shared secrets.</param>
        /// <param name="hashService">The hash service for computing and verifying hashes.</param>
        /// <param name="doubleRatchetService">The double ratchet service for message encryption and decryption.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public SessionManager(
            IKeyStore keyStore,
            IEncryptionService encryptionService,
            IKeyExchangeService keyExchangeService,
            IHashService hashService,
            IDoubleRatchetService doubleRatchetService)
        {
            _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
            _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
            _doubleRatchetService = doubleRatchetService ?? throw new ArgumentNullException(nameof(doubleRatchetService));
        }

        /// <inheritdoc/>
        public async Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey, byte[] remotePreKeySignature)
        {
            if (remoteIdentityKey == null) throw new ArgumentNullException(nameof(remoteIdentityKey));
            if (remotePreKey == null) throw new ArgumentNullException(nameof(remotePreKey));
            if (remotePreKeySignature == null) throw new ArgumentNullException(nameof(remotePreKeySignature));

            // Generate local identity key if not exists
            var localIdentityKey = await _keyStore.GetKeyAsync("local_identity_key");
            if (localIdentityKey == null)
            {
                var (publicKey, privateKey) = await _keyExchangeService.GenerateKeyPairAsync();
                await _keyStore.StoreKeyAsync("local_identity_key", publicKey);
                await _keyStore.StoreKeyAsync("local_identity_private_key", privateKey);
                localIdentityKey = publicKey;
            }

            // Perform X3DH key agreement
            var (rootKey, sendingChainKey, receivingChainKey) = await _keyExchangeService.PerformKeyExchangeAsync(
                localIdentityKey,
                remoteIdentityKey,
                remotePreKey);

            // Generate ratchet keys
            var (sendingRatchetKey, _) = await _keyExchangeService.GenerateKeyPairAsync();
            var (receivingRatchetKey, _) = await _keyExchangeService.GenerateKeyPairAsync();

            // Store keys
            await _keyStore.StoreKeyAsync("root_key", rootKey);
            await _keyStore.StoreKeyAsync("sending_chain_key", sendingChainKey);
            await _keyStore.StoreKeyAsync("receiving_chain_key", receivingChainKey);
            await _keyStore.StoreKeyAsync("sending_ratchet_key", sendingRatchetKey);
            await _keyStore.StoreKeyAsync("receiving_ratchet_key", receivingRatchetKey);

            // Create the session state
            var sessionState = await _doubleRatchetService.InitializeSessionAsync(
                rootKey,
                sendingRatchetKey,
                receivingRatchetKey);

            // Store the session state
            await _keyStore.StoreSessionStateAsync(sessionState.SessionId, sessionState);

            return sessionState.SessionId;
        }

        /// <inheritdoc/>
        public async Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentNullException(nameof(sessionId));
            if (message == null) throw new ArgumentNullException(nameof(message));

            // Get the session state
            var sessionState = await _keyStore.GetSessionStateAsync(sessionId);
            if (sessionState == null)
            {
                throw new InvalidOperationException($"Session not found: {sessionId}");
            }

            // Deserialize the signal message
            var signalMessage = new SignalMessage(
                message, // Content
                new byte[32], // MAC (placeholder)
                new byte[16], // IV (placeholder)
                sessionState.RemoteIdentityKey,
                sessionState.ReceivingRatchetKey);

            // Decrypt the message
            var (decryptedMessage, updatedState) = await _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage);

            // Update the session state
            await _keyStore.StoreSessionStateAsync(sessionId, updatedState);

            return decryptedMessage;
        }

        /// <inheritdoc/>
        public async Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentNullException(nameof(sessionId));
            if (message == null) throw new ArgumentNullException(nameof(message));

            // Get the session state
            var sessionState = await _keyStore.GetSessionStateAsync(sessionId);
            if (sessionState == null)
            {
                throw new InvalidOperationException($"Session not found: {sessionId}");
            }

            // Encrypt the message
            var (signalMessage, updatedState) = await _doubleRatchetService.EncryptMessageAsync(sessionState, message);

            // Update the session state
            await _keyStore.StoreSessionStateAsync(sessionId, updatedState);

            // Return the encrypted message
            return signalMessage.Content;
        }

        /// <inheritdoc/>
        public async Task DeleteSessionAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentNullException(nameof(sessionId));

            // Delete the session state
            await _keyStore.DeleteSessionStateAsync(sessionId);
        }
    }
} 