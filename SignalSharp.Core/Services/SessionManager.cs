using System;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Services
{
    /// <summary>
    /// Manages cryptographic sessions for secure messaging.
    /// </summary>
    /// <remarks>
    /// The SessionManager provides:
    /// - Session creation and management
    /// - Message encryption and decryption
    /// - Key storage and retrieval
    /// - Session state management
    /// - Protection against message replay attacks
    /// </remarks>
    public class SessionManager : ISessionManager
    {
        private readonly IKeyStore _keyStore;
        private readonly IEncryptionService _encryptionService;
        private readonly IKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;
        private readonly IDoubleRatchetService _doubleRatchetService;

        /// <summary>
        /// Initializes a new instance of the SessionManager class.
        /// </summary>
        /// <param name="keyStore">The key store for persistent storage.</param>
        /// <param name="encryptionService">The encryption service for message encryption/decryption.</param>
        /// <param name="keyExchangeService">The key exchange service for key agreement.</param>
        /// <param name="hashService">The hash service for key derivation.</param>
        /// <param name="doubleRatchetService">The double ratchet service for forward secrecy.</param>
        /// <exception cref="ArgumentNullException">Thrown when any of the parameters are null.</exception>
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

        /// <summary>
        /// Creates a new session with the specified parameters.
        /// </summary>
        /// <param name="remoteIdentityKey">The remote party's identity public key.</param>
        /// <param name="remotePreKey">The remote party's prekey public key.</param>
        /// <param name="remotePreKeySignature">The remote party's prekey signature.</param>
        /// <returns>The session ID for the newly created session.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any required parameter is empty.</exception>
        /// <exception cref="InvalidOperationException">Thrown when session creation fails.</exception>
        public async Task<string> CreateSessionAsync(
            byte[] remoteIdentityKey,
            byte[] remotePreKey,
            byte[] remotePreKeySignature)
        {
            if (remoteIdentityKey == null) throw new ArgumentNullException(nameof(remoteIdentityKey));
            if (remotePreKey == null) throw new ArgumentNullException(nameof(remotePreKey));
            if (remotePreKeySignature == null) throw new ArgumentNullException(nameof(remotePreKeySignature));

            if (remoteIdentityKey.Length == 0) throw new ArgumentException("Remote identity key cannot be empty", nameof(remoteIdentityKey));
            if (remotePreKey.Length == 0) throw new ArgumentException("Remote prekey cannot be empty", nameof(remotePreKey));
            if (remotePreKeySignature.Length == 0) throw new ArgumentException("Remote prekey signature cannot be empty", nameof(remotePreKeySignature));

            try
            {
                // Generate local identity key pair
                var (localIdentityPublicKey, localIdentityPrivateKey) = await _keyExchangeService.GenerateKeyPairAsync();

                // Store local identity keys
                await _keyStore.StoreKeyAsync("local_identity_key", localIdentityPublicKey);
                await _keyStore.StoreKeyAsync("local_identity_private_key", localIdentityPrivateKey);

                // Generate root key
                var rootKey = await _hashService.GenerateRandomBytesAsync(32);
                await _keyStore.StoreKeyAsync("root_key", rootKey);

                // Initialize double ratchet
                var (sendingChainKey, receivingChainKey) = await _doubleRatchetService.InitializeRatchetAsync(
                    rootKey,
                    remotePreKey,
                    true);

                // Store chain keys
                await _keyStore.StoreKeyAsync("sending_chain_key", sendingChainKey);
                await _keyStore.StoreKeyAsync("receiving_chain_key", receivingChainKey);

                // Generate and store ratchet keys
                var (sendingRatchetKey, receivingRatchetKey) = await _keyExchangeService.GenerateKeyPairAsync();
                await _keyStore.StoreKeyAsync("sending_ratchet_key", sendingRatchetKey);
                await _keyStore.StoreKeyAsync("receiving_ratchet_key", receivingRatchetKey);

                // Create session state
                var sessionState = new SessionState
                {
                    SessionId = Guid.NewGuid().ToString(),
                    RemoteIdentityKey = remoteIdentityKey,
                    RemotePreKey = remotePreKey,
                    RemotePreKeySignature = remotePreKeySignature,
                    LocalIdentityKey = localIdentityPublicKey,
                    RootKey = rootKey,
                    SendingChainKey = sendingChainKey,
                    ReceivingChainKey = receivingChainKey,
                    SendingRatchetKey = sendingRatchetKey,
                    ReceivingRatchetKey = receivingRatchetKey,
                    MessageNumber = 0,
                    PreviousMessageNumber = 0
                };

                // Store session state
                await _keyStore.StoreSessionStateAsync(sessionState.SessionId, sessionState);

                return sessionState.SessionId;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to create session", ex);
            }
        }

        /// <summary>
        /// Processes an incoming encrypted message.
        /// </summary>
        /// <param name="sessionId">The ID of the session to use.</param>
        /// <param name="encryptedMessage">The encrypted message to process.</param>
        /// <returns>The decrypted message.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any parameter is empty.</exception>
        /// <exception cref="InvalidOperationException">Thrown when message processing fails.</exception>
        public async Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] encryptedMessage)
        {
            if (sessionId == null) throw new ArgumentNullException(nameof(sessionId));
            if (encryptedMessage == null) throw new ArgumentNullException(nameof(encryptedMessage));
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));
            if (encryptedMessage.Length == 0) throw new ArgumentException("Encrypted message cannot be empty", nameof(encryptedMessage));

            try
            {
                // Get session state
                var sessionState = await _keyStore.GetSessionStateAsync(sessionId);
                if (sessionState == null)
                {
                    throw new InvalidOperationException($"Session {sessionId} not found");
                }

                // Get receiving chain key
                var receivingChainKey = await _keyStore.GetKeyAsync("receiving_chain_key");
                if (receivingChainKey == null)
                {
                    throw new InvalidOperationException("Receiving chain key not found");
                }

                // Perform ratchet step
                var (newChainKey, messageKey) = await _doubleRatchetService.RatchetStepAsync(
                    receivingChainKey,
                    sessionState.MessageNumber);

                // Update session state
                sessionState.ReceivingChainKey = newChainKey;
                sessionState.MessageNumber++;
                await _keyStore.StoreSessionStateAsync(sessionId, sessionState);
                await _keyStore.StoreKeyAsync("receiving_chain_key", newChainKey);

                // Decrypt message
                var decryptedMessage = await _encryptionService.DecryptAsync(messageKey, encryptedMessage);

                return decryptedMessage;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to process incoming message", ex);
            }
        }

        /// <summary>
        /// Encrypts a message for sending.
        /// </summary>
        /// <param name="sessionId">The ID of the session to use.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any parameter is empty.</exception>
        /// <exception cref="InvalidOperationException">Thrown when message encryption fails.</exception>
        public async Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message)
        {
            if (sessionId == null) throw new ArgumentNullException(nameof(sessionId));
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));
            if (message.Length == 0) throw new ArgumentException("Message cannot be empty", nameof(message));

            try
            {
                // Get session state
                var sessionState = await _keyStore.GetSessionStateAsync(sessionId);
                if (sessionState == null)
                {
                    throw new InvalidOperationException($"Session {sessionId} not found");
                }

                // Get sending chain key
                var sendingChainKey = await _keyStore.GetKeyAsync("sending_chain_key");
                if (sendingChainKey == null)
                {
                    throw new InvalidOperationException("Sending chain key not found");
                }

                // Perform ratchet step
                var (newChainKey, messageKey) = await _doubleRatchetService.RatchetStepAsync(
                    sendingChainKey,
                    sessionState.MessageNumber);

                // Update session state
                sessionState.SendingChainKey = newChainKey;
                sessionState.MessageNumber++;
                await _keyStore.StoreSessionStateAsync(sessionId, sessionState);
                await _keyStore.StoreKeyAsync("sending_chain_key", newChainKey);

                // Encrypt message
                var encryptedMessage = await _encryptionService.EncryptAsync(messageKey, message);

                return encryptedMessage;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to encrypt message", ex);
            }
        }

        /// <summary>
        /// Deletes a session and its associated keys.
        /// </summary>
        /// <param name="sessionId">The ID of the session to delete.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
        /// <exception cref="ArgumentException">Thrown when sessionId is empty.</exception>
        /// <exception cref="InvalidOperationException">Thrown when session deletion fails.</exception>
        public async Task DeleteSessionAsync(string sessionId)
        {
            if (sessionId == null) throw new ArgumentNullException(nameof(sessionId));
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentException("Session ID cannot be empty", nameof(sessionId));

            try
            {
                // Delete session state
                await _keyStore.DeleteSessionStateAsync(sessionId);

                // Delete session-specific keys
                await _keyStore.DeleteKeyAsync("local_identity_key");
                await _keyStore.DeleteKeyAsync("local_identity_private_key");
                await _keyStore.DeleteKeyAsync("root_key");
                await _keyStore.DeleteKeyAsync("sending_chain_key");
                await _keyStore.DeleteKeyAsync("receiving_chain_key");
                await _keyStore.DeleteKeyAsync("sending_ratchet_key");
                await _keyStore.DeleteKeyAsync("receiving_ratchet_key");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to delete session", ex);
            }
        }
    }
} 