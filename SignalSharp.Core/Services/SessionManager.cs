using System;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Exceptions;

namespace SignalSharp.Core.Services
{
    /// <summary>
    /// Manages Signal protocol sessions.
    /// </summary>
    public class SessionManager : ISessionManager
    {
        private readonly IKeyStore _keyStore;
        private readonly IEncryptionService _encryptionService;
        private readonly IKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;
        private readonly IDoubleRatchetService _doubleRatchetService;
        private readonly IJsonSerializer _jsonSerializer;

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionManager"/> class.
        /// </summary>
        /// <param name="keyStore">The key store for session state persistence.</param>
        /// <param name="encryptionService">The encryption service for message encryption.</param>
        /// <param name="keyExchangeService">The key exchange service for key agreement.</param>
        /// <param name="hashService">The hash service for key derivation.</param>
        /// <param name="doubleRatchetService">The double ratchet service for forward secrecy.</param>
        /// <param name="jsonSerializer">The JSON serializer for session state serialization.</param>
        /// <exception cref="ArgumentNullException">Thrown when any of the parameters are null.</exception>
        public SessionManager(
            IKeyStore keyStore,
            IEncryptionService encryptionService,
            IKeyExchangeService keyExchangeService,
            IHashService hashService,
            IDoubleRatchetService doubleRatchetService,
            IJsonSerializer jsonSerializer)
        {
            _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
            _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
            _doubleRatchetService = doubleRatchetService ?? throw new ArgumentNullException(nameof(doubleRatchetService));
            _jsonSerializer = jsonSerializer ?? throw new ArgumentNullException(nameof(jsonSerializer));
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

            try
            {
                // Generate local identity key pair
                var (localIdentityPublicKey, localIdentityPrivateKey) = await _keyExchangeService.GenerateKeyPairAsync();

                // Generate root key using a secure random number generator
                var rootKey = new byte[32];
                using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                {
                    rng.GetBytes(rootKey);
                }

                // Generate initial chain keys
                var sendingChainKey = new byte[32];
                var receivingChainKey = new byte[32];
                using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                {
                    rng.GetBytes(sendingChainKey);
                    rng.GetBytes(receivingChainKey);
                }

                // Generate and store ratchet keys
                var (sendingRatchetKey, receivingRatchetKey) = await _keyExchangeService.GenerateKeyPairAsync();

                // Initialize session state
                var sessionState = new SessionState(
                    sessionId,
                    localIdentityPublicKey,
                    remoteIdentityKey,
                    rootKey,
                    sendingChainKey,
                    receivingChainKey,
                    sendingRatchetKey,
                    receivingRatchetKey);

                // Initialize session with double ratchet
                var initializedState = await _doubleRatchetService.InitializeSessionAsync(
                    rootKey,
                    sendingRatchetKey,
                    receivingRatchetKey);

                // Save session state
                await SaveSessionStateAsync(initializedState);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to create session", ex);
            }
        }

        /// <inheritdoc/>
        public async Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] encryptedMessage)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            var sessionState = await GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new SessionNotFoundException($"Session {sessionId} not found.", sessionId);

            var signalMessage = new SignalMessage
            {
                Ciphertext = encryptedMessage,
                SenderIdentityKey = sessionState.RemoteIdentityKey,
                SenderEphemeralKey = sessionState.ReceivingRatchetKey,
                MessageNumber = sessionState.ReceivingMessageNumber
            };

            var (decryptedMessage, updatedState) = await _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage);
            await SaveSessionStateAsync(updatedState);
            return decryptedMessage;
        }

        /// <inheritdoc/>
        public async Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            var sessionState = await GetSessionStateAsync(sessionId);
            if (sessionState == null)
                throw new SessionNotFoundException($"Session {sessionId} not found.", sessionId);

            var (signalMessage, updatedState) = await _doubleRatchetService.EncryptMessageAsync(sessionState, message);
            await SaveSessionStateAsync(updatedState);
            return signalMessage.Ciphertext;
        }

        /// <inheritdoc/>
        public async Task DeleteSessionAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            await _keyStore.DeleteAsync(sessionId);
        }

        /// <inheritdoc/>
        public async Task<SessionState?> GetSessionStateAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            var sessionStateJson = await _keyStore.GetAsync(sessionId);
            if (string.IsNullOrEmpty(sessionStateJson))
                throw new SessionNotFoundException($"Session {sessionId} not found.", sessionId);

            return _jsonSerializer.Deserialize<SessionState>(sessionStateJson);
        }

        /// <inheritdoc/>
        public async Task SaveSessionStateAsync(SessionState sessionState)
        {
            if (sessionState == null)
                throw new ArgumentNullException(nameof(sessionState));

            var sessionStateJson = _jsonSerializer.Serialize(sessionState);
            await _keyStore.SetAsync(sessionState.SessionId, sessionStateJson);
        }
    }
} 