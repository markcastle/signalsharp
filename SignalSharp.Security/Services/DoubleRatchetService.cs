using System;
using System.Linq;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Security.Services
{
    /// <summary>
    /// Implements the Double Ratchet algorithm for secure messaging with forward secrecy.
    /// </summary>
    /// <remarks>
    /// The Double Ratchet algorithm provides:
    /// - Forward secrecy through key rotation
    /// - Protection against message replay attacks
    /// - Protection against message skipping attacks
    /// - Perfect forward secrecy through ratcheting
    /// </remarks>
    public class DoubleRatchetService : IDoubleRatchetService
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IEcKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;
        private const int KeyLength = 32; // 256 bits

        /// <summary>
        /// Initializes a new instance of the DoubleRatchetService class.
        /// </summary>
        /// <param name="encryptionService">The encryption service used for message encryption/decryption.</param>
        /// <param name="keyExchangeService">The key exchange service used for ratchet key generation.</param>
        /// <param name="hashService">The hash service used for key derivation.</param>
        /// <exception cref="ArgumentNullException">Thrown when any of the parameters are null.</exception>
        public DoubleRatchetService(
            IEncryptionService encryptionService,
            IEcKeyExchangeService keyExchangeService,
            IHashService hashService)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
            _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
        }

        /// <summary>
        /// Initializes a new ratchet session with the provided parameters.
        /// </summary>
        /// <param name="rootKey">The root key for the session.</param>
        /// <param name="remoteRatchetKey">The remote party's ratchet public key.</param>
        /// <param name="isInitiator">Whether this party initiated the session.</param>
        /// <returns>A tuple containing the sending and receiving chain keys.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rootKey or remoteRatchetKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when rootKey or remoteRatchetKey is empty.</exception>
        public async Task<(byte[] sendingChainKey, byte[] receivingChainKey)> InitializeRatchetAsync(
            byte[] rootKey,
            byte[] remoteRatchetKey,
            bool isInitiator)
        {
            if (rootKey == null) throw new ArgumentNullException(nameof(rootKey));
            if (remoteRatchetKey == null) throw new ArgumentNullException(nameof(remoteRatchetKey));
            if (rootKey.Length == 0) throw new ArgumentException("Root key cannot be empty", nameof(rootKey));
            if (remoteRatchetKey.Length == 0) throw new ArgumentException("Remote ratchet key cannot be empty", nameof(remoteRatchetKey));

            // Generate a new ratchet key pair
            var (ratchetPublicKey, ratchetPrivateKey) = await _keyExchangeService.GenerateKeyPairAsync();

            // Perform key exchange
            var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(ratchetPrivateKey, remoteRatchetKey);
            if (sharedSecret == null || sharedSecret.Length == 0)
                throw new InvalidOperationException("Failed to compute shared secret");

            // Derive chain keys
            var (sendingChainKey, receivingChainKey) = await DeriveChainKeysAsync(rootKey, sharedSecret, isInitiator);

            return (sendingChainKey, receivingChainKey);
        }

        /// <summary>
        /// Performs a ratchet step to generate new message keys.
        /// </summary>
        /// <param name="chainKey">The current chain key.</param>
        /// <param name="messageNumber">The message number for key derivation.</param>
        /// <returns>A tuple containing the new chain key and message key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when chainKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when chainKey is empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when messageNumber is negative.</exception>
        public async Task<(byte[] newChainKey, byte[] messageKey)> RatchetStepAsync(
            byte[] chainKey,
            uint messageNumber)
        {
            if (chainKey == null) throw new ArgumentNullException(nameof(chainKey));
            if (chainKey.Length == 0) throw new ArgumentException("Chain key cannot be empty", nameof(chainKey));

            // Derive message key
            var messageKey = await _hashService.DeriveKeyAsync(chainKey, System.Text.Encoding.UTF8.GetBytes($"message_{messageNumber}"), KeyLength);
            if (messageKey == null || messageKey.Length == 0)
                throw new InvalidOperationException("Failed to derive message key");

            // Derive new chain key
            var newChainKey = await _hashService.DeriveKeyAsync(chainKey, System.Text.Encoding.UTF8.GetBytes("chain"), KeyLength);
            if (newChainKey == null || newChainKey.Length == 0)
                throw new InvalidOperationException("Failed to derive new chain key");

            return (newChainKey, messageKey);
        }

        /// <summary>
        /// Derives chain keys from the root key and shared secret.
        /// </summary>
        /// <param name="rootKey">The root key for key derivation.</param>
        /// <param name="sharedSecret">The shared secret from key exchange.</param>
        /// <param name="isInitiator">Whether this party initiated the session.</param>
        /// <returns>A tuple containing the sending and receiving chain keys.</returns>
        /// <exception cref="ArgumentNullException">Thrown when rootKey or sharedSecret is null.</exception>
        /// <exception cref="ArgumentException">Thrown when rootKey or sharedSecret is empty.</exception>
        private async Task<(byte[] sendingChainKey, byte[] receivingChainKey)> DeriveChainKeysAsync(
            byte[] rootKey,
            byte[] sharedSecret,
            bool isInitiator)
        {
            if (rootKey == null) throw new ArgumentNullException(nameof(rootKey));
            if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
            if (rootKey.Length == 0) throw new ArgumentException("Root key cannot be empty", nameof(rootKey));
            if (sharedSecret.Length == 0) throw new ArgumentException("Shared secret cannot be empty", nameof(sharedSecret));

            // Derive chain keys based on initiator status
            var (sendingChainKey, receivingChainKey) = isInitiator
                ? (await DeriveChainKeyAsync(rootKey, sharedSecret, "sending"),
                   await DeriveChainKeyAsync(rootKey, sharedSecret, "receiving"))
                : (await DeriveChainKeyAsync(rootKey, sharedSecret, "receiving"),
                   await DeriveChainKeyAsync(rootKey, sharedSecret, "sending"));

            if (sendingChainKey == null || sendingChainKey.Length == 0)
                throw new InvalidOperationException("Failed to derive sending chain key");
            if (receivingChainKey == null || receivingChainKey.Length == 0)
                throw new InvalidOperationException("Failed to derive receiving chain key");

            return (sendingChainKey, receivingChainKey);
        }

        /// <summary>
        /// Derives a chain key from the root key and shared secret.
        /// </summary>
        /// <param name="rootKey">The root key for key derivation.</param>
        /// <param name="sharedSecret">The shared secret from key exchange.</param>
        /// <param name="purpose">The purpose of the chain key ("sending" or "receiving").</param>
        /// <returns>The derived chain key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when rootKey or sharedSecret is empty, or purpose is invalid.</exception>
        private async Task<byte[]> DeriveChainKeyAsync(
            byte[] rootKey,
            byte[] sharedSecret,
            string purpose)
        {
            if (rootKey == null) throw new ArgumentNullException(nameof(rootKey));
            if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
            if (purpose == null) throw new ArgumentNullException(nameof(purpose));
            if (rootKey.Length == 0) throw new ArgumentException("Root key cannot be empty", nameof(rootKey));
            if (sharedSecret.Length == 0) throw new ArgumentException("Shared secret cannot be empty", nameof(sharedSecret));
            if (purpose != "sending" && purpose != "receiving")
                throw new ArgumentException("Purpose must be either 'sending' or 'receiving'", nameof(purpose));

            // Combine root key and shared secret
            var combined = new byte[rootKey.Length + sharedSecret.Length];
            Buffer.BlockCopy(rootKey, 0, combined, 0, rootKey.Length);
            Buffer.BlockCopy(sharedSecret, 0, combined, rootKey.Length, sharedSecret.Length);

            // Derive chain key using HKDF
            var chainKey = await _hashService.DeriveKeyAsync(combined, System.Text.Encoding.UTF8.GetBytes(purpose), KeyLength);
            if (chainKey == null || chainKey.Length == 0)
                throw new InvalidOperationException($"Failed to derive {purpose} chain key");

            return chainKey;
        }

        /// <inheritdoc/>
        public async Task<SessionState> InitializeSessionAsync(byte[] rootKey, byte[] sendingRatchetKey, byte[] receivingRatchetKey)
        {
            if (rootKey == null || rootKey.Length == 0)
                throw new ArgumentException("Root key cannot be empty", nameof(rootKey));
            if (sendingRatchetKey == null || sendingRatchetKey.Length == 0)
                throw new ArgumentException("Sending ratchet key cannot be empty", nameof(sendingRatchetKey));
            if (receivingRatchetKey == null || receivingRatchetKey.Length == 0)
                throw new ArgumentException("Receiving ratchet key cannot be empty", nameof(receivingRatchetKey));

            try
            {
                // Generate initial chain keys
                var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey);
                if (sharedSecret == null || sharedSecret.Length == 0)
                    throw new InvalidOperationException("Failed to compute shared secret");

                var (sendingChainKey, receivingChainKey) = await InitializeRatchetAsync(rootKey, sharedSecret, true);
                if (sendingChainKey == null || sendingChainKey.Length == 0)
                    throw new InvalidOperationException("Failed to initialize sending chain key");
                if (receivingChainKey == null || receivingChainKey.Length == 0)
                    throw new InvalidOperationException("Failed to initialize receiving chain key");

                // Create session state
                return new SessionState(
                    Guid.NewGuid().ToString(),
                    sendingRatchetKey,
                    receivingRatchetKey,
                    rootKey,
                    sendingChainKey,
                    receivingChainKey,
                    sendingRatchetKey,
                    receivingRatchetKey);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to initialize session", ex);
            }
        }

        /// <inheritdoc/>
        public async Task<(SignalMessage Message, SessionState UpdatedState)> EncryptMessageAsync(SessionState sessionState, byte[] message)
        {
            if (sessionState == null)
                throw new ArgumentNullException(nameof(sessionState));
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (sessionState.SendingChainKey == null || sessionState.SendingChainKey.Length == 0)
                throw new InvalidOperationException("Sending chain key cannot be empty");
            if (sessionState.SendingRatchetKey == null || sessionState.SendingRatchetKey.Length == 0)
                throw new InvalidOperationException("Sending ratchet key cannot be empty");

            try
            {
                // Perform ratchet step to get message key and new chain key
                var (newChainKey, messageKey) = await RatchetStepAsync(sessionState.SendingChainKey, sessionState.SendingMessageNumber);

                // Encrypt message
                var encryptedMessage = await _encryptionService.EncryptAsync(message, messageKey);
                if (encryptedMessage == null || encryptedMessage.Length == 0)
                    throw new InvalidOperationException("Failed to encrypt message");

                // Compute MAC using message key
                var mac = await _hashService.ComputeKeyedHashAsync(encryptedMessage, messageKey);
                if (mac == null || mac.Length == 0)
                    throw new InvalidOperationException("Failed to compute MAC");

                // Create signal message
                var signalMessage = new SignalMessage
                {
                    RatchetKey = sessionState.SendingRatchetKey,
                    MessageNumber = sessionState.SendingMessageNumber,
                    Ciphertext = encryptedMessage,
                    Mac = mac
                };

                // Update session state
                var updatedState = new SessionState(
                    sessionState.SessionId,
                    sessionState.LocalIdentityKey,
                    sessionState.RemoteIdentityKey,
                    sessionState.RootKey,
                    newChainKey,
                    sessionState.ReceivingChainKey,
                    sessionState.SendingRatchetKey,
                    sessionState.ReceivingRatchetKey)
                {
                    SendingMessageNumber = sessionState.SendingMessageNumber + 1
                };

                return (signalMessage, updatedState);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to encrypt message", ex);
            }
        }

        /// <inheritdoc/>
        public async Task<(byte[] DecryptedMessage, SessionState UpdatedState)> DecryptMessageAsync(SessionState sessionState, SignalMessage message)
        {
            if (sessionState == null)
                throw new ArgumentNullException(nameof(sessionState));
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (sessionState.ReceivingChainKey == null || sessionState.ReceivingChainKey.Length == 0)
                throw new InvalidOperationException("Receiving chain key cannot be empty");
            if (message.Ciphertext == null || message.Ciphertext.Length == 0)
                throw new InvalidOperationException("Message ciphertext cannot be empty");
            if (message.Mac == null || message.Mac.Length == 0)
                throw new InvalidOperationException("Message MAC cannot be empty");

            try
            {
                // First perform ratchet step to get message key and new chain key
                var (newChainKey, messageKey) = await RatchetStepAsync(sessionState.ReceivingChainKey, message.MessageNumber);

                // Verify MAC
                if (!await _hashService.VerifyKeyedHashAsync(message.Ciphertext, messageKey, message.Mac))
                    throw new InvalidOperationException("Message authenticity verification failed");

                // Decrypt message using message key
                var decryptedMessage = await _encryptionService.DecryptAsync(message.Ciphertext, messageKey);
                if (decryptedMessage == null || decryptedMessage.Length == 0)
                    throw new InvalidOperationException("Failed to decrypt message");

                // Update session state
                var updatedState = new SessionState(
                    sessionState.SessionId,
                    sessionState.LocalIdentityKey,
                    sessionState.RemoteIdentityKey,
                    sessionState.RootKey,
                    sessionState.SendingChainKey,
                    newChainKey,
                    sessionState.SendingRatchetKey,
                    sessionState.ReceivingRatchetKey)
                {
                    ReceivingMessageNumber = message.MessageNumber + 1
                };

                return (decryptedMessage, updatedState);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to decrypt message", ex);
            }
        }

        /// <inheritdoc/>
        public async Task<SessionState> RatchetSendingAsync(SessionState sessionState)
        {
            if (sessionState == null) throw new ArgumentNullException(nameof(sessionState));

            // Generate new ratchet key pair
            var (newRatchetPublicKey, newRatchetPrivateKey) = await _keyExchangeService.GenerateKeyPairAsync();

            // Compute shared secret
            var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(newRatchetPrivateKey, sessionState.ReceivingRatchetKey);

            // Derive new chain key
            var newChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(sharedSecret, newRatchetPublicKey);

            // Update session state
            return new SessionState(
                sessionState.SessionId,
                sessionState.LocalIdentityKey,
                sessionState.RemoteIdentityKey,
                sessionState.RootKey,
                newChainKey,
                sessionState.ReceivingChainKey,
                newRatchetPublicKey,
                sessionState.ReceivingRatchetKey)
            {
                SendingMessageNumber = 0,
                ReceivingMessageNumber = sessionState.ReceivingMessageNumber,
                PreviousSendingMessageNumber = sessionState.SendingMessageNumber,
                PreviousReceivingMessageNumber = sessionState.PreviousReceivingMessageNumber
            };
        }

        /// <inheritdoc/>
        public async Task<SessionState> RatchetReceivingAsync(SessionState sessionState, byte[] newRatchetKey)
        {
            if (sessionState == null) throw new ArgumentNullException(nameof(sessionState));
            if (newRatchetKey == null) throw new ArgumentNullException(nameof(newRatchetKey));

            // Compute shared secret
            var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(sessionState.SendingRatchetKey, newRatchetKey);

            // Derive new chain key
            var newChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(sharedSecret, newRatchetKey);

            // Update session state
            return new SessionState(
                sessionState.SessionId,
                sessionState.LocalIdentityKey,
                sessionState.RemoteIdentityKey,
                sessionState.RootKey,
                sessionState.SendingChainKey,
                newChainKey,
                sessionState.SendingRatchetKey,
                newRatchetKey)
            {
                SendingMessageNumber = sessionState.SendingMessageNumber,
                ReceivingMessageNumber = 0,
                PreviousSendingMessageNumber = sessionState.PreviousSendingMessageNumber,
                PreviousReceivingMessageNumber = sessionState.ReceivingMessageNumber
            };
        }
    }
} 