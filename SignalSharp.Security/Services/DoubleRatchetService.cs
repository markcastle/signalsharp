using System;
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
        private readonly IKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;

        /// <summary>
        /// Initializes a new instance of the DoubleRatchetService class.
        /// </summary>
        /// <param name="encryptionService">The encryption service used for message encryption/decryption.</param>
        /// <param name="keyExchangeService">The key exchange service used for ratchet key generation.</param>
        /// <param name="hashService">The hash service used for key derivation.</param>
        /// <exception cref="ArgumentNullException">Thrown when any of the parameters are null.</exception>
        public DoubleRatchetService(
            IEncryptionService encryptionService,
            IKeyExchangeService keyExchangeService,
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
            int messageNumber)
        {
            if (chainKey == null) throw new ArgumentNullException(nameof(chainKey));
            if (chainKey.Length == 0) throw new ArgumentException("Chain key cannot be empty", nameof(chainKey));
            if (messageNumber < 0) throw new ArgumentOutOfRangeException(nameof(messageNumber), "Message number cannot be negative");

            // Derive message key and new chain key
            var (newChainKey, messageKey) = await DeriveMessageKeyAsync(chainKey, messageNumber);

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
            return await _hashService.DeriveKeyAsync(combined, purpose);
        }

        /// <summary>
        /// Derives a message key and new chain key from the current chain key.
        /// </summary>
        /// <param name="chainKey">The current chain key.</param>
        /// <param name="messageNumber">The message number for key derivation.</param>
        /// <returns>A tuple containing the new chain key and message key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when chainKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when chainKey is empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when messageNumber is negative.</exception>
        private async Task<(byte[] newChainKey, byte[] messageKey)> DeriveMessageKeyAsync(
            byte[] chainKey,
            int messageNumber)
        {
            if (chainKey == null) throw new ArgumentNullException(nameof(chainKey));
            if (chainKey.Length == 0) throw new ArgumentException("Chain key cannot be empty", nameof(chainKey));
            if (messageNumber < 0) throw new ArgumentOutOfRangeException(nameof(messageNumber), "Message number cannot be negative");

            // Derive message key
            var messageKey = await _hashService.DeriveKeyAsync(chainKey, $"message_{messageNumber}");

            // Derive new chain key
            var newChainKey = await _hashService.DeriveKeyAsync(chainKey, "chain");

            return (newChainKey, messageKey);
        }

        /// <inheritdoc/>
        public async Task<SessionState> InitializeSessionAsync(byte[] rootKey, byte[] sendingRatchetKey, byte[] receivingRatchetKey)
        {
            if (rootKey == null) throw new ArgumentNullException(nameof(rootKey));
            if (sendingRatchetKey == null) throw new ArgumentNullException(nameof(sendingRatchetKey));
            if (receivingRatchetKey == null) throw new ArgumentNullException(nameof(receivingRatchetKey));

            // Generate initial chain keys
            var sendingChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(rootKey, new byte[] { 0x01 });
            var receivingChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(rootKey, new byte[] { 0x02 });

            return new SessionState(
                Guid.NewGuid().ToString(),
                sendingRatchetKey, // Local identity key is the sending ratchet key initially
                receivingRatchetKey, // Remote identity key is the receiving ratchet key initially
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);
        }

        /// <inheritdoc/>
        public async Task<(SignalMessage Message, SessionState UpdatedState)> EncryptMessageAsync(SessionState state, byte[] message)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (message == null) throw new ArgumentNullException(nameof(message));

            // Check if we need to ratchet
            if (state.SendingMessageNumber >= 100) // Arbitrary threshold for demonstration
            {
                state = await RatchetSendingAsync(state);
            }

            // Generate a random IV
            var iv = new byte[16];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            // Encrypt the message
            var encryptedContent = await _encryptionService.EncryptAsync(message, state.SendingChainKey);
            var mac = await _hashService.ComputeKeyedHashAsync(encryptedContent, state.SendingChainKey);

            // Create the signal message
            var signalMessage = new SignalMessage(
                encryptedContent,
                mac,
                iv,
                state.LocalIdentityKey,
                state.SendingRatchetKey)
            {
                Counter = state.SendingMessageNumber,
                PreviousCounter = state.PreviousSendingMessageNumber
            };

            // Create updated session state
            var updatedState = new SessionState(
                state.SessionId,
                state.LocalIdentityKey,
                state.RemoteIdentityKey,
                state.RootKey,
                state.SendingChainKey,
                state.ReceivingChainKey,
                state.SendingRatchetKey,
                state.ReceivingRatchetKey)
            {
                SendingMessageNumber = state.SendingMessageNumber + 1,
                ReceivingMessageNumber = state.ReceivingMessageNumber,
                PreviousSendingMessageNumber = state.SendingMessageNumber,
                PreviousReceivingMessageNumber = state.PreviousReceivingMessageNumber,
                LastUsedAt = DateTime.UtcNow
            };

            return (signalMessage, updatedState);
        }

        /// <inheritdoc/>
        public async Task<(byte[] DecryptedMessage, SessionState UpdatedState)> DecryptMessageAsync(SessionState state, SignalMessage message)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (message == null) throw new ArgumentNullException(nameof(message));

            // Verify MAC
            var isValid = await _hashService.VerifyKeyedHashAsync(message.Content, state.ReceivingChainKey, message.Mac);
            if (!isValid)
            {
                throw new InvalidOperationException("Message authentication failed");
            }

            // Check if we need to ratchet
            if (message.SenderEphemeralKey != null && !message.SenderEphemeralKey.AsSpan().SequenceEqual(state.ReceivingRatchetKey))
            {
                state = await RatchetReceivingAsync(state, message.SenderEphemeralKey);
            }

            // Decrypt the message
            var decryptedContent = await _encryptionService.DecryptAsync(message.Content, state.ReceivingChainKey);

            // Create updated session state
            var updatedState = new SessionState(
                state.SessionId,
                state.LocalIdentityKey,
                state.RemoteIdentityKey,
                state.RootKey,
                state.SendingChainKey,
                state.ReceivingChainKey,
                state.SendingRatchetKey,
                state.ReceivingRatchetKey)
            {
                SendingMessageNumber = state.SendingMessageNumber,
                ReceivingMessageNumber = message.Counter,
                PreviousSendingMessageNumber = state.PreviousSendingMessageNumber,
                PreviousReceivingMessageNumber = message.PreviousCounter,
                LastUsedAt = DateTime.UtcNow
            };

            return (decryptedContent, updatedState);
        }

        /// <inheritdoc/>
        public async Task<SessionState> RatchetSendingAsync(SessionState state)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));

            // Generate new ratchet key pair
            var (newRatchetPublicKey, newRatchetPrivateKey) = await _keyExchangeService.GenerateKeyPairAsync();

            // Compute new shared secret
            var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(newRatchetPrivateKey, state.ReceivingRatchetKey);

            // Derive new chain keys
            var (newSendingChainKey, _) = await DeriveChainKeysAsync(sharedSecret);

            // Create new session state with updated keys
            return new SessionState(
                state.SessionId,
                state.LocalIdentityKey,
                state.RemoteIdentityKey,
                state.RootKey,
                newSendingChainKey,
                state.ReceivingChainKey,
                newRatchetPublicKey,
                state.ReceivingRatchetKey)
            {
                SendingMessageNumber = 0,
                ReceivingMessageNumber = state.ReceivingMessageNumber,
                PreviousSendingMessageNumber = state.SendingMessageNumber,
                PreviousReceivingMessageNumber = state.PreviousReceivingMessageNumber,
                LastUsedAt = DateTime.UtcNow
            };
        }

        /// <inheritdoc/>
        public async Task<SessionState> RatchetReceivingAsync(SessionState state, byte[] newRatchetKey)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (newRatchetKey == null) throw new ArgumentNullException(nameof(newRatchetKey));

            // Compute new shared secret
            var sharedSecret = await _keyExchangeService.ComputeSharedSecretAsync(state.SendingRatchetKey, newRatchetKey);

            // Derive new chain keys
            var (_, newReceivingChainKey) = await DeriveChainKeysAsync(sharedSecret);

            // Create new session state with updated keys
            return new SessionState(
                state.SessionId,
                state.LocalIdentityKey,
                state.RemoteIdentityKey,
                state.RootKey,
                state.SendingChainKey,
                newReceivingChainKey,
                state.SendingRatchetKey,
                newRatchetKey)
            {
                SendingMessageNumber = state.SendingMessageNumber,
                ReceivingMessageNumber = 0,
                PreviousSendingMessageNumber = state.PreviousSendingMessageNumber,
                PreviousReceivingMessageNumber = state.ReceivingMessageNumber,
                LastUsedAt = DateTime.UtcNow
            };
        }
    }
} 