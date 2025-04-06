using System;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Security.Services
{
    /// <summary>
    /// Implements the Double Ratchet algorithm for the Signal protocol.
    /// This service handles continuous key rotation and message encryption/decryption.
    /// </summary>
    public class DoubleRatchetService : IDoubleRatchetService
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IKeyExchangeService _keyExchangeService;
        private readonly IHashService _hashService;

        /// <summary>
        /// Initializes a new instance of the <see cref="DoubleRatchetService"/> class.
        /// </summary>
        /// <param name="encryptionService">The encryption service.</param>
        /// <param name="keyExchangeService">The key exchange service.</param>
        /// <param name="hashService">The hash service.</param>
        public DoubleRatchetService(
            IEncryptionService encryptionService,
            IKeyExchangeService keyExchangeService,
            IHashService hashService)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
            _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
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

        private async Task<(byte[] SendingChainKey, byte[] ReceivingChainKey)> DeriveChainKeysAsync(byte[] sharedSecret)
        {
            var sendingChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(sharedSecret);
            var receivingChainKey = await _keyExchangeService.DeriveSymmetricKeyAsync(sharedSecret);
            return (sendingChainKey, receivingChainKey);
        }
    }
} 