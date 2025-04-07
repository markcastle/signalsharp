using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;

namespace SignalSharp.Tests.Security
{
    /// <summary>
    /// Test suite for the DoubleRatchetService which implements the Signal protocol's Double Ratchet algorithm.
    /// </summary>
    /// <remarks>
    /// These tests verify that the Double Ratchet implementation correctly:
    /// - Initializes new cryptographic sessions
    /// - Encrypts messages with forward secrecy
    /// - Decrypts messages with proper authentication
    /// - Performs cryptographic ratcheting operations 
    /// - Updates session state during message exchange
    /// 
    /// The Double Ratchet algorithm is a critical security component that provides
    /// both forward secrecy and break-in recovery for secure communications.
    /// </remarks>
    public class DoubleRatchetServiceTests
    {
        /// <summary>
        /// Mock of the elliptic curve key exchange service used for shared secret generation.
        /// </summary>
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;

        /// <summary>
        /// Mock of the encryption service used for symmetric encryption operations.
        /// </summary>
        private readonly Mock<IEncryptionService> _encryptionServiceMock;

        /// <summary>
        /// Mock of the hash service used for key derivation and message authentication.
        /// </summary>
        private readonly Mock<IHashService> _hashServiceMock;

        /// <summary>
        /// The DoubleRatchetService instance being tested.
        /// </summary>
        private readonly IDoubleRatchetService _doubleRatchetService;

        /// <summary>
        /// Initializes a new instance of the DoubleRatchetServiceTests class.
        /// Sets up all the required mock dependencies and creates the DoubleRatchetService for testing.
        /// </summary>
        public DoubleRatchetServiceTests()
        {
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _hashServiceMock = new Mock<IHashService>();
            _doubleRatchetService = new DoubleRatchetService(
                _encryptionServiceMock.Object,
                _keyExchangeServiceMock.Object,
                _hashServiceMock.Object);
        }

        /// <summary>
        /// Tests that a new session state can be initialized with proper cryptographic keys.
        /// </summary>
        /// <remarks>
        /// This test verifies the session initialization process which includes:
        /// 1. Computing shared secrets from ratchet keys
        /// 2. Generating new ratchet key pairs
        /// 3. Deriving chain keys from shared secrets
        /// 4. Creating a properly structured session state
        /// 
        /// Session initialization is the first step in establishing secure communication
        /// and creates the initial cryptographic state for the Double Ratchet algorithm.
        /// </remarks>
        [Fact]
        public async Task InitializeSessionAsync_ShouldCreateSessionState()
        {
            // Arrange
            byte[] rootKey = { 1, 2, 3 };
            byte[] sendingRatchetKey = { 4, 5, 6 };
            byte[] receivingRatchetKey = { 7, 8, 9 };
            byte[] sharedSecret = { 10, 11, 12 };
            byte[] sendingChainKey = { 13, 14, 15 };
            byte[] receivingChainKey = { 16, 17, 18 };

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((sendingRatchetKey, sendingRatchetKey));

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    It.Is<byte[]>(k => k.SequenceEqual(rootKey.Concat(sharedSecret).ToArray())),
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "sending"),
                    32))
                .ReturnsAsync(sendingChainKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    It.Is<byte[]>(k => k.SequenceEqual(rootKey.Concat(sharedSecret).ToArray())),
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "receiving"),
                    32))
                .ReturnsAsync(receivingChainKey);

            // Act
            SessionState result = await _doubleRatchetService.InitializeSessionAsync(rootKey, sendingRatchetKey, receivingRatchetKey);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(rootKey, result.RootKey);
            Assert.Equal(sendingRatchetKey, result.SendingRatchetKey);
            Assert.Equal(receivingRatchetKey, result.ReceivingRatchetKey);
            Assert.Equal(sendingChainKey, result.SendingChainKey);
            Assert.Equal(receivingChainKey, result.ReceivingChainKey);
        }

        /// <summary>
        /// Tests that messages can be properly encrypted using the Double Ratchet algorithm.
        /// </summary>
        /// <remarks>
        /// This test verifies the message encryption process which includes:
        /// 1. Deriving message keys from the sending chain key
        /// 2. Advancing the chain key through ratcheting
        /// 3. Encrypting the message with the derived message key
        /// 4. Computing a message authentication code (MAC)
        /// 5. Updating the session state
        /// 
        /// The encryption process creates a new message key for each message, providing
        /// forward secrecy by ensuring that compromise of one message does not compromise
        /// future messages. The test ensures that the session state is properly updated
        /// to reflect the advancement of the ratchet.
        /// </remarks>
        [Fact]
        public async Task EncryptMessageAsync_ShouldEncryptMessageAndComputeHash()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };
            byte[] message = { 22, 23, 24 };
            byte[] ciphertext = { 25, 26, 27 };
            byte[] mac = { 28, 29, 30 };
            byte[] sharedSecret = { 31, 32, 33 };

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            byte[] newChainKey = { 34, 35, 36 };
            byte[] messageKey = { 37, 38, 39 };

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    sendingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "message_0"),
                    32))
                .ReturnsAsync(messageKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    sendingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "chain"),
                    32))
                .ReturnsAsync(newChainKey);

            _encryptionServiceMock
                .Setup(x => x.EncryptAsync(message, messageKey))
                .ReturnsAsync(ciphertext);

            _hashServiceMock
                .Setup(x => x.ComputeKeyedHashAsync(ciphertext, sendingChainKey))
                .ReturnsAsync(mac);

            // Act
            (SignalMessage? result, SessionState? updatedState) = await _doubleRatchetService.EncryptMessageAsync(sessionState, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(ciphertext, result.Ciphertext);
            Assert.Equal((uint)0, result.MessageNumber);
            Assert.Equal(sendingRatchetKey, result.RatchetKey);
            Assert.Equal(newChainKey, updatedState.SendingChainKey);
            Assert.Equal(receivingChainKey, updatedState.ReceivingChainKey);
        }

        /// <summary>
        /// Tests that messages can be properly decrypted and authenticated using the Double Ratchet algorithm.
        /// </summary>
        /// <remarks>
        /// This test verifies the message decryption process which includes:
        /// 1. Deriving message keys from the receiving chain key
        /// 2. Verifying the message authentication code (MAC)
        /// 3. Decrypting the message with the derived message key
        /// 4. Advancing the receiving chain key through ratcheting
        /// 5. Updating the session state
        /// 
        /// The decryption process ensures that messages can only be read by the intended
        /// recipient and that the messages have not been tampered with. The test also
        /// ensures that the session state is properly updated after decryption.
        /// </remarks>
        [Fact]
        public async Task DecryptMessageAsync_ShouldVerifyHashAndDecryptMessage()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };
            byte[] ciphertext = { 22, 23, 24 };
            byte[] mac = { 25, 26, 27 };
            byte[] messageKey = { 37, 38, 39 };
            byte[] newChainKey = { 34, 35, 36 };
            byte[] plaintext = { 40, 41, 42 };

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(new byte[] { 31, 32, 33 });

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    receivingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "message_0"),
                    32))
                .ReturnsAsync(messageKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    receivingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "chain"),
                    32))
                .ReturnsAsync(newChainKey);

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(ciphertext, messageKey, mac))
                .ReturnsAsync(true);

            _encryptionServiceMock
                .Setup(x => x.DecryptAsync(ciphertext, messageKey))
                .ReturnsAsync(plaintext);

            SignalMessage signalMessage = new()
            {
                Ciphertext = ciphertext,
                Mac = mac,
                MessageNumber = 0,
                RatchetKey = receivingRatchetKey
            };

            // Act
            (byte[]? decryptedMessage, SessionState? updatedState) = await _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage);

            // Assert
            Assert.NotNull(decryptedMessage);
            Assert.Equal(plaintext, decryptedMessage);
            Assert.Equal(newChainKey, updatedState.ReceivingChainKey);
            Assert.Equal(sendingChainKey, updatedState.SendingChainKey);
        }

        /// <summary>
        /// Tests that message decryption fails with appropriate exception when message authentication fails.
        /// </summary>
        /// <remarks>
        /// This test verifies the security behavior when presented with potentially tampered messages:
        /// 1. The MAC verification fails, indicating message tampering or corruption
        /// 2. The decryption operation should throw an exception rather than process invalid data
        /// 
        /// This security check is critical for preventing attacks where an adversary
        /// might attempt to modify messages in transit. The test ensures that the
        /// implementation properly rejects messages that fail integrity verification.
        /// </remarks>
        [Fact]
        public async Task DecryptMessageAsync_ShouldThrowIfHashVerificationFails()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = new byte[32];
            byte[] remoteIdentityKey = new byte[32];
            byte[] rootKey = new byte[32];
            byte[] sendingChainKey = new byte[32];
            byte[] receivingChainKey = new byte[32];
            byte[] sendingRatchetKey = new byte[32];
            byte[] receivingRatchetKey = new byte[32];
            byte[] ciphertext = new byte[32];
            byte[] mac = new byte[32];
            byte[] sharedSecret = new byte[32];
            byte[] newChainKey = new byte[32];

            // Initialize the arrays with non-zero values
            new Random().NextBytes(localIdentityKey);
            new Random().NextBytes(remoteIdentityKey);
            new Random().NextBytes(rootKey);
            new Random().NextBytes(sendingChainKey);
            new Random().NextBytes(receivingChainKey);
            new Random().NextBytes(sendingRatchetKey);
            new Random().NextBytes(receivingRatchetKey);
            new Random().NextBytes(ciphertext);
            new Random().NextBytes(mac);
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(newChainKey);

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(sharedSecret, receivingRatchetKey))
                .ReturnsAsync(newChainKey);

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(ciphertext, newChainKey, mac))
                .ReturnsAsync(false);

            SignalMessage signalMessage = new()
            {
                Ciphertext = ciphertext,
                Mac = mac,
                SenderIdentityKey = remoteIdentityKey,
                SenderEphemeralKey = receivingRatchetKey,
                MessageNumber = 0,
                RatchetKey = receivingRatchetKey
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage));
        }

        /// <summary>
        /// Tests that the sending ratchet correctly advances when triggered.
        /// </summary>
        /// <remarks>
        /// This test verifies the ratchet advancement process which includes:
        /// 1. Generating new ratchet key pairs
        /// 2. Computing a new shared secret with the recipient's ratchet key
        /// 3. Deriving new chain keys from the shared secret
        /// 4. Updating the session state with the new keys
        /// 
        /// The ratchet advancement is a key component of the Double Ratchet algorithm,
        /// providing break-in recovery by ensuring that compromise of current keys 
        /// cannot be used to decrypt future messages. This test ensures that the 
        /// cryptographic state evolves correctly during communication.
        /// </remarks>
        [Fact]
        public async Task RatchetSendingAsync_ShouldUpdateChainKeys()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = new byte[32];
            byte[] remoteIdentityKey = new byte[32];
            byte[] rootKey = new byte[32];
            byte[] sendingChainKey = new byte[32];
            byte[] receivingChainKey = new byte[32];
            byte[] sendingRatchetKey = new byte[32];
            byte[] receivingRatchetKey = new byte[32];
            byte[] newRatchetKey = new byte[32];
            byte[] sharedSecret = new byte[32];
            byte[] newSendingChainKey = new byte[32];
            byte[] newReceivingChainKey = new byte[32];

            // Initialize the arrays with non-zero values
            new Random().NextBytes(localIdentityKey);
            new Random().NextBytes(remoteIdentityKey);
            new Random().NextBytes(rootKey);
            new Random().NextBytes(sendingChainKey);
            new Random().NextBytes(receivingChainKey);
            new Random().NextBytes(sendingRatchetKey);
            new Random().NextBytes(receivingRatchetKey);
            new Random().NextBytes(newRatchetKey);
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(newSendingChainKey);
            new Random().NextBytes(newReceivingChainKey);

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((newRatchetKey, newRatchetKey));

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(newRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(sharedSecret, newRatchetKey))
                .ReturnsAsync(newSendingChainKey);

            // Act
            SessionState result = await _doubleRatchetService.RatchetSendingAsync(sessionState);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(rootKey, result.RootKey);
            Assert.Equal(newSendingChainKey, result.SendingChainKey);
            Assert.Equal(receivingChainKey, result.ReceivingChainKey);
            Assert.Equal(newRatchetKey, result.SendingRatchetKey);
            Assert.Equal(receivingRatchetKey, result.ReceivingRatchetKey);
        }
    }
}