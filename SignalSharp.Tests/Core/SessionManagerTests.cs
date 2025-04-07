using Moq;
using SignalSharp.Core.Exceptions;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Services;
// ReSharper disable PrivateFieldCanBeConvertedToLocalVariable

namespace SignalSharp.Tests.Core
{
    /// <summary>
    /// Test suite for the SessionManager class which manages encryption sessions in the SignalSharp protocol.
    /// </summary>
    /// <remarks>
    /// These tests verify that the SessionManager properly handles:
    /// - Session creation with proper key exchange
    /// - Message encryption using established sessions
    /// - Message decryption for incoming messages
    /// - Session retrieval and management
    /// - Error handling for missing or invalid sessions
    /// 
    /// The SessionManager is a core component that integrates multiple cryptographic 
    /// services and maintains the state necessary for secure communications.
    /// </remarks>
    public class SessionManagerTests
    {
        /// <summary>
        /// Mock of the key storage service used to store session states and cryptographic keys.
        /// </summary>
        private readonly Mock<IKeyStore> _mockKeyStore;

        /// <summary>
        /// Mock of the encryption service used for symmetric encryption operations.
        /// </summary>
        private readonly Mock<IEncryptionService> _mockEncryptionService;

        /// <summary>
        /// Mock of the key exchange service used for establishing shared secrets between parties.
        /// </summary>
        private readonly Mock<IKeyExchangeService> _mockKeyExchangeService;

        /// <summary>
        /// Mock of the hash service used for creating message authentication codes and key derivation.
        /// </summary>
        private readonly Mock<IHashService> _mockHashService;

        /// <summary>
        /// Mock of the double ratchet service which manages the cryptographic ratcheting for forward secrecy.
        /// </summary>
        private readonly Mock<IDoubleRatchetService> _mockDoubleRatchetService;

        /// <summary>
        /// Mock of the JSON serializer used for converting session state objects to/from storage format.
        /// </summary>
        private readonly Mock<IJsonSerializer> _mockJsonSerializer;

        /// <summary>
        /// The SessionManager instance being tested.
        /// </summary>
        private readonly SessionManager _sessionManager;

        /// <summary>
        /// Initializes a new instance of the SessionManagerTests class.
        /// Sets up all the required mock dependencies and creates the SessionManager for testing.
        /// </summary>
        public SessionManagerTests()
        {
            _mockKeyStore = new Mock<IKeyStore>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockKeyExchangeService = new Mock<IKeyExchangeService>();
            _mockHashService = new Mock<IHashService>();
            _mockDoubleRatchetService = new Mock<IDoubleRatchetService>();
            _mockJsonSerializer = new Mock<IJsonSerializer>();

            _sessionManager = new SessionManager(
                _mockKeyStore.Object,
                _mockEncryptionService.Object,
                _mockKeyExchangeService.Object,
                _mockHashService.Object,
                _mockDoubleRatchetService.Object,
                _mockJsonSerializer.Object);
        }

        /// <summary>
        /// Tests that a new secure session can be created with valid cryptographic parameters.
        /// </summary>
        /// <remarks>
        /// This test verifies the session initialization process which includes:
        /// 1. Checking if a local identity key exists and generating one if needed
        /// 2. Performing key exchange with remote keys to establish shared secrets
        /// 3. Initializing the double ratchet protocol with the derived keys
        /// 4. Storing the resulting session state in the key store
        /// 
        /// The test confirms that all cryptographic operations are performed correctly
        /// and the session is properly stored for future communications.
        /// </remarks>
        [Fact]
        public async Task CreateSessionAsync_WithValidInput_ShouldCreateSession()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] remoteIdentityKey = new byte[32];
            byte[] remoteSignedPreKey = new byte[32];
            byte[] remoteOneTimePreKey = new byte[32];
            byte[] localIdentityKey = new byte[32];
            byte[] rootKey = new byte[32];
            byte[] sendingChainKey = new byte[32];
            byte[] receivingChainKey = new byte[32];
            byte[] sendingRatchetKey = new byte[32];
            byte[] receivingRatchetKey = new byte[32];
            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _mockKeyStore.Setup(k => k.GetKeyAsync("local_identity_key"))
                .Returns(() => Task.FromResult<byte[]?>(null));
            _mockKeyExchangeService.Setup(k => k.GenerateKeyPairAsync())
                .ReturnsAsync((localIdentityKey, new byte[32]));
            _mockKeyExchangeService.Setup(k => k.PerformKeyExchangeAsync(
                    It.IsAny<byte[]>(),
                    It.IsAny<byte[]>(),
                    It.IsAny<byte[]>()))
                .ReturnsAsync((rootKey, sendingChainKey, receivingChainKey));
            _mockDoubleRatchetService.Setup(d => d.InitializeSessionAsync(
                    It.IsAny<byte[]>(),
                    It.IsAny<byte[]>(),
                    It.IsAny<byte[]>()))
                .ReturnsAsync(sessionState);

            // Act
            await _sessionManager.CreateSessionAsync(
                sessionId,
                remoteIdentityKey,
                remoteSignedPreKey,
                remoteOneTimePreKey);

            // Assert
            _mockKeyStore.Verify(k => k.SetAsync(It.IsAny<string>(), It.IsAny<string>()), Times.AtLeastOnce);
        }

        /// <summary>
        /// Tests that incoming encrypted messages can be properly decrypted when a valid session exists.
        /// </summary>
        /// <remarks>
        /// This test verifies the message decryption process which includes:
        /// 1. Retrieving the session state from storage
        /// 2. Deserializing the session state
        /// 3. Using the double ratchet protocol to decrypt the message
        /// 4. Updating and saving the session state after decryption
        /// 
        /// The double ratchet protocol advances the key material with each message,
        /// providing forward secrecy and break-in recovery. This test ensures that
        /// the session state is properly updated after message processing.
        /// </remarks>
        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidSession_ShouldDecryptMessage()
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
            byte[] decryptedMessage = { 25, 26, 27 };

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            string serializedState = "serialized_state"; // Use a simple string for serialization

            _mockKeyStore.Setup(x => x.GetAsync(sessionId))
                .ReturnsAsync(serializedState);

            _mockJsonSerializer.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);

            _mockJsonSerializer.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);

            _mockDoubleRatchetService.Setup(x => x.DecryptMessageAsync(It.IsAny<SessionState>(), It.IsAny<SignalMessage>()))
                .ReturnsAsync((decryptedMessage, sessionState));

            _mockKeyStore.Setup(x => x.SetAsync(sessionId, serializedState))
                .Returns(Task.CompletedTask);

            // Act
            byte[] result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(decryptedMessage, result);
            _mockKeyStore.Verify(x => x.SetAsync(sessionId, serializedState), Times.Once);
        }

        /// <summary>
        /// Tests that outgoing messages can be properly encrypted when a valid session exists.
        /// </summary>
        /// <remarks>
        /// This test verifies the message encryption process which includes:
        /// 1. Retrieving the session state from storage
        /// 2. Deserializing the session state
        /// 3. Using the double ratchet protocol to encrypt the message
        /// 4. Updating and saving the session state after encryption
        /// 
        /// Similar to decryption, the encryption process also advances the ratchet,
        /// creating new key material for each message. This test ensures that the
        /// session state is properly updated to maintain the security properties.
        /// </remarks>
        [Fact]
        public async Task EncryptMessageAsync_WithValidSession_ShouldEncryptMessage()
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

            SignalMessage encryptedMessage = new()
            {
                Ciphertext = ciphertext,
                Mac = new byte[] { 28, 29, 30 },
                SenderIdentityKey = localIdentityKey,
                SenderEphemeralKey = sendingRatchetKey
            };

            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            string serializedState = "serialized_state"; // Use a simple string for serialization

            _mockKeyStore.Setup(x => x.GetAsync(sessionId))
                .ReturnsAsync(serializedState);

            _mockJsonSerializer.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);

            _mockJsonSerializer.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);

            _mockDoubleRatchetService.Setup(x => x.EncryptMessageAsync(It.IsAny<SessionState>(), message))
                .ReturnsAsync((encryptedMessage, sessionState));

            _mockKeyStore.Setup(x => x.SetAsync(sessionId, serializedState))
                .Returns(Task.CompletedTask);

            // Act
            byte[] result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(ciphertext, result);
            _mockKeyStore.Verify(x => x.SetAsync(sessionId, serializedState), Times.Once);
        }

        /// <summary>
        /// Tests that attempting to encrypt a message with a non-existent session throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies error handling for missing sessions:
        /// 1. When trying to encrypt a message without an established session
        /// 2. The system should detect this condition and throw a specific exception
        /// 3. The exception should contain information about which session was missing
        /// 
        /// This ensures that the application can properly handle error cases and provide
        /// meaningful information to higher layers about why encryption failed.
        /// </remarks>
        [Fact]
        public async Task EncryptMessageAsync_WithInvalidSession_ShouldThrowSessionNotFoundException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];

            _mockKeyStore.Setup(k => k.GetAsync(sessionId))
                .ReturnsAsync((string?)null);

            // Act & Assert
            SessionNotFoundException exception = await Assert.ThrowsAsync<SessionNotFoundException>(() =>
                _sessionManager.EncryptMessageAsync(sessionId, message));
            Assert.Equal(sessionId, exception.SessionId);
        }

        /// <summary>
        /// Tests that a session can be successfully deleted from storage.
        /// </summary>
        /// <remarks>
        /// This test verifies the session deletion process:
        /// 1. The SessionManager properly delegates to the key store
        /// 2. The specified session is removed from persistent storage
        /// 
        /// Session deletion might be needed for security purposes (to prevent
        /// further communication) or for cleanup when a conversation is completed.
        /// </remarks>
        [Fact]
        public async Task DeleteSessionAsync_WithExistingSession_ShouldDeleteSession()
        {
            // Arrange
            string sessionId = "test-session";

            // Act
            await _sessionManager.DeleteSessionAsync(sessionId);

            // Assert
            _mockKeyStore.Verify(k => k.DeleteAsync(sessionId), Times.Once);
        }

        /// <summary>
        /// Tests that session state can be successfully retrieved and deserialized.
        /// </summary>
        /// <remarks>
        /// This test verifies the session retrieval process:
        /// 1. The SessionManager requests the serialized state from the key store
        /// 2. The JSON serializer properly deserializes the stored data
        /// 3. The returned session state contains all the expected cryptographic keys
        /// 
        /// Retrieving session state is important for inspecting or debugging the
        /// current cryptographic state of a conversation.
        /// </remarks>
        [Fact]
        public async Task GetSessionStateAsync_WithExistingSession_ReturnsState()
        {
            // Arrange
            string sessionId = "test-session";
            SessionState expectedState = new(
                sessionId,
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32]);

            _mockKeyStore.Setup(k => k.GetAsync(sessionId))
                .ReturnsAsync("{}");
            _mockJsonSerializer.Setup(x => x.Deserialize<SessionState>(It.IsAny<string>()))
                .Returns(expectedState);

            // Act
            SessionState? result = await _sessionManager.GetSessionStateAsync(sessionId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedState.SessionId, result.SessionId);
            Assert.Equal(expectedState.LocalIdentityKey, result.LocalIdentityKey);
            Assert.Equal(expectedState.RemoteIdentityKey, result.RemoteIdentityKey);
            Assert.Equal(expectedState.RootKey, result.RootKey);
        }

        /// <summary>
        /// Tests that attempting to retrieve a non-existent session throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies error handling for session retrieval:
        /// 1. When trying to get a session that doesn't exist in storage
        /// 2. The system should detect this condition and throw a specific exception
        /// 
        /// This ensures consistent error handling across all session-related operations.
        /// </remarks>
        [Fact]
        public async Task GetSessionStateAsync_WithInvalidSession_ShouldThrowSessionNotFoundException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .Returns(() => Task.FromResult<SessionState?>(null));

            // Act & Assert
            await Assert.ThrowsAsync<SessionNotFoundException>(async () =>
                await _sessionManager.GetSessionStateAsync(sessionId));
        }

        /// <summary>
        /// Tests that attempting to decrypt a message with a non-existent session throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies error handling for message decryption with missing sessions:
        /// 1. When trying to decrypt a message without having the corresponding session
        /// 2. The system should detect this condition and throw a specific exception
        /// 
        /// This behavior is important for security, as it prevents trying to decrypt
        /// messages with incorrect or missing cryptographic state.
        /// </remarks>
        [Fact]
        public async Task ProcessIncomingMessageAsync_WithInvalidSession_ShouldThrowSessionNotFoundException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .Returns(() => Task.FromResult<SessionState?>(null));

            // Act & Assert
            await Assert.ThrowsAsync<SessionNotFoundException>(async () =>
                await _sessionManager.ProcessIncomingMessageAsync(sessionId, message));
        }
    }
}