using System;
using System.Threading.Tasks;
using Moq;
using Xunit;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Services;
using SignalSharp.Core.Exceptions;
using System.Text.Json;

namespace SignalSharp.Tests.Core
{
    public class SessionManagerTests
    {
        private readonly Mock<IKeyStore> _mockKeyStore;
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<IKeyExchangeService> _mockKeyExchangeService;
        private readonly Mock<IHashService> _mockHashService;
        private readonly Mock<IDoubleRatchetService> _mockDoubleRatchetService;
        private readonly Mock<IJsonSerializer> _mockJsonSerializer;
        private readonly SessionManager _sessionManager;

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

        [Fact]
        public async Task CreateSessionAsync_WithValidInput_ShouldCreateSession()
        {
            // Arrange
            var sessionId = "test-session";
            var remoteIdentityKey = new byte[32];
            var remoteSignedPreKey = new byte[32];
            var remoteOneTimePreKey = new byte[32];
            var localIdentityKey = new byte[32];
            var rootKey = new byte[32];
            var sendingChainKey = new byte[32];
            var receivingChainKey = new byte[32];
            var sendingRatchetKey = new byte[32];
            var receivingRatchetKey = new byte[32];
            var sessionState = new SessionState(
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

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidSession_ShouldDecryptMessage()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };
            var message = new byte[] { 22, 23, 24 };
            var decryptedMessage = new byte[] { 25, 26, 27 };

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            var serializedState = "serialized_state"; // Use a simple string for serialization

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
            var result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(decryptedMessage, result);
            _mockKeyStore.Verify(x => x.SetAsync(sessionId, serializedState), Times.Once);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidSession_ShouldEncryptMessage()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };
            var message = new byte[] { 22, 23, 24 };
            var ciphertext = new byte[] { 25, 26, 27 };

            var encryptedMessage = new SignalMessage
            {
                Ciphertext = ciphertext,
                Mac = new byte[] { 28, 29, 30 },
                SenderIdentityKey = localIdentityKey,
                SenderEphemeralKey = sendingRatchetKey
            };

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            var serializedState = "serialized_state"; // Use a simple string for serialization

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
            var result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(ciphertext, result);
            _mockKeyStore.Verify(x => x.SetAsync(sessionId, serializedState), Times.Once);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithInvalidSession_ShouldThrowSessionNotFoundException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];

            _mockKeyStore.Setup(k => k.GetAsync(sessionId))
                .ReturnsAsync((string?)null);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<SessionNotFoundException>(() =>
                _sessionManager.EncryptMessageAsync(sessionId, message));
            Assert.Equal(sessionId, exception.SessionId);
        }

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

        [Fact]
        public async Task GetSessionStateAsync_WithExistingSession_ReturnsState()
        {
            // Arrange
            var sessionId = "test-session";
            var expectedState = new SessionState(
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
            var result = await _sessionManager.GetSessionStateAsync(sessionId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedState.SessionId, result.SessionId);
            Assert.Equal(expectedState.LocalIdentityKey, result.LocalIdentityKey);
            Assert.Equal(expectedState.RemoteIdentityKey, result.RemoteIdentityKey);
            Assert.Equal(expectedState.RootKey, result.RootKey);
        }

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

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithInvalidSession_ShouldThrowSessionNotFoundException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];
            var signalMessage = new SignalMessage(
                new byte[32],
                new byte[32],
                new byte[16],
                new byte[32],
                new byte[32]);

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .Returns(() => Task.FromResult<SessionState?>(null));

            // Act & Assert
            await Assert.ThrowsAsync<SessionNotFoundException>(async () =>
                await _sessionManager.ProcessIncomingMessageAsync(sessionId, message));
        }
    }
} 