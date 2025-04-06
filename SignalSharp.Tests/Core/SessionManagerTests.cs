using System;
using System.Threading.Tasks;
using Moq;
using Xunit;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Services;

namespace SignalSharp.Tests.Core
{
    public class SessionManagerTests
    {
        private readonly Mock<IKeyStore> _mockKeyStore;
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<IKeyExchangeService> _mockKeyExchangeService;
        private readonly Mock<IHashService> _mockHashService;
        private readonly Mock<IDoubleRatchetService> _mockDoubleRatchetService;
        private readonly SessionManager _sessionManager;

        public SessionManagerTests()
        {
            _mockKeyStore = new Mock<IKeyStore>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockKeyExchangeService = new Mock<IKeyExchangeService>();
            _mockHashService = new Mock<IHashService>();
            _mockDoubleRatchetService = new Mock<IDoubleRatchetService>();

            _sessionManager = new SessionManager(
                _mockKeyStore.Object,
                _mockEncryptionService.Object,
                _mockKeyExchangeService.Object,
                _mockHashService.Object,
                _mockDoubleRatchetService.Object);
        }

        [Fact]
        public async Task CreateSessionAsync_WithValidInput_ShouldCreateSession()
        {
            // Arrange
            var remoteIdentityKey = new byte[32];
            var remotePreKey = new byte[32];
            var remotePreKeySignature = new byte[64];
            var localIdentityKey = new byte[32];
            var rootKey = new byte[32];
            var sendingChainKey = new byte[32];
            var receivingChainKey = new byte[32];
            var sendingRatchetKey = new byte[32];
            var receivingRatchetKey = new byte[32];
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _mockKeyStore.Setup(k => k.GetKeyAsync("local_identity_key"))
                .ReturnsAsync((byte[])null);
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
            var result = await _sessionManager.CreateSessionAsync(
                remoteIdentityKey,
                remotePreKey,
                remotePreKeySignature);

            // Assert
            Assert.Equal(sessionState.SessionId, result);
            _mockKeyStore.Verify(k => k.StoreKeyAsync(It.IsAny<string>(), It.IsAny<byte[]>()), Times.Exactly(7));
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(sessionState.SessionId, sessionState), Times.Once);
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidSession_ShouldDecryptMessage()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];
            var sessionState = new SessionState(
                sessionId,
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32]);
            var decryptedMessage = new byte[32];
            var updatedState = new SessionState(
                sessionId,
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32]);

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync(sessionState);
            _mockDoubleRatchetService.Setup(d => d.DecryptMessageAsync(
                    It.IsAny<SessionState>(),
                    It.IsAny<SignalMessage>()))
                .ReturnsAsync((decryptedMessage, updatedState));

            // Act
            byte[] result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.Equal(decryptedMessage, result);
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(sessionId, updatedState), Times.Once);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidSession_ShouldEncryptMessage()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];
            var sessionState = new SessionState(
                sessionId,
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32]);
            var signalMessage = new SignalMessage(
                new byte[32],
                new byte[32],
                new byte[16],
                new byte[32],
                new byte[32]);
            var updatedState = new SessionState(
                sessionId,
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32],
                new byte[32]);

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync(sessionState);
            _mockDoubleRatchetService.Setup(d => d.EncryptMessageAsync(
                    It.IsAny<SessionState>(),
                    It.IsAny<byte[]>()))
                .ReturnsAsync((signalMessage, updatedState));

            // Act
            byte[] result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.Equal(signalMessage.Content, result);
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(sessionId, updatedState), Times.Once);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithInvalidSession_ShouldThrowInvalidOperationException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync((SessionState)null);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _sessionManager.EncryptMessageAsync(sessionId, message));
        }

        [Fact]
        public async Task DeleteSessionAsync_WithValidSession_ShouldDeleteSession()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();

            // Act
            await _sessionManager.DeleteSessionAsync(sessionId);

            // Assert
            _mockKeyStore.Verify(k => k.DeleteSessionStateAsync(sessionId), Times.Once);
        }
    }
} 