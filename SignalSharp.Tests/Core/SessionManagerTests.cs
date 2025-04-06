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
        private readonly SessionManager _sessionManager;

        public SessionManagerTests()
        {
            _mockKeyStore = new Mock<IKeyStore>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockKeyExchangeService = new Mock<IKeyExchangeService>();
            _mockHashService = new Mock<IHashService>();

            _sessionManager = new SessionManager(
                _mockKeyStore.Object,
                _mockEncryptionService.Object,
                _mockKeyExchangeService.Object,
                _mockHashService.Object);
        }

        [Fact]
        public async Task CreateSessionAsync_WithValidParameters_ShouldCreateSession()
        {
            // Arrange
            byte[] remoteIdentityKey = new byte[32];
            byte[] remotePreKey = new byte[32];
            byte[] remotePreKeySignature = new byte[32];
            byte[] localIdentityKey = new byte[32];
            byte[] rootKey = new byte[32];
            byte[] sendingChainKey = new byte[32];
            byte[] receivingChainKey = new byte[32];
            byte[] sendingRatchetKey = new byte[32];

            _mockKeyStore.Setup(k => k.GetIdentityKeyAsync())
                .ReturnsAsync(localIdentityKey);

            _mockHashService.Setup(h => h.VerifyKeyedHashAsync(remotePreKey, remoteIdentityKey, remotePreKeySignature))
                .ReturnsAsync(true);

            _mockKeyExchangeService.Setup(k => k.PerformKeyExchangeAsync(localIdentityKey, remoteIdentityKey, remotePreKey))
                .ReturnsAsync((rootKey, sendingChainKey, receivingChainKey));

            _mockKeyStore.Setup(k => k.GenerateEphemeralKeyPairAsync())
                .ReturnsAsync(sendingRatchetKey);

            // Act
            string sessionId = await _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature);

            // Assert
            Assert.NotNull(sessionId);
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(It.IsAny<string>(), It.IsAny<SessionState>()), Times.Once);
        }

        [Fact]
        public async Task CreateSessionAsync_WithNullLocalIdentityKey_ShouldThrowInvalidOperationException()
        {
            // Arrange
            byte[] remoteIdentityKey = new byte[32];
            byte[] remotePreKey = new byte[32];
            byte[] remotePreKeySignature = new byte[32];

            _mockKeyStore.Setup(k => k.GetIdentityKeyAsync())
                .ReturnsAsync((byte[])null);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature));
        }

        [Fact]
        public async Task CreateSessionAsync_WithInvalidSignature_ShouldThrowInvalidOperationException()
        {
            // Arrange
            byte[] remoteIdentityKey = new byte[32];
            byte[] remotePreKey = new byte[32];
            byte[] remotePreKeySignature = new byte[32];
            byte[] localIdentityKey = new byte[32];

            _mockKeyStore.Setup(k => k.GetIdentityKeyAsync())
                .ReturnsAsync(localIdentityKey);

            _mockHashService.Setup(h => h.VerifyKeyedHashAsync(remotePreKey, remoteIdentityKey, remotePreKeySignature))
                .ReturnsAsync(false);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidSession_ShouldProcessMessage()
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

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync(sessionState);

            // Act
            byte[] result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(sessionId, It.IsAny<SessionState>()), Times.Once);
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithInvalidSession_ShouldThrowInvalidOperationException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();
            byte[] message = new byte[32];

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync((SessionState)null);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _sessionManager.ProcessIncomingMessageAsync(sessionId, message));
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

            _mockKeyStore.Setup(k => k.GetSessionStateAsync(sessionId))
                .ReturnsAsync(sessionState);

            // Act
            byte[] result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            _mockKeyStore.Verify(k => k.StoreSessionStateAsync(sessionId, It.IsAny<SessionState>()), Times.Once);
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