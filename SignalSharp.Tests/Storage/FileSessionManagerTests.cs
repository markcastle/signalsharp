using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Storage.Services;
using SignalSharp.Serialization.SystemTextJson;

namespace SignalSharp.Tests.Storage
{
    public class FileSessionManagerTests : IDisposable
    {
        private readonly string _testDirectory;
        private readonly Mock<IKeyStore> _keyStoreMock;
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly IJsonSerializer _jsonSerializer;
        private readonly FileSessionManager _sessionManager;

        public FileSessionManagerTests()
        {
            _testDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            _keyStoreMock = new Mock<IKeyStore>();
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _jsonSerializer = new SystemTextJsonSerializer();
            _sessionManager = new FileSessionManager(_testDirectory, _keyStoreMock.Object, _encryptionServiceMock.Object, _jsonSerializer);

            // Set up default key store responses
            _keyStoreMock.Setup(x => x.GetKeyAsync("local_identity_key")).ReturnsAsync(new byte[] { 10, 11, 12 });
            _keyStoreMock.Setup(x => x.GetKeyAsync("root_key")).ReturnsAsync(new byte[] { 13, 14, 15 });
            _keyStoreMock.Setup(x => x.GetKeyAsync("sending_chain_key")).ReturnsAsync(new byte[] { 16, 17, 18 });
            _keyStoreMock.Setup(x => x.GetKeyAsync("receiving_chain_key")).ReturnsAsync(new byte[] { 19, 20, 21 });
            _keyStoreMock.Setup(x => x.GetKeyAsync("sending_ratchet_key")).ReturnsAsync(new byte[] { 22, 23, 24 });
            _keyStoreMock.Setup(x => x.GetKeyAsync("receiving_ratchet_key")).ReturnsAsync(new byte[] { 25, 26, 27 });
        }

        public void Dispose()
        {
            if (Directory.Exists(_testDirectory))
                Directory.Delete(_testDirectory, true);
        }

        [Fact]
        public async Task CreateSessionAsync_WithValidParameters_ShouldCreateSession()
        {
            // Arrange
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remotePreKey = new byte[] { 4, 5, 6 };
            var remotePreKeySignature = new byte[] { 7, 8, 9 };

            // Act
            var sessionId = await _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature);

            // Assert
            Assert.NotNull(sessionId);
            Assert.True(File.Exists(Path.Combine(_testDirectory, $"{sessionId}.json")));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidMessage_ShouldDecryptMessage()
        {
            // Arrange
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remotePreKey = new byte[] { 4, 5, 6 };
            var remotePreKeySignature = new byte[] { 7, 8, 9 };
            var message = new byte[] { 1, 2, 3 };
            var decryptedMessage = new byte[] { 4, 5, 6 };

            var sessionId = await _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature);
            _encryptionServiceMock.Setup(x => x.DecryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(decryptedMessage);

            // Act
            var result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.Equal(decryptedMessage, result);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidMessage_ShouldEncryptMessage()
        {
            // Arrange
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remotePreKey = new byte[] { 4, 5, 6 };
            var remotePreKeySignature = new byte[] { 7, 8, 9 };
            var message = new byte[] { 1, 2, 3 };
            var encryptedMessage = new byte[] { 4, 5, 6 };

            var sessionId = await _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature);
            _encryptionServiceMock.Setup(x => x.EncryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(encryptedMessage);

            // Act
            var result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.Equal(encryptedMessage, result);
        }

        [Fact]
        public async Task DeleteSessionAsync_WithExistingSession_ShouldDeleteSession()
        {
            // Arrange
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remotePreKey = new byte[] { 4, 5, 6 };
            var remotePreKeySignature = new byte[] { 7, 8, 9 };

            var sessionId = await _sessionManager.CreateSessionAsync(remoteIdentityKey, remotePreKey, remotePreKeySignature);
            var filePath = Path.Combine(_testDirectory, $"{sessionId}.json");

            // Act
            await _sessionManager.DeleteSessionAsync(sessionId);

            // Assert
            Assert.False(File.Exists(filePath));
        }

        [Fact]
        public async Task CreateSessionAsync_WithNullRemoteIdentityKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[]? remoteIdentityKey = null;
            var remotePreKey = new byte[] { 4, 5, 6 };
            var remotePreKeySignature = new byte[] { 7, 8, 9 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.CreateSessionAsync(remoteIdentityKey!, remotePreKey, remotePreKeySignature));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithNullSessionId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? sessionId = null;
            var message = new byte[] { 1, 2, 3 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.ProcessIncomingMessageAsync(sessionId!, message));
        }

        [Fact]
        public async Task EncryptMessageAsync_WithNullMessage_ShouldThrowArgumentNullException()
        {
            // Arrange
            var sessionId = Guid.NewGuid().ToString();
            byte[]? message = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.EncryptMessageAsync(sessionId, message!));
        }
    }
} 