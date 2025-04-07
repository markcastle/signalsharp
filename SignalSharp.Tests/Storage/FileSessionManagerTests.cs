using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Storage.Services;
using SignalSharp.Serialization.SystemTextJson;
using System.Text.Json;

namespace SignalSharp.Tests.Storage
{
    public class FileSessionManagerTests : IDisposable
    {
        private readonly string _testDirectory;
        private readonly Mock<IKeyStore> _keyStoreMock;
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly Mock<IJsonSerializer> _jsonSerializerMock;
        private readonly FileSessionManager _sessionManager;

        public FileSessionManagerTests()
        {
            _testDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testDirectory);

            _keyStoreMock = new Mock<IKeyStore>();
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _jsonSerializerMock = new Mock<IJsonSerializer>();

            _sessionManager = new FileSessionManager(
                _testDirectory,
                _keyStoreMock.Object,
                _encryptionServiceMock.Object,
                _jsonSerializerMock.Object);

            // Set up default key store responses
            _keyStoreMock.Setup(x => x.GetAsync("local_identity_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 10, 11, 12 }));
            _keyStoreMock.Setup(x => x.GetAsync("root_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 13, 14, 15 }));
            _keyStoreMock.Setup(x => x.GetAsync("sending_chain_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 16, 17, 18 }));
            _keyStoreMock.Setup(x => x.GetAsync("receiving_chain_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 19, 20, 21 }));
            _keyStoreMock.Setup(x => x.GetAsync("sending_ratchet_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 22, 23, 24 }));
            _keyStoreMock.Setup(x => x.GetAsync("receiving_ratchet_key")).ReturnsAsync(Convert.ToBase64String(new byte[] { 25, 26, 27 }));
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
            var sessionId = "test-session";
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remoteSignedPreKey = new byte[] { 4, 5, 6 };
            var remoteOneTimePreKey = new byte[] { 7, 8, 9 };

            // Act
            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);

            // Assert
            Assert.True(File.Exists(Path.Combine(_testDirectory, $"{sessionId}.json")));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidMessage_ShouldDecryptMessage()
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

            var filePath = Path.Combine(_testDirectory, $"{sessionId}.json");
            var serializedState = JsonSerializer.Serialize(sessionState);
            _jsonSerializerMock.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);
            _jsonSerializerMock.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);
            await File.WriteAllTextAsync(filePath, serializedState);

            _encryptionServiceMock.Setup(x => x.DecryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(decryptedMessage);

            // Act
            var result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(decryptedMessage, result);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidMessage_ShouldEncryptMessage()
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
            var encryptedBytes = new byte[] { 25, 26, 27 };

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            var filePath = Path.Combine(_testDirectory, $"{sessionId}.json");
            var serializedState = JsonSerializer.Serialize(sessionState);
            _jsonSerializerMock.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);
            _jsonSerializerMock.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);
            await File.WriteAllTextAsync(filePath, serializedState);

            _encryptionServiceMock.Setup(x => x.EncryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(encryptedBytes);

            // Act
            var result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(encryptedBytes, result);
        }

        [Fact]
        public async Task DeleteSessionAsync_WithExistingSession_ShouldDeleteSession()
        {
            // Arrange
            var sessionId = "test-session";
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remoteSignedPreKey = new byte[] { 4, 5, 6 };
            var remoteOneTimePreKey = new byte[] { 7, 8, 9 };

            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);
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
            var sessionId = "test-session";
            byte[]? remoteIdentityKey = null;
            var remoteSignedPreKey = new byte[] { 4, 5, 6 };
            var remoteOneTimePreKey = new byte[] { 7, 8, 9 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey!, remoteSignedPreKey, remoteOneTimePreKey));
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
        public async Task GetSessionStateAsync_WithExistingSession_ReturnsState()
        {
            // Arrange
            var sessionId = "test-session";
            var remoteIdentityKey = new byte[] { 1, 2, 3 };
            var remoteSignedPreKey = new byte[] { 4, 5, 6 };
            var remoteOneTimePreKey = new byte[] { 7, 8, 9 };

            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);

            var expectedState = new SessionState(
                sessionId,
                new byte[] { 10, 11, 12 },
                remoteIdentityKey,
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 },
                new byte[] { 22, 23, 24 },
                new byte[] { 25, 26, 27 });

            _jsonSerializerMock.Setup(x => x.Deserialize<SessionState>(It.IsAny<string>()))
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
    }
} 