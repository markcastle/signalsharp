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
            string? sessionId = "test-session";
            byte[]? remoteIdentityKey = { 1, 2, 3 };
            byte[]? remoteSignedPreKey = { 4, 5, 6 };
            byte[]? remoteOneTimePreKey = { 7, 8, 9 };

            // Act
            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);

            // Assert
            Assert.True(File.Exists(Path.Combine(_testDirectory, $"{sessionId}.json")));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithValidMessage_ShouldDecryptMessage()
        {
            // Arrange
            string? sessionId = "test-session";
            byte[]? localIdentityKey = { 1, 2, 3 };
            byte[]? remoteIdentityKey = { 4, 5, 6 };
            byte[]? rootKey = { 7, 8, 9 };
            byte[]? sendingChainKey = { 10, 11, 12 };
            byte[]? receivingChainKey = { 13, 14, 15 };
            byte[]? sendingRatchetKey = { 16, 17, 18 };
            byte[]? receivingRatchetKey = { 19, 20, 21 };
            byte[]? message = { 22, 23, 24 };
            byte[]? decryptedMessage = { 25, 26, 27 };

            SessionState? sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            string? filePath = Path.Combine(_testDirectory, $"{sessionId}.json");
            string? serializedState = JsonSerializer.Serialize(sessionState);
            _jsonSerializerMock.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);
            _jsonSerializerMock.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);
            await File.WriteAllTextAsync(filePath, serializedState);

            _encryptionServiceMock.Setup(x => x.DecryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(decryptedMessage);

            // Act
            byte[]? result = await _sessionManager.ProcessIncomingMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(decryptedMessage, result);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidMessage_ShouldEncryptMessage()
        {
            // Arrange
            string? sessionId = "test-session";
            byte[]? localIdentityKey = { 1, 2, 3 };
            byte[]? remoteIdentityKey = { 4, 5, 6 };
            byte[]? rootKey = { 7, 8, 9 };
            byte[]? sendingChainKey = { 10, 11, 12 };
            byte[]? receivingChainKey = { 13, 14, 15 };
            byte[]? sendingRatchetKey = { 16, 17, 18 };
            byte[]? receivingRatchetKey = { 19, 20, 21 };
            byte[]? message = { 22, 23, 24 };
            byte[]? encryptedBytes = { 25, 26, 27 };

            SessionState? sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            string? filePath = Path.Combine(_testDirectory, $"{sessionId}.json");
            string? serializedState = JsonSerializer.Serialize(sessionState);
            _jsonSerializerMock.Setup(x => x.Serialize(It.IsAny<SessionState>()))
                .Returns(serializedState);
            _jsonSerializerMock.Setup(x => x.Deserialize<SessionState>(serializedState))
                .Returns(sessionState);
            await File.WriteAllTextAsync(filePath, serializedState);

            _encryptionServiceMock.Setup(x => x.EncryptAsync(message, It.IsAny<byte[]>()))
                .ReturnsAsync(encryptedBytes);

            // Act
            byte[]? result = await _sessionManager.EncryptMessageAsync(sessionId, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(encryptedBytes, result);
        }

        [Fact]
        public async Task DeleteSessionAsync_WithExistingSession_ShouldDeleteSession()
        {
            // Arrange
            string? sessionId = "test-session";
            byte[]? remoteIdentityKey = { 1, 2, 3 };
            byte[]? remoteSignedPreKey = { 4, 5, 6 };
            byte[]? remoteOneTimePreKey = { 7, 8, 9 };

            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);
            string? filePath = Path.Combine(_testDirectory, $"{sessionId}.json");

            // Act
            await _sessionManager.DeleteSessionAsync(sessionId);

            // Assert
            Assert.False(File.Exists(filePath));
        }

        [Fact]
        public async Task CreateSessionAsync_WithNullRemoteIdentityKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? sessionId = "test-session";
            byte[]? remoteIdentityKey = null;
            byte[]? remoteSignedPreKey = { 4, 5, 6 };
            byte[]? remoteOneTimePreKey = { 7, 8, 9 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey!, remoteSignedPreKey, remoteOneTimePreKey));
        }

        [Fact]
        public async Task ProcessIncomingMessageAsync_WithNullSessionId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? sessionId = null;
            byte[]? message = { 1, 2, 3 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _sessionManager.ProcessIncomingMessageAsync(sessionId!, message));
        }

        [Fact]
        public async Task GetSessionStateAsync_WithExistingSession_ReturnsState()
        {
            // Arrange
            string? sessionId = "test-session";
            byte[]? remoteIdentityKey = { 1, 2, 3 };
            byte[]? remoteSignedPreKey = { 4, 5, 6 };
            byte[]? remoteOneTimePreKey = { 7, 8, 9 };

            await _sessionManager.CreateSessionAsync(sessionId, remoteIdentityKey, remoteSignedPreKey, remoteOneTimePreKey);

            SessionState? expectedState = new(
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
            SessionState? result = await _sessionManager.GetSessionStateAsync(sessionId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedState.SessionId, result.SessionId);
            Assert.Equal(expectedState.LocalIdentityKey, result.LocalIdentityKey);
            Assert.Equal(expectedState.RemoteIdentityKey, result.RemoteIdentityKey);
            Assert.Equal(expectedState.RootKey, result.RootKey);
        }
    }
} 