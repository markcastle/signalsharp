using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Storage.Services;

namespace SignalSharp.Tests.Storage
{
    public class FileKeyStoreTests : IDisposable
    {
        private readonly string _testDirectory;
        private readonly FileKeyStore _keyStore;
        private readonly Mock<IJsonSerializer> _mockJsonSerializer;
        private readonly Mock<IEncryptionService> _mockEncryptionService;

        public FileKeyStoreTests()
        {
            _testDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            _mockJsonSerializer = new Mock<IJsonSerializer>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _keyStore = new FileKeyStore(_testDirectory, _mockJsonSerializer.Object, _mockEncryptionService.Object);

            // Set up default encryption service responses
            _mockEncryptionService.Setup(x => x.GenerateKeyAsync())
                .ReturnsAsync(new byte[] { 1, 2, 3, 4 });
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            _mockEncryptionService.Setup(x => x.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
        }

        public void Dispose()
        {
            if (Directory.Exists(_testDirectory))
                Directory.Delete(_testDirectory, true);
        }

        [Fact]
        public async Task StoreKeyAsync_WithValidParameters_ShouldStoreKey()
        {
            // Arrange
            var keyId = "test_key";
            var key = new byte[] { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);

            // Act
            await _keyStore.StoreKeyAsync(keyId, key);

            // Assert
            var filePath = Path.Combine(_testDirectory, "v1_test_key.key");
            Assert.True(File.Exists(filePath));
            var storedKey = await File.ReadAllBytesAsync(filePath);
            Assert.Equal(key, storedKey);
        }

        [Fact]
        public async Task GetKeyAsync_WithExistingKey_ShouldReturnKey()
        {
            // Arrange
            var keyId = "test_key";
            var key = new byte[] { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            _mockEncryptionService.Setup(x => x.DecryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync(keyId, key);

            // Act
            var result = await _keyStore.GetKeyAsync(keyId);

            // Assert
            Assert.Equal(key, result);
        }

        [Fact]
        public async Task GetKeyAsync_WithNonExistentKey_ShouldReturnNull()
        {
            // Arrange
            var keyId = "non_existent_key";

            // Act
            var result = await _keyStore.GetKeyAsync(keyId);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task DeleteKeyAsync_WithExistingKey_ShouldDeleteKey()
        {
            // Arrange
            var keyId = "test_key";
            var key = new byte[] { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync(keyId, key);

            // Act
            await _keyStore.DeleteKeyAsync(keyId);

            // Assert
            var filePath = Path.Combine(_testDirectory, "v1_test_key.key");
            Assert.False(File.Exists(filePath));
        }

        [Fact]
        public async Task StoreKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;
            var key = new byte[] { 1, 2, 3 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.StoreKeyAsync(keyId!, key));
        }

        [Fact]
        public async Task StoreKeyAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var keyId = "test_key";
            byte[]? key = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.StoreKeyAsync(keyId, key!));
        }

        [Fact]
        public async Task GetKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.GetKeyAsync(keyId!));
        }

        [Fact]
        public async Task DeleteKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.DeleteKeyAsync(keyId!));
        }

        [Fact]
        public async Task GetIdentityKeyAsync_WithExistingKey_ShouldReturnKey()
        {
            // Arrange
            var key = new byte[] { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            _mockEncryptionService.Setup(x => x.DecryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync("identity", key);

            // Act
            var result = await _keyStore.GetIdentityKeyAsync();

            // Assert
            Assert.Equal(key, result);
        }

        [Fact]
        public async Task GetIdentityKeyAsync_WithNoKey_ShouldReturnNull()
        {
            // Act
            var result = await _keyStore.GetIdentityKeyAsync();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GenerateEphemeralKeyPairAsync_ShouldGenerateAndStoreKey()
        {
            // Arrange
            var generatedKey = new byte[] { 1, 2, 3, 4 };
            _mockEncryptionService.Setup(x => x.GenerateKeyAsync())
                .ReturnsAsync(generatedKey);
            _mockEncryptionService.Setup(x => x.EncryptAsync(generatedKey, It.IsAny<byte[]>()))
                .ReturnsAsync(generatedKey);
            _mockEncryptionService.Setup(x => x.DecryptAsync(generatedKey, It.IsAny<byte[]>()))
                .ReturnsAsync(generatedKey);

            // Act
            var result = await _keyStore.GenerateEphemeralKeyPairAsync();

            // Assert
            Assert.NotNull(result);
            Assert.Equal(generatedKey, result);
            _mockEncryptionService.Verify(x => x.GenerateKeyAsync(), Times.Once);
        }

        [Fact]
        public async Task StoreSessionStateAsync_WithValidParameters_ShouldStoreState()
        {
            // Arrange
            var sessionId = "test_session";
            var sessionState = new SessionState(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            var json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);

            // Act
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Assert
            var filePath = Path.Combine(_testDirectory, "sessions", "v1_test_session.json");
            Assert.True(File.Exists(filePath));
            var storedJson = await File.ReadAllTextAsync(filePath);
            Assert.Equal(json, storedJson);
        }

        [Fact]
        public async Task GetSessionStateAsync_WithExistingState_ShouldReturnState()
        {
            // Arrange
            var sessionId = "test_session";
            var sessionState = new SessionState(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            var json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockJsonSerializer.Setup(x => x.Deserialize<SessionState>(json))
                .Returns(sessionState);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            _mockEncryptionService.Setup(x => x.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Act
            var result = await _keyStore.GetSessionStateAsync(sessionId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(sessionState.SessionId, result.SessionId);
        }

        [Fact]
        public async Task DeleteSessionStateAsync_WithExistingState_ShouldDeleteState()
        {
            // Arrange
            var sessionId = "test_session";
            var sessionState = new SessionState(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            var json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Act
            await _keyStore.DeleteSessionStateAsync(sessionId);

            // Assert
            var filePath = Path.Combine(_testDirectory, "sessions", "v1_test_session.json");
            Assert.False(File.Exists(filePath));
        }
    }
} 