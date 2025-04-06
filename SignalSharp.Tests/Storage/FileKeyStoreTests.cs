using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using SignalSharp.Storage.Services;

namespace SignalSharp.Tests.Storage
{
    public class FileKeyStoreTests : IDisposable
    {
        private readonly string _testDirectory;
        private readonly FileKeyStore _keyStore;

        public FileKeyStoreTests()
        {
            _testDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            _keyStore = new FileKeyStore(_testDirectory);
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

            // Act
            await _keyStore.StoreKeyAsync(keyId, key);

            // Assert
            var filePath = Path.Combine(_testDirectory, $"{keyId}.key");
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
            await _keyStore.StoreKeyAsync(keyId, key);

            // Act
            await _keyStore.DeleteKeyAsync(keyId);

            // Assert
            var filePath = Path.Combine(_testDirectory, $"{keyId}.key");
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
    }
} 