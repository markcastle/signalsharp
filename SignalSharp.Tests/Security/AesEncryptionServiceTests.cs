using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Tests.Security
{
    public class AesEncryptionServiceTests
    {
        private readonly AesEncryptionService _service;

        public AesEncryptionServiceTests()
        {
            _service = new AesEncryptionService();
        }

        [Fact]
        public async Task GenerateKeyAsync_ShouldReturn32ByteKey()
        {
            // Act
            var key = await _service.GenerateKeyAsync();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length); // 256 bits = 32 bytes
        }

        [Fact]
        public async Task EncryptAsync_WithValidInput_ShouldEncryptData()
        {
            // Arrange
            var key = await _service.GenerateKeyAsync();
            var plainText = Encoding.UTF8.GetBytes("Hello, Signal!");

            // Act
            var encrypted = await _service.EncryptAsync(plainText, key);

            // Assert
            Assert.NotNull(encrypted);
            Assert.True(encrypted.Length > plainText.Length); // Due to IV and padding
            Assert.NotEqual(plainText, encrypted); // Encrypted data should be different
        }

        [Fact]
        public async Task DecryptAsync_WithValidInput_ShouldDecryptToOriginalData()
        {
            // Arrange
            var key = await _service.GenerateKeyAsync();
            var originalText = "Hello, Signal!";
            var plainText = Encoding.UTF8.GetBytes(originalText);

            // Act
            var encrypted = await _service.EncryptAsync(plainText, key);
            var decrypted = await _service.DecryptAsync(encrypted, key);
            var decryptedText = Encoding.UTF8.GetString(decrypted);

            // Assert
            Assert.Equal(originalText, decryptedText);
        }

        [Fact]
        public async Task EncryptAsync_WithNullPlainText_ShouldThrowArgumentNullException()
        {
            // Arrange
            var key = await _service.GenerateKeyAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.EncryptAsync(null, key));
        }

        [Fact]
        public async Task EncryptAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var plainText = Encoding.UTF8.GetBytes("Hello, Signal!");

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.EncryptAsync(plainText, null));
        }

        [Fact]
        public async Task DecryptAsync_WithInvalidKey_ShouldProduceDifferentResult()
        {
            // Arrange
            var key1 = await _service.GenerateKeyAsync();
            var key2 = await _service.GenerateKeyAsync();
            var originalText = "Hello, Signal!";
            var plainText = Encoding.UTF8.GetBytes(originalText);

            // Act
            var encrypted = await _service.EncryptAsync(plainText, key1);

            // Assert
            await Assert.ThrowsAsync<CryptographicException>(() => 
                _service.DecryptAsync(encrypted, key2));
        }

        [Fact]
        public async Task DecryptAsync_WithInvalidCipherText_ShouldThrowArgumentException()
        {
            // Arrange
            var key = await _service.GenerateKeyAsync();
            var invalidCipherText = new byte[8]; // Too short to contain IV

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.DecryptAsync(invalidCipherText, key));
        }
    }
} 