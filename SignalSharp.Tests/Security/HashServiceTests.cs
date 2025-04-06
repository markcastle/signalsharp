using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using SignalSharp.Security.Services;

namespace SignalSharp.Tests.Security
{
    public class HashServiceTests
    {
        private readonly HashService _hashService;

        public HashServiceTests()
        {
            _hashService = new HashService();
        }

        [Fact]
        public async Task ComputeHashAsync_WithValidData_ShouldReturnHash()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");

            // Act
            var hash = await _hashService.ComputeHashAsync(data);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length); // SHA-256 produces 32 bytes
        }

        [Fact]
        public async Task ComputeHashAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] data = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.ComputeHashAsync(data));
        }

        [Fact]
        public async Task ComputeKeyedHashAsync_WithValidDataAndKey_ShouldReturnHash()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var key = Encoding.UTF8.GetBytes("SecretKey");

            // Act
            var hash = await _hashService.ComputeKeyedHashAsync(data, key);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length); // HMACSHA256 produces 32 bytes
        }

        [Fact]
        public async Task ComputeKeyedHashAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] data = null;
            var key = Encoding.UTF8.GetBytes("SecretKey");

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.ComputeKeyedHashAsync(data, key));
        }

        [Fact]
        public async Task ComputeKeyedHashAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            byte[] key = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.ComputeKeyedHashAsync(data, key));
        }

        [Fact]
        public async Task VerifyHashAsync_WithMatchingHash_ShouldReturnTrue()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var hash = await _hashService.ComputeHashAsync(data);

            // Act
            var result = await _hashService.VerifyHashAsync(data, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task VerifyHashAsync_WithNonMatchingHash_ShouldReturnFalse()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var differentData = Encoding.UTF8.GetBytes("Hello, Different!");
            var hash = await _hashService.ComputeHashAsync(data);

            // Act
            var result = await _hashService.VerifyHashAsync(differentData, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task VerifyHashAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] data = null;
            var hash = new byte[32];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.VerifyHashAsync(data, hash));
        }

        [Fact]
        public async Task VerifyHashAsync_WithNullHash_ShouldThrowArgumentNullException()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            byte[] hash = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.VerifyHashAsync(data, hash));
        }

        [Fact]
        public async Task VerifyKeyedHashAsync_WithMatchingHash_ShouldReturnTrue()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var key = Encoding.UTF8.GetBytes("SecretKey");
            var hash = await _hashService.ComputeKeyedHashAsync(data, key);

            // Act
            var result = await _hashService.VerifyKeyedHashAsync(data, key, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task VerifyKeyedHashAsync_WithNonMatchingHash_ShouldReturnFalse()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var differentData = Encoding.UTF8.GetBytes("Hello, Different!");
            var key = Encoding.UTF8.GetBytes("SecretKey");
            var hash = await _hashService.ComputeKeyedHashAsync(data, key);

            // Act
            var result = await _hashService.VerifyKeyedHashAsync(differentData, key, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task VerifyKeyedHashAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] data = null;
            var key = Encoding.UTF8.GetBytes("SecretKey");
            var hash = new byte[32];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.VerifyKeyedHashAsync(data, key, hash));
        }

        [Fact]
        public async Task VerifyKeyedHashAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            byte[] key = null;
            var hash = new byte[32];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.VerifyKeyedHashAsync(data, key, hash));
        }

        [Fact]
        public async Task VerifyKeyedHashAsync_WithNullHash_ShouldThrowArgumentNullException()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, Signal!");
            var key = Encoding.UTF8.GetBytes("SecretKey");
            byte[] hash = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _hashService.VerifyKeyedHashAsync(data, key, hash));
        }
    }
} 