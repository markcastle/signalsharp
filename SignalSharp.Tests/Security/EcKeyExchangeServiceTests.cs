using System;
using System.Threading.Tasks;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Tests.Security
{
    public class EcKeyExchangeServiceTests
    {
        private readonly EcKeyExchangeService _service;

        public EcKeyExchangeServiceTests()
        {
            _service = new EcKeyExchangeService();
        }

        [Fact]
        public async Task GenerateKeyPair_ReturnsValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();

            // Assert
            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.Equal(64, publicKey.Length); // 32 bytes for X + 32 bytes for Y
            Assert.Equal(32, privateKey.Length); // 32 bytes for private key
        }

        [Fact]
        public async Task ComputeSharedSecret_WithValidKeys_ReturnsSharedSecret()
        {
            // Arrange
            var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();

            // Act
            var sharedSecret = await _service.ComputeSharedSecretAsync(privateKey, publicKey);

            // Assert
            Assert.NotNull(sharedSecret);
            Assert.Equal(32, sharedSecret.Length); // 32 bytes for shared secret
        }

        [Fact]
        public async Task DeriveSymmetricKey_WithValidInput_ReturnsSymmetricKey()
        {
            // Arrange
            var sharedSecret = new byte[32];
            var salt = new byte[32];
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(salt);

            // Act
            var symmetricKey = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt);

            // Assert
            Assert.NotNull(symmetricKey);
            Assert.Equal(32, symmetricKey.Length); // 32 bytes for symmetric key
        }

        [Fact]
        public async Task SignAndVerify_WithValidData_VerifiesSuccessfully()
        {
            // Arrange
            var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();
            var data = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            var signature = await _service.SignAsync(privateKey, data);
            var isValid = await _service.VerifyAsync(publicKey, data, signature);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (publicKey, _) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.ComputeSharedSecretAsync(null!, publicKey));
        }

        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (_, privateKey) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.ComputeSharedSecretAsync(privateKey, null!));
        }

        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithNullSharedSecret_ShouldThrowArgumentNullException()
        {
            // Arrange
            var salt = new byte[32];
            new Random().NextBytes(salt);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.DeriveSymmetricKeyAsync(null!, salt));
        }

        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithNullSalt_ShouldThrowArgumentNullException()
        {
            // Arrange
            var sharedSecret = new byte[32];
            new Random().NextBytes(sharedSecret);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.DeriveSymmetricKeyAsync(sharedSecret, null!));
        }
    }
} 