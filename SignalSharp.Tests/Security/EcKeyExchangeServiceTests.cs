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
        public async Task GenerateKeyPairAsync_ShouldGenerateValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = await _service.GenerateKeyPairAsync();

            // Assert
            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.NotEmpty(publicKey);
            Assert.NotEmpty(privateKey);
        }

        [Fact]
        public async Task ComputeSharedSecretAsync_WithValidKeys_ShouldProduceSameSecretForBothParties()
        {
            // Arrange
            var (alicePublicKey, alicePrivateKey) = await _service.GenerateKeyPairAsync();
            var (bobPublicKey, bobPrivateKey) = await _service.GenerateKeyPairAsync();

            // Act
            var aliceSharedSecret = await _service.ComputeSharedSecretAsync(alicePrivateKey, bobPublicKey);
            var bobSharedSecret = await _service.ComputeSharedSecretAsync(bobPrivateKey, alicePublicKey);

            // Assert
            Assert.Equal(aliceSharedSecret, bobSharedSecret);
        }

        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithSameInputs_ShouldProduceSameKey()
        {
            // Arrange
            var sharedSecret = new byte[] { 1, 2, 3, 4, 5 };
            var salt = new byte[] { 6, 7, 8, 9, 10 };

            // Act
            var key1 = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt);
            var key2 = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt);

            // Assert
            Assert.Equal(key1, key2);
        }

        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithDifferentSalts_ShouldProduceDifferentKeys()
        {
            // Arrange
            var sharedSecret = new byte[] { 1, 2, 3, 4, 5 };
            var salt1 = new byte[] { 6, 7, 8, 9, 10 };
            var salt2 = new byte[] { 11, 12, 13, 14, 15 };

            // Act
            var key1 = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt1);
            var key2 = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt2);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (publicKey, _) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.ComputeSharedSecretAsync(null, publicKey));
        }

        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            var (_, privateKey) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.ComputeSharedSecretAsync(privateKey, null));
        }

        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithNullSharedSecret_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _service.DeriveSymmetricKeyAsync(null));
        }
    }
} 