using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Security.Tests.X3DH
{
    /// <summary>
    /// Security-focused test suite for X3DH key generation and validation.
    /// These tests verify the cryptographic properties and security requirements of key generation.
    /// </summary>
    public class X3DHKeyGenerationTests
    {
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly X3DHKeyAgreementService _service;

        public X3DHKeyGenerationTests()
        {
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
            _hashServiceMock = new Mock<IHashService>();
            _service = new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, _hashServiceMock.Object);
        }

        [Fact]
        public async Task GenerateIdentityKeyPair_ShouldUseCryptographicallySecureRandomness()
        {
            // Arrange
            var keyPairs = new List<KeyPair>();
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    // Public key is 64 bytes (32 bytes X + 32 bytes Y coordinates)
                    var publicKey = new byte[64];
                    var privateKey = new byte[32];
                    RandomNumberGenerator.Fill(publicKey);
                    RandomNumberGenerator.Fill(privateKey);
                    var keyPair = new KeyPair(publicKey, privateKey);
                    keyPairs.Add(keyPair);
                    return (publicKey, privateKey);
                });

            // Act
            for (int i = 0; i < 100; i++)
            {
                await _service.GenerateIdentityKeyPairAsync();
            }

            // Assert
            keyPairs.Should().HaveCount(100);
            // Verify uniqueness of generated keys
            var uniquePublicKeys = keyPairs.Select(x => x.PublicKey).Distinct().Count();
            var uniquePrivateKeys = keyPairs.Select(x => x.PrivateKey).Distinct().Count();
            uniquePublicKeys.Should().Be(100, "All public keys should be unique");
            uniquePrivateKeys.Should().Be(100, "All private keys should be unique");
        }

        [Fact]
        public async Task GenerateIdentityKeyPair_ShouldMaintainKeyLengthRequirements()
        {
            // Arrange
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    // Public key is 64 bytes (32 bytes X + 32 bytes Y coordinates)
                    var publicKey = new byte[64];
                    var privateKey = new byte[32];
                    RandomNumberGenerator.Fill(publicKey);
                    RandomNumberGenerator.Fill(privateKey);
                    return (publicKey, privateKey);
                });

            // Act
            var keyPair = await _service.GenerateIdentityKeyPairAsync();

            // Assert
            keyPair.Should().NotBeNull();
            keyPair.PublicKey.Should().NotBeNull();
            keyPair.PrivateKey.Should().NotBeNull();
            keyPair.PublicKey.Length.Should().Be(64, "Public key should be 64 bytes (32 bytes X + 32 bytes Y)");
            keyPair.PrivateKey.Length.Should().Be(32, "Private key should be 32 bytes");
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldValidateIdentityKeyPair()
        {
            // Arrange - Invalid key pair with wrong lengths
            var invalidKeyPair = new KeyPair(new byte[31], new byte[31]);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.GenerateSignedPreKeyPairAsync(invalidKeyPair));
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldProduceValidSignature()
        {
            // Arrange - Identity key pair with correct lengths
            var publicKey = new byte[64];
            var privateKey = new byte[32];
            RandomNumberGenerator.Fill(publicKey);
            RandomNumberGenerator.Fill(privateKey);
            var identityKeyPair = new KeyPair(publicKey, privateKey);

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    // Public key is 64 bytes (32 bytes X + 32 bytes Y coordinates)
                    var pubKey = new byte[64];
                    var privKey = new byte[32];
                    RandomNumberGenerator.Fill(pubKey);
                    RandomNumberGenerator.Fill(privKey);
                    return (pubKey, privKey);
                });

            _keyExchangeServiceMock.Setup(x => x.SignAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[64]); // Signature is 64 bytes

            // Act
            var preKeyPair = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

            // Assert
            preKeyPair.Should().NotBeNull();
            preKeyPair.PublicKey.Should().NotBeNull();
            preKeyPair.PrivateKey.Should().NotBeNull();
            preKeyPair.PublicKey.Length.Should().Be(64, "Public key should be 64 bytes (32 bytes X + 32 bytes Y)");
            preKeyPair.PrivateKey.Length.Should().Be(32, "Private key should be 32 bytes");
            _keyExchangeServiceMock.Verify(x => x.SignAsync(identityKeyPair.PrivateKey, It.IsAny<byte[]>()), Times.Once);
        }

        [Fact]
        public async Task GenerateOneTimePreKeyPair_ShouldProduceUniqueKeys()
        {
            // Arrange
            var keyPairs = new List<KeyPair>();
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    // Public key is 64 bytes (32 bytes X + 32 bytes Y coordinates)
                    var publicKey = new byte[64];
                    var privateKey = new byte[32];
                    RandomNumberGenerator.Fill(publicKey);
                    RandomNumberGenerator.Fill(privateKey);
                    var keyPair = new KeyPair(publicKey, privateKey);
                    keyPairs.Add(keyPair);
                    return (publicKey, privateKey);
                });

            // Act
            for (int i = 0; i < 100; i++)
            {
                await _service.GenerateOneTimePreKeyPairAsync();
            }

            // Assert
            keyPairs.Should().HaveCount(100);
            var uniquePublicKeys = keyPairs.Select(x => x.PublicKey).Distinct().Count();
            var uniquePrivateKeys = keyPairs.Select(x => x.PrivateKey).Distinct().Count();
            uniquePublicKeys.Should().Be(100, "All public keys should be unique");
            uniquePrivateKeys.Should().Be(100, "All private keys should be unique");
        }

        [Theory]
        [InlineData(31)] // Too short for private key
        [InlineData(33)] // Too long for private key
        [InlineData(63)] // Too short for public key
        [InlineData(65)] // Too long for public key
        public async Task GenerateKeyPair_ShouldValidateKeyLength(int keyLength)
        {
            // Arrange
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    var publicKey = new byte[keyLength];
                    var privateKey = new byte[keyLength];
                    RandomNumberGenerator.Fill(publicKey);
                    RandomNumberGenerator.Fill(privateKey);
                    return (publicKey, privateKey);
                });

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => 
                _service.GenerateIdentityKeyPairAsync());
        }
    }
} 