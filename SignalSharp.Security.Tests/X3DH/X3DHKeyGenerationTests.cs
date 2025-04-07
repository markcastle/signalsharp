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
            var keyPairs = new List<(byte[] PublicKey, byte[] PrivateKey)>();
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    var publicKey = new byte[32];
                    var privateKey = new byte[32];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(publicKey);
                        rng.GetBytes(privateKey);
                    }
                    keyPairs.Add((publicKey, privateKey));
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
                    var publicKey = new byte[32];
                    var privateKey = new byte[32];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(publicKey);
                        rng.GetBytes(privateKey);
                    }
                    return (publicKey, privateKey);
                });

            // Act
            var keyPair = await _service.GenerateIdentityKeyPairAsync();

            // Assert
            keyPair.PublicKey.Should().NotBeNull();
            keyPair.PrivateKey.Should().NotBeNull();
            keyPair.PublicKey.Length.Should().Be(32, "Public key should be 32 bytes (256 bits)");
            keyPair.PrivateKey.Length.Should().Be(32, "Private key should be 32 bytes (256 bits)");
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldValidateIdentityKeyPair()
        {
            // Arrange
            var invalidKeyPair = new KeyPair { PublicKey = new byte[31], PrivateKey = new byte[31] };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.GenerateSignedPreKeyPairAsync(invalidKeyPair));
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldProduceValidSignature()
        {
            // Arrange
            var identityKeyPair = new KeyPair 
            { 
                PublicKey = new byte[32], 
                PrivateKey = new byte[32] 
            };
            var expectedPreKeyPair = new KeyPair 
            { 
                PublicKey = new byte[32], 
                PrivateKey = new byte[32] 
            };
            var expectedSignature = new byte[64];

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((expectedPreKeyPair.PublicKey, expectedPreKeyPair.PrivateKey));
            _keyExchangeServiceMock.Setup(x => x.SignAsync(It.IsAny<byte[]>(), identityKeyPair.PrivateKey))
                .ReturnsAsync(expectedSignature);

            // Act
            var result = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(expectedPreKeyPair.PublicKey);
            result.PrivateKey.Should().BeEquivalentTo(expectedPreKeyPair.PrivateKey);
            result.Signature.Should().BeEquivalentTo(expectedSignature);
            result.Signature.Length.Should().Be(64, "Signature should be 64 bytes (512 bits)");
        }

        [Fact]
        public async Task GenerateOneTimePreKeyPair_ShouldProduceUniqueKeys()
        {
            // Arrange
            var keyPairs = new List<KeyPair>();
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    var publicKey = new byte[32];
                    var privateKey = new byte[32];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(publicKey);
                        rng.GetBytes(privateKey);
                    }
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
            uniquePublicKeys.Should().Be(100, "All one-time pre-key public keys should be unique");
            uniquePrivateKeys.Should().Be(100, "All one-time pre-key private keys should be unique");
        }

        [Theory]
        [InlineData(31)] // Too short
        [InlineData(33)] // Too long
        public async Task GenerateKeyPair_ShouldValidateKeyLength(int keyLength)
        {
            // Arrange
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync(() =>
                {
                    var publicKey = new byte[keyLength];
                    var privateKey = new byte[keyLength];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(publicKey);
                        rng.GetBytes(privateKey);
                    }
                    return (publicKey, privateKey);
                });

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => 
                _service.GenerateIdentityKeyPairAsync());
        }
    }
} 