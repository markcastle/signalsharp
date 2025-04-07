using System;
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
    /// Security-focused test suite for the X3DH key agreement protocol implementation.
    /// These tests verify cryptographic correctness and security properties of the X3DH implementation.
    /// </summary>
    public class X3DHProtocolTests
    {
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly X3DHKeyAgreementService _service;

        public X3DHProtocolTests()
        {
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
            _hashServiceMock = new Mock<IHashService>();
            _service = new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, _hashServiceMock.Object);
        }

        [Fact]
        public async Task GenerateIdentityKeyPair_ShouldProduceValidKeyPair()
        {
            // Arrange
            var expectedPublicKey = new byte[32];
            var expectedPrivateKey = new byte[32];
            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((expectedPublicKey, expectedPrivateKey));

            // Act
            var result = await _service.GenerateIdentityKeyPairAsync();

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(expectedPublicKey);
            result.PrivateKey.Should().BeEquivalentTo(expectedPrivateKey);
            result.PublicKey.Length.Should().Be(32);
            result.PrivateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldSignWithIdentityKey()
        {
            // Arrange
            var identityKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var expectedPreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
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
            _keyExchangeServiceMock.Verify(x => x.SignAsync(It.IsAny<byte[]>(), identityKeyPair.PrivateKey), Times.Once);
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldFollowX3DHSpecification()
        {
            // Arrange
            var identityKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var signedPreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32], Signature = new byte[64] };
            var oneTimePreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var remoteIdentityKey = new byte[32];
            var remoteSignedPreKey = new byte[32];
            var remoteOneTimePreKey = new byte[32];
            var expectedSharedSecret = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(expectedSharedSecret);
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(expectedSharedSecret);

            // Act
            var result = await _service.PerformKeyAgreementAsync(
                identityKeyPair,
                signedPreKeyPair,
                oneTimePreKeyPair,
                remoteIdentityKey,
                remoteSignedPreKey,
                remoteOneTimePreKey);

            // Assert
            result.Should().NotBeNull();
            result.Should().BeEquivalentTo(expectedSharedSecret);
            result.Length.Should().Be(32);
            
            // Verify all required DH exchanges were performed
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Exactly(4));
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldHandleMissingOneTimePreKey()
        {
            // Arrange
            var identityKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var signedPreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32], Signature = new byte[64] };
            var oneTimePreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var remoteIdentityKey = new byte[32];
            var remoteSignedPreKey = new byte[32];
            var expectedSharedSecret = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(expectedSharedSecret);
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(expectedSharedSecret);

            // Act
            var result = await _service.PerformKeyAgreementAsync(
                identityKeyPair,
                signedPreKeyPair,
                oneTimePreKeyPair,
                remoteIdentityKey,
                remoteSignedPreKey,
                null);

            // Assert
            result.Should().NotBeNull();
            result.Should().BeEquivalentTo(expectedSharedSecret);
            result.Length.Should().Be(32);
            
            // Verify only required DH exchanges were performed (3 instead of 4)
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Exactly(3));
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        [InlineData(new byte[31])] // Too short
        [InlineData(new byte[33])] // Too long
        public async Task PerformKeyAgreement_ShouldValidateKeyLengths(byte[] invalidKey)
        {
            // Arrange
            var identityKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var signedPreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32], Signature = new byte[64] };
            var oneTimePreKeyPair = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => _service.PerformKeyAgreementAsync(
                identityKeyPair,
                signedPreKeyPair,
                oneTimePreKeyPair,
                invalidKey,
                new byte[32],
                new byte[32]));
        }
    }
} 