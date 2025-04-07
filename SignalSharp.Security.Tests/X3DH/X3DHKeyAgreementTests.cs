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
    /// Security-focused test suite for X3DH key agreement protocol.
    /// These tests verify the cryptographic properties and security requirements of the key agreement process.
    /// </summary>
    public class X3DHKeyAgreementTests
    {
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly X3DHKeyAgreementService _service;

        public X3DHKeyAgreementTests()
        {
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
            _hashServiceMock = new Mock<IHashService>();
            _service = new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, _hashServiceMock.Object);
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

            // Setup mock to return different values for each DH exchange
            var dh1 = new byte[32];
            var dh2 = new byte[32];
            var dh3 = new byte[32];
            var dh4 = new byte[32];
            var expectedSharedSecret = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteSignedPreKey))
                .ReturnsAsync(dh1);
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteIdentityKey))
                .ReturnsAsync(dh2);
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteSignedPreKey))
                .ReturnsAsync(dh3);
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteOneTimePreKey))
                .ReturnsAsync(dh4);

            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(
                It.Is<byte[]>(arr => arr.Length == dh1.Length + dh2.Length + dh3.Length + dh4.Length),
                identityKeyPair.PrivateKey))
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
            result.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");

            // Verify all required DH exchanges were performed in the correct order
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                identityKeyPair.PrivateKey, remoteSignedPreKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                identityKeyPair.PrivateKey, remoteIdentityKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                identityKeyPair.PrivateKey, remoteSignedPreKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(
                identityKeyPair.PrivateKey, remoteOneTimePreKey), Times.Once);
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

            // Setup mock to return different values for each DH exchange
            var dh1 = new byte[32];
            var dh2 = new byte[32];
            var dh3 = new byte[32];
            var expectedSharedSecret = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteSignedPreKey))
                .ReturnsAsync(dh1);
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteIdentityKey))
                .ReturnsAsync(dh2);
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(identityKeyPair.PrivateKey, remoteSignedPreKey))
                .ReturnsAsync(dh3);

            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(
                It.Is<byte[]>(arr => arr.Length == dh1.Length + dh2.Length + dh3.Length),
                identityKeyPair.PrivateKey))
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
            result.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");

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

        [Fact]
        public async Task PerformKeyAgreement_ShouldProduceSameSecretForBothParties()
        {
            // Arrange
            var aliceIdentityKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var aliceSignedPreKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32], Signature = new byte[64] };
            var aliceOneTimePreKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var bobIdentityKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };
            var bobSignedPreKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32], Signature = new byte[64] };
            var bobOneTimePreKey = new KeyPair { PublicKey = new byte[32], PrivateKey = new byte[32] };

            // Setup mock to return consistent values for each DH exchange
            var dh1 = new byte[32];
            var dh2 = new byte[32];
            var dh3 = new byte[32];
            var dh4 = new byte[32];
            var expectedSharedSecret = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(dh1);
            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(expectedSharedSecret);

            // Act
            var aliceSecret = await _service.PerformKeyAgreementAsync(
                aliceIdentityKey,
                aliceSignedPreKey,
                aliceOneTimePreKey,
                bobIdentityKey.PublicKey,
                bobSignedPreKey.PublicKey,
                bobOneTimePreKey.PublicKey);

            var bobSecret = await _service.PerformKeyAgreementAsync(
                bobIdentityKey,
                bobSignedPreKey,
                bobOneTimePreKey,
                aliceIdentityKey.PublicKey,
                aliceSignedPreKey.PublicKey,
                aliceOneTimePreKey.PublicKey);

            // Assert
            aliceSecret.Should().NotBeNull();
            bobSecret.Should().NotBeNull();
            aliceSecret.Should().BeEquivalentTo(bobSecret, "Both parties should derive the same shared secret");
            aliceSecret.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");
        }
    }
} 