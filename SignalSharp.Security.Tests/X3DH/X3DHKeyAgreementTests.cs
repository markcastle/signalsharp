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
    /// Test suite for the X3DHKeyAgreementService which implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
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
        public async Task GenerateIdentityKeyPair_ReturnsValidKeyPair()
        {
            // Arrange
            var publicKeyX = new byte[32];
            var publicKeyY = new byte[32];
            var privateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                publicKeyX[i] = (byte)i;
                publicKeyY[i] = (byte)(i + 32);
                privateKey[i] = (byte)(i + 64);
            }
            var publicKey = publicKeyX.Concat(publicKeyY).ToArray();

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((publicKey, privateKey));

            // Act
            var result = await _service.GenerateIdentityKeyPairAsync();

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(publicKey);
            result.PrivateKey.Should().BeEquivalentTo(privateKey);
            result.PublicKey.Length.Should().Be(64);
            result.PrivateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_WithValidIdentityKeyPair_ReturnsValidKeyPair()
        {
            // Arrange
            var identityPublicKeyX = new byte[32];
            var identityPublicKeyY = new byte[32];
            var identityPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                identityPublicKeyX[i] = (byte)i;
                identityPublicKeyY[i] = (byte)(i + 32);
                identityPrivateKey[i] = (byte)(i + 64);
            }
            var identityPublicKey = identityPublicKeyX.Concat(identityPublicKeyY).ToArray();
            var identityKeyPair = new KeyPair(identityPublicKey, identityPrivateKey);

            var publicKeyX = new byte[32];
            var publicKeyY = new byte[32];
            var privateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                publicKeyX[i] = (byte)(i + 96);
                publicKeyY[i] = (byte)(i + 128);
                privateKey[i] = (byte)(i + 160);
            }
            var publicKey = publicKeyX.Concat(publicKeyY).ToArray();
            var signature = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                signature[i] = (byte)(i + 192);
            }

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((publicKey, privateKey));
            _keyExchangeServiceMock.Setup(x => x.SignAsync(identityKeyPair.PrivateKey, publicKey))
                .ReturnsAsync(signature);

            // Act
            var result = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(publicKey);
            result.PrivateKey.Should().BeEquivalentTo(privateKey);
            result.PublicKey.Length.Should().Be(64);
            result.PrivateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldFollowX3DHSpecification()
        {
            // Arrange
            var aliceIdentityPrivateKey = new byte[32];
            var aliceIdentityPublicKeyX = new byte[32];
            var aliceIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPrivateKey[i] = (byte)i;
                aliceIdentityPublicKeyX[i] = (byte)(i + 32);
                aliceIdentityPublicKeyY[i] = (byte)(i + 64);
            }
            var aliceIdentityPublicKey = aliceIdentityPublicKeyX.Concat(aliceIdentityPublicKeyY).ToArray();

            var aliceEphemeralPrivateKey = new byte[32];
            var aliceEphemeralPublicKeyX = new byte[32];
            var aliceEphemeralPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceEphemeralPrivateKey[i] = (byte)(i + 96);
                aliceEphemeralPublicKeyX[i] = (byte)(i + 128);
                aliceEphemeralPublicKeyY[i] = (byte)(i + 160);
            }
            var aliceEphemeralPublicKey = aliceEphemeralPublicKeyX.Concat(aliceEphemeralPublicKeyY).ToArray();

            var bobIdentityPrivateKey = new byte[32];
            var bobIdentityPublicKeyX = new byte[32];
            var bobIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobIdentityPrivateKey[i] = (byte)(i + 192);
                bobIdentityPublicKeyX[i] = (byte)(i + 224);
                bobIdentityPublicKeyY[i] = (byte)(i + 256);
            }
            var bobIdentityPublicKey = bobIdentityPublicKeyX.Concat(bobIdentityPublicKeyY).ToArray();

            var bobSignedPreKeyPrivateKey = new byte[32];
            var bobSignedPreKeyPublicKeyX = new byte[32];
            var bobSignedPreKeyPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobSignedPreKeyPrivateKey[i] = (byte)(i + 288);
                bobSignedPreKeyPublicKeyX[i] = (byte)(i + 320);
                bobSignedPreKeyPublicKeyY[i] = (byte)(i + 352);
            }
            var bobSignedPreKeyPublicKey = bobSignedPreKeyPublicKeyX.Concat(bobSignedPreKeyPublicKeyY).ToArray();

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.Is<int>(l => l == 32),
                It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            // Act
            var sharedSecret = await _service.PerformKeyAgreementAsync(
                aliceIdentityPrivateKey,
                aliceEphemeralPrivateKey,
                bobIdentityPublicKey,
                bobSignedPreKeyPublicKey,
                null);

            // Assert
            sharedSecret.Should().NotBeNull();
            sharedSecret.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Exactly(3));
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldHandleMissingOneTimePreKey()
        {
            // Arrange
            var aliceIdentityPrivateKey = new byte[32];
            var aliceIdentityPublicKeyX = new byte[32];
            var aliceIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPrivateKey[i] = (byte)i;
                aliceIdentityPublicKeyX[i] = (byte)(i + 32);
                aliceIdentityPublicKeyY[i] = (byte)(i + 64);
            }
            var aliceIdentityPublicKey = aliceIdentityPublicKeyX.Concat(aliceIdentityPublicKeyY).ToArray();

            var aliceEphemeralPrivateKey = new byte[32];
            var aliceEphemeralPublicKeyX = new byte[32];
            var aliceEphemeralPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceEphemeralPrivateKey[i] = (byte)(i + 96);
                aliceEphemeralPublicKeyX[i] = (byte)(i + 128);
                aliceEphemeralPublicKeyY[i] = (byte)(i + 160);
            }
            var aliceEphemeralPublicKey = aliceEphemeralPublicKeyX.Concat(aliceEphemeralPublicKeyY).ToArray();

            var bobIdentityPrivateKey = new byte[32];
            var bobIdentityPublicKeyX = new byte[32];
            var bobIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobIdentityPrivateKey[i] = (byte)(i + 192);
                bobIdentityPublicKeyX[i] = (byte)(i + 224);
                bobIdentityPublicKeyY[i] = (byte)(i + 256);
            }
            var bobIdentityPublicKey = bobIdentityPublicKeyX.Concat(bobIdentityPublicKeyY).ToArray();

            var bobSignedPreKeyPrivateKey = new byte[32];
            var bobSignedPreKeyPublicKeyX = new byte[32];
            var bobSignedPreKeyPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobSignedPreKeyPrivateKey[i] = (byte)(i + 288);
                bobSignedPreKeyPublicKeyX[i] = (byte)(i + 320);
                bobSignedPreKeyPublicKeyY[i] = (byte)(i + 352);
            }
            var bobSignedPreKeyPublicKey = bobSignedPreKeyPublicKeyX.Concat(bobSignedPreKeyPublicKeyY).ToArray();

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.Is<int>(l => l == 32),
                It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            // Act
            var sharedSecret = await _service.PerformKeyAgreementAsync(
                aliceIdentityPrivateKey,
                aliceEphemeralPrivateKey,
                bobIdentityPublicKey,
                bobSignedPreKeyPublicKey,
                null);

            // Assert
            sharedSecret.Should().NotBeNull();
            sharedSecret.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Exactly(3));
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldValidateKeyLengths()
        {
            // Arrange
            var invalidPrivateKey = new byte[31];
            var invalidPublicKeyX = new byte[31];
            var invalidPublicKeyY = new byte[31];
            var invalidPublicKey = invalidPublicKeyX.Concat(invalidPublicKeyY).ToArray();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.PerformKeyAgreementAsync(
                    invalidPrivateKey,
                    invalidPrivateKey,
                    invalidPublicKey,
                    invalidPublicKey,
                    null));
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldProduceSameSecretForBothParties()
        {
            // Arrange
            var aliceIdentityPrivateKey = new byte[32];
            var aliceIdentityPublicKeyX = new byte[32];
            var aliceIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPrivateKey[i] = (byte)i;
                aliceIdentityPublicKeyX[i] = (byte)(i + 32);
                aliceIdentityPublicKeyY[i] = (byte)(i + 64);
            }
            var aliceIdentityPublicKey = aliceIdentityPublicKeyX.Concat(aliceIdentityPublicKeyY).ToArray();

            var aliceEphemeralPrivateKey = new byte[32];
            var aliceEphemeralPublicKeyX = new byte[32];
            var aliceEphemeralPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceEphemeralPrivateKey[i] = (byte)(i + 96);
                aliceEphemeralPublicKeyX[i] = (byte)(i + 128);
                aliceEphemeralPublicKeyY[i] = (byte)(i + 160);
            }
            var aliceEphemeralPublicKey = aliceEphemeralPublicKeyX.Concat(aliceEphemeralPublicKeyY).ToArray();

            var bobIdentityPrivateKey = new byte[32];
            var bobIdentityPublicKeyX = new byte[32];
            var bobIdentityPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobIdentityPrivateKey[i] = (byte)(i + 192);
                bobIdentityPublicKeyX[i] = (byte)(i + 224);
                bobIdentityPublicKeyY[i] = (byte)(i + 256);
            }
            var bobIdentityPublicKey = bobIdentityPublicKeyX.Concat(bobIdentityPublicKeyY).ToArray();

            var bobSignedPreKeyPrivateKey = new byte[32];
            var bobSignedPreKeyPublicKeyX = new byte[32];
            var bobSignedPreKeyPublicKeyY = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobSignedPreKeyPrivateKey[i] = (byte)(i + 288);
                bobSignedPreKeyPublicKeyX[i] = (byte)(i + 320);
                bobSignedPreKeyPublicKeyY[i] = (byte)(i + 352);
            }
            var bobSignedPreKeyPublicKey = bobSignedPreKeyPublicKeyX.Concat(bobSignedPreKeyPublicKeyY).ToArray();

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.Is<int>(l => l == 32),
                It.IsAny<byte[]>()))
                .ReturnsAsync(new byte[32]);

            // Act
            var aliceSharedSecret = await _service.PerformKeyAgreementAsync(
                aliceIdentityPrivateKey,
                aliceEphemeralPrivateKey,
                bobIdentityPublicKey,
                bobSignedPreKeyPublicKey,
                null);

            var bobSharedSecret = await _service.PerformKeyAgreementAsync(
                bobIdentityPrivateKey,
                bobSignedPreKeyPrivateKey,
                aliceIdentityPublicKey,
                aliceEphemeralPublicKey,
                null);

            // Assert
            aliceSharedSecret.Should().NotBeNull();
            bobSharedSecret.Should().NotBeNull();
            aliceSharedSecret.Should().BeEquivalentTo(bobSharedSecret, "Both parties should derive the same shared secret");
        }
    }
} 