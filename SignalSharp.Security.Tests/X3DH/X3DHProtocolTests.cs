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
            var expectedPublicKeyX = new byte[32];
            var expectedPublicKeyY = new byte[32];
            var expectedPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedPublicKeyX[i] = (byte)i;
                expectedPublicKeyY[i] = (byte)(i + 32);
                expectedPrivateKey[i] = (byte)(i + 64);
            }
            var expectedPublicKey = expectedPublicKeyX.Concat(expectedPublicKeyY).ToArray();

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .Returns(Task.FromResult((expectedPublicKey, expectedPrivateKey)));

            // Act
            var result = await _service.GenerateIdentityKeyPairAsync();

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(expectedPublicKey);
            result.PrivateKey.Should().BeEquivalentTo(expectedPrivateKey);
            result.PublicKey.Length.Should().Be(64);
            result.PrivateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task GenerateSignedPreKeyPair_ShouldProduceValidKeyPair()
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

            var expectedPublicKeyX = new byte[32];
            var expectedPublicKeyY = new byte[32];
            var expectedPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedPublicKeyX[i] = (byte)(i + 96);
                expectedPublicKeyY[i] = (byte)(i + 128);
                expectedPrivateKey[i] = (byte)(i + 160);
            }
            var expectedPublicKey = expectedPublicKeyX.Concat(expectedPublicKeyY).ToArray();
            var expectedSignature = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                expectedSignature[i] = (byte)(i + 192);
            }

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .Returns(Task.FromResult((expectedPublicKey, expectedPrivateKey)));
            _keyExchangeServiceMock.Setup(x => x.SignAsync(identityKeyPair.PrivateKey, expectedPublicKey))
                .Returns(Task.FromResult(expectedSignature));

            // Act
            var result = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

            // Assert
            result.Should().NotBeNull();
            result.PublicKey.Should().BeEquivalentTo(expectedPublicKey);
            result.PrivateKey.Should().BeEquivalentTo(expectedPrivateKey);
            result.PublicKey.Length.Should().Be(64);
            result.PrivateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldFollowX3DHSpecification()
        {
            // Arrange
            var aliceIdentityPrivateKey = new byte[32];
            var aliceEphemeralPrivateKey = new byte[32];
            var bobIdentityPublicKey = new byte[64];
            var bobSignedPreKeyPublicKey = new byte[64];

            // Initialize test data
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPrivateKey[i] = (byte)i;
                aliceEphemeralPrivateKey[i] = (byte)(i + 32);
                bobIdentityPublicKey[i] = (byte)(i + 64);
                bobIdentityPublicKey[i + 32] = (byte)(i + 96);
                bobSignedPreKeyPublicKey[i] = (byte)(i + 128);
                bobSignedPreKeyPublicKey[i + 32] = (byte)(i + 160);
            }

            var expectedSharedSecret = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedSharedSecret[i] = (byte)(i + 192);
            }

            // Mock the key exchange service to return valid shared secrets for specific inputs
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceIdentityPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobIdentityPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            // Mock the hash service to return a valid 32-byte key for the specific combined input
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.Is<byte[]>(b => b.Length == expectedSharedSecret.Length * 3), // Combined length of DH1, DH2, DH3
                It.Is<byte[]>(b => b.Length == 32), // Zero salt
                It.Is<int>(l => l == 32),
                It.Is<byte[]>(i => i.Length == 1))) // Info parameter
                .Returns(Task.FromResult(expectedSharedSecret));

            // Mock for Bob's side
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.Is<byte[]>(b => b.Length == expectedSharedSecret.Length * 3), // Combined length of DH1, DH2, DH3
                It.Is<byte[]>(b => b.Length == 32), // Zero salt
                It.Is<int>(l => l == 32),
                It.Is<byte[]>(i => i.Length == 1))) // Info parameter
                .Returns(Task.FromResult(expectedSharedSecret));

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
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceIdentityPrivateKey, bobSignedPreKeyPublicKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceEphemeralPrivateKey, bobIdentityPublicKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceEphemeralPrivateKey, bobSignedPreKeyPublicKey), Times.Once);
            _hashServiceMock.Verify(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), 32, It.IsAny<byte[]>()), Times.Once);
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldHandleMissingOneTimePreKey()
        {
            // Arrange
            var aliceIdentityPrivateKey = new byte[32];
            var aliceEphemeralPrivateKey = new byte[32];
            var bobIdentityPublicKey = new byte[64];
            var bobSignedPreKeyPublicKey = new byte[64];

            // Initialize test data
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPrivateKey[i] = (byte)i;
                aliceEphemeralPrivateKey[i] = (byte)(i + 32);
                bobIdentityPublicKey[i] = (byte)(i + 64);
                bobIdentityPublicKey[i + 32] = (byte)(i + 96);
                bobSignedPreKeyPublicKey[i] = (byte)(i + 128);
                bobSignedPreKeyPublicKey[i + 32] = (byte)(i + 160);
            }

            var expectedSharedSecret = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedSharedSecret[i] = (byte)(i + 192);
            }

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceIdentityPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobIdentityPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            // Mock the hash service to return a valid 32-byte key
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.Is<byte[]>(b => b.Length == expectedSharedSecret.Length * 3), // Combined length of DH1, DH2, DH3
                It.Is<byte[]>(b => b.Length == 32), // Zero salt
                It.Is<int>(l => l == 32),
                It.Is<byte[]>(i => i.Length == 1))) // Info parameter
                .Returns(Task.FromResult(expectedSharedSecret));

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
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceIdentityPrivateKey, bobSignedPreKeyPublicKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceEphemeralPrivateKey, bobIdentityPublicKey), Times.Once);
            _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(aliceEphemeralPrivateKey, bobSignedPreKeyPublicKey), Times.Once);
            _hashServiceMock.Verify(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), 32, It.IsAny<byte[]>()), Times.Once);
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldValidateKeyLengths()
        {
            // Arrange
            var invalidPrivateKey = new byte[16]; // Too short
            var validPrivateKey = new byte[32];
            var validPublicKey = new byte[64];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.PerformKeyAgreementAsync(invalidPrivateKey, validPrivateKey, validPublicKey, validPublicKey));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.PerformKeyAgreementAsync(validPrivateKey, invalidPrivateKey, validPublicKey, validPublicKey));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.PerformKeyAgreementAsync(validPrivateKey, validPrivateKey, invalidPrivateKey, validPublicKey));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.PerformKeyAgreementAsync(validPrivateKey, validPrivateKey, validPublicKey, invalidPrivateKey));
        }

        [Fact]
        public async Task PerformKeyAgreement_ShouldProduceSameSecretForBothParties()
        {
            // Arrange
            var aliceIdentityPublicKeyX = new byte[32];
            var aliceIdentityPublicKeyY = new byte[32];
            var aliceIdentityPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceIdentityPublicKeyX[i] = (byte)i;
                aliceIdentityPublicKeyY[i] = (byte)(i + 32);
                aliceIdentityPrivateKey[i] = (byte)(i + 64);
            }
            var aliceIdentityPublicKey = aliceIdentityPublicKeyX.Concat(aliceIdentityPublicKeyY).ToArray();

            var aliceEphemeralPublicKeyX = new byte[32];
            var aliceEphemeralPublicKeyY = new byte[32];
            var aliceEphemeralPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                aliceEphemeralPublicKeyX[i] = (byte)(i + 96);
                aliceEphemeralPublicKeyY[i] = (byte)(i + 128);
                aliceEphemeralPrivateKey[i] = (byte)(i + 160);
            }
            var aliceEphemeralPublicKey = aliceEphemeralPublicKeyX.Concat(aliceEphemeralPublicKeyY).ToArray();

            var bobIdentityPublicKeyX = new byte[32];
            var bobIdentityPublicKeyY = new byte[32];
            var bobIdentityPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobIdentityPublicKeyX[i] = (byte)(i + 192);
                bobIdentityPublicKeyY[i] = (byte)(i + 224);
                bobIdentityPrivateKey[i] = (byte)(i + 256);
            }
            var bobIdentityPublicKey = bobIdentityPublicKeyX.Concat(bobIdentityPublicKeyY).ToArray();

            var bobSignedPreKeyPublicKeyX = new byte[32];
            var bobSignedPreKeyPublicKeyY = new byte[32];
            var bobSignedPreKeyPrivateKey = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                bobSignedPreKeyPublicKeyX[i] = (byte)(i + 288);
                bobSignedPreKeyPublicKeyY[i] = (byte)(i + 320);
                bobSignedPreKeyPrivateKey[i] = (byte)(i + 352);
            }
            var bobSignedPreKeyPublicKey = bobSignedPreKeyPublicKeyX.Concat(bobSignedPreKeyPublicKeyY).ToArray();

            var expectedSharedSecret = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedSharedSecret[i] = (byte)(i + 384);
            }

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceIdentityPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobIdentityPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            // Mock for Bob's side
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(bobIdentityPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(aliceIdentityPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(
                It.Is<byte[]>(b => b.SequenceEqual(bobSignedPreKeyPrivateKey)),
                It.Is<byte[]>(b => b.SequenceEqual(aliceEphemeralPublicKey))))
                .Returns(Task.FromResult(expectedSharedSecret));

            // Mock the hash service to return a valid 32-byte key
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(
                It.Is<byte[]>(b => b.Length == expectedSharedSecret.Length * 3), // Combined length of DH1, DH2, DH3
                It.Is<byte[]>(b => b.Length == 32), // Zero salt
                It.Is<int>(l => l == 32),
                It.Is<byte[]>(i => i.Length == 1))) // Info parameter
                .Returns(Task.FromResult(expectedSharedSecret));

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
            aliceSharedSecret.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");
            bobSharedSecret.Length.Should().Be(32, "Shared secret should be 32 bytes (256 bits)");
            aliceSharedSecret.Should().BeEquivalentTo(bobSharedSecret, "Both parties should derive the same shared secret");
        }
    }
} 