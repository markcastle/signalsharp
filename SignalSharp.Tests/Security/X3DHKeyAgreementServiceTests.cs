using System;
using System.Threading.Tasks;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Tests.Security;

public class X3DHKeyAgreementServiceTests
{
    private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
    private readonly Mock<IHashService> _hashServiceMock;
    private readonly X3DHKeyAgreementService _service;

    public X3DHKeyAgreementServiceTests()
    {
        _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
        _hashServiceMock = new Mock<IHashService>();
        _service = new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, _hashServiceMock.Object);
    }

    [Fact]
    public void Constructor_WithNullKeyExchangeService_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new X3DHKeyAgreementService(null!, _hashServiceMock.Object));
    }

    [Fact]
    public void Constructor_WithNullHashService_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, null!));
    }

    [Fact]
    public async Task GenerateIdentityKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        var (publicKey, privateKey) = (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));

        // Act
        var result = await _service.GenerateIdentityKeyPairAsync();

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
    }

    [Fact]
    public async Task GenerateSignedPreKeyPair_WithValidIdentityKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        var identityKeyPair = new KeyPair(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        var (publicKey, privateKey) = (new byte[] { 7, 8, 9 }, new byte[] { 10, 11, 12 });
        var signature = new byte[] { 13, 14, 15 };

        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));
        _keyExchangeServiceMock.Setup(x => x.SignAsync(identityKeyPair.PrivateKey, publicKey))
            .ReturnsAsync(signature);

        // Act
        var result = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
        _keyExchangeServiceMock.Verify(x => x.SignAsync(identityKeyPair.PrivateKey, publicKey), Times.Once);
    }

    [Fact]
    public async Task GenerateOneTimePreKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        var (publicKey, privateKey) = (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));

        // Act
        var result = await _service.GenerateOneTimePreKeyPairAsync();

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
    }

    [Fact]
    public async Task PerformKeyAgreement_WithNullParameters_ThrowsInvalidOperationException()
    {
        // Arrange
        var initiatorIdentityKey = new byte[] { 1, 2, 3 };
        var initiatorEphemeralKey = new byte[] { 4, 5, 6 };
        var recipientIdentityKey = new byte[] { 7, 8, 9 };
        var recipientSignedPreKey = new byte[] { 10, 11, 12 };
        var recipientOneTimePreKey = new byte[] { 13, 14, 15 };

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.PerformKeyAgreementAsync(null!, initiatorEphemeralKey, recipientIdentityKey, recipientSignedPreKey));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.PerformKeyAgreementAsync(initiatorIdentityKey, null!, recipientIdentityKey, recipientSignedPreKey));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.PerformKeyAgreementAsync(initiatorIdentityKey, initiatorEphemeralKey, null!, recipientSignedPreKey));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.PerformKeyAgreementAsync(initiatorIdentityKey, initiatorEphemeralKey, recipientIdentityKey, null!));
    }

    [Fact]
    public async Task PerformKeyAgreement_ReturnsValidSharedSecret()
    {
        // Arrange
        var initiatorIdentityKey = new byte[] { 1, 2, 3 };
        var initiatorEphemeralKey = new byte[] { 4, 5, 6 };
        var recipientIdentityKey = new byte[] { 7, 8, 9 };
        var recipientSignedPreKey = new byte[] { 10, 11, 12 };
        var recipientOneTimePreKey = new byte[] { 13, 14, 15 };

        var dh1 = new byte[] { 16, 17, 18 };
        var dh2 = new byte[] { 19, 20, 21 };
        var dh3 = new byte[] { 22, 23, 24 };
        var dh4 = new byte[] { 25, 26, 27 };
        var expectedSecret = new byte[] { 28, 29, 30 };

        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey))
            .ReturnsAsync(dh1);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey))
            .ReturnsAsync(dh2);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey))
            .ReturnsAsync(dh3);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey))
            .ReturnsAsync(dh4);
        _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(
                It.Is<byte[]>(arr => arr.Length == dh1.Length + dh2.Length + dh3.Length + dh4.Length),
                initiatorIdentityKey))
            .ReturnsAsync(expectedSecret);

        // Act
        var result = await _service.PerformKeyAgreementAsync(
            initiatorIdentityKey,
            initiatorEphemeralKey,
            recipientIdentityKey,
            recipientSignedPreKey,
            recipientOneTimePreKey);

        // Assert
        Assert.Equal(expectedSecret, result);
        _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey), Times.Once);
        _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey), Times.Once);
        _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey), Times.Once);
        _keyExchangeServiceMock.Verify(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey), Times.Once);
        _hashServiceMock.Verify(x => x.ComputeKeyedHashAsync(
            It.Is<byte[]>(arr => arr.Length == dh1.Length + dh2.Length + dh3.Length + dh4.Length),
            initiatorIdentityKey), Times.Once);
    }
} 