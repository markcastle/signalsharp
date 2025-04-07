using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;

namespace SignalSharp.Tests.Security;

/// <summary>
/// Test suite for the X3DHKeyAgreementService which implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
/// </summary>
/// <remarks>
/// These tests verify that the X3DH implementation correctly:
/// - Generates the various cryptographic key pairs required by the protocol
/// - Performs the multi-stage key agreement process
/// - Correctly computes shared secrets from multiple Diffie-Hellman exchanges
/// - Validates inputs properly with appropriate exceptions
/// 
/// The X3DH protocol is a critical security component of the Signal protocol that provides
/// strong authentication and establishes initial shared secrets between parties who
/// may not be online at the same time. It's the foundation for the double ratchet algorithm.
/// </remarks>
public class X3DhKeyAgreementServiceTests
{
    /// <summary>
    /// Mock of the elliptic curve key exchange service used for cryptographic operations.
    /// </summary>
    private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;

    /// <summary>
    /// Mock of the hash service used for key derivation and combining DH outputs.
    /// </summary>
    private readonly Mock<IHashService> _hashServiceMock;

    /// <summary>
    /// The X3DHKeyAgreementService instance being tested.
    /// </summary>
    private readonly X3DHKeyAgreementService _service;

    /// <summary>
    /// Initializes a new instance of the X3DhKeyAgreementServiceTests class.
    /// Sets up all the required mock dependencies and creates the X3DHKeyAgreementService for testing.
    /// </summary>
    public X3DhKeyAgreementServiceTests()
    {
        _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
        _hashServiceMock = new Mock<IHashService>();
        _service = new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, _hashServiceMock.Object);
    }

    /// <summary>
    /// Tests that the constructor properly validates the key exchange service parameter.
    /// </summary>
    /// <remarks>
    /// This test verifies proper dependency validation:
    /// - The service should reject null dependencies with an ArgumentNullException
    /// 
    /// This ensures that the X3DH service cannot be instantiated without its required
    /// cryptographic services, which would lead to runtime errors during operation.
    /// </remarks>
    [Fact]
    public void Constructor_WithNullKeyExchangeService_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new X3DHKeyAgreementService(null!, _hashServiceMock.Object));
    }

    /// <summary>
    /// Tests that the constructor properly validates the hash service parameter.
    /// </summary>
    /// <remarks>
    /// This test verifies proper dependency validation:
    /// - The service should reject null dependencies with an ArgumentNullException
    /// 
    /// The hash service is essential for the X3DH protocol to derive the final shared
    /// secret from multiple Diffie-Hellman exchanges.
    /// </remarks>
    [Fact]
    public void Constructor_WithNullHashService_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new X3DHKeyAgreementService(_keyExchangeServiceMock.Object, null!));
    }

    /// <summary>
    /// Tests that identity key pair generation returns a valid key pair.
    /// </summary>
    /// <remarks>
    /// This test verifies that:
    /// 1. The identity key pair is correctly generated
    /// 2. The result contains both public and private key components
    /// 
    /// The identity key pair is a long-term key that represents a user's persistent
    /// cryptographic identity in the Signal protocol. It's used for authentication
    /// and to sign other keys, establishing a chain of trust.
    /// </remarks>
    [Fact]
    public async Task GenerateIdentityKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        (byte[]? publicKey, byte[]? privateKey) = (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));

        // Act
        KeyPair result = await _service.GenerateIdentityKeyPairAsync();

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
    }

    /// <summary>
    /// Tests that a signed pre-key pair can be generated with a valid identity key pair.
    /// </summary>
    /// <remarks>
    /// This test verifies that:
    /// 1. The signed pre-key pair is correctly generated
    /// 2. The pre-key is properly signed with the identity private key
    /// 
    /// Signed pre-keys are medium-term keys that are signed by the identity key to prove
    /// authenticity. They allow the initiator to authenticate the recipient's pre-key
    /// bundle before establishing communication. The signature ensures that the pre-key
    /// actually belongs to the claimed identity.
    /// </remarks>
    [Fact]
    public async Task GenerateSignedPreKeyPair_WithValidIdentityKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        KeyPair identityKeyPair = new(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        (byte[]? publicKey, byte[]? privateKey) = (new byte[] { 7, 8, 9 }, new byte[] { 10, 11, 12 });
        byte[] signature = { 13, 14, 15 };

        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));
        _keyExchangeServiceMock.Setup(x => x.SignAsync(identityKeyPair.PrivateKey, publicKey))
            .ReturnsAsync(signature);

        // Act
        KeyPair result = await _service.GenerateSignedPreKeyPairAsync(identityKeyPair);

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
        _keyExchangeServiceMock.Verify(x => x.SignAsync(identityKeyPair.PrivateKey, publicKey), Times.Once);
    }

    /// <summary>
    /// Tests that a one-time pre-key pair can be generated.
    /// </summary>
    /// <remarks>
    /// This test verifies that:
    /// 1. The one-time pre-key pair is correctly generated
    /// 2. The result contains both public and private key components
    /// 
    /// One-time pre-keys are ephemeral keys used only once for initial key agreement.
    /// They provide additional security by ensuring that each session uses unique
    /// key material, even if the same identity and signed pre-keys are reused.
    /// This helps prevent replay attacks and provides forward secrecy.
    /// </remarks>
    [Fact]
    public async Task GenerateOneTimePreKeyPair_ReturnsValidKeyPair()
    {
        // Arrange
        (byte[]? publicKey, byte[]? privateKey) = (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });
        _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
            .ReturnsAsync((publicKey, privateKey));

        // Act
        KeyPair result = await _service.GenerateOneTimePreKeyPairAsync();

        // Assert
        Assert.Equal(publicKey, result.PublicKey);
        Assert.Equal(privateKey, result.PrivateKey);
        _keyExchangeServiceMock.Verify(x => x.GenerateKeyPairAsync(), Times.Once);
    }

    /// <summary>
    /// Tests that the key agreement method properly validates input parameters.
    /// </summary>
    /// <remarks>
    /// This test verifies input validation for the X3DH protocol:
    /// - Each required key parameter should be non-null
    /// - The method should throw an InvalidOperationException for any null key
    /// 
    /// Proper validation is critical for security, as attempting to perform the
    /// X3DH protocol with missing keys would result in cryptographically insecure
    /// or incomplete key agreement.
    /// </remarks>
    [Fact]
    public async Task PerformKeyAgreement_WithNullParameters_ThrowsInvalidOperationException()
    {
        // Arrange
        byte[] initiatorIdentityKey = { 1, 2, 3 };
        byte[] initiatorEphemeralKey = { 4, 5, 6 };
        byte[] recipientIdentityKey = { 7, 8, 9 };
        byte[] recipientSignedPreKey = { 10, 11, 12 };
        // ReSharper disable once UnusedVariable
        byte[] recipientOneTimePreKey = { 13, 14, 15 };

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

    /// <summary>
    /// Tests that the X3DH key agreement process correctly computes a shared secret.
    /// </summary>
    /// <remarks>
    /// This test verifies the core X3DH protocol implementation:
    /// 1. All four Diffie-Hellman exchanges are performed correctly
    /// 2. The resulting shared secrets (DH1-DH4) are combined properly
    /// 3. A final shared secret is derived using a key derivation function
    /// 
    /// The X3DH protocol combines multiple Diffie-Hellman exchanges to provide strong
    /// security properties:
    /// - DH1: Initiator identity key + Recipient signed pre-key
    /// - DH2: Initiator ephemeral key + Recipient identity key
    /// - DH3: Initiator ephemeral key + Recipient signed pre-key
    /// - DH4: Initiator ephemeral key + Recipient one-time pre-key
    /// 
    /// These multiple exchanges ensure that the security of the protocol does not
    /// rely on a single key pair, providing authentication of both parties and
    /// forward secrecy properties.
    /// </remarks>
    [Fact]
    public async Task PerformKeyAgreement_ReturnsValidSharedSecret()
    {
        // Arrange
        byte[] initiatorIdentityKey = { 1, 2, 3 };
        byte[] initiatorEphemeralKey = { 4, 5, 6 };
        byte[] recipientIdentityKey = { 7, 8, 9 };
        byte[] recipientSignedPreKey = { 10, 11, 12 };
        byte[] recipientOneTimePreKey = { 13, 14, 15 };

        byte[] dh1 = { 16, 17, 18 };
        byte[] dh2 = { 19, 20, 21 };
        byte[] dh3 = { 22, 23, 24 };
        byte[] dh4 = { 25, 26, 27 };
        byte[] expectedSecret = { 28, 29, 30 };

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
        byte[] result = await _service.PerformKeyAgreementAsync(
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