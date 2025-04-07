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
        var publicKey = new byte[64]; // 64-byte public key
        var privateKey = new byte[32]; // 32-byte private key
        for (int i = 0; i < publicKey.Length; i++) publicKey[i] = (byte)i;
        for (int i = 0; i < privateKey.Length; i++) privateKey[i] = (byte)(i + 100);

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
        var identityPublicKey = new byte[64];
        var identityPrivateKey = new byte[32];
        var publicKey = new byte[64];
        var privateKey = new byte[32];
        var signature = new byte[64]; // Typical ECDSA signature length

        for (int i = 0; i < identityPublicKey.Length; i++) identityPublicKey[i] = (byte)i;
        for (int i = 0; i < identityPrivateKey.Length; i++) identityPrivateKey[i] = (byte)(i + 100);
        for (int i = 0; i < publicKey.Length; i++) publicKey[i] = (byte)(i + 150);
        for (int i = 0; i < privateKey.Length; i++) privateKey[i] = (byte)(i + 200);
        for (int i = 0; i < signature.Length; i++) signature[i] = (byte)(i + 250);

        KeyPair identityKeyPair = new(identityPublicKey, identityPrivateKey);

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
        var publicKey = new byte[64];
        var privateKey = new byte[32];
        for (int i = 0; i < publicKey.Length; i++) publicKey[i] = (byte)i;
        for (int i = 0; i < privateKey.Length; i++) privateKey[i] = (byte)(i + 100);

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
        var initiatorIdentityKey = new byte[32];
        var initiatorEphemeralKey = new byte[32];
        var recipientIdentityKey = new byte[64];
        var recipientSignedPreKey = new byte[64];
        var recipientOneTimePreKey = new byte[64];

        for (int i = 0; i < initiatorIdentityKey.Length; i++) initiatorIdentityKey[i] = (byte)i;
        for (int i = 0; i < initiatorEphemeralKey.Length; i++) initiatorEphemeralKey[i] = (byte)(i + 50);
        for (int i = 0; i < recipientIdentityKey.Length; i++) recipientIdentityKey[i] = (byte)(i + 100);
        for (int i = 0; i < recipientSignedPreKey.Length; i++) recipientSignedPreKey[i] = (byte)(i + 150);
        for (int i = 0; i < recipientOneTimePreKey.Length; i++) recipientOneTimePreKey[i] = (byte)(i + 200);

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
        var initiatorIdentityKey = new byte[32];
        var initiatorEphemeralKey = new byte[32];
        var recipientIdentityKey = new byte[64];
        var recipientSignedPreKey = new byte[64];
        var recipientOneTimePreKey = new byte[64];

        for (int i = 0; i < initiatorIdentityKey.Length; i++) initiatorIdentityKey[i] = (byte)i;
        for (int i = 0; i < initiatorEphemeralKey.Length; i++) initiatorEphemeralKey[i] = (byte)(i + 50);
        for (int i = 0; i < recipientIdentityKey.Length; i++) recipientIdentityKey[i] = (byte)(i + 100);
        for (int i = 0; i < recipientSignedPreKey.Length; i++) recipientSignedPreKey[i] = (byte)(i + 150);
        for (int i = 0; i < recipientOneTimePreKey.Length; i++) recipientOneTimePreKey[i] = (byte)(i + 200);

        var dh1 = new byte[32];
        var dh2 = new byte[32];
        var dh3 = new byte[32];
        var dh4 = new byte[32];
        var expectedSecret = new byte[32];

        for (int i = 0; i < 32; i++)
        {
            dh1[i] = (byte)(i + 1);
            dh2[i] = (byte)(i + 2);
            dh3[i] = (byte)(i + 3);
            dh4[i] = (byte)(i + 4);
            expectedSecret[i] = (byte)(i + 5);
        }

        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey))
            .ReturnsAsync(dh1);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey))
            .ReturnsAsync(dh2);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey))
            .ReturnsAsync(dh3);
        _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey))
            .ReturnsAsync(dh4);

        var combinedDh = new byte[dh1.Length + dh2.Length + dh3.Length + dh4.Length];
        Buffer.BlockCopy(dh1, 0, combinedDh, 0, dh1.Length);
        Buffer.BlockCopy(dh2, 0, combinedDh, dh1.Length, dh2.Length);
        Buffer.BlockCopy(dh3, 0, combinedDh, dh1.Length + dh2.Length, dh3.Length);
        Buffer.BlockCopy(dh4, 0, combinedDh, dh1.Length + dh2.Length + dh3.Length, dh4.Length);

        _hashServiceMock.Setup(x => x.DeriveKeyAsync(
            It.Is<byte[]>(b => b.Length == dh1.Length + dh2.Length + dh3.Length + dh4.Length),
            It.Is<byte[]>(b => b.Length == 32), // Zero salt
            It.Is<int>(l => l == 32),
            It.Is<byte[]>(i => i.Length == 1))) // Info parameter
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
        _hashServiceMock.Verify(x => x.DeriveKeyAsync(
            It.Is<byte[]>(b => b.Length == dh1.Length + dh2.Length + dh3.Length + dh4.Length),
            It.Is<byte[]>(b => b.Length == 32), // Zero salt
            It.Is<int>(l => l == 32),
            It.Is<byte[]>(i => i.Length == 1)), Times.Once); // Info parameter
    }
}