using SignalSharp.Security.Services;

namespace SignalSharp.Tests.Security
{
    /// <summary>
    /// Test suite for the EcKeyExchangeService which provides elliptic curve cryptography operations.
    /// </summary>
    /// <remarks>
    /// These tests verify the functionality of the elliptic curve cryptography service, which is 
    /// responsible for:
    /// - Generating cryptographically secure key pairs
    /// - Computing shared secrets using Diffie-Hellman key exchange
    /// - Deriving symmetric keys from shared secrets
    /// - Signing data and verifying signatures
    /// 
    /// Elliptic curve cryptography is a fundamental building block for the Signal protocol,
    /// providing the asymmetric cryptography needed for secure key exchange and authentication.
    /// </remarks>
    public class EcKeyExchangeServiceTests
    {
        /// <summary>
        /// The EcKeyExchangeService instance being tested.
        /// </summary>
        private readonly EcKeyExchangeService _service;

        // ReSharper disable once ConvertConstructorToMemberInitializers
        /// <summary>
        /// Initializes a new instance of the EcKeyExchangeServiceTests class.
        /// Creates a fresh EcKeyExchangeService instance for each test.
        /// </summary>
        public EcKeyExchangeServiceTests()
        {
            _service = new EcKeyExchangeService();
        }

        /// <summary>
        /// Tests that key pair generation produces valid public and private keys with the correct sizes.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The generated public key is not null and has the correct length (64 bytes)
        /// 2. The generated private key is not null and has the correct length (32 bytes)
        /// 
        /// The public key is 64 bytes because it contains both X and Y coordinates (32 bytes each)
        /// of the elliptic curve point. The private key is a 32-byte scalar value.
        /// 
        /// Properly sized keys are essential for the security of the cryptographic operations.
        /// </remarks>
        [Fact]
        public async Task GenerateKeyPair_ReturnsValidKeyPair()
        {
            // Act
            (byte[]? publicKey, byte[]? privateKey) = await _service.GenerateKeyPairAsync();

            // Assert
            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.Equal(64, publicKey.Length); // 32 bytes for X + 32 bytes for Y
            Assert.Equal(32, privateKey.Length); // 32 bytes for private key
        }

        /// <summary>
        /// Tests that a shared secret can be successfully computed from a valid key pair.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The computed shared secret is not null
        /// 2. The shared secret has the correct length (32 bytes)
        /// 
        /// Shared secret computation is the core of the Diffie-Hellman key exchange protocol,
        /// allowing two parties to establish a shared secret over an insecure channel.
        /// This shared secret can then be used to derive symmetric encryption keys.
        /// </remarks>
        [Fact]
        public async Task ComputeSharedSecret_WithValidKeys_ReturnsSharedSecret()
        {
            // Arrange
            (byte[]? publicKey, byte[]? privateKey) = await _service.GenerateKeyPairAsync();

            // Act
            byte[] sharedSecret = await _service.ComputeSharedSecretAsync(privateKey, publicKey);

            // Assert
            Assert.NotNull(sharedSecret);
            Assert.Equal(32, sharedSecret.Length); // 32 bytes for shared secret
        }

        /// <summary>
        /// Tests that a symmetric key can be derived from a shared secret and salt.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The derived symmetric key is not null
        /// 2. The symmetric key has the correct length (32 bytes)
        /// 
        /// Key derivation function (KDF) is used to transform a shared secret into
        /// a symmetric encryption key, typically using a cryptographic hash function.
        /// The salt provides additional randomization to prevent pre-computation attacks.
        /// 
        /// The 32-byte (256-bit) output is suitable for use with AES-256 encryption.
        /// </remarks>
        [Fact]
        public async Task DeriveSymmetricKey_WithValidInput_ReturnsSymmetricKey()
        {
            // Arrange
            byte[] sharedSecret = new byte[32];
            byte[] salt = new byte[32];
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(salt);

            // Act
            byte[] symmetricKey = await _service.DeriveSymmetricKeyAsync(sharedSecret, salt);

            // Assert
            Assert.NotNull(symmetricKey);
            Assert.Equal(32, symmetricKey.Length); // 32 bytes for symmetric key
        }

        /// <summary>
        /// Tests the digital signature functionality by signing data and verifying the signature.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A signature can be generated using a private key
        /// 2. The signature can be successfully verified using the corresponding public key
        /// 
        /// Digital signatures provide authentication and integrity verification,
        /// ensuring that messages were sent by the claimed sender and have not been modified.
        /// 
        /// This functionality is essential for authenticating the identity keys and signed
        /// pre-keys in the Signal protocol's key exchange process.
        /// </remarks>
        [Fact]
        public async Task SignAndVerify_WithValidData_VerifiesSuccessfully()
        {
            // Arrange
            (byte[]? publicKey, byte[]? privateKey) = await _service.GenerateKeyPairAsync();
            byte[] data = { 1, 2, 3, 4, 5 };

            // Act
            byte[] signature = await _service.SignAsync(privateKey, data);
            bool isValid = await _service.VerifyAsync(publicKey, data, signature);

            // Assert
            Assert.True(isValid);
        }

        /// <summary>
        /// Tests that computing a shared secret with a null private key throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies proper input validation:
        /// - The service should reject null private keys with an ArgumentNullException
        /// 
        /// Input validation is critical for security, as attempting to perform
        /// cryptographic operations with invalid inputs could lead to security vulnerabilities.
        /// </remarks>
        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            (byte[]? publicKey, _) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.ComputeSharedSecretAsync(null!, publicKey));
        }

        /// <summary>
        /// Tests that computing a shared secret with a null public key throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies proper input validation:
        /// - The service should reject null public keys with an ArgumentNullException
        /// 
        /// This validation ensures that cryptographic operations are not attempted
        /// with missing or invalid key material.
        /// </remarks>
        [Fact]
        public async Task ComputeSharedSecretAsync_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            (_, byte[]? privateKey) = await _service.GenerateKeyPairAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.ComputeSharedSecretAsync(privateKey, null!));
        }

        /// <summary>
        /// Tests that deriving a symmetric key with a null shared secret throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies proper input validation:
        /// - The service should reject null shared secrets with an ArgumentNullException
        /// 
        /// This validation prevents potential security issues or cryptographic failures
        /// that could occur if key derivation were attempted with missing input material.
        /// </remarks>
        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithNullSharedSecret_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] salt = new byte[32];
            new Random().NextBytes(salt);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.DeriveSymmetricKeyAsync(null!, salt));
        }

        /// <summary>
        /// Tests that deriving a symmetric key with a null salt throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies proper input validation:
        /// - The service should reject null salt values with an ArgumentNullException
        /// 
        /// The salt is an important component of secure key derivation, providing
        /// additional entropy and preventing pre-computation attacks.
        /// </remarks>
        [Fact]
        public async Task DeriveSymmetricKeyAsync_WithNullSalt_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] sharedSecret = new byte[32];
            new Random().NextBytes(sharedSecret);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.DeriveSymmetricKeyAsync(sharedSecret, null!));
        }
    }
}