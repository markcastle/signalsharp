using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Storage.Services;
// ReSharper disable UnusedParameter.Local

namespace SignalSharp.Tests.Storage
{
    /// <summary>
    /// Test suite for the FileKeyStore which provides persistent storage for cryptographic keys and session states.
    /// </summary>
    /// <remarks>
    /// These tests verify that the FileKeyStore correctly:
    /// - Stores and retrieves cryptographic keys to/from the file system
    /// - Manages session states for secure communications
    /// - Encrypts sensitive data before storage
    /// - Validates inputs with appropriate exceptions
    /// - Handles file system operations safely
    /// 
    /// Secure storage is a critical component of the Signal protocol implementation,
    /// ensuring that keys and session states persist across application restarts
    /// while maintaining their confidentiality.
    /// </remarks>
    public class FileKeyStoreTests : IDisposable
    {
        /// <summary>
        /// Temporary directory used for testing file operations.
        /// </summary>
        private readonly string _testDirectory;

        /// <summary>
        /// The FileKeyStore instance being tested.
        /// </summary>
        private readonly FileKeyStore _keyStore;

        /// <summary>
        /// Mock of the JSON serializer used for converting session states to/from JSON.
        /// </summary>
        private readonly Mock<IJsonSerializer> _mockJsonSerializer;

        /// <summary>
        /// Mock of the encryption service used for encrypting stored keys and session data.
        /// </summary>
        private readonly Mock<IEncryptionService> _mockEncryptionService;

        /// <summary>
        /// Initializes a new instance of the FileKeyStoreTests class.
        /// Creates a temporary directory and sets up the FileKeyStore with mock dependencies.
        /// </summary>
        public FileKeyStoreTests()
        {
            _testDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testDirectory);
            _mockJsonSerializer = new Mock<IJsonSerializer>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _keyStore = new FileKeyStore(_testDirectory, _mockJsonSerializer.Object, _mockEncryptionService.Object);

            // Set up default encryption service responses
            _mockEncryptionService.Setup(x => x.GenerateKeyAsync())
                .ReturnsAsync(new byte[] { 1, 2, 3, 4 });
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                // ReSharper disable once UnusedParameter.Local
                .ReturnsAsync((byte[] data, byte[] key) => data);
            _mockEncryptionService.Setup(x => x.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                // ReSharper disable once UnusedParameter.Local
                .ReturnsAsync((byte[] data, byte[] key) => data);
        }

        /// <summary>
        /// Cleans up test resources by deleting the temporary directory.
        /// </summary>
        public void Dispose()
        {
            if (Directory.Exists(_testDirectory))
                Directory.Delete(_testDirectory, true);
        }

        /// <summary>
        /// Tests that a cryptographic key can be successfully stored to the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The key is correctly written to a file in the specified location
        /// 2. The key is encrypted before storage (in a real implementation)
        /// 
        /// Secure storage of cryptographic keys is essential for maintaining the security
        /// of the Signal protocol across application sessions. Proper file naming and
        /// directory structure ensure keys can be retrieved consistently.
        /// </remarks>
        [Fact]
        public async Task StoreKeyAsync_WithValidParameters_ShouldStoreKey()
        {
            // Arrange
            string keyId = "test_key";
            byte[] key = { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);

            // Act
            await _keyStore.StoreKeyAsync(keyId, key);

            // Assert
            string filePath = Path.Combine(_testDirectory, "v1_test_key.key");
            Assert.True(File.Exists(filePath));
            byte[] storedKey = await File.ReadAllBytesAsync(filePath);
            Assert.Equal(key, storedKey);
        }

        /// <summary>
        /// Tests that a stored key can be successfully retrieved from the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A previously stored key can be read from the file system
        /// 2. The key is decrypted after retrieval (in a real implementation)
        /// 
        /// Key retrieval is essential for the Signal protocol to maintain consistent
        /// cryptographic identities and access the private keys needed for decryption
        /// and signing operations.
        /// </remarks>
        [Fact]
        public async Task GetKeyAsync_WithExistingKey_ShouldReturnKey()
        {
            // Arrange
            string keyId = "test_key";
            byte[] key = { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            _mockEncryptionService.Setup(x => x.DecryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync(keyId, key);

            // Act
            byte[]? result = await _keyStore.GetKeyAsync(keyId);

            // Assert
            Assert.Equal(key, result);
        }

        /// <summary>
        /// Tests that requesting a non-existent key returns null rather than throwing an exception.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. When a key doesn't exist, the method returns null
        /// 2. The system gracefully handles missing keys
        /// 
        /// This behavior allows the application to detect when a key is missing and
        /// generate a new one if needed, which is important for handling first-time
        /// setup or key rotation scenarios.
        /// </remarks>
        [Fact]
        public async Task GetKeyAsync_WithNonExistentKey_ShouldReturnNull()
        {
            // Arrange
            string keyId = "non_existent_key";
            string filePath = Path.Combine(_testDirectory, $"v1_{keyId}.key");
            if (File.Exists(filePath))
                File.Delete(filePath);

            // Act
            byte[]? result = await _keyStore.GetKeyAsync(keyId);

            // Assert
            Assert.Null(result);
        }

        /// <summary>
        /// Tests that a key can be successfully deleted from the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A key file is properly removed from the file system when deleted
        /// 
        /// Key deletion is necessary for security operations like key rotation,
        /// where outdated keys should be completely removed to prevent their use
        /// in cryptographic operations.
        /// </remarks>
        [Fact]
        public async Task DeleteKeyAsync_WithExistingKey_ShouldDeleteKey()
        {
            // Arrange
            string keyId = "test_key";
            byte[] key = { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync(keyId, key);

            // Act
            await _keyStore.DeleteKeyAsync(keyId);

            // Assert
            string filePath = Path.Combine(_testDirectory, "v1_test_key.key");
            Assert.False(File.Exists(filePath));
        }

        /// <summary>
        /// Tests that attempting to store a key with a null ID throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation:
        /// - The key store should reject null key IDs with an ArgumentNullException
        /// 
        /// Proper validation prevents potential issues with file paths and ensures
        /// that keys are stored with valid, retrievable identifiers.
        /// </remarks>
        [Fact]
        public async Task StoreKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;
            byte[] key = { 1, 2, 3 };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.StoreKeyAsync(keyId!, key));
        }

        /// <summary>
        /// Tests that attempting to store a null key throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation:
        /// - The key store should reject null key data with an ArgumentNullException
        /// 
        /// This validation prevents storing invalid cryptographic material that would
        /// cause security failures when later retrieved and used.
        /// </remarks>
        [Fact]
        public async Task StoreKeyAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            string keyId = "test_key";
            byte[]? key = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.StoreKeyAsync(keyId, key!));
        }

        /// <summary>
        /// Tests that attempting to retrieve a key with a null ID throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation:
        /// - The key store should reject null key IDs with an ArgumentNullException
        /// 
        /// This validation prevents potential file system access issues and ensures
        /// that key retrieval operations have valid search parameters.
        /// </remarks>
        [Fact]
        public async Task GetKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.GetKeyAsync(keyId!));
        }

        /// <summary>
        /// Tests that attempting to delete a key with a null ID throws the appropriate exception.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation:
        /// - The key store should reject null key IDs with an ArgumentNullException
        /// 
        /// This validation prevents potential file system access issues during deletion
        /// operations and ensures that the correct file is targeted.
        /// </remarks>
        [Fact]
        public async Task DeleteKeyAsync_WithNullKeyId_ShouldThrowArgumentNullException()
        {
            // Arrange
            string? keyId = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _keyStore.DeleteKeyAsync(keyId!));
        }

        /// <summary>
        /// Tests that the identity key can be successfully retrieved when it exists.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The special "identity" key can be retrieved from storage
        /// 
        /// The identity key is a critical component in the Signal protocol, representing
        /// the user's persistent cryptographic identity. It's used for signing operations
        /// and for authenticating the user to other participants.
        /// </remarks>
        [Fact]
        public async Task GetIdentityKeyAsync_WithExistingKey_ShouldReturnKey()
        {
            // Arrange
            byte[] key = { 1, 2, 3 };
            _mockEncryptionService.Setup(x => x.EncryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            _mockEncryptionService.Setup(x => x.DecryptAsync(key, It.IsAny<byte[]>()))
                .ReturnsAsync(key);
            await _keyStore.StoreKeyAsync("identity", key);

            // Act
            byte[]? result = await _keyStore.GetIdentityKeyAsync();

            // Assert
            Assert.Equal(key, result);
        }

        /// <summary>
        /// Tests that requesting a non-existent identity key returns null rather than throwing an exception.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. When the identity key doesn't exist, the method returns null
        /// 
        /// This behavior allows the application to detect when the identity key is missing
        /// and generate a new one, which is essential for first-time setup.
        /// </remarks>
        [Fact]
        public async Task GetIdentityKeyAsync_WithNoKey_ShouldReturnNull()
        {
            // Arrange
            string filePath = Path.Combine(_testDirectory, "v1_identity.key");
            if (File.Exists(filePath))
                File.Delete(filePath);

            // Act
            byte[]? result = await _keyStore.GetIdentityKeyAsync();

            // Assert
            Assert.Null(result);
        }

        /// <summary>
        /// Tests that an ephemeral key pair can be generated and stored.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A new key pair is correctly generated
        /// 2. Both public and private key components are returned
        /// 
        /// Ephemeral key pairs are essential for the Signal protocol's security properties,
        /// providing forward secrecy by using unique keys for each session. These keys
        /// should be properly generated with cryptographically secure randomness.
        /// </remarks>
        [Fact]
        public async Task GenerateEphemeralKeyPairAsync_ShouldGenerateAndStoreKey()
        {
            // Arrange
            byte[] publicKey = { 1, 2, 3, 4 };
            byte[] privateKey = { 5, 6, 7, 8 };
            KeyPair expectedKeyPair = new(publicKey, privateKey);
            _mockEncryptionService.SetupSequence(x => x.GenerateKeyAsync())
                .ReturnsAsync(publicKey)
                .ReturnsAsync(privateKey);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            _mockEncryptionService.Setup(x => x.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);

            // Act
            KeyPair result = await _keyStore.GenerateEphemeralKeyPairAsync();

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedKeyPair.PublicKey, result.PublicKey);
            Assert.Equal(expectedKeyPair.PrivateKey, result.PrivateKey);
            _mockEncryptionService.Verify(x => x.GenerateKeyAsync(), Times.Exactly(2));
        }

        /// <summary>
        /// Tests that a session state can be successfully stored to the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. The session state is properly serialized to JSON
        /// 2. The serialized data is stored in the correct location
        /// 
        /// Session states contain the cryptographic state for ongoing communications
        /// in the Signal protocol. Proper storage ensures that secure communications
        /// can continue across application restarts.
        /// </remarks>
        [Fact]
        public async Task StoreSessionStateAsync_WithValidParameters_ShouldStoreState()
        {
            // Arrange
            string sessionId = "test_session";
            SessionState sessionState = new(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            string json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);

            // Act
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Assert
            string filePath = Path.Combine(_testDirectory, "sessions", "v1_test_session.json");
            Assert.True(File.Exists(filePath));
            string storedJson = await File.ReadAllTextAsync(filePath);
            Assert.Equal(json, storedJson);
        }

        /// <summary>
        /// Tests that a stored session state can be successfully retrieved from the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A previously stored session state can be read from the file system
        /// 2. The serialized data is properly deserialized back into a SessionState object
        /// 
        /// Retrieving session states is essential for the Signal protocol to continue
        /// secure communications with the correct cryptographic context, maintaining
        /// forward secrecy and break-in recovery properties.
        /// </remarks>
        [Fact]
        public async Task GetSessionStateAsync_WithExistingState_ShouldReturnState()
        {
            // Arrange
            const string sessionId = "test_session";
            SessionState sessionState = new(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            const string json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockJsonSerializer.Setup(x => x.Deserialize<SessionState>(json))
                .Returns(sessionState);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            _mockEncryptionService.Setup(x => x.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Act
            SessionState? result = await _keyStore.GetSessionStateAsync(sessionId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(sessionState.SessionId, result.SessionId);
        }

        /// <summary>
        /// Tests that a session state can be successfully deleted from the file system.
        /// </summary>
        /// <remarks>
        /// This test verifies that:
        /// 1. A session state file is properly removed from the file system when deleted
        /// 
        /// Session state deletion is necessary for clearing completed or compromised
        /// sessions, ensuring that outdated cryptographic material is not reused.
        /// </remarks>
        [Fact]
        public async Task DeleteSessionStateAsync_WithExistingState_ShouldDeleteState()
        {
            // Arrange
            string sessionId = "test_session";
            SessionState sessionState = new(
                sessionId,
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 },
                new byte[] { 13, 14, 15 },
                new byte[] { 16, 17, 18 },
                new byte[] { 19, 20, 21 });
            string json = "{}";
            _mockJsonSerializer.Setup(x => x.Serialize(sessionState))
                .Returns(json);
            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync((byte[] data, byte[] key) => data);
            await _keyStore.StoreSessionStateAsync(sessionId, sessionState);

            // Act
            await _keyStore.DeleteSessionStateAsync(sessionId);

            // Assert
            string filePath = Path.Combine(_testDirectory, "sessions", "v1_test_session.json");
            Assert.False(File.Exists(filePath));
        }
    }
}