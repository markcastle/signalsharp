using SignalSharp.Security.Services;
using System.Security.Cryptography;
using System.Text;

namespace SignalSharp.Tests.Security
{
    /// <summary>
    /// Test suite for validating the functionality of the AesEncryptionService.
    /// These tests verify encryption/decryption operations, key generation, and error handling.
    /// </summary>
    /// <remarks>
    /// The AesEncryptionService is responsible for providing secure encryption and decryption
    /// using the AES algorithm. These tests ensure that:
    /// - Keys are properly generated with the expected size (256 bits)
    /// - Data is correctly encrypted and cannot be read without decryption
    /// - Data can be properly decrypted back to its original form
    /// - The service handles error cases appropriately
    /// </remarks>
    public class AesEncryptionServiceTests
    {
        /// <summary>
        /// Instance of the AesEncryptionService under test.
        /// </summary>
        private readonly AesEncryptionService _service;

        // ReSharper disable once ConvertConstructorToMemberInitializers
        /// <summary>
        /// Initializes a new instance of the AesEncryptionServiceTests class.
        /// Creates a fresh AesEncryptionService instance for each test.
        /// </summary>
        public AesEncryptionServiceTests()
        {
            _service = new AesEncryptionService();
        }

        /// <summary>
        /// Tests that the key generation method produces a cryptographically secure key of the correct length.
        /// </summary>
        /// <remarks>
        /// AES-256 requires a 32-byte (256-bit) key. This test verifies that our service
        /// generates keys with the correct size to ensure proper encryption strength.
        /// </remarks>
        [Fact]
        public async Task GenerateKeyAsync_ShouldReturn32ByteKey()
        {
            // Act - Generate a new encryption key
            byte[] key = await _service.GenerateKeyAsync();

            // Assert - Verify the key is not null and is exactly 32 bytes (256 bits) in length
            Assert.NotNull(key);
            Assert.Equal(32, key.Length); // 256 bits = 32 bytes
        }

        /// <summary>
        /// Verifies that data is properly encrypted and transformed from its original state.
        /// </summary>
        /// <remarks>
        /// This test confirms that:
        /// 1. The encrypted output is not null
        /// 2. The encrypted data is larger than the input (due to IV and padding)
        /// 3. The encrypted output differs from the original plaintext
        /// 
        /// These conditions ensure that encryption is actually occurring and producing
        /// the expected transformations on the input data.
        /// </remarks>
        [Fact]
        public async Task EncryptAsync_WithValidInput_ShouldEncryptData()
        {
            // Arrange - Create a key and prepare plaintext data for encryption
            byte[] key = await _service.GenerateKeyAsync();
            byte[] plainText = "Hello, Signal!"u8.ToArray();

            // Act - Encrypt the plaintext data using the generated key
            byte[] encrypted = await _service.EncryptAsync(plainText, key);

            // Assert - Verify the encryption produced valid output
            Assert.NotNull(encrypted);
            Assert.True(encrypted.Length > plainText.Length); // Due to IV and padding
            Assert.NotEqual(plainText, encrypted); // Encrypted data should be different
        }

        /// <summary>
        /// Tests that the full encryption and decryption cycle correctly preserves the original data.
        /// </summary>
        /// <remarks>
        /// This test verifies the core functionality of the encryption service by confirming that
        /// data can be encrypted and then correctly decrypted back to its original form.
        /// 
        /// The test uses a string as input data to make it easier to verify equality after
        /// the encryption/decryption cycle is complete.
        /// </remarks>
        [Fact]
        public async Task DecryptAsync_WithValidInput_ShouldDecryptToOriginalData()
        {
            // Arrange - Create a key and prepare plaintext data
            byte[] key = await _service.GenerateKeyAsync();
            string originalText = "Hello, Signal!";
            byte[] plainText = Encoding.UTF8.GetBytes(originalText);

            // Act - Encrypt the data, then decrypt it back
            byte[] encrypted = await _service.EncryptAsync(plainText, key);
            byte[] decrypted = await _service.DecryptAsync(encrypted, key);
            string decryptedText = Encoding.UTF8.GetString(decrypted);

            // Assert - Verify the decrypted text matches the original
            Assert.Equal(originalText, decryptedText);
        }

        /// <summary>
        /// Tests that the encryption method correctly rejects null plaintext data.
        /// </summary>
        /// <remarks>
        /// This test verifies that the service properly validates input parameters by
        /// throwing an ArgumentNullException when plaintext is null, preventing errors
        /// that would occur if encryption were attempted with null data.
        /// </remarks>
        [Fact]
        public async Task EncryptAsync_WithNullPlainText_ShouldThrowArgumentNullException()
        {
            // Arrange - Create a valid key but leave plaintext null
            byte[] key = await _service.GenerateKeyAsync();

            // Act & Assert - Verify that attempting to encrypt null data throws the expected exception
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.EncryptAsync(null!, key));
        }

        /// <summary>
        /// Tests that the encryption method correctly rejects null encryption keys.
        /// </summary>
        /// <remarks>
        /// This test ensures that the service validates the encryption key parameter
        /// by throwing an ArgumentNullException when key is null, preventing potential
        /// security issues or cryptographic errors.
        /// </remarks>
        [Fact]
        public async Task EncryptAsync_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Arrange - Create valid plaintext but leave key null
            byte[] plainText = "Hello, Signal!"u8.ToArray();

            // Act & Assert - Verify that attempting to encrypt with a null key throws the expected exception
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _service.EncryptAsync(plainText, null!));
        }

        /// <summary>
        /// Tests that decryption fails when using an incorrect key.
        /// </summary>
        /// <remarks>
        /// This test verifies a critical security property of the encryption service:
        /// data encrypted with one key cannot be decrypted with a different key.
        /// 
        /// The test generates two different keys, encrypts data with the first key,
        /// then attempts to decrypt with the second key, expecting a cryptographic exception.
        /// </remarks>
        [Fact]
        public async Task DecryptAsync_WithInvalidKey_ShouldThrowCryptographicException()
        {
            // Arrange - Create two different keys and encrypt data with the first key
            byte[] key1 = await _service.GenerateKeyAsync();
            byte[] key2 = await _service.GenerateKeyAsync();
            byte[] plainText = "Hello, Signal!"u8.ToArray();
            byte[] encrypted = await _service.EncryptAsync(plainText, key1);

            // Act & Assert - Verify that attempting to decrypt with the wrong key throws a cryptographic exception
            await Assert.ThrowsAsync<CryptographicException>(() =>
                _service.DecryptAsync(encrypted, key2));
        }

        /// <summary>
        /// Tests that decryption properly rejects malformed ciphertext data.
        /// </summary>
        /// <remarks>
        /// This test verifies that the decryption method validates input parameters by
        /// rejecting ciphertext that is clearly invalid (too short to contain the necessary
        /// cryptographic elements like IV and HMAC).
        /// 
        /// AES ciphertext must contain at minimum an IV (16 bytes) plus at least one block of data,
        /// so a 5-byte array cannot possibly be valid ciphertext.
        /// </remarks>
        [Fact]
        public async Task DecryptAsync_WithInvalidCipherText_ShouldThrowArgumentException()
        {
            // Arrange - Create a valid key but provide invalid ciphertext that's too short
            byte[] key = await _service.GenerateKeyAsync();
            byte[] invalidCipherText = { 1, 2, 3, 4, 5 }; // Too short to be valid

            // Act & Assert - Verify that attempting to decrypt invalid data throws the expected exception
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _service.DecryptAsync(invalidCipherText, key));
        }
    }
}