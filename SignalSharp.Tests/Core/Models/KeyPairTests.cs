using SignalSharp.Core.Models;

namespace SignalSharp.Tests.Core.Models
{
    /// <summary>
    /// Test suite for the KeyPair class which represents an asymmetric cryptographic key pair.
    /// </summary>
    /// <remarks>
    /// These tests verify that the KeyPair class:
    /// - Correctly initializes with valid public and private key data
    /// - Properly validates input parameters with appropriate exceptions
    /// - Implements equality comparison correctly for both positive and negative cases
    /// - Provides consistent hash code generation for use in collections
    /// 
    /// A KeyPair is a fundamental building block in asymmetric cryptography, containing
    /// both the public key (which can be shared) and the private key (which must be kept secret).
    /// </remarks>
    public class KeyPairTests
    {
        /// <summary>
        /// Tests that a KeyPair can be successfully created with valid public and private keys.
        /// </summary>
        /// <remarks>
        /// This test verifies the basic functionality of the KeyPair constructor:
        /// 1. The object is correctly instantiated
        /// 2. Both public and private keys are properly stored
        /// 3. The stored values match those provided to the constructor
        /// 
        /// This ensures that the fundamental purpose of the class - 
        /// to encapsulate a key pair - works correctly.
        /// </remarks>
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateKeyPair()
        {
            // Arrange
            byte[] publicKey = { 1, 2, 3, 4, 5 };
            byte[] privateKey = { 6, 7, 8, 9, 10 };

            // Act
            KeyPair keyPair = new(publicKey, privateKey);

            // Assert
            Assert.NotNull(keyPair);
            Assert.Equal(publicKey, keyPair.PublicKey);
            Assert.Equal(privateKey, keyPair.PrivateKey);
        }

        /// <summary>
        /// Tests that the KeyPair constructor throws an appropriate exception when the public key is null.
        /// </summary>
        /// <remarks>
        /// This test verifies parameter validation in the KeyPair constructor:
        /// - A KeyPair must have a valid public key
        /// - The constructor should reject null public keys with an ArgumentNullException
        /// 
        /// This prevents the creation of invalid key pairs that would cause cryptographic operations to fail.
        /// </remarks>
        [Fact]
        public void Constructor_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[]? publicKey = null;
            byte[] privateKey = new byte[32];

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyPair(publicKey!, privateKey));
        }

        /// <summary>
        /// Tests that the KeyPair constructor throws an appropriate exception when the private key is null.
        /// </summary>
        /// <remarks>
        /// This test verifies parameter validation in the KeyPair constructor:
        /// - A KeyPair must have a valid private key
        /// - The constructor should reject null private keys with an ArgumentNullException
        /// 
        /// This prevents the creation of incomplete key pairs that would be unusable for signing or decryption.
        /// </remarks>
        [Fact]
        public void Constructor_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] publicKey = new byte[32];
            byte[]? privateKey = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyPair(publicKey, privateKey!));
        }

        /// <summary>
        /// Tests that the KeyPair constructor throws an appropriate exception when the public key is empty.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation for the public key:
        /// - An empty array is not a valid public key
        /// - The constructor should reject empty public keys with an ArgumentException
        /// 
        /// This ensures that the key pair contains meaningful cryptographic material.
        /// </remarks>
        [Fact]
        public void Constructor_WithEmptyPublicKey_ShouldThrowArgumentException()
        {
            // Arrange
            byte[] publicKey = Array.Empty<byte>();
            byte[] privateKey = { 6, 7, 8, 9, 10 };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new KeyPair(publicKey, privateKey));
        }

        /// <summary>
        /// Tests that the KeyPair constructor throws an appropriate exception when the private key is empty.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation for the private key:
        /// - An empty array is not a valid private key
        /// - The constructor should reject empty private keys with an ArgumentException
        /// 
        /// This prevents the creation of key pairs with inadequate security properties.
        /// </remarks>
        [Fact]
        public void Constructor_WithEmptyPrivateKey_ShouldThrowArgumentException()
        {
            // Arrange
            byte[] publicKey = { 1, 2, 3, 4, 5 };
            byte[] privateKey = Array.Empty<byte>();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new KeyPair(publicKey, privateKey));
        }

        /// <summary>
        /// Tests that the Equals method returns true when comparing identical key pairs.
        /// </summary>
        /// <remarks>
        /// This test verifies the equality comparison logic:
        /// - Two KeyPair instances with the same public and private keys should be considered equal
        /// - The Equals method should correctly identify identical key pairs
        /// 
        /// Proper equality comparison is important for collections and caching operations.
        /// </remarks>
        [Fact]
        public void Equals_WithSameKeyPair_ShouldReturnTrue()
        {
            // Arrange
            byte[] publicKey = { 1, 2, 3, 4, 5 };
            byte[] privateKey = { 6, 7, 8, 9, 10 };
            KeyPair keyPair1 = new(publicKey, privateKey);
            KeyPair keyPair2 = new(publicKey, privateKey);

            // Act
            bool result = keyPair1.Equals(keyPair2);

            // Assert
            Assert.True(result);
        }

        /// <summary>
        /// Tests that the Equals method returns false when comparing different key pairs.
        /// </summary>
        /// <remarks>
        /// This test verifies the inequality comparison logic:
        /// - Two KeyPair instances with different public and private keys should not be considered equal
        /// - The Equals method should correctly identify different key pairs
        /// 
        /// This ensures that cryptographic operations use the intended keys.
        /// </remarks>
        [Fact]
        public void Equals_WithDifferentKeyPair_ShouldReturnFalse()
        {
            // Arrange
            KeyPair keyPair1 = new(
                new byte[] { 1, 2, 3, 4, 5 },
                new byte[] { 6, 7, 8, 9, 10 });
            KeyPair keyPair2 = new(
                new byte[] { 11, 12, 13, 14, 15 },
                new byte[] { 16, 17, 18, 19, 20 });

            // Act
            bool result = keyPair1.Equals(keyPair2);

            // Assert
            Assert.False(result);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for identical key pairs.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code consistency:
        /// - Two equal objects should produce the same hash code
        /// - The hash code should be consistent for the same KeyPair data
        /// 
        /// This is essential for using KeyPair objects in hash-based collections like
        /// HashSet and Dictionary, ensuring that equal keys hash to the same bucket.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithSameKeyPair_ShouldReturnSameHashCode()
        {
            // Arrange
            byte[] publicKey = { 1, 2, 3, 4, 5 };
            byte[] privateKey = { 6, 7, 8, 9, 10 };
            KeyPair keyPair1 = new(publicKey, privateKey);
            KeyPair keyPair2 = new(publicKey, privateKey);

            // Act
            int hashCode1 = keyPair1.GetHashCode();
            int hashCode2 = keyPair2.GetHashCode();

            // Assert
            Assert.Equal(hashCode1, hashCode2);
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for different key pairs.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code differentiation:
        /// - Different key pairs should produce different hash codes (with high probability)
        /// - The hash function should have good distribution properties
        /// 
        /// While hash collisions are theoretically possible, distinct cryptographic
        /// keys should generally produce different hash codes for efficient collection operations.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithDifferentKeyPair_ShouldReturnDifferentHashCode()
        {
            // Arrange
            KeyPair keyPair1 = new(
                new byte[] { 1, 2, 3, 4, 5 },
                new byte[] { 6, 7, 8, 9, 10 });
            KeyPair keyPair2 = new(
                new byte[] { 11, 12, 13, 14, 15 },
                new byte[] { 16, 17, 18, 19, 20 });

            // Act
            int hashCode1 = keyPair1.GetHashCode();
            int hashCode2 = keyPair2.GetHashCode();

            // Assert
            Assert.NotEqual(hashCode1, hashCode2);
        }
    }
}