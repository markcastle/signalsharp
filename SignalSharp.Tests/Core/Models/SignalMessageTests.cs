using SignalSharp.Core.Models;

namespace SignalSharp.Tests.Core.Models
{
    /// <summary>
    /// Test suite for the SignalMessage class which represents an encrypted message in the Signal protocol.
    /// </summary>
    /// <remarks>
    /// These tests verify that the SignalMessage class:
    /// - Correctly initializes with valid cryptographic elements and parameters
    /// - Properly validates input parameters with appropriate exceptions
    /// - Implements equality comparison correctly for both positive and negative cases
    /// - Provides consistent hash code generation for use in collections
    /// 
    /// The SignalMessage is a fundamental data structure in the Signal protocol that contains
    /// the encrypted content and cryptographic metadata necessary for secure message exchange,
    /// including authentication data and key material for the Double Ratchet algorithm.
    /// </remarks>
    public class SignalMessageTests
    {
        /// <summary>
        /// Tests that a SignalMessage can be successfully created with valid parameters.
        /// </summary>
        /// <remarks>
        /// This test verifies the basic functionality of the SignalMessage constructor:
        /// 1. The object is correctly instantiated with all required cryptographic elements
        /// 2. All properties are properly set to their initial values
        /// 3. Message type and counters are initialized to their default values
        /// 
        /// The SignalMessage encapsulates both the encrypted content and the cryptographic
        /// metadata required for decryption and authentication, including:
        /// - The encrypted content itself
        /// - Message Authentication Code (MAC) for integrity verification
        /// - Initialization Vector (IV) used in the encryption
        /// - Sender's identity key for authentication
        /// - Sender's ephemeral ratchet key for the Double Ratchet algorithm
        /// </remarks>
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateMessage()
        {
            // Arrange
            byte[] content = { 1, 2, 3 };
            byte[] mac = { 4, 5, 6 };
            byte[] iv = { 7, 8, 9 };
            byte[] senderIdentityKey = { 10, 11, 12 };
            byte[] senderEphemeralKey = { 13, 14, 15 };

            // Act
            SignalMessage message = new(content, mac, iv, senderIdentityKey, senderEphemeralKey);

            // Assert
            Assert.Equal(content, message.Content);
            Assert.Equal(mac, message.Mac);
            Assert.Equal(iv, message.Iv);
            Assert.Equal(senderIdentityKey, message.SenderIdentityKey);
            Assert.Equal(senderEphemeralKey, message.SenderEphemeralKey);
            Assert.Equal(MessageType.Regular, message.Type);
            Assert.Equal(0u, message.Counter);
            Assert.Equal(0u, message.PreviousCounter);
        }

        /// <summary>
        /// Tests that the SignalMessage constructor throws appropriate exceptions when null parameters are provided.
        /// </summary>
        /// <remarks>
        /// This parameterized test verifies null parameter validation for all constructor parameters:
        /// - Each required cryptographic element is systematically tested with a null value
        /// - The constructor should throw an ArgumentNullException for each null parameter
        /// - The exception should identify the correct parameter name
        /// 
        /// Proper validation is critical for security, as missing or invalid cryptographic
        /// elements could lead to failed authentication or decryption, compromising the
        /// confidentiality and integrity guarantees of the Signal protocol.
        /// </remarks>
        [Theory]
        [InlineData(null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "content")]
        [InlineData(new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "mac")]
        [InlineData(new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, "iv")]
        [InlineData(new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, "senderIdentityKey")]
        [InlineData(new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, "senderEphemeralKey")]
        public void Constructor_WithNullParameters_ShouldThrowArgumentNullException(
            byte[] content,
            byte[] mac,
            byte[] iv,
            byte[] senderIdentityKey,
            byte[] senderEphemeralKey,
            string paramName)
        {
            // Act & Assert
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
                new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey));
            Assert.Equal(paramName, exception.ParamName);
        }

        /// <summary>
        /// Tests that the Equals method returns true when comparing identical signal messages.
        /// </summary>
        /// <remarks>
        /// This test verifies the equality comparison logic:
        /// - Two SignalMessage instances with the same cryptographic elements should be considered equal
        /// - Both instance Equals and operator == should identify identical messages
        /// - Operator != should return false for identical messages
        /// 
        /// Proper equality comparison is important for message deduplication and for
        /// verifying message integrity through the protocol layers.
        /// </remarks>
        [Fact]
        public void Equals_WithSameParameters_ShouldReturnTrue()
        {
            // Arrange
            byte[] content = { 1, 2, 3 };
            byte[] mac = { 4, 5, 6 };
            byte[] iv = { 7, 8, 9 };
            byte[] senderIdentityKey = { 10, 11, 12 };
            byte[] senderEphemeralKey = { 13, 14, 15 };

            SignalMessage message1 = new(content, mac, iv, senderIdentityKey, senderEphemeralKey);
            SignalMessage message2 = new(content, mac, iv, senderIdentityKey, senderEphemeralKey);

            // Act & Assert
            Assert.True(message1.Equals(message2));
            Assert.True(message1 == message2);
            Assert.False(message1 != message2);
        }

        /// <summary>
        /// Tests that the Equals method returns false when comparing different signal messages.
        /// </summary>
        /// <remarks>
        /// This test verifies the inequality comparison logic:
        /// - Two SignalMessage instances with different cryptographic elements should not be considered equal
        /// - Both instance Equals and operator == should identify different messages
        /// - Operator != should return true for different messages
        /// 
        /// This ensures that message processing can distinguish between unique messages
        /// and prevent security issues like message replay or manipulation.
        /// </remarks>
        [Fact]
        public void Equals_WithDifferentParameters_ShouldReturnFalse()
        {
            // Arrange
            byte[] content1 = { 1, 2, 3 };
            byte[] mac1 = { 4, 5, 6 };
            byte[] iv1 = { 7, 8, 9 };
            byte[] senderIdentityKey1 = { 10, 11, 12 };
            byte[] senderEphemeralKey1 = { 13, 14, 15 };

            byte[] content2 = { 2, 3, 4 };
            byte[] mac2 = { 5, 6, 7 };
            byte[] iv2 = { 8, 9, 10 };
            byte[] senderIdentityKey2 = { 11, 12, 13 };
            byte[] senderEphemeralKey2 = { 14, 15, 16 };

            SignalMessage message1 = new(content1, mac1, iv1, senderIdentityKey1, senderEphemeralKey1);
            SignalMessage message2 = new(content2, mac2, iv2, senderIdentityKey2, senderEphemeralKey2);

            // Act & Assert
            Assert.False(message1.Equals(message2));
            Assert.False(message1 == message2);
            Assert.True(message1 != message2);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for identical signal messages.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code consistency:
        /// - Two equal messages should produce the same hash code
        /// - The hash code should be consistent for the same message content and metadata
        /// 
        /// This is essential for using SignalMessage objects in hash-based collections
        /// like dictionaries and sets that might be used for message processing.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithSameParameters_ShouldReturnSameHashCode()
        {
            // Arrange
            byte[] content = { 1, 2, 3 };
            byte[] mac = { 4, 5, 6 };
            byte[] iv = { 7, 8, 9 };
            byte[] senderIdentityKey = { 10, 11, 12 };
            byte[] senderEphemeralKey = { 13, 14, 15 };

            SignalMessage message1 = new(content, mac, iv, senderIdentityKey, senderEphemeralKey);
            SignalMessage message2 = new(content, mac, iv, senderIdentityKey, senderEphemeralKey);

            // Act & Assert
            Assert.Equal(message1.GetHashCode(), message2.GetHashCode());
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for different signal messages.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code differentiation:
        /// - Different messages should produce different hash codes (with high probability)
        /// - The hash function should have good distribution properties for message data
        /// 
        /// While hash collisions are theoretically possible, distinct messages with
        /// different cryptographic elements should generally produce different hash codes
        /// to ensure efficient collection operations and message processing.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithDifferentParameters_ShouldReturnDifferentHashCode()
        {
            // Arrange
            byte[] content1 = { 1, 2, 3 };
            byte[] mac1 = { 4, 5, 6 };
            byte[] iv1 = { 7, 8, 9 };
            byte[] senderIdentityKey1 = { 10, 11, 12 };
            byte[] senderEphemeralKey1 = { 13, 14, 15 };

            byte[] content2 = { 2, 3, 4 };
            byte[] mac2 = { 5, 6, 7 };
            byte[] iv2 = { 8, 9, 10 };
            byte[] senderIdentityKey2 = { 11, 12, 13 };
            byte[] senderEphemeralKey2 = { 14, 15, 16 };

            SignalMessage message1 = new(content1, mac1, iv1, senderIdentityKey1, senderEphemeralKey1);
            SignalMessage message2 = new(content2, mac2, iv2, senderIdentityKey2, senderEphemeralKey2);

            // Act & Assert
            Assert.NotEqual(message1.GetHashCode(), message2.GetHashCode());
        }
    }
}