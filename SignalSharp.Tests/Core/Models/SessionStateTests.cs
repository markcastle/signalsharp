using SignalSharp.Core.Models;

namespace SignalSharp.Tests.Core.Models
{
    /// <summary>
    /// Test suite for the SessionState class which represents the cryptographic state of a Signal protocol session.
    /// </summary>
    /// <remarks>
    /// These tests verify that the SessionState class:
    /// - Correctly initializes with valid cryptographic keys and parameters
    /// - Properly validates input parameters with appropriate exceptions
    /// - Implements equality comparison correctly for both positive and negative cases
    /// - Provides consistent hash code generation for use in collections
    /// 
    /// The SessionState is a critical component in the Signal protocol as it maintains
    /// the cryptographic state necessary for the Double Ratchet algorithm, including
    /// root keys, chain keys, and ratchet keys that evolve with each message exchange.
    /// </remarks>
    public class SessionStateTests
    {
        /// <summary>
        /// Tests that a SessionState can be successfully created with valid parameters.
        /// </summary>
        /// <remarks>
        /// This test verifies the basic functionality of the SessionState constructor:
        /// 1. The object is correctly instantiated with all required parameters
        /// 2. All properties are properly set to their initial values
        /// 3. Message counters are initialized to zero
        /// 4. Timestamp fields are set to reasonable values
        /// 
        /// The SessionState encapsulates all cryptographic material needed for the Double Ratchet
        /// algorithm, which provides forward secrecy and break-in recovery for message exchanges.
        /// </remarks>
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateSessionState()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };

            // Act
            SessionState sessionState = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            // Assert
            Assert.Equal(sessionId, sessionState.SessionId);
            Assert.Equal(localIdentityKey, sessionState.LocalIdentityKey);
            Assert.Equal(remoteIdentityKey, sessionState.RemoteIdentityKey);
            Assert.Equal(rootKey, sessionState.RootKey);
            Assert.Equal(sendingChainKey, sessionState.SendingChainKey);
            Assert.Equal(receivingChainKey, sessionState.ReceivingChainKey);
            Assert.Equal(sendingRatchetKey, sessionState.SendingRatchetKey);
            Assert.Equal(receivingRatchetKey, sessionState.ReceivingRatchetKey);
            Assert.Equal(0u, sessionState.SendingMessageNumber);
            Assert.Equal(0u, sessionState.ReceivingMessageNumber);
            Assert.Equal(0u, sessionState.PreviousSendingMessageNumber);
            Assert.Equal(0u, sessionState.PreviousReceivingMessageNumber);
            Assert.True(sessionState.CreatedAt <= DateTime.UtcNow);
            Assert.True(sessionState.LastUsedAt <= DateTime.UtcNow);
        }

        /// <summary>
        /// Tests that the SessionState constructor throws appropriate exceptions when null parameters are provided.
        /// </summary>
        /// <remarks>
        /// This parameterized test verifies null parameter validation for all constructor parameters:
        /// - Each required parameter is systematically tested with a null value
        /// - The constructor should throw an ArgumentNullException for each null parameter
        /// - The exception should identify the correct parameter name
        /// 
        /// Proper validation prevents the creation of incomplete session states that would
        /// be unusable for cryptographic operations and could lead to security vulnerabilities.
        /// </remarks>
        [Theory]
        [InlineData(null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "sessionId")]
        [InlineData("test", null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "localIdentityKey")]
        [InlineData("test", new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "remoteIdentityKey")]
        [InlineData("test", new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "rootKey")]
        [InlineData("test", new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, "sendingChainKey")]
        [InlineData("test", new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, new byte[] { 1 }, "receivingChainKey")]
        [InlineData("test", new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, new byte[] { 1 }, "sendingRatchetKey")]
        [InlineData("test", new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, new byte[] { 1 }, null, "receivingRatchetKey")]
        public void Constructor_WithNullParameters_ShouldThrowArgumentNullException(
            string sessionId,
            byte[] localIdentityKey,
            byte[] remoteIdentityKey,
            byte[] rootKey,
            byte[] sendingChainKey,
            byte[] receivingChainKey,
            byte[] sendingRatchetKey,
            byte[] receivingRatchetKey,
            string paramName)
        {
            // Act & Assert
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() =>
                new SessionState(
                    sessionId,
                    localIdentityKey,
                    remoteIdentityKey,
                    rootKey,
                    sendingChainKey,
                    receivingChainKey,
                    sendingRatchetKey,
                    receivingRatchetKey));
            Assert.Equal(paramName, exception.ParamName);
        }

        /// <summary>
        /// Tests that the SessionState constructor throws an appropriate exception when an empty session ID is provided.
        /// </summary>
        /// <remarks>
        /// This test verifies input validation for the sessionId parameter:
        /// - An empty string is not a valid session identifier
        /// - The constructor should reject empty session IDs with an ArgumentException
        /// 
        /// Session identifiers are used to retrieve and store session states, so they must
        /// contain meaningful values to ensure proper session management.
        /// </remarks>
        [Fact]
        public void Constructor_WithEmptySessionId_ShouldThrowArgumentException()
        {
            // Arrange
            string sessionId = string.Empty;
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                new SessionState(
                    sessionId,
                    localIdentityKey,
                    remoteIdentityKey,
                    rootKey,
                    sendingChainKey,
                    receivingChainKey,
                    sendingRatchetKey,
                    receivingRatchetKey));
        }

        /// <summary>
        /// Tests that the Equals method returns true when comparing identical session states.
        /// </summary>
        /// <remarks>
        /// This test verifies the equality comparison logic:
        /// - Two SessionState instances with the same parameter values should be considered equal
        /// - Both instance Equals and operator == should identify identical session states
        /// - Operator != should return false for identical session states
        /// 
        /// Proper equality comparison is essential for session management, especially when
        /// determining if a session state has changed after cryptographic operations.
        /// </remarks>
        [Fact]
        public void Equals_WithSameParameters_ShouldReturnTrue()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };

            SessionState sessionState1 = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            SessionState sessionState2 = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            // Act & Assert
            Assert.True(sessionState1.Equals(sessionState2));
            Assert.True(sessionState1 == sessionState2);
            Assert.False(sessionState1 != sessionState2);
        }

        /// <summary>
        /// Tests that the Equals method returns false when comparing different session states.
        /// </summary>
        /// <remarks>
        /// This test verifies the inequality comparison logic:
        /// - Two SessionState instances with different parameter values should not be considered equal
        /// - Both instance Equals and operator == should identify different session states
        /// - Operator != should return true for different session states
        /// 
        /// This ensures that cryptographic operations use the intended session state and
        /// that state changes are properly detected.
        /// </remarks>
        [Fact]
        public void Equals_WithDifferentParameters_ShouldReturnFalse()
        {
            // Arrange
            string sessionId1 = "test-session-1";
            byte[] localIdentityKey1 = { 1, 2, 3 };
            byte[] remoteIdentityKey1 = { 4, 5, 6 };
            byte[] rootKey1 = { 7, 8, 9 };
            byte[] sendingChainKey1 = { 10, 11, 12 };
            byte[] receivingChainKey1 = { 13, 14, 15 };
            byte[] sendingRatchetKey1 = { 16, 17, 18 };
            byte[] receivingRatchetKey1 = { 19, 20, 21 };

            string sessionId2 = "test-session-2";
            byte[] localIdentityKey2 = { 2, 3, 4 };
            byte[] remoteIdentityKey2 = { 5, 6, 7 };
            byte[] rootKey2 = { 8, 9, 10 };
            byte[] sendingChainKey2 = { 11, 12, 13 };
            byte[] receivingChainKey2 = { 14, 15, 16 };
            byte[] sendingRatchetKey2 = { 17, 18, 19 };
            byte[] receivingRatchetKey2 = { 20, 21, 22 };

            SessionState sessionState1 = new(
                sessionId1,
                localIdentityKey1,
                remoteIdentityKey1,
                rootKey1,
                sendingChainKey1,
                receivingChainKey1,
                sendingRatchetKey1,
                receivingRatchetKey1);

            SessionState sessionState2 = new(
                sessionId2,
                localIdentityKey2,
                remoteIdentityKey2,
                rootKey2,
                sendingChainKey2,
                receivingChainKey2,
                sendingRatchetKey2,
                receivingRatchetKey2);

            // Act & Assert
            Assert.False(sessionState1.Equals(sessionState2));
            Assert.False(sessionState1 == sessionState2);
            Assert.True(sessionState1 != sessionState2);
        }

        /// <summary>
        /// Tests that GetHashCode returns the same value for identical session states.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code consistency:
        /// - Two equal session states should produce the same hash code
        /// - The hash code should be consistent for the same SessionState parameter values
        /// 
        /// This is essential for using SessionState objects in hash-based collections
        /// and for caching session states during cryptographic operations.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithSameParameters_ShouldReturnSameHashCode()
        {
            // Arrange
            string sessionId = "test-session";
            byte[] localIdentityKey = { 1, 2, 3 };
            byte[] remoteIdentityKey = { 4, 5, 6 };
            byte[] rootKey = { 7, 8, 9 };
            byte[] sendingChainKey = { 10, 11, 12 };
            byte[] receivingChainKey = { 13, 14, 15 };
            byte[] sendingRatchetKey = { 16, 17, 18 };
            byte[] receivingRatchetKey = { 19, 20, 21 };

            SessionState sessionState1 = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            SessionState sessionState2 = new(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            // Act & Assert
            Assert.Equal(sessionState1.GetHashCode(), sessionState2.GetHashCode());
        }

        /// <summary>
        /// Tests that GetHashCode returns different values for different session states.
        /// </summary>
        /// <remarks>
        /// This test verifies hash code differentiation:
        /// - Different session states should produce different hash codes (with high probability)
        /// - The hash function should have good distribution properties for cryptographic material
        /// 
        /// While hash collisions are theoretically possible, distinct session states with
        /// different cryptographic keys should generally produce different hash codes for
        /// efficient collection operations and state caching.
        /// </remarks>
        [Fact]
        public void GetHashCode_WithDifferentParameters_ShouldReturnDifferentHashCode()
        {
            // Arrange
            string sessionId1 = "test-session-1";
            byte[] localIdentityKey1 = { 1, 2, 3 };
            byte[] remoteIdentityKey1 = { 4, 5, 6 };
            byte[] rootKey1 = { 7, 8, 9 };
            byte[] sendingChainKey1 = { 10, 11, 12 };
            byte[] receivingChainKey1 = { 13, 14, 15 };
            byte[] sendingRatchetKey1 = { 16, 17, 18 };
            byte[] receivingRatchetKey1 = { 19, 20, 21 };

            string sessionId2 = "test-session-2";
            byte[] localIdentityKey2 = { 2, 3, 4 };
            byte[] remoteIdentityKey2 = { 5, 6, 7 };
            byte[] rootKey2 = { 8, 9, 10 };
            byte[] sendingChainKey2 = { 11, 12, 13 };
            byte[] receivingChainKey2 = { 14, 15, 16 };
            byte[] sendingRatchetKey2 = { 17, 18, 19 };
            byte[] receivingRatchetKey2 = { 20, 21, 22 };

            SessionState sessionState1 = new(
                sessionId1,
                localIdentityKey1,
                remoteIdentityKey1,
                rootKey1,
                sendingChainKey1,
                receivingChainKey1,
                sendingRatchetKey1,
                receivingRatchetKey1);

            SessionState sessionState2 = new(
                sessionId2,
                localIdentityKey2,
                remoteIdentityKey2,
                rootKey2,
                sendingChainKey2,
                receivingChainKey2,
                sendingRatchetKey2,
                receivingRatchetKey2);

            // Act & Assert
            Assert.NotEqual(sessionState1.GetHashCode(), sessionState2.GetHashCode());
        }
    }
}