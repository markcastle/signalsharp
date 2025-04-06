using System;
using Xunit;
using SignalSharp.Core.Models;

namespace SignalSharp.Tests.Core.Models
{
    public class SessionStateTests
    {
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateSessionState()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };

            // Act
            var sessionState = new SessionState(
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
            var exception = Assert.Throws<ArgumentNullException>(() =>
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

        [Fact]
        public void Constructor_WithEmptySessionId_ShouldThrowArgumentException()
        {
            // Arrange
            var sessionId = string.Empty;
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };

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

        [Fact]
        public void Equals_WithSameParameters_ShouldReturnTrue()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };

            var sessionState1 = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            var sessionState2 = new SessionState(
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

        [Fact]
        public void Equals_WithDifferentParameters_ShouldReturnFalse()
        {
            // Arrange
            var sessionId1 = "test-session-1";
            var localIdentityKey1 = new byte[] { 1, 2, 3 };
            var remoteIdentityKey1 = new byte[] { 4, 5, 6 };
            var rootKey1 = new byte[] { 7, 8, 9 };
            var sendingChainKey1 = new byte[] { 10, 11, 12 };
            var receivingChainKey1 = new byte[] { 13, 14, 15 };
            var sendingRatchetKey1 = new byte[] { 16, 17, 18 };
            var receivingRatchetKey1 = new byte[] { 19, 20, 21 };

            var sessionId2 = "test-session-2";
            var localIdentityKey2 = new byte[] { 2, 3, 4 };
            var remoteIdentityKey2 = new byte[] { 5, 6, 7 };
            var rootKey2 = new byte[] { 8, 9, 10 };
            var sendingChainKey2 = new byte[] { 11, 12, 13 };
            var receivingChainKey2 = new byte[] { 14, 15, 16 };
            var sendingRatchetKey2 = new byte[] { 17, 18, 19 };
            var receivingRatchetKey2 = new byte[] { 20, 21, 22 };

            var sessionState1 = new SessionState(
                sessionId1,
                localIdentityKey1,
                remoteIdentityKey1,
                rootKey1,
                sendingChainKey1,
                receivingChainKey1,
                sendingRatchetKey1,
                receivingRatchetKey1);

            var sessionState2 = new SessionState(
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

        [Fact]
        public void GetHashCode_WithSameParameters_ShouldReturnSameHashCode()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };

            var sessionState1 = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            var sessionState2 = new SessionState(
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

        [Fact]
        public void GetHashCode_WithDifferentParameters_ShouldReturnDifferentHashCode()
        {
            // Arrange
            var sessionId1 = "test-session-1";
            var localIdentityKey1 = new byte[] { 1, 2, 3 };
            var remoteIdentityKey1 = new byte[] { 4, 5, 6 };
            var rootKey1 = new byte[] { 7, 8, 9 };
            var sendingChainKey1 = new byte[] { 10, 11, 12 };
            var receivingChainKey1 = new byte[] { 13, 14, 15 };
            var sendingRatchetKey1 = new byte[] { 16, 17, 18 };
            var receivingRatchetKey1 = new byte[] { 19, 20, 21 };

            var sessionId2 = "test-session-2";
            var localIdentityKey2 = new byte[] { 2, 3, 4 };
            var remoteIdentityKey2 = new byte[] { 5, 6, 7 };
            var rootKey2 = new byte[] { 8, 9, 10 };
            var sendingChainKey2 = new byte[] { 11, 12, 13 };
            var receivingChainKey2 = new byte[] { 14, 15, 16 };
            var sendingRatchetKey2 = new byte[] { 17, 18, 19 };
            var receivingRatchetKey2 = new byte[] { 20, 21, 22 };

            var sessionState1 = new SessionState(
                sessionId1,
                localIdentityKey1,
                remoteIdentityKey1,
                rootKey1,
                sendingChainKey1,
                receivingChainKey1,
                sendingRatchetKey1,
                receivingRatchetKey1);

            var sessionState2 = new SessionState(
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