using System;
using SignalSharp.Core.Models;
using Xunit;

namespace SignalSharp.Tests.Core.Models
{
    public class SignalMessageTests
    {
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateMessage()
        {
            // Arrange
            var content = new byte[] { 1, 2, 3 };
            var mac = new byte[] { 4, 5, 6 };
            var iv = new byte[] { 7, 8, 9 };
            var senderIdentityKey = new byte[] { 10, 11, 12 };
            var senderEphemeralKey = new byte[] { 13, 14, 15 };

            // Act
            var message = new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey);

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
            var exception = Assert.Throws<ArgumentNullException>(() =>
                new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey));
            Assert.Equal(paramName, exception.ParamName);
        }

        [Fact]
        public void Equals_WithSameParameters_ShouldReturnTrue()
        {
            // Arrange
            var content = new byte[] { 1, 2, 3 };
            var mac = new byte[] { 4, 5, 6 };
            var iv = new byte[] { 7, 8, 9 };
            var senderIdentityKey = new byte[] { 10, 11, 12 };
            var senderEphemeralKey = new byte[] { 13, 14, 15 };

            var message1 = new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey);
            var message2 = new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey);

            // Act & Assert
            Assert.True(message1.Equals(message2));
            Assert.True(message1 == message2);
            Assert.False(message1 != message2);
        }

        [Fact]
        public void Equals_WithDifferentParameters_ShouldReturnFalse()
        {
            // Arrange
            var content1 = new byte[] { 1, 2, 3 };
            var mac1 = new byte[] { 4, 5, 6 };
            var iv1 = new byte[] { 7, 8, 9 };
            var senderIdentityKey1 = new byte[] { 10, 11, 12 };
            var senderEphemeralKey1 = new byte[] { 13, 14, 15 };

            var content2 = new byte[] { 2, 3, 4 };
            var mac2 = new byte[] { 5, 6, 7 };
            var iv2 = new byte[] { 8, 9, 10 };
            var senderIdentityKey2 = new byte[] { 11, 12, 13 };
            var senderEphemeralKey2 = new byte[] { 14, 15, 16 };

            var message1 = new SignalMessage(content1, mac1, iv1, senderIdentityKey1, senderEphemeralKey1);
            var message2 = new SignalMessage(content2, mac2, iv2, senderIdentityKey2, senderEphemeralKey2);

            // Act & Assert
            Assert.False(message1.Equals(message2));
            Assert.False(message1 == message2);
            Assert.True(message1 != message2);
        }

        [Fact]
        public void GetHashCode_WithSameParameters_ShouldReturnSameHashCode()
        {
            // Arrange
            var content = new byte[] { 1, 2, 3 };
            var mac = new byte[] { 4, 5, 6 };
            var iv = new byte[] { 7, 8, 9 };
            var senderIdentityKey = new byte[] { 10, 11, 12 };
            var senderEphemeralKey = new byte[] { 13, 14, 15 };

            var message1 = new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey);
            var message2 = new SignalMessage(content, mac, iv, senderIdentityKey, senderEphemeralKey);

            // Act & Assert
            Assert.Equal(message1.GetHashCode(), message2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_WithDifferentParameters_ShouldReturnDifferentHashCode()
        {
            // Arrange
            var content1 = new byte[] { 1, 2, 3 };
            var mac1 = new byte[] { 4, 5, 6 };
            var iv1 = new byte[] { 7, 8, 9 };
            var senderIdentityKey1 = new byte[] { 10, 11, 12 };
            var senderEphemeralKey1 = new byte[] { 13, 14, 15 };

            var content2 = new byte[] { 2, 3, 4 };
            var mac2 = new byte[] { 5, 6, 7 };
            var iv2 = new byte[] { 8, 9, 10 };
            var senderIdentityKey2 = new byte[] { 11, 12, 13 };
            var senderEphemeralKey2 = new byte[] { 14, 15, 16 };

            var message1 = new SignalMessage(content1, mac1, iv1, senderIdentityKey1, senderEphemeralKey1);
            var message2 = new SignalMessage(content2, mac2, iv2, senderIdentityKey2, senderEphemeralKey2);

            // Act & Assert
            Assert.NotEqual(message1.GetHashCode(), message2.GetHashCode());
        }
    }
} 