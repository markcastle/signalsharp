using System;
using Xunit;
using SignalSharp.Core.Models;

namespace SignalSharp.Tests.Core.Models
{
    public class KeyPairTests
    {
        [Fact]
        public void Constructor_WithValidParameters_ShouldCreateKeyPair()
        {
            // Arrange
            var publicKey = new byte[] { 1, 2, 3, 4, 5 };
            var privateKey = new byte[] { 6, 7, 8, 9, 10 };

            // Act
            var keyPair = new KeyPair(publicKey, privateKey);

            // Assert
            Assert.NotNull(keyPair);
            Assert.Equal(publicKey, keyPair.PublicKey);
            Assert.Equal(privateKey, keyPair.PrivateKey);
        }

        [Fact]
        public void Constructor_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[]? publicKey = null;
            byte[] privateKey = new byte[32];

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyPair(publicKey!, privateKey));
        }

        [Fact]
        public void Constructor_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Arrange
            byte[] publicKey = new byte[32];
            byte[]? privateKey = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyPair(publicKey, privateKey!));
        }

        [Fact]
        public void Constructor_WithEmptyPublicKey_ShouldThrowArgumentException()
        {
            // Arrange
            var publicKey = Array.Empty<byte>();
            var privateKey = new byte[] { 6, 7, 8, 9, 10 };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new KeyPair(publicKey, privateKey));
        }

        [Fact]
        public void Constructor_WithEmptyPrivateKey_ShouldThrowArgumentException()
        {
            // Arrange
            var publicKey = new byte[] { 1, 2, 3, 4, 5 };
            var privateKey = Array.Empty<byte>();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new KeyPair(publicKey, privateKey));
        }

        [Fact]
        public void Equals_WithSameKeyPair_ShouldReturnTrue()
        {
            // Arrange
            var publicKey = new byte[] { 1, 2, 3, 4, 5 };
            var privateKey = new byte[] { 6, 7, 8, 9, 10 };
            var keyPair1 = new KeyPair(publicKey, privateKey);
            var keyPair2 = new KeyPair(publicKey, privateKey);

            // Act
            var result = keyPair1.Equals(keyPair2);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Equals_WithDifferentKeyPair_ShouldReturnFalse()
        {
            // Arrange
            var keyPair1 = new KeyPair(
                new byte[] { 1, 2, 3, 4, 5 },
                new byte[] { 6, 7, 8, 9, 10 });
            var keyPair2 = new KeyPair(
                new byte[] { 11, 12, 13, 14, 15 },
                new byte[] { 16, 17, 18, 19, 20 });

            // Act
            var result = keyPair1.Equals(keyPair2);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void GetHashCode_WithSameKeyPair_ShouldReturnSameHashCode()
        {
            // Arrange
            var publicKey = new byte[] { 1, 2, 3, 4, 5 };
            var privateKey = new byte[] { 6, 7, 8, 9, 10 };
            var keyPair1 = new KeyPair(publicKey, privateKey);
            var keyPair2 = new KeyPair(publicKey, privateKey);

            // Act
            var hashCode1 = keyPair1.GetHashCode();
            var hashCode2 = keyPair2.GetHashCode();

            // Assert
            Assert.Equal(hashCode1, hashCode2);
        }

        [Fact]
        public void GetHashCode_WithDifferentKeyPair_ShouldReturnDifferentHashCode()
        {
            // Arrange
            var keyPair1 = new KeyPair(
                new byte[] { 1, 2, 3, 4, 5 },
                new byte[] { 6, 7, 8, 9, 10 });
            var keyPair2 = new KeyPair(
                new byte[] { 11, 12, 13, 14, 15 },
                new byte[] { 16, 17, 18, 19, 20 });

            // Act
            var hashCode1 = keyPair1.GetHashCode();
            var hashCode2 = keyPair2.GetHashCode();

            // Assert
            Assert.NotEqual(hashCode1, hashCode2);
        }
    }
} 