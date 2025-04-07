using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;
using SignalSharp.Core.Interfaces;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Security.Tests.CryptographicPrimitives
{
    /// <summary>
    /// Security-focused test suite for cryptographic primitives.
    /// These tests verify the security properties and correctness of the cryptographic implementations.
    /// </summary>
    public class CryptographicPrimitivesTests
    {
        [Fact]
        public async Task AesEncryption_ShouldUseSecureParameters()
        {
            // Arrange
            var service = new AesEncryptionService();
            var key = new byte[32]; // 256-bit key
            var message = new byte[64];

            // Act
            var encrypted = await service.EncryptAsync(message, key);
            var decrypted = await service.DecryptAsync(encrypted, key);

            // Assert
            decrypted.Should().BeEquivalentTo(message);
            encrypted.Should().NotBeEquivalentTo(message);
            encrypted.Length.Should().BeGreaterThan(message.Length); // Due to IV and padding
        }

        [Fact]
        public async Task AesEncryption_ShouldUseUniqueIVs()
        {
            // Arrange
            var service = new AesEncryptionService();
            var key = new byte[32];
            var message = new byte[64];

            // Act
            var encrypted1 = await service.EncryptAsync(message, key);
            var encrypted2 = await service.EncryptAsync(message, key);

            // Assert
            encrypted1.Should().NotBeEquivalentTo(encrypted2);
        }

        [Fact]
        public async Task EcKeyExchange_ShouldGenerateValidKeyPairs()
        {
            // Arrange
            var service = new EcKeyExchangeService();

            // Act
            var (publicKey, privateKey) = await service.GenerateKeyPairAsync();

            // Assert
            publicKey.Should().NotBeNull();
            privateKey.Should().NotBeNull();
            publicKey.Length.Should().Be(32);
            privateKey.Length.Should().Be(32);
        }

        [Fact]
        public async Task EcKeyExchange_ShouldComputeSameSharedSecret()
        {
            // Arrange
            var service = new EcKeyExchangeService();
            var (alicePublic, alicePrivate) = await service.GenerateKeyPairAsync();
            var (bobPublic, bobPrivate) = await service.GenerateKeyPairAsync();

            // Act
            var aliceSecret = await service.ComputeSharedSecretAsync(alicePrivate, bobPublic);
            var bobSecret = await service.ComputeSharedSecretAsync(bobPrivate, alicePublic);

            // Assert
            aliceSecret.Should().NotBeNull();
            bobSecret.Should().NotBeNull();
            aliceSecret.Should().BeEquivalentTo(bobSecret);
            aliceSecret.Length.Should().Be(32);
        }

        [Fact]
        public async Task HashService_ShouldProduceConsistentHashes()
        {
            // Arrange
            var service = new HashService();
            var input = new byte[64];
            var salt = new byte[32];

            // Act
            var hash1 = await service.DeriveKeyAsync(input, salt, 32);
            var hash2 = await service.DeriveKeyAsync(input, salt, 32);

            // Assert
            hash1.Should().NotBeNull();
            hash2.Should().NotBeNull();
            hash1.Should().BeEquivalentTo(hash2);
            hash1.Length.Should().Be(32);
        }

        [Fact]
        public async Task HashService_ShouldProduceDifferentHashesForDifferentSalts()
        {
            // Arrange
            var service = new HashService();
            var input = new byte[64];
            var salt1 = new byte[32];
            var salt2 = new byte[32];
            salt2[0] = 1; // Make salt2 different from salt1

            // Act
            var hash1 = await service.DeriveKeyAsync(input, salt1, 32);
            var hash2 = await service.DeriveKeyAsync(input, salt2, 32);

            // Assert
            hash1.Should().NotBeEquivalentTo(hash2);
        }

        [Fact]
        public async Task HashService_ShouldVerifyKeyedHashes()
        {
            // Arrange
            var service = new HashService();
            var message = new byte[64];
            var key = new byte[32];

            // Act
            var hash = await service.ComputeKeyedHashAsync(message, key);
            var isValid = await service.VerifyKeyedHashAsync(message, key, hash);

            // Assert
            hash.Should().NotBeNull();
            hash.Length.Should().Be(32);
            isValid.Should().BeTrue();
        }

        [Fact]
        public async Task HashService_ShouldDetectTamperedMessages()
        {
            // Arrange
            var service = new HashService();
            var message = new byte[64];
            var key = new byte[32];
            var hash = await service.ComputeKeyedHashAsync(message, key);
            message[0] = 1; // Tamper with the message

            // Act
            var isValid = await service.VerifyKeyedHashAsync(message, key, hash);

            // Assert
            isValid.Should().BeFalse();
        }

        [Theory]
        [InlineData(16)]  // Too short
        [InlineData(48)]  // Too long
        public async Task AesEncryption_ShouldValidateKeyLength(int keyLength)
        {
            // Arrange
            var service = new AesEncryptionService();
            var key = new byte[keyLength];
            var message = new byte[64];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                service.EncryptAsync(message, key));
        }

        [Fact]
        public async Task EcKeyExchange_ShouldHandleInvalidKeys()
        {
            // Arrange
            var service = new EcKeyExchangeService();
            var invalidKey = new byte[31]; // Wrong length

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                service.ComputeSharedSecretAsync(invalidKey, new byte[32]));
        }
    }
} 