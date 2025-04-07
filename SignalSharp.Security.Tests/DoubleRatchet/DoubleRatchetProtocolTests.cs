using System;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;
using Xunit;

namespace SignalSharp.Security.Tests.DoubleRatchet
{
    /// <summary>
    /// Security-focused test suite for the Double Ratchet protocol implementation.
    /// These tests verify cryptographic correctness and security properties of the Double Ratchet implementation.
    /// </summary>
    public class DoubleRatchetProtocolTests
    {
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly DoubleRatchetService _service;

        public DoubleRatchetProtocolTests()
        {
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
            _hashServiceMock = new Mock<IHashService>();
            _service = new DoubleRatchetService(
                _encryptionServiceMock.Object,
                _keyExchangeServiceMock.Object,
                _hashServiceMock.Object);
        }

        [Fact]
        public async Task InitializeSession_ShouldCreateValidSessionState()
        {
            // Arrange
            var rootKey = new byte[32];
            var sendingRatchetKey = new byte[32];
            var receivingRatchetKey = new byte[32];
            var sharedSecret = new byte[32];
            var sendingChainKey = new byte[32];
            var receivingChainKey = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(sharedSecret);
            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(sendingChainKey)
                .ReturnsAsync(receivingChainKey);

            // Act
            var result = await _service.InitializeSessionAsync(rootKey, sendingRatchetKey, receivingRatchetKey);

            // Assert
            result.Should().NotBeNull();
            result.RootKey.Should().BeEquivalentTo(rootKey);
            result.SendingRatchetKey.Should().BeEquivalentTo(sendingRatchetKey);
            result.ReceivingRatchetKey.Should().BeEquivalentTo(receivingRatchetKey);
            result.SendingChainKey.Should().BeEquivalentTo(sendingChainKey);
            result.ReceivingChainKey.Should().BeEquivalentTo(receivingChainKey);
            result.SendingMessageNumber.Should().Be(0);
            result.ReceivingMessageNumber.Should().Be(0);
        }

        [Fact]
        public async Task EncryptMessage_ShouldPerformRatchetStep()
        {
            // Arrange
            var sessionState = CreateTestSessionState();
            var message = new byte[32];
            var messageKey = new byte[32];
            var newChainKey = new byte[32];
            var encryptedMessage = new byte[64];
            var mac = new byte[32];

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(messageKey)
                .ReturnsAsync(newChainKey);
            _encryptionServiceMock.Setup(x => x.EncryptAsync(message, messageKey))
                .ReturnsAsync(encryptedMessage);
            _hashServiceMock.Setup(x => x.ComputeKeyedHashAsync(encryptedMessage, messageKey))
                .ReturnsAsync(mac);

            // Act
            var (result, updatedState) = await _service.EncryptMessageAsync(sessionState, message);

            // Assert
            result.Should().NotBeNull();
            result.Ciphertext.Should().BeEquivalentTo(encryptedMessage);
            result.MessageNumber.Should().Be(sessionState.SendingMessageNumber);
            result.Mac.Should().BeEquivalentTo(mac);
            updatedState.SendingMessageNumber.Should().Be(sessionState.SendingMessageNumber + 1);
            updatedState.SendingChainKey.Should().BeEquivalentTo(newChainKey);
        }

        [Fact]
        public async Task DecryptMessage_ShouldVerifyMessageAuthenticity()
        {
            // Arrange
            var sessionState = CreateTestSessionState();
            var message = new SignalMessage
            {
                Ciphertext = new byte[64],
                MessageNumber = 0,
                Mac = new byte[32]
            };
            var messageKey = new byte[32];
            var newChainKey = new byte[32];
            var decryptedMessage = new byte[32];

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(messageKey)
                .ReturnsAsync(newChainKey);
            _hashServiceMock.Setup(x => x.VerifyKeyedHashAsync(message.Ciphertext, messageKey, message.Mac))
                .ReturnsAsync(true);
            _encryptionServiceMock.Setup(x => x.DecryptAsync(message.Ciphertext, messageKey))
                .ReturnsAsync(decryptedMessage);

            // Act
            var (result, updatedState) = await _service.DecryptMessageAsync(sessionState, message);

            // Assert
            result.Should().BeEquivalentTo(decryptedMessage);
            updatedState.ReceivingMessageNumber.Should().Be(sessionState.ReceivingMessageNumber + 1);
            updatedState.ReceivingChainKey.Should().BeEquivalentTo(newChainKey);
        }

        [Fact]
        public async Task DecryptMessage_ShouldRejectTamperedMessages()
        {
            // Arrange
            var sessionState = CreateTestSessionState();
            var message = new SignalMessage
            {
                Ciphertext = new byte[64],
                MessageNumber = 0,
                Mac = new byte[32]
            };

            _hashServiceMock.Setup(x => x.DeriveKeyAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>()))
                .ReturnsAsync(new byte[32]);
            _hashServiceMock.Setup(x => x.VerifyKeyedHashAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(false);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => 
                _service.DecryptMessageAsync(sessionState, message));
        }

        [Fact]
        public async Task RatchetSending_ShouldGenerateNewRatchetKey()
        {
            // Arrange
            var sessionState = CreateTestSessionState();
            var newRatchetKey = new byte[32];
            var sharedSecret = new byte[32];
            var newChainKey = new byte[32];

            _keyExchangeServiceMock.Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((newRatchetKey, new byte[32]));
            _keyExchangeServiceMock.Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(sharedSecret);
            _keyExchangeServiceMock.Setup(x => x.DeriveSymmetricKeyAsync(sharedSecret, newRatchetKey))
                .ReturnsAsync(newChainKey);

            // Act
            var result = await _service.RatchetSendingAsync(sessionState);

            // Assert
            result.Should().NotBeNull();
            result.SendingRatchetKey.Should().BeEquivalentTo(newRatchetKey);
            result.SendingChainKey.Should().BeEquivalentTo(newChainKey);
            result.SendingMessageNumber.Should().Be(0);
            result.PreviousSendingMessageNumber.Should().Be(sessionState.SendingMessageNumber);
        }

        private static SessionState CreateTestSessionState()
        {
            return new SessionState(
                "test-session",
                new byte[32], // LocalIdentityKey
                new byte[32], // RemoteIdentityKey
                new byte[32], // RootKey
                new byte[32], // SendingChainKey
                new byte[32], // ReceivingChainKey
                new byte[32], // SendingRatchetKey
                new byte[32]  // ReceivingRatchetKey
            );
        }
    }
} 