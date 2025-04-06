using System;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Security.Services;
using Xunit;
using System.Threading;

namespace SignalSharp.Tests.Security
{
    public class DoubleRatchetServiceTests
    {
        private readonly Mock<IKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly IDoubleRatchetService _doubleRatchetService;

        public DoubleRatchetServiceTests()
        {
            _keyExchangeServiceMock = new Mock<IKeyExchangeService>();
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _hashServiceMock = new Mock<IHashService>();
            _doubleRatchetService = new DoubleRatchetService(
                _encryptionServiceMock.Object,
                _keyExchangeServiceMock.Object,
                _hashServiceMock.Object);
        }

        [Fact]
        public async Task InitializeSessionAsync_ShouldCreateSessionState()
        {
            // Arrange
            var rootKey = new byte[] { 1, 2, 3 };
            var sendingRatchetKey = new byte[] { 4, 5, 6 };
            var receivingRatchetKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(It.Is<byte[]>(x => x.SequenceEqual(rootKey)), It.Is<byte[]>(x => x.SequenceEqual(new byte[] { 0x01 }))))
                .ReturnsAsync(sendingChainKey);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(It.Is<byte[]>(x => x.SequenceEqual(rootKey)), It.Is<byte[]>(x => x.SequenceEqual(new byte[] { 0x02 }))))
                .ReturnsAsync(receivingChainKey);

            // Act
            var result = await _doubleRatchetService.InitializeSessionAsync(rootKey, sendingRatchetKey, receivingRatchetKey);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(rootKey, result.RootKey);
            Assert.Equal(sendingRatchetKey, result.SendingRatchetKey);
            Assert.Equal(receivingRatchetKey, result.ReceivingRatchetKey);
            Assert.Equal(sendingChainKey, result.SendingChainKey);
            Assert.Equal(receivingChainKey, result.ReceivingChainKey);
        }

        [Fact]
        public async Task EncryptMessageAsync_ShouldEncryptMessageAndComputeHash()
        {
            // Arrange
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                new byte[] { 1, 2, 3 }, // Local identity key
                new byte[] { 4, 5, 6 }, // Remote identity key
                new byte[] { 7, 8, 9 }, // Root key
                new byte[] { 10, 11, 12 }, // Sending chain key
                new byte[] { 13, 14, 15 }, // Receiving chain key
                new byte[] { 16, 17, 18 }, // Sending ratchet key
                new byte[] { 19, 20, 21 }); // Receiving ratchet key

            var message = new byte[] { 1, 2, 3 };
            var encryptedContent = new byte[] { 4, 5, 6 };
            var mac = new byte[] { 7, 8, 9 };

            _encryptionServiceMock
                .Setup(x => x.EncryptAsync(
                    It.Is<byte[]>(x => x == message),
                    It.Is<byte[]>(x => x == sessionState.SendingChainKey)))
                .ReturnsAsync(encryptedContent);

            _hashServiceMock
                .Setup(x => x.ComputeKeyedHashAsync(
                    It.Is<byte[]>(x => x == encryptedContent),
                    It.Is<byte[]>(x => x == sessionState.SendingChainKey)))
                .ReturnsAsync(mac);

            // Act
            var (signalMessage, updatedState) = await _doubleRatchetService.EncryptMessageAsync(sessionState, message);

            // Assert
            Assert.NotNull(signalMessage);
            Assert.Equal(encryptedContent, signalMessage.Content);
            Assert.Equal(mac, signalMessage.Mac);
            Assert.Equal(sessionState.LocalIdentityKey, signalMessage.SenderIdentityKey);
            Assert.Equal(sessionState.SendingRatchetKey, signalMessage.SenderEphemeralKey);
            Assert.Equal(sessionState.SendingMessageNumber + 1, updatedState.SendingMessageNumber);
        }

        [Fact]
        public async Task DecryptMessageAsync_ShouldVerifyHashAndDecryptMessage()
        {
            // Arrange
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                new byte[] { 1, 2, 3 }, // Local identity key
                new byte[] { 4, 5, 6 }, // Remote identity key
                new byte[] { 7, 8, 9 }, // Root key
                new byte[] { 10, 11, 12 }, // Sending chain key
                new byte[] { 13, 14, 15 }, // Receiving chain key
                new byte[] { 16, 17, 18 }, // Sending ratchet key
                new byte[] { 19, 20, 21 }); // Receiving ratchet key

            var signalMessage = new SignalMessage(
                new byte[] { 1, 2, 3 }, // Content
                new byte[] { 4, 5, 6 }, // MAC
                new byte[] { 7, 8, 9 }, // IV
                sessionState.RemoteIdentityKey,
                sessionState.ReceivingRatchetKey)
            {
                Counter = 1,
                PreviousCounter = 0
            };

            var decryptedContent = new byte[] { 10, 11, 12 };

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(
                    It.Is<byte[]>(x => x == signalMessage.Content),
                    It.Is<byte[]>(x => x == sessionState.ReceivingChainKey),
                    It.Is<byte[]>(x => x == signalMessage.Mac)))
                .ReturnsAsync(true);

            _encryptionServiceMock
                .Setup(x => x.DecryptAsync(
                    It.Is<byte[]>(x => x == signalMessage.Content),
                    It.Is<byte[]>(x => x == sessionState.ReceivingChainKey)))
                .ReturnsAsync(decryptedContent);

            // Act
            var (result, updatedState) = await _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage);

            // Assert
            Assert.Equal(decryptedContent, result);
            Assert.Equal(signalMessage.Counter, updatedState.ReceivingMessageNumber);
        }

        [Fact]
        public async Task DecryptMessageAsync_ShouldThrowIfHashVerificationFails()
        {
            // Arrange
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                new byte[] { 1, 2, 3 }, // Local identity key
                new byte[] { 4, 5, 6 }, // Remote identity key
                new byte[] { 7, 8, 9 }, // Root key
                new byte[] { 10, 11, 12 }, // Sending chain key
                new byte[] { 13, 14, 15 }, // Receiving chain key
                new byte[] { 16, 17, 18 }, // Sending ratchet key
                new byte[] { 19, 20, 21 }); // Receiving ratchet key

            var signalMessage = new SignalMessage(
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                sessionState.RemoteIdentityKey,
                sessionState.ReceivingRatchetKey);

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(
                    It.Is<byte[]>(x => x == signalMessage.Content),
                    It.Is<byte[]>(x => x == sessionState.ReceivingChainKey),
                    It.Is<byte[]>(x => x == signalMessage.Mac)))
                .ReturnsAsync(false);

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage));
        }

        [Fact]
        public async Task RatchetSendingAsync_ShouldUpdateChainKeys()
        {
            // Arrange
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                new byte[] { 1, 2, 3 }, // Local identity key
                new byte[] { 4, 5, 6 }, // Remote identity key
                new byte[] { 7, 8, 9 }, // Root key
                new byte[] { 10, 11, 12 }, // Sending chain key
                new byte[] { 13, 14, 15 }, // Receiving chain key
                new byte[] { 16, 17, 18 }, // Sending ratchet key
                new byte[] { 19, 20, 21 }); // Receiving ratchet key

            var newRatchetPublicKey = new byte[] { 1, 2, 3 };
            var newRatchetPrivateKey = new byte[] { 4, 5, 6 };
            var newSendingChainKey = new byte[] { 7, 8, 9 };
            var sharedSecret = new byte[] { 10, 11, 12 };

            _keyExchangeServiceMock
                .Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((newRatchetPublicKey, newRatchetPrivateKey));

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(
                    It.Is<byte[]>(x => x == newRatchetPrivateKey),
                    It.Is<byte[]>(x => x == sessionState.ReceivingRatchetKey)))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(It.Is<byte[]>(x => x == sharedSecret), It.IsAny<byte[]>()))
                .ReturnsAsync(newSendingChainKey);

            // Act
            var result = await _doubleRatchetService.RatchetSendingAsync(sessionState);

            // Assert
            Assert.Equal(newRatchetPublicKey, result.SendingRatchetKey);
            Assert.Equal(newSendingChainKey, result.SendingChainKey);
            Assert.Equal(0u, result.SendingMessageNumber);
        }

        [Fact]
        public async Task RatchetReceivingAsync_ShouldUpdateChainKeys()
        {
            // Arrange
            var sessionState = new SessionState(
                Guid.NewGuid().ToString(),
                new byte[] { 1, 2, 3 }, // Local identity key
                new byte[] { 4, 5, 6 }, // Remote identity key
                new byte[] { 7, 8, 9 }, // Root key
                new byte[] { 10, 11, 12 }, // Sending chain key
                new byte[] { 13, 14, 15 }, // Receiving chain key
                new byte[] { 16, 17, 18 }, // Sending ratchet key
                new byte[] { 19, 20, 21 }); // Receiving ratchet key

            var newRatchetKey = new byte[] { 1, 2, 3 };
            var newReceivingChainKey = new byte[] { 4, 5, 6 };
            var sharedSecret = new byte[] { 7, 8, 9 };

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(
                    It.Is<byte[]>(x => x == sessionState.SendingRatchetKey),
                    It.Is<byte[]>(x => x == newRatchetKey)))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(It.Is<byte[]>(x => x == sharedSecret), It.IsAny<byte[]>()))
                .ReturnsAsync(newReceivingChainKey);

            // Act
            var result = await _doubleRatchetService.RatchetReceivingAsync(sessionState, newRatchetKey);

            // Assert
            Assert.Equal(newRatchetKey, result.ReceivingRatchetKey);
            Assert.Equal(newReceivingChainKey, result.ReceivingChainKey);
            Assert.Equal(0u, result.ReceivingMessageNumber);
        }
    }
} 