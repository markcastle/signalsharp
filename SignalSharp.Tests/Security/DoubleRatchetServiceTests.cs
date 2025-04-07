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
        private readonly Mock<IEcKeyExchangeService> _keyExchangeServiceMock;
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly Mock<IHashService> _hashServiceMock;
        private readonly IDoubleRatchetService _doubleRatchetService;

        public DoubleRatchetServiceTests()
        {
            _keyExchangeServiceMock = new Mock<IEcKeyExchangeService>();
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
            var sharedSecret = new byte[] { 10, 11, 12 };
            var sendingChainKey = new byte[] { 13, 14, 15 };
            var receivingChainKey = new byte[] { 16, 17, 18 };

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((sendingRatchetKey, sendingRatchetKey));

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    It.Is<byte[]>(k => k.SequenceEqual(rootKey.Concat(sharedSecret).ToArray())),
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "sending"),
                    32))
                .ReturnsAsync(sendingChainKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    It.Is<byte[]>(k => k.SequenceEqual(rootKey.Concat(sharedSecret).ToArray())),
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "receiving"),
                    32))
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
            var sessionId = "test-session";
            var localIdentityKey = new byte[] { 1, 2, 3 };
            var remoteIdentityKey = new byte[] { 4, 5, 6 };
            var rootKey = new byte[] { 7, 8, 9 };
            var sendingChainKey = new byte[] { 10, 11, 12 };
            var receivingChainKey = new byte[] { 13, 14, 15 };
            var sendingRatchetKey = new byte[] { 16, 17, 18 };
            var receivingRatchetKey = new byte[] { 19, 20, 21 };
            var message = new byte[] { 22, 23, 24 };
            var ciphertext = new byte[] { 25, 26, 27 };
            var mac = new byte[] { 28, 29, 30 };
            var sharedSecret = new byte[] { 31, 32, 33 };

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            var newChainKey = new byte[] { 34, 35, 36 };
            var messageKey = new byte[] { 37, 38, 39 };

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    sendingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "message_0"),
                    32))
                .ReturnsAsync(messageKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    sendingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "chain"),
                    32))
                .ReturnsAsync(newChainKey);

            _encryptionServiceMock
                .Setup(x => x.EncryptAsync(message, messageKey))
                .ReturnsAsync(ciphertext);

            _hashServiceMock
                .Setup(x => x.ComputeKeyedHashAsync(ciphertext, sendingChainKey))
                .ReturnsAsync(mac);

            var signalMessage = new SignalMessage
            {
                Ciphertext = ciphertext,
                MessageNumber = 0,
                RatchetKey = sendingRatchetKey
            };

            // Act
            var (result, updatedState) = await _doubleRatchetService.EncryptMessageAsync(sessionState, message);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(ciphertext, result.Ciphertext);
            Assert.Equal((uint)0, result.MessageNumber);
            Assert.Equal(sendingRatchetKey, result.RatchetKey);
            Assert.Equal(newChainKey, updatedState.SendingChainKey);
            Assert.Equal(receivingChainKey, updatedState.ReceivingChainKey);
        }

        [Fact]
        public async Task DecryptMessageAsync_ShouldVerifyHashAndDecryptMessage()
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
            var ciphertext = new byte[] { 22, 23, 24 };
            var mac = new byte[] { 25, 26, 27 };
            var messageKey = new byte[] { 37, 38, 39 };
            var newChainKey = new byte[] { 34, 35, 36 };
            var plaintext = new byte[] { 40, 41, 42 };

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(new byte[] { 31, 32, 33 });

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    receivingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "message_0"),
                    32))
                .ReturnsAsync(messageKey);

            _hashServiceMock
                .Setup(x => x.DeriveKeyAsync(
                    receivingChainKey,
                    It.Is<byte[]>(p => System.Text.Encoding.UTF8.GetString(p) == "chain"),
                    32))
                .ReturnsAsync(newChainKey);

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(ciphertext, messageKey, mac))
                .ReturnsAsync(true);

            _encryptionServiceMock
                .Setup(x => x.DecryptAsync(ciphertext, messageKey))
                .ReturnsAsync(plaintext);

            var signalMessage = new SignalMessage
            {
                Ciphertext = ciphertext,
                Mac = mac,
                MessageNumber = 0,
                RatchetKey = receivingRatchetKey
            };

            // Act
            var (decryptedMessage, updatedState) = await _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage);

            // Assert
            Assert.NotNull(decryptedMessage);
            Assert.Equal(plaintext, decryptedMessage);
            Assert.Equal(newChainKey, updatedState.ReceivingChainKey);
            Assert.Equal(sendingChainKey, updatedState.SendingChainKey);
        }

        [Fact]
        public async Task DecryptMessageAsync_ShouldThrowIfHashVerificationFails()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[32];
            var remoteIdentityKey = new byte[32];
            var rootKey = new byte[32];
            var sendingChainKey = new byte[32];
            var receivingChainKey = new byte[32];
            var sendingRatchetKey = new byte[32];
            var receivingRatchetKey = new byte[32];
            var ciphertext = new byte[32];
            var mac = new byte[32];
            var sharedSecret = new byte[32];
            var newChainKey = new byte[32];

            // Initialize the arrays with non-zero values
            new Random().NextBytes(localIdentityKey);
            new Random().NextBytes(remoteIdentityKey);
            new Random().NextBytes(rootKey);
            new Random().NextBytes(sendingChainKey);
            new Random().NextBytes(receivingChainKey);
            new Random().NextBytes(sendingRatchetKey);
            new Random().NextBytes(receivingRatchetKey);
            new Random().NextBytes(ciphertext);
            new Random().NextBytes(mac);
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(newChainKey);

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(sendingRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(sharedSecret, receivingRatchetKey))
                .ReturnsAsync(newChainKey);

            _hashServiceMock
                .Setup(x => x.VerifyKeyedHashAsync(ciphertext, newChainKey, mac))
                .ReturnsAsync(false);

            var signalMessage = new SignalMessage
            {
                Ciphertext = ciphertext,
                Mac = mac,
                SenderIdentityKey = remoteIdentityKey,
                SenderEphemeralKey = receivingRatchetKey,
                MessageNumber = 0,
                RatchetKey = receivingRatchetKey
            };

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _doubleRatchetService.DecryptMessageAsync(sessionState, signalMessage));
        }

        [Fact]
        public async Task RatchetSendingAsync_ShouldUpdateChainKeys()
        {
            // Arrange
            var sessionId = "test-session";
            var localIdentityKey = new byte[32];
            var remoteIdentityKey = new byte[32];
            var rootKey = new byte[32];
            var sendingChainKey = new byte[32];
            var receivingChainKey = new byte[32];
            var sendingRatchetKey = new byte[32];
            var receivingRatchetKey = new byte[32];
            var newRatchetKey = new byte[32];
            var sharedSecret = new byte[32];
            var newSendingChainKey = new byte[32];
            var newReceivingChainKey = new byte[32];

            // Initialize the arrays with non-zero values
            new Random().NextBytes(localIdentityKey);
            new Random().NextBytes(remoteIdentityKey);
            new Random().NextBytes(rootKey);
            new Random().NextBytes(sendingChainKey);
            new Random().NextBytes(receivingChainKey);
            new Random().NextBytes(sendingRatchetKey);
            new Random().NextBytes(receivingRatchetKey);
            new Random().NextBytes(newRatchetKey);
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(newSendingChainKey);
            new Random().NextBytes(newReceivingChainKey);

            var sessionState = new SessionState(
                sessionId,
                localIdentityKey,
                remoteIdentityKey,
                rootKey,
                sendingChainKey,
                receivingChainKey,
                sendingRatchetKey,
                receivingRatchetKey);

            _keyExchangeServiceMock
                .Setup(x => x.GenerateKeyPairAsync())
                .ReturnsAsync((newRatchetKey, newRatchetKey));

            _keyExchangeServiceMock
                .Setup(x => x.ComputeSharedSecretAsync(newRatchetKey, receivingRatchetKey))
                .ReturnsAsync(sharedSecret);

            _keyExchangeServiceMock
                .Setup(x => x.DeriveSymmetricKeyAsync(sharedSecret, newRatchetKey))
                .ReturnsAsync(newSendingChainKey);

            // Act
            var result = await _doubleRatchetService.RatchetSendingAsync(sessionState);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(rootKey, result.RootKey);
            Assert.Equal(newSendingChainKey, result.SendingChainKey);
            Assert.Equal(receivingChainKey, result.ReceivingChainKey);
            Assert.Equal(newRatchetKey, result.SendingRatchetKey);
            Assert.Equal(receivingRatchetKey, result.ReceivingRatchetKey);
        }
    }
} 