using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SignalSharp.Core;
using SignalSharp.Core.Options;
using SignalSharp.Security;
using Xunit;

namespace SignalSharp.DependencyInjection.Tests
{
    public class SignalSharpFactoryTests
    {
        [Fact]
        public void CreateDefault_CreatesFactoryWithDefaultOptions()
        {
            // Arrange
            var baseDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            try
            {
                // Act
                var factory = SignalSharpFactory.CreateDefault(baseDirectory);

                // Assert
                Assert.NotNull(factory);
            }
            finally
            {
                // Cleanup
                if (Directory.Exists(baseDirectory))
                {
                    Directory.Delete(baseDirectory, true);
                }
            }
        }

        [Fact]
        public void CreateDefault_WithEmptyBaseDirectory_ThrowsArgumentException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                SignalSharpFactory.CreateDefault(string.Empty);
            });

            Assert.Equal("Base directory cannot be null or empty. (Parameter 'baseDirectory')", exception.Message);
        }

        [Fact]
        public void CreateDefault_WithNullBaseDirectory_ThrowsArgumentNullException()
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                SignalSharpFactory.CreateDefault(null);
            });

            Assert.Equal("baseDirectory", exception.ParamName);
        }

        [Fact]
        public async Task CreateIdentityKeyPairAsync_CreatesIdentityKeyPair()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);

            // Act
            var identityKeyPair = await factory.CreateIdentityKeyPairAsync();

            // Assert
            Assert.NotNull(identityKeyPair);
            Assert.NotNull(identityKeyPair.PublicKey);
            Assert.NotNull(identityKeyPair.PrivateKey);
            Assert.True(identityKeyPair.PublicKey.Length > 0);
            Assert.True(identityKeyPair.PrivateKey.Length > 0);
        }

        [Fact]
        public async Task CreateSignedPreKeyPairAsync_CreatesSignedPreKeyPair()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);

            // Act
            var signedPreKeyPair = await factory.CreateSignedPreKeyPairAsync();

            // Assert
            Assert.NotNull(signedPreKeyPair);
            Assert.NotNull(signedPreKeyPair.PublicKey);
            Assert.NotNull(signedPreKeyPair.PrivateKey);
            Assert.True(signedPreKeyPair.PublicKey.Length > 0);
            Assert.True(signedPreKeyPair.PrivateKey.Length > 0);
        }

        [Fact]
        public async Task CreateOneTimePreKeyPairAsync_CreatesOneTimePreKeyPair()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);

            // Act
            var oneTimePreKeyPair = await factory.CreateOneTimePreKeyPairAsync();

            // Assert
            Assert.NotNull(oneTimePreKeyPair);
            Assert.NotNull(oneTimePreKeyPair.PublicKey);
            Assert.NotNull(oneTimePreKeyPair.PrivateKey);
            Assert.True(oneTimePreKeyPair.PublicKey.Length > 0);
            Assert.True(oneTimePreKeyPair.PrivateKey.Length > 0);
        }

        [Fact]
        public async Task CreateSessionAsync_CreatesSession()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);
            var identityKeyPair = await factory.CreateIdentityKeyPairAsync();

            // Act
            var sessionState = await factory.CreateSessionAsync("test-recipient", identityKeyPair);

            // Assert
            Assert.NotNull(sessionState);
            Assert.NotNull(sessionState.SessionId);
            Assert.True(sessionState.SessionId.Length > 0);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithInvalidParameters_ThrowsArgumentException()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await factory.EncryptMessageAsync(null, new byte[] { 1, 2, 3 });
            });

            Assert.Equal("recipientId", exception.ParamName);
        }

        [Fact]
        public async Task EncryptMessageAsync_EncryptsMessage()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);
            var identityKeyPair = await factory.CreateIdentityKeyPairAsync();
            var sessionState = await factory.CreateSessionAsync("test-recipient", identityKeyPair);

            // Act
            var encryptedMessage = await factory.EncryptMessageAsync("test-recipient", new byte[] { 1, 2, 3 });

            // Assert
            Assert.NotNull(encryptedMessage);
            Assert.True(encryptedMessage.Length > 0);
        }

        [Fact]
        public async Task DecryptMessageAsync_WithInvalidParameters_ThrowsArgumentException()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await factory.DecryptMessageAsync(null, new byte[] { 1, 2, 3 });
            });

            Assert.Equal("senderId", exception.ParamName);
        }

        [Fact]
        public async Task DecryptMessageAsync_DecryptsMessage()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSignalSharp(options => { });
            var serviceProvider = services.BuildServiceProvider();
            var options = serviceProvider.GetRequiredService<IOptions<SignalSharpOptions>>();
            var factory = new SignalSharpFactory(serviceProvider, options);
            var identityKeyPair = await factory.CreateIdentityKeyPairAsync();
            var sessionState = await factory.CreateSessionAsync("test-recipient", identityKeyPair);
            var message = new byte[] { 1, 2, 3 };
            var encryptedMessage = await factory.EncryptMessageAsync("test-recipient", message);

            // Act
            var decryptedMessage = await factory.DecryptMessageAsync("test-recipient", encryptedMessage);

            // Assert
            Assert.NotNull(decryptedMessage);
            Assert.Equal(message, decryptedMessage);
        }
    }
} 