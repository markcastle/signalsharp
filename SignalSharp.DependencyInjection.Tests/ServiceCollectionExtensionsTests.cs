using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using SignalSharp.Core;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Options;
using SignalSharp.Security;
using SignalSharp.Security.Services;
using SignalSharp.Storage;
using SignalSharp.Storage.Services;
using SignalSharp.Serialization.SystemTextJson;
using SignalSharp.Serialization.NewtonsoftJson;
using Xunit;

namespace SignalSharp.DependencyInjection.Tests
{
    public class ServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddSignalSharp_RegistersRequiredServices()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSignalSharp(options => { });

            // Assert
            var serviceProvider = services.BuildServiceProvider();

            // Check that all required services are registered
            Assert.NotNull(serviceProvider.GetService<IJsonSerializer>());
            Assert.NotNull(serviceProvider.GetService<IKeyStore>());
            Assert.NotNull(serviceProvider.GetService<IEncryptionService>());
            Assert.NotNull(serviceProvider.GetService<IKeyExchangeService>());
            Assert.NotNull(serviceProvider.GetService<IHashService>());
            Assert.NotNull(serviceProvider.GetService<IX3DHKeyAgreementService>());
            Assert.NotNull(serviceProvider.GetService<IDoubleRatchetService>());
            Assert.NotNull(serviceProvider.GetService<ISessionManager>());
            Assert.NotNull(serviceProvider.GetService<SignalSharpOptions>());
        }

        [Fact]
        public void AddSignalSharp_WithFileKeyStore_RegistersFileKeyStore()
        {
            // Arrange
            var services = new ServiceCollection();
            var keyStorePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            try
            {
                // Act
                services.AddSignalSharp(options =>
                {
                    options.KeyStoreOptions.Type = KeyStoreType.File;
                    options.KeyStoreOptions.Path = keyStorePath;
                });

                // Assert
                var serviceProvider = services.BuildServiceProvider();
                var keyStore = serviceProvider.GetService<IKeyStore>();

                Assert.NotNull(keyStore);
                Assert.IsType<FileKeyStore>(keyStore);
            }
            finally
            {
                // Cleanup
                if (Directory.Exists(keyStorePath))
                {
                    Directory.Delete(keyStorePath, true);
                }
            }
        }

        [Fact]
        public void AddSignalSharp_WithSystemTextJson_RegistersSystemTextJsonSerializer()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSignalSharp(options =>
            {
                options.JsonSerializerOptions.Type = JsonSerializerType.SystemTextJson;
            });

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            var jsonSerializer = serviceProvider.GetService<IJsonSerializer>();

            Assert.NotNull(jsonSerializer);
            Assert.IsType<SystemTextJsonSerializer>(jsonSerializer);
        }

        [Fact]
        public void AddSignalSharp_WithNewtonsoftJson_RegistersNewtonsoftJsonSerializer()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSignalSharp(options =>
            {
                options.JsonSerializerOptions.Type = JsonSerializerType.NewtonsoftJson;
            });

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            var jsonSerializer = serviceProvider.GetService<IJsonSerializer>();

            Assert.NotNull(jsonSerializer);
            Assert.IsType<NewtonsoftJsonSerializer>(jsonSerializer);
        }

        [Fact]
        public void AddSignalSharp_WithFileSessionManager_RegistersFileSessionManager()
        {
            // Arrange
            var services = new ServiceCollection();
            var sessionManagerPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            try
            {
                // Act
                services.AddSignalSharp(options =>
                {
                    options.SessionManagerOptions.Type = SessionManagerType.File;
                    options.SessionManagerOptions.Path = sessionManagerPath;
                });

                // Assert
                var serviceProvider = services.BuildServiceProvider();
                var sessionManager = serviceProvider.GetService<ISessionManager>();

                Assert.NotNull(sessionManager);
                Assert.IsType<FileSessionManager>(sessionManager);
            }
            finally
            {
                // Cleanup
                if (Directory.Exists(sessionManagerPath))
                {
                    Directory.Delete(sessionManagerPath, true);
                }
            }
        }

        [Fact]
        public void AddSignalSharp_WithCustomKeyStore_ThrowsIfFactoryNotProvided()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                services.AddSignalSharp(options =>
                {
                    options.KeyStoreOptions.Type = KeyStoreType.Custom;
                });
            });

            Assert.Equal("Custom key store type requires a factory to be specified.", exception.Message);
        }

        [Fact]
        public void AddSignalSharp_WithCustomJsonSerializer_ThrowsIfFactoryNotProvided()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                services.AddSignalSharp(options =>
                {
                    options.JsonSerializerOptions.Type = JsonSerializerType.Custom;
                });
            });

            Assert.Equal("Custom JSON serializer type requires a factory to be specified.", exception.Message);
        }

        [Fact]
        public void AddSignalSharp_WithCustomSessionManager_ThrowsIfFactoryNotProvided()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                services.AddSignalSharp(options =>
                {
                    options.SessionManagerOptions.Type = SessionManagerType.Custom;
                });
            });

            Assert.Equal("Custom session manager type requires a factory to be specified.", exception.Message);
        }

        [Fact]
        public void AddSignalSharp_WithCustomKeyStoreFactory_RegistersCustomKeyStore()
        {
            // Arrange
            var services = new ServiceCollection();
            var customKeyStore = new MockKeyStore();

            // Act
            services.AddSignalSharp(options =>
            {
                options.KeyStoreOptions.Type = KeyStoreType.Custom;
                options.KeyStoreOptions.KeyStoreFactory = _ => customKeyStore;
            });

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            var keyStore = serviceProvider.GetService<IKeyStore>();

            Assert.NotNull(keyStore);
            Assert.Same(customKeyStore, keyStore);
        }

        [Fact]
        public void AddSignalSharp_WithCustomJsonSerializerFactory_RegistersCustomJsonSerializer()
        {
            // Arrange
            var services = new ServiceCollection();
            var customJsonSerializer = new MockJsonSerializer();

            // Act
            services.AddSignalSharp(options =>
            {
                options.JsonSerializerOptions.Type = JsonSerializerType.Custom;
                options.JsonSerializerOptions.JsonSerializerFactory = _ => customJsonSerializer;
            });

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            var jsonSerializer = serviceProvider.GetService<IJsonSerializer>();

            Assert.NotNull(jsonSerializer);
            Assert.Same(customJsonSerializer, jsonSerializer);
        }

        [Fact]
        public void AddSignalSharp_WithCustomSessionManagerFactory_RegistersCustomSessionManager()
        {
            // Arrange
            var services = new ServiceCollection();
            var customSessionManager = new MockSessionManager();

            // Act
            services.AddSignalSharp(options =>
            {
                options.SessionManagerOptions.Type = SessionManagerType.Custom;
                options.SessionManagerOptions.SessionManagerFactory = _ => customSessionManager;
            });

            // Assert
            var serviceProvider = services.BuildServiceProvider();
            var sessionManager = serviceProvider.GetService<ISessionManager>();

            Assert.NotNull(sessionManager);
            Assert.Same(customSessionManager, sessionManager);
        }

        private class MockKeyStore : IKeyStore
        {
            public Task<byte[]> GetKeyAsync(string keyId)
            {
                return Task.FromResult(new byte[0]);
            }

            public Task StoreKeyAsync(string keyId, byte[] key)
            {
                return Task.CompletedTask;
            }

            public Task DeleteKeyAsync(string keyId)
            {
                return Task.CompletedTask;
            }

            public Task<bool> KeyExistsAsync(string keyId)
            {
                return Task.FromResult(false);
            }

            public Task<byte[]> GetIdentityKeyAsync()
            {
                return Task.FromResult(new byte[0]);
            }

            public Task<byte[]> GenerateEphemeralKeyPairAsync()
            {
                return Task.FromResult(new byte[0]);
            }

            public Task StoreSessionStateAsync(string sessionId, SessionState sessionState)
            {
                return Task.CompletedTask;
            }

            public Task<SessionState> GetSessionStateAsync(string sessionId)
            {
                return Task.FromResult<SessionState>(null);
            }

            public Task DeleteSessionStateAsync(string sessionId)
            {
                return Task.CompletedTask;
            }

            public Task<string?> GetAsync(string key)
            {
                return Task.FromResult<string?>(null);
            }

            public Task SetAsync(string key, string value)
            {
                return Task.CompletedTask;
            }

            public Task DeleteAsync(string key)
            {
                return Task.CompletedTask;
            }
        }

        private class MockJsonSerializer : IJsonSerializer
        {
            public T Deserialize<T>(string json) where T : class
            {
                return null;
            }

            public string Serialize<T>(T value) where T : class
            {
                return string.Empty;
            }

            public Task<T> DeserializeAsync<T>(string json) where T : class
            {
                return Task.FromResult<T>(null);
            }

            public Task<string> SerializeAsync<T>(T value) where T : class
            {
                return Task.FromResult(string.Empty);
            }
        }

        private class MockSessionManager : ISessionManager
        {
            public Task CreateSessionAsync(string sessionId, byte[] remoteIdentityKey, byte[] remoteSignedPreKey, byte[] remoteOneTimePreKey)
            {
                return Task.CompletedTask;
            }

            public Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] encryptedMessage)
            {
                return Task.FromResult(new byte[0]);
            }

            public Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message)
            {
                return Task.FromResult(new byte[0]);
            }

            public Task DeleteSessionAsync(string sessionId)
            {
                return Task.CompletedTask;
            }

            public Task<SessionState?> GetSessionStateAsync(string sessionId)
            {
                return Task.FromResult<SessionState?>(null);
            }

            public Task SaveSessionStateAsync(SessionState sessionState)
            {
                return Task.CompletedTask;
            }
        }
    }
} 