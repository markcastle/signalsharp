using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Storage.Services
{
    /// <summary>
    /// Implementation of IKeyStore that stores keys in the file system.
    /// </summary>
    public class FileKeyStore : IKeyStore
    {
        private readonly string _storageDirectory;
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IEncryptionService _encryptionService;
        private const string IdentityKeyId = "identity";
        private const string KeyVersionPrefix = "v1_";

        /// <summary>
        /// Initializes a new instance of the <see cref="FileKeyStore"/> class.
        /// </summary>
        /// <param name="storageDirectory">The base directory where keys will be stored.</param>
        /// <param name="jsonSerializer">The JSON serializer to use for session state serialization.</param>
        /// <param name="encryptionService">The encryption service to use for key encryption.</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public FileKeyStore(string storageDirectory, IJsonSerializer jsonSerializer, IEncryptionService encryptionService)
        {
            if (string.IsNullOrEmpty(storageDirectory))
                throw new ArgumentNullException(nameof(storageDirectory));
            if (jsonSerializer == null)
                throw new ArgumentNullException(nameof(jsonSerializer));
            if (encryptionService == null)
                throw new ArgumentNullException(nameof(encryptionService));

            _storageDirectory = storageDirectory;
            _jsonSerializer = jsonSerializer;
            _encryptionService = encryptionService;
            Directory.CreateDirectory(_storageDirectory);
            Directory.CreateDirectory(Path.Combine(_storageDirectory, "sessions"));
        }

        /// <inheritdoc/>
        public async Task StoreKeyAsync(string keyId, byte[] key)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{keyId}.key");
            var encryptedKey = await _encryptionService.EncryptAsync(key, await GetMasterKeyAsync());
            await File.WriteAllBytesAsync(filePath, encryptedKey);
        }

        /// <inheritdoc/>
        public async Task<byte[]?> GetKeyAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{keyId}.key");
            if (!File.Exists(filePath))
                return null;

            var encryptedKey = await File.ReadAllBytesAsync(filePath);
            return await _encryptionService.DecryptAsync(encryptedKey, await GetMasterKeyAsync());
        }

        /// <inheritdoc/>
        public async Task DeleteKeyAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{keyId}.key");
            if (File.Exists(filePath))
            {
                // Securely delete the file by overwriting it with random data before deletion
                var fileInfo = new FileInfo(filePath);
                var random = new byte[fileInfo.Length];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(random);
                }
                await File.WriteAllBytesAsync(filePath, random);
                await Task.Run(() => File.Delete(filePath));
            }
        }

        /// <inheritdoc/>
        public Task<bool> KeyExistsAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{keyId}.key");
            return Task.FromResult(File.Exists(filePath));
        }

        /// <inheritdoc/>
        public async Task<byte[]?> GetIdentityKeyAsync()
        {
            return await GetKeyAsync(IdentityKeyId);
        }

        /// <inheritdoc/>
        public async Task<KeyPair> GenerateEphemeralKeyPairAsync()
        {
            var publicKey = await _encryptionService.GenerateKeyAsync();
            var privateKey = await _encryptionService.GenerateKeyAsync();
            return new KeyPair(publicKey, privateKey);
        }

        /// <inheritdoc/>
        public async Task StoreSessionStateAsync(string sessionId, SessionState sessionState)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));
            if (sessionState == null)
                throw new ArgumentNullException(nameof(sessionState));

            var filePath = Path.Combine(_storageDirectory, "sessions", $"{KeyVersionPrefix}{sessionId}.json");
            var json = _jsonSerializer.Serialize(sessionState);
            var encryptedJson = await _encryptionService.EncryptAsync(
                System.Text.Encoding.UTF8.GetBytes(json),
                await GetMasterKeyAsync());
            await File.WriteAllBytesAsync(filePath, encryptedJson);
        }

        /// <inheritdoc/>
        public async Task<SessionState?> GetSessionStateAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            var filePath = Path.Combine(_storageDirectory, "sessions", $"{KeyVersionPrefix}{sessionId}.json");
            if (!File.Exists(filePath))
                return null;

            var encryptedJson = await File.ReadAllBytesAsync(filePath);
            var json = System.Text.Encoding.UTF8.GetString(
                await _encryptionService.DecryptAsync(encryptedJson, await GetMasterKeyAsync()));
            return _jsonSerializer.Deserialize<SessionState>(json);
        }

        /// <inheritdoc/>
        public async Task DeleteSessionStateAsync(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentNullException(nameof(sessionId));

            var filePath = Path.Combine(_storageDirectory, "sessions", $"{KeyVersionPrefix}{sessionId}.json");
            if (File.Exists(filePath))
            {
                // Securely delete the file by overwriting it with random data before deletion
                var fileInfo = new FileInfo(filePath);
                var random = new byte[fileInfo.Length];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(random);
                }
                await File.WriteAllBytesAsync(filePath, random);
                await Task.Run(() => File.Delete(filePath));
            }
        }

        /// <inheritdoc/>
        public async Task<string?> GetAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{key}.json");
            if (!File.Exists(filePath))
                return null;

            var encryptedJson = await File.ReadAllBytesAsync(filePath);
            var json = System.Text.Encoding.UTF8.GetString(
                await _encryptionService.DecryptAsync(encryptedJson, await GetMasterKeyAsync()));
            return json;
        }

        /// <inheritdoc/>
        public async Task SetAsync(string key, string value)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{key}.json");
            var encryptedJson = await _encryptionService.EncryptAsync(
                System.Text.Encoding.UTF8.GetBytes(value),
                await GetMasterKeyAsync());
            await File.WriteAllBytesAsync(filePath, encryptedJson);
        }

        /// <inheritdoc/>
        public async Task DeleteAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            var filePath = Path.Combine(_storageDirectory, $"{KeyVersionPrefix}{key}.json");
            if (File.Exists(filePath))
            {
                // Securely delete the file by overwriting it with random data before deletion
                var fileInfo = new FileInfo(filePath);
                var random = new byte[fileInfo.Length];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(random);
                }
                await File.WriteAllBytesAsync(filePath, random);
                await Task.Run(() => File.Delete(filePath));
            }
        }

        private async Task<byte[]> GetMasterKeyAsync()
        {
            var masterKeyPath = Path.Combine(_storageDirectory, "master.key");
            if (!File.Exists(masterKeyPath))
            {
                var masterKey = await _encryptionService.GenerateKeyAsync();
                await File.WriteAllBytesAsync(masterKeyPath, masterKey);
                return masterKey;
            }
            return await File.ReadAllBytesAsync(masterKeyPath);
        }
    }
} 