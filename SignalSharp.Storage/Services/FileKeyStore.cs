using System;
using System.IO;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Storage.Services
{
    /// <summary>
    /// Implementation of IKeyStore that stores keys in the file system.
    /// </summary>
    public class FileKeyStore : IKeyStore
    {
        private readonly string _storageDirectory;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileKeyStore"/> class.
        /// </summary>
        /// <param name="storageDirectory">The base directory where keys will be stored.</param>
        /// <exception cref="ArgumentNullException">Thrown when storageDirectory is null.</exception>
        public FileKeyStore(string storageDirectory)
        {
            if (string.IsNullOrEmpty(storageDirectory))
                throw new ArgumentNullException(nameof(storageDirectory));

            _storageDirectory = storageDirectory;
            Directory.CreateDirectory(_storageDirectory);
        }

        /// <inheritdoc/>
        public async Task StoreKeyAsync(string keyId, byte[] key)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var filePath = Path.Combine(_storageDirectory, $"{keyId}.key");
            await File.WriteAllBytesAsync(filePath, key);
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetKeyAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{keyId}.key");
            if (!File.Exists(filePath))
                return null!;

            return await File.ReadAllBytesAsync(filePath);
        }

        /// <inheritdoc/>
        public async Task DeleteKeyAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{keyId}.key");
            if (File.Exists(filePath))
            {
                await Task.Run(() => File.Delete(filePath));
            }
        }

        /// <inheritdoc/>
        public Task<bool> KeyExistsAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentNullException(nameof(keyId));

            var filePath = Path.Combine(_storageDirectory, $"{keyId}.key");
            return Task.FromResult(File.Exists(filePath));
        }
    }
} 