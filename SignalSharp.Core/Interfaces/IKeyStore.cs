using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for storing and retrieving cryptographic keys.
    /// </summary>
    public interface IKeyStore
    {
        /// <summary>
        /// Stores a key with the specified identifier.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to store.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when keyId or key is null.</exception>
        Task StoreKeyAsync(string keyId, byte[] key);

        /// <summary>
        /// Retrieves a key by its identifier.
        /// </summary>
        /// <param name="keyId">The identifier of the key to retrieve.</param>
        /// <returns>The retrieved key, or null if not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when keyId is null.</exception>
        Task<byte[]> GetKeyAsync(string keyId);

        /// <summary>
        /// Deletes a key by its identifier.
        /// </summary>
        /// <param name="keyId">The identifier of the key to delete.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when keyId is null.</exception>
        Task DeleteKeyAsync(string keyId);

        /// <summary>
        /// Checks if a key exists for the specified identifier.
        /// </summary>
        /// <param name="keyId">The identifier to check.</param>
        /// <returns>True if the key exists, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when keyId is null.</exception>
        Task<bool> KeyExistsAsync(string keyId);
    }
} 