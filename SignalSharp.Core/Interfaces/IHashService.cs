using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for cryptographic hashing operations.
    /// </summary>
    public interface IHashService
    {
        /// <summary>
        /// Computes a hash of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>The computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data is null.</exception>
        Task<byte[]> ComputeHashAsync(byte[] data);

        /// <summary>
        /// Computes a keyed hash (HMAC) of the specified data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="key">The key to use for the HMAC.</param>
        /// <returns>The computed keyed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data or key is null.</exception>
        Task<byte[]> ComputeKeyedHashAsync(byte[] data, byte[] key);

        /// <summary>
        /// Verifies that the specified hash matches the computed hash of the data.
        /// </summary>
        /// <param name="data">The data to verify.</param>
        /// <param name="hash">The hash to verify against.</param>
        /// <returns>True if the hash matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data or hash is null.</exception>
        Task<bool> VerifyHashAsync(byte[] data, byte[] hash);

        /// <summary>
        /// Verifies that the specified keyed hash matches the computed keyed hash of the data.
        /// </summary>
        /// <param name="data">The data to verify.</param>
        /// <param name="key">The key used for the HMAC.</param>
        /// <param name="hash">The hash to verify against.</param>
        /// <returns>True if the hash matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data, key, or hash is null.</exception>
        Task<bool> VerifyKeyedHashAsync(byte[] data, byte[] key, byte[] hash);
    }
} 