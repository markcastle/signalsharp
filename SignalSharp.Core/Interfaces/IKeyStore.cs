using System;
using System.Threading.Tasks;
using SignalSharp.Core.Models;

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
        Task<byte[]?> GetKeyAsync(string keyId);

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

        /// <summary>
        /// Gets the identity key.
        /// </summary>
        /// <returns>The identity key, or null if not found.</returns>
        Task<byte[]?> GetIdentityKeyAsync();

        /// <summary>
        /// Generates a new ephemeral key pair.
        /// </summary>
        /// <returns>The generated ephemeral key pair.</returns>
        Task<KeyPair> GenerateEphemeralKeyPairAsync();

        /// <summary>
        /// Stores a session state.
        /// </summary>
        /// <param name="sessionId">The identifier for the session.</param>
        /// <param name="sessionState">The session state to store.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId or sessionState is null.</exception>
        Task StoreSessionStateAsync(string sessionId, SessionState sessionState);

        /// <summary>
        /// Gets a session state by its identifier.
        /// </summary>
        /// <param name="sessionId">The identifier of the session state to retrieve.</param>
        /// <returns>The retrieved session state, or null if not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
        Task<SessionState?> GetSessionStateAsync(string sessionId);

        /// <summary>
        /// Deletes a session state by its identifier.
        /// </summary>
        /// <param name="sessionId">The identifier of the session state to delete.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
        Task DeleteSessionStateAsync(string sessionId);

        /// <summary>
        /// Gets a value from the key store.
        /// </summary>
        /// <param name="key">The key to retrieve.</param>
        /// <returns>The value associated with the key, or null if not found.</returns>
        Task<string?> GetAsync(string key);

        /// <summary>
        /// Sets a value in the key store.
        /// </summary>
        /// <param name="key">The key to store.</param>
        /// <param name="value">The value to store.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task SetAsync(string key, string value);

        /// <summary>
        /// Deletes a value from the key store.
        /// </summary>
        /// <param name="key">The key to delete.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task DeleteAsync(string key);
    }
} 