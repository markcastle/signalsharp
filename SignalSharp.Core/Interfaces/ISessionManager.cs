using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for managing Signal protocol sessions.
    /// </summary>
    public interface ISessionManager
    {
        /// <summary>
        /// Creates a new session with a remote party.
        /// </summary>
        /// <param name="remoteIdentityKey">The remote party's identity key.</param>
        /// <param name="remotePreKey">The remote party's pre-key.</param>
        /// <param name="remotePreKeySignature">The signature of the remote party's pre-key.</param>
        /// <returns>The session ID for the newly created session.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey, byte[] remotePreKeySignature);

        /// <summary>
        /// Processes an incoming message and returns the decrypted content.
        /// </summary>
        /// <param name="sessionId">The ID of the session to use.</param>
        /// <param name="message">The encrypted message to process.</param>
        /// <returns>The decrypted message content.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId or message is null.</exception>
        Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] message);

        /// <summary>
        /// Encrypts a message for a specific session.
        /// </summary>
        /// <param name="sessionId">The ID of the session to use.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <returns>The encrypted message.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId or message is null.</exception>
        Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message);

        /// <summary>
        /// Deletes a session and its associated keys.
        /// </summary>
        /// <param name="sessionId">The ID of the session to delete.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
        Task DeleteSessionAsync(string sessionId);
    }
} 