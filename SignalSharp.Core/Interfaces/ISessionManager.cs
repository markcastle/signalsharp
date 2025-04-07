using SignalSharp.Core.Models;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for managing Signal protocol sessions.
    /// </summary>
    public interface ISessionManager
    {
        /// <summary>
        /// Creates a new session with a remote party.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="remoteIdentityKey">The remote party's identity key.</param>
        /// <param name="remoteSignedPreKey">The remote party's signed pre-key.</param>
        /// <param name="remoteOneTimePreKey">The remote party's one-time pre-key.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task CreateSessionAsync(string sessionId, byte[] remoteIdentityKey, byte[] remoteSignedPreKey, byte[] remoteOneTimePreKey);

        /// <summary>
        /// Processes an incoming message and returns the decrypted content.
        /// </summary>
        /// <param name="sessionId">The session ID.</param>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <returns>The decrypted message.</returns>
        Task<byte[]> ProcessIncomingMessageAsync(string sessionId, byte[] encryptedMessage);

        /// <summary>
        /// Encrypts a message for a specific session.
        /// </summary>
        /// <param name="sessionId">The session ID.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <returns>The encrypted message.</returns>
        Task<byte[]> EncryptMessageAsync(string sessionId, byte[] message);

        /// <summary>
        /// Deletes a session and its associated keys.
        /// </summary>
        /// <param name="sessionId">The session ID.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task DeleteSessionAsync(string sessionId);

        /// <summary>
        /// Gets the session state for a specific session.
        /// </summary>
        /// <param name="sessionId">The session ID.</param>
        /// <returns>The session state, or null if the session does not exist.</returns>
        Task<SessionState?> GetSessionStateAsync(string sessionId);

        /// <summary>
        /// Saves the session state for a specific session.
        /// </summary>
        /// <param name="sessionState">The session state to save.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        Task SaveSessionStateAsync(SessionState sessionState);
    }
} 