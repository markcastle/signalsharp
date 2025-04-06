using System;
using System.Threading.Tasks;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for implementing the Double Ratchet algorithm in the Signal protocol.
    /// This service handles the continuous key rotation and message encryption/decryption.
    /// </summary>
    public interface IDoubleRatchetService
    {
        /// <summary>
        /// Initializes a new ratchet session with the provided keys.
        /// </summary>
        /// <param name="rootKey">The root key derived from X3DH.</param>
        /// <param name="sendingRatchetKey">The initial sending ratchet key.</param>
        /// <param name="receivingRatchetKey">The initial receiving ratchet key.</param>
        /// <returns>A new session state with initialized ratchet chains.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        Task<SessionState> InitializeSessionAsync(byte[] rootKey, byte[] sendingRatchetKey, byte[] receivingRatchetKey);

        /// <summary>
        /// Encrypts a message using the current sending chain.
        /// </summary>
        /// <param name="sessionState">The current session state.</param>
        /// <param name="message">The message to encrypt.</param>
        /// <returns>A tuple containing the encrypted message and updated session state.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        Task<(SignalMessage Message, SessionState UpdatedState)> EncryptMessageAsync(SessionState sessionState, byte[] message);

        /// <summary>
        /// Decrypts a message using the current receiving chain.
        /// </summary>
        /// <param name="sessionState">The current session state.</param>
        /// <param name="message">The message to decrypt.</param>
        /// <returns>A tuple containing the decrypted message and updated session state.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when message decryption fails.</exception>
        Task<(byte[] DecryptedMessage, SessionState UpdatedState)> DecryptMessageAsync(SessionState sessionState, SignalMessage message);

        /// <summary>
        /// Performs a sending ratchet step, generating new chain keys.
        /// </summary>
        /// <param name="sessionState">The current session state.</param>
        /// <returns>The updated session state with new chain keys.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sessionState is null.</exception>
        Task<SessionState> RatchetSendingAsync(SessionState sessionState);

        /// <summary>
        /// Performs a receiving ratchet step, generating new chain keys.
        /// </summary>
        /// <param name="sessionState">The current session state.</param>
        /// <param name="newRatchetKey">The new ratchet key received from the remote party.</param>
        /// <returns>The updated session state with new chain keys.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        Task<SessionState> RatchetReceivingAsync(SessionState sessionState, byte[] newRatchetKey);
    }
} 