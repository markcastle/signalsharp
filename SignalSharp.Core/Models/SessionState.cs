using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents the state of a Signal protocol session.
    /// </summary>
    public class SessionState
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SessionState"/> class.
        /// </summary>
        /// <param name="sessionId">The unique identifier for the session.</param>
        /// <param name="localIdentityKey">The local identity key.</param>
        /// <param name="remoteIdentityKey">The remote identity key.</param>
        /// <param name="rootKey">The root key used in the ratchet.</param>
        /// <param name="sendingChainKey">The sending chain key.</param>
        /// <param name="receivingChainKey">The receiving chain key.</param>
        /// <param name="sendingRatchetKey">The sending ratchet key.</param>
        /// <param name="receivingRatchetKey">The receiving ratchet key.</param>
        public SessionState(
            string sessionId,
            byte[] localIdentityKey,
            byte[] remoteIdentityKey,
            byte[] rootKey,
            byte[] sendingChainKey,
            byte[] receivingChainKey,
            byte[] sendingRatchetKey,
            byte[] receivingRatchetKey)
        {
            SessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
            LocalIdentityKey = localIdentityKey ?? throw new ArgumentNullException(nameof(localIdentityKey));
            RemoteIdentityKey = remoteIdentityKey ?? throw new ArgumentNullException(nameof(remoteIdentityKey));
            RootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));
            SendingChainKey = sendingChainKey ?? throw new ArgumentNullException(nameof(sendingChainKey));
            ReceivingChainKey = receivingChainKey ?? throw new ArgumentNullException(nameof(receivingChainKey));
            SendingRatchetKey = sendingRatchetKey ?? throw new ArgumentNullException(nameof(sendingRatchetKey));
            ReceivingRatchetKey = receivingRatchetKey ?? throw new ArgumentNullException(nameof(receivingRatchetKey));
            CreatedAt = DateTime.UtcNow;
            LastUsedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Gets the unique identifier for the session.
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Gets the local identity key.
        /// </summary>
        public byte[] LocalIdentityKey { get; }

        /// <summary>
        /// Gets the remote identity key.
        /// </summary>
        public byte[] RemoteIdentityKey { get; }

        /// <summary>
        /// Gets the root key used in the ratchet.
        /// </summary>
        public byte[] RootKey { get; }

        /// <summary>
        /// Gets the sending chain key.
        /// </summary>
        public byte[] SendingChainKey { get; }

        /// <summary>
        /// Gets the receiving chain key.
        /// </summary>
        public byte[] ReceivingChainKey { get; }

        /// <summary>
        /// Gets the sending ratchet key.
        /// </summary>
        public byte[] SendingRatchetKey { get; }

        /// <summary>
        /// Gets the receiving ratchet key.
        /// </summary>
        public byte[] ReceivingRatchetKey { get; }

        /// <summary>
        /// Gets or sets the current sending message number.
        /// </summary>
        public uint SendingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the current receiving message number.
        /// </summary>
        public uint ReceivingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the previous sending message number.
        /// </summary>
        public uint PreviousSendingMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the previous receiving message number.
        /// </summary>
        public uint PreviousReceivingMessageNumber { get; set; }

        /// <summary>
        /// Gets the timestamp when the session was created.
        /// </summary>
        public DateTime CreatedAt { get; }

        /// <summary>
        /// Gets or sets the timestamp when the session was last used.
        /// </summary>
        public DateTime LastUsedAt { get; set; }
    }
} 