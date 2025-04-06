using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents the state of a Signal protocol session.
    /// </summary>
    public class SessionState : IEquatable<SessionState>
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

            if (string.IsNullOrEmpty(sessionId))
                throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
            if (localIdentityKey.Length == 0)
                throw new ArgumentException("Local identity key cannot be empty.", nameof(localIdentityKey));
            if (remoteIdentityKey.Length == 0)
                throw new ArgumentException("Remote identity key cannot be empty.", nameof(remoteIdentityKey));
            if (rootKey.Length == 0)
                throw new ArgumentException("Root key cannot be empty.", nameof(rootKey));
            if (sendingChainKey.Length == 0)
                throw new ArgumentException("Sending chain key cannot be empty.", nameof(sendingChainKey));
            if (receivingChainKey.Length == 0)
                throw new ArgumentException("Receiving chain key cannot be empty.", nameof(receivingChainKey));
            if (sendingRatchetKey.Length == 0)
                throw new ArgumentException("Sending ratchet key cannot be empty.", nameof(sendingRatchetKey));
            if (receivingRatchetKey.Length == 0)
                throw new ArgumentException("Receiving ratchet key cannot be empty.", nameof(receivingRatchetKey));

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

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other">The object to compare with the current object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false.</returns>
        public bool Equals(SessionState other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return SessionId == other.SessionId &&
                   LocalIdentityKey.AsSpan().SequenceEqual(other.LocalIdentityKey) &&
                   RemoteIdentityKey.AsSpan().SequenceEqual(other.RemoteIdentityKey) &&
                   RootKey.AsSpan().SequenceEqual(other.RootKey) &&
                   SendingChainKey.AsSpan().SequenceEqual(other.SendingChainKey) &&
                   ReceivingChainKey.AsSpan().SequenceEqual(other.ReceivingChainKey) &&
                   SendingRatchetKey.AsSpan().SequenceEqual(other.SendingRatchetKey) &&
                   ReceivingRatchetKey.AsSpan().SequenceEqual(other.ReceivingRatchetKey) &&
                   SendingMessageNumber == other.SendingMessageNumber &&
                   ReceivingMessageNumber == other.ReceivingMessageNumber &&
                   PreviousSendingMessageNumber == other.PreviousSendingMessageNumber &&
                   PreviousReceivingMessageNumber == other.PreviousReceivingMessageNumber;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false.</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SessionState)obj);
        }

        /// <summary>
        /// Gets a hash code for the current object.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(SessionId);
            foreach (var b in LocalIdentityKey)
                hash.Add(b);
            foreach (var b in RemoteIdentityKey)
                hash.Add(b);
            foreach (var b in RootKey)
                hash.Add(b);
            foreach (var b in SendingChainKey)
                hash.Add(b);
            foreach (var b in ReceivingChainKey)
                hash.Add(b);
            foreach (var b in SendingRatchetKey)
                hash.Add(b);
            foreach (var b in ReceivingRatchetKey)
                hash.Add(b);
            hash.Add(SendingMessageNumber);
            hash.Add(ReceivingMessageNumber);
            hash.Add(PreviousSendingMessageNumber);
            hash.Add(PreviousReceivingMessageNumber);
            return hash.ToHashCode();
        }

        public static bool operator ==(SessionState left, SessionState right)
        {
            if (ReferenceEquals(left, null))
                return ReferenceEquals(right, null);
            return left.Equals(right);
        }

        public static bool operator !=(SessionState left, SessionState right)
        {
            return !(left == right);
        }
    }
} 