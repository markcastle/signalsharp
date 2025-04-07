using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents a decrypted message in the Signal protocol.
    /// </summary>
    public class DecryptedMessage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptedMessage"/> class.
        /// </summary>
        /// <param name="content">The decrypted message content.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        public DecryptedMessage(byte[] content, byte[] senderIdentityKey)
        {
            Content = content ?? throw new ArgumentNullException(nameof(content));
            SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));

            if (content.Length == 0)
                throw new ArgumentException("Content cannot be empty.", nameof(content));
            if (senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be empty.", nameof(senderIdentityKey));
        }

        /// <summary>
        /// Gets the decrypted message content.
        /// </summary>
        public byte[] Content { get; }

        /// <summary>
        /// Gets the sender's identity key.
        /// </summary>
        public byte[] SenderIdentityKey { get; }
    }
} 