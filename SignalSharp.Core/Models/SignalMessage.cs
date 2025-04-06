using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents an encrypted message in the Signal protocol.
    /// </summary>
    public class SignalMessage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignalMessage"/> class.
        /// </summary>
        /// <param name="content">The encrypted message content.</param>
        /// <param name="mac">The message authentication code.</param>
        /// <param name="iv">The initialization vector used for encryption.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        /// <param name="senderEphemeralKey">The sender's ephemeral key.</param>
        public SignalMessage(
            byte[] content,
            byte[] mac,
            byte[] iv,
            byte[] senderIdentityKey,
            byte[] senderEphemeralKey)
        {
            Content = content ?? throw new ArgumentNullException(nameof(content));
            Mac = mac ?? throw new ArgumentNullException(nameof(mac));
            Iv = iv ?? throw new ArgumentNullException(nameof(iv));
            SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));
            SenderEphemeralKey = senderEphemeralKey ?? throw new ArgumentNullException(nameof(senderEphemeralKey));
        }

        /// <summary>
        /// Gets or sets the type of the message.
        /// </summary>
        public MessageType Type { get; set; }

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[] Content { get; }

        /// <summary>
        /// Gets or sets the message authentication code.
        /// </summary>
        public byte[] Mac { get; }

        /// <summary>
        /// Gets or sets the initialization vector used for encryption.
        /// </summary>
        public byte[] Iv { get; }

        /// <summary>
        /// Gets or sets the sender's identity key.
        /// </summary>
        public byte[] SenderIdentityKey { get; }

        /// <summary>
        /// Gets or sets the sender's ephemeral key.
        /// </summary>
        public byte[] SenderEphemeralKey { get; }

        /// <summary>
        /// Gets or sets the counter used in the ratchet.
        /// </summary>
        public uint Counter { get; set; }

        /// <summary>
        /// Gets or sets the previous counter value.
        /// </summary>
        public uint PreviousCounter { get; set; }
    }

    /// <summary>
    /// Defines the types of messages in the Signal protocol.
    /// </summary>
    public enum MessageType
    {
        /// <summary>
        /// Initial message in a new session.
        /// </summary>
        Initial,

        /// <summary>
        /// Regular encrypted message.
        /// </summary>
        Regular,

        /// <summary>
        /// Message containing a new ratchet key.
        /// </summary>
        Ratchet
    }
} 