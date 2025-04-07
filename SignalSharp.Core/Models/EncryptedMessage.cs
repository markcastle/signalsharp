using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents an encrypted message in the Signal protocol.
    /// </summary>
    public class EncryptedMessage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedMessage"/> class.
        /// </summary>
        /// <param name="ciphertext">The encrypted message content.</param>
        /// <param name="mac">The message authentication code.</param>
        /// <param name="iv">The initialization vector used for encryption.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        /// <param name="senderEphemeralKey">The sender's ephemeral key.</param>
        public EncryptedMessage(
            byte[] ciphertext,
            byte[] mac,
            byte[] iv,
            byte[] senderIdentityKey,
            byte[] senderEphemeralKey)
        {
            Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
            Mac = mac ?? throw new ArgumentNullException(nameof(mac));
            Iv = iv ?? throw new ArgumentNullException(nameof(iv));
            SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));
            SenderEphemeralKey = senderEphemeralKey ?? throw new ArgumentNullException(nameof(senderEphemeralKey));

            if (ciphertext.Length == 0)
                throw new ArgumentException("Ciphertext cannot be empty.", nameof(ciphertext));
            if (mac.Length == 0)
                throw new ArgumentException("MAC cannot be empty.", nameof(mac));
            if (iv.Length == 0)
                throw new ArgumentException("IV cannot be empty.", nameof(iv));
            if (senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be empty.", nameof(senderIdentityKey));
            if (senderEphemeralKey.Length == 0)
                throw new ArgumentException("Sender ephemeral key cannot be empty.", nameof(senderEphemeralKey));
        }

        /// <summary>
        /// Gets the encrypted message content.
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Gets the message authentication code.
        /// </summary>
        public byte[] Mac { get; }

        /// <summary>
        /// Gets the initialization vector used for encryption.
        /// </summary>
        public byte[] Iv { get; }

        /// <summary>
        /// Gets the sender's identity key.
        /// </summary>
        public byte[] SenderIdentityKey { get; }

        /// <summary>
        /// Gets the sender's ephemeral key.
        /// </summary>
        public byte[] SenderEphemeralKey { get; }
    }
} 