using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents an encrypted message in the Signal protocol.
    /// </summary>
    public class SignalMessage : IEquatable<SignalMessage>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignalMessage"/> class.
        /// </summary>
        public SignalMessage()
        {
            Type = MessageType.Regular;
            Content = Array.Empty<byte>();
            Mac = Array.Empty<byte>();
            Iv = Array.Empty<byte>();
            SenderIdentityKey = Array.Empty<byte>();
            SenderEphemeralKey = Array.Empty<byte>();
            Ciphertext = Array.Empty<byte>();
            MessageNumber = 0;
            RatchetKey = Array.Empty<byte>();
        }

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
            Ciphertext = Array.Empty<byte>();
            MessageNumber = 0;
            RatchetKey = Array.Empty<byte>();

            if (content.Length == 0)
                throw new ArgumentException("Content cannot be empty.", nameof(content));
            if (mac.Length == 0)
                throw new ArgumentException("MAC cannot be empty.", nameof(mac));
            if (iv.Length == 0)
                throw new ArgumentException("IV cannot be empty.", nameof(iv));
            if (senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be empty.", nameof(senderIdentityKey));
            if (senderEphemeralKey.Length == 0)
                throw new ArgumentException("Sender ephemeral key cannot be empty.", nameof(senderEphemeralKey));

            Type = MessageType.Regular;
        }

        /// <summary>
        /// Gets or sets the type of the message.
        /// </summary>
        public MessageType Type { get; set; }

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[] Content { get; set; }

        /// <summary>
        /// Gets or sets the message authentication code.
        /// </summary>
        public byte[] Mac { get; set; }

        /// <summary>
        /// Gets or sets the initialization vector used for encryption.
        /// </summary>
        public byte[] Iv { get; set; }

        /// <summary>
        /// Gets or sets the sender's identity key.
        /// </summary>
        public byte[] SenderIdentityKey { get; set; }

        /// <summary>
        /// Gets or sets the sender's ephemeral key.
        /// </summary>
        public byte[] SenderEphemeralKey { get; set; }

        /// <summary>
        /// Gets or sets the counter used in the ratchet.
        /// </summary>
        public uint Counter { get; set; }

        /// <summary>
        /// Gets or sets the previous counter value.
        /// </summary>
        public uint PreviousCounter { get; set; }

        /// <summary>
        /// Gets or sets the ciphertext of the message.
        /// </summary>
        public byte[] Ciphertext { get; set; }

        /// <summary>
        /// Gets or sets the message number in the ratchet chain.
        /// </summary>
        public uint MessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the ratchet key used for this message.
        /// </summary>
        public byte[] RatchetKey { get; set; }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other">The object to compare with the current object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false.</returns>
        public bool Equals(SignalMessage other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return Type == other.Type &&
                   Content.AsSpan().SequenceEqual(other.Content) &&
                   Mac.AsSpan().SequenceEqual(other.Mac) &&
                   Iv.AsSpan().SequenceEqual(other.Iv) &&
                   SenderIdentityKey.AsSpan().SequenceEqual(other.SenderIdentityKey) &&
                   SenderEphemeralKey.AsSpan().SequenceEqual(other.SenderEphemeralKey) &&
                   Counter == other.Counter &&
                   PreviousCounter == other.PreviousCounter &&
                   Ciphertext.AsSpan().SequenceEqual(other.Ciphertext) &&
                   MessageNumber == other.MessageNumber &&
                   RatchetKey.AsSpan().SequenceEqual(other.RatchetKey);
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

            return Equals((SignalMessage)obj);
        }

        /// <summary>
        /// Serves as the default hash function.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Type);
            foreach (var b in Content)
                hash.Add(b);
            foreach (var b in Mac)
                hash.Add(b);
            foreach (var b in Iv)
                hash.Add(b);
            foreach (var b in SenderIdentityKey)
                hash.Add(b);
            foreach (var b in SenderEphemeralKey)
                hash.Add(b);
            hash.Add(Counter);
            hash.Add(PreviousCounter);
            foreach (var b in Ciphertext)
                hash.Add(b);
            hash.Add(MessageNumber);
            foreach (var b in RatchetKey)
                hash.Add(b);
            return hash.ToHashCode();
        }

        public static bool operator ==(SignalMessage left, SignalMessage right)
        {
            if (ReferenceEquals(left, null))
                return ReferenceEquals(right, null);
            return left.Equals(right);
        }

        public static bool operator !=(SignalMessage left, SignalMessage right)
        {
            return !(left == right);
        }
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