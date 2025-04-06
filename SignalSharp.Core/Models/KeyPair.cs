using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents a public/private key pair used in the Signal protocol.
    /// </summary>
    public class KeyPair : IEquatable<KeyPair>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyPair"/> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when publicKey or privateKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when publicKey or privateKey is empty.</exception>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));

            if (publicKey.Length == 0)
                throw new ArgumentException("Public key cannot be empty.", nameof(publicKey));
            if (privateKey.Length == 0)
                throw new ArgumentException("Private key cannot be empty.", nameof(privateKey));
        }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public byte[] PublicKey { get; }

        /// <summary>
        /// Gets the private key.
        /// </summary>
        public byte[] PrivateKey { get; }

        /// <summary>
        /// Creates a new key pair with the specified keys.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <returns>A new instance of <see cref="KeyPair"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when publicKey or privateKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when publicKey or privateKey is empty.</exception>
        public static KeyPair Create(byte[] publicKey, byte[] privateKey)
        {
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other">The object to compare with the current object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false.</returns>
        public bool Equals(KeyPair other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return PublicKey.AsSpan().SequenceEqual(other.PublicKey) &&
                   PrivateKey.AsSpan().SequenceEqual(other.PrivateKey);
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
            return Equals((KeyPair)obj);
        }

        /// <summary>
        /// Gets a hash code for the current object.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            foreach (var b in PublicKey)
                hash.Add(b);
            foreach (var b in PrivateKey)
                hash.Add(b);
            return hash.ToHashCode();
        }

        public static bool operator ==(KeyPair left, KeyPair right)
        {
            if (ReferenceEquals(left, null))
                return ReferenceEquals(right, null);
            return left.Equals(right);
        }

        public static bool operator !=(KeyPair left, KeyPair right)
        {
            return !(left == right);
        }
    }
} 