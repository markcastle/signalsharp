using System;

namespace SignalSharp.Core.Models
{
    /// <summary>
    /// Represents a public/private key pair used in the Signal protocol.
    /// </summary>
    public class KeyPair
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyPair"/> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when publicKey or privateKey is null.</exception>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
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
        public static KeyPair Create(byte[] publicKey, byte[] privateKey)
        {
            return new KeyPair(publicKey, privateKey);
        }
    }
} 