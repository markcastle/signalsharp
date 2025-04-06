using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for key exchange operations using elliptic curve cryptography.
    /// </summary>
    public interface IKeyExchangeService
    {
        /// <summary>
        /// Generates a new key pair for key exchange.
        /// </summary>
        /// <returns>A tuple containing the public and private key.</returns>
        Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync();

        /// <summary>
        /// Computes a shared secret using the local private key and remote public key.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="remotePublicKey">The remote public key.</param>
        /// <returns>The computed shared secret.</returns>
        /// <exception cref="ArgumentNullException">Thrown when privateKey or remotePublicKey is null.</exception>
        Task<byte[]> ComputeSharedSecretAsync(byte[] privateKey, byte[] remotePublicKey);

        /// <summary>
        /// Derives a symmetric key from the shared secret.
        /// </summary>
        /// <param name="sharedSecret">The shared secret to derive the key from.</param>
        /// <param name="salt">Optional salt for key derivation. If not provided, a default salt will be used.</param>
        /// <returns>The derived symmetric key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sharedSecret is null.</exception>
        Task<byte[]> DeriveSymmetricKeyAsync(byte[] sharedSecret, byte[]? salt = default);

        /// <summary>
        /// Performs a key exchange operation using the X3DH protocol.
        /// </summary>
        /// <param name="localIdentityKey">The local identity key.</param>
        /// <param name="remoteIdentityKey">The remote identity key.</param>
        /// <param name="remotePreKey">The remote pre-key.</param>
        /// <returns>A tuple containing the root key, sending chain key, and receiving chain key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        Task<(byte[] RootKey, byte[] SendingChainKey, byte[] ReceivingChainKey)> PerformKeyExchangeAsync(
            byte[] localIdentityKey,
            byte[] remoteIdentityKey,
            byte[] remotePreKey);
    }
} 