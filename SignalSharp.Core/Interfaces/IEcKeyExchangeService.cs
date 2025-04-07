using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for elliptic curve key exchange operations.
    /// </summary>
    public interface IEcKeyExchangeService
    {
        /// <summary>
        /// Generates a new key pair.
        /// </summary>
        /// <returns>A tuple containing the public and private keys.</returns>
        Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync();

        /// <summary>
        /// Signs data using a private key.
        /// </summary>
        /// <param name="privateKey">The private key to sign with.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature.</returns>
        Task<byte[]> SignAsync(byte[] privateKey, byte[] data);

        /// <summary>
        /// Verifies a signature using a public key.
        /// </summary>
        /// <param name="publicKey">The public key to verify with.</param>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        Task<bool> VerifyAsync(byte[] publicKey, byte[] data, byte[] signature);

        /// <summary>
        /// Performs a Diffie-Hellman key agreement.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="privateKey">The private key of this party.</param>
        /// <returns>The shared secret.</returns>
        Task<byte[]> DiffieHellmanAsync(byte[] publicKey, byte[] privateKey);

        /// <summary>
        /// Computes a shared secret using ECDH.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>The shared secret.</returns>
        Task<byte[]> ComputeSharedSecretAsync(byte[] privateKey, byte[] publicKey);

        /// <summary>
        /// Derives a symmetric key from a shared secret.
        /// </summary>
        /// <param name="sharedSecret">The shared secret to derive from.</param>
        /// <param name="salt">The salt to use in key derivation.</param>
        /// <returns>The derived symmetric key.</returns>
        Task<byte[]> DeriveSymmetricKeyAsync(byte[] sharedSecret, byte[] salt);
    }
} 