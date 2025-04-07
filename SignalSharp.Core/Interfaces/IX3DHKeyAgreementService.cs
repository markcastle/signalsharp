using System.Threading.Tasks;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for X3DH key agreement protocol operations.
    /// </summary>
    public interface IX3DHKeyAgreementService
    {
        /// <summary>
        /// Generates a new identity key pair.
        /// </summary>
        /// <returns>A new identity key pair.</returns>
        Task<KeyPair> GenerateIdentityKeyPairAsync();

        /// <summary>
        /// Generates a new signed pre-key pair.
        /// </summary>
        /// <param name="identityKeyPair">The identity key pair to sign with.</param>
        /// <returns>A new signed pre-key pair.</returns>
        Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair);

        /// <summary>
        /// Generates a new one-time pre-key pair.
        /// </summary>
        /// <returns>A new one-time pre-key pair.</returns>
        Task<KeyPair> GenerateOneTimePreKeyPairAsync();

        /// <summary>
        /// Performs the X3DH key agreement protocol.
        /// </summary>
        /// <param name="remoteIdentityKey">The remote party's identity key.</param>
        /// <param name="remoteSignedPreKey">The remote party's signed pre-key.</param>
        /// <param name="remoteOneTimePreKey">The remote party's one-time pre-key.</param>
        /// <param name="localIdentityKey">The local party's identity key.</param>
        /// <param name="localSignedPreKey">The local party's signed pre-key.</param>
        /// <returns>The shared secret.</returns>
        Task<byte[]> PerformKeyAgreementAsync(
            byte[] remoteIdentityKey,
            byte[] remoteSignedPreKey,
            byte[] remoteOneTimePreKey,
            byte[] localIdentityKey,
            byte[] localSignedPreKey);
    }
} 