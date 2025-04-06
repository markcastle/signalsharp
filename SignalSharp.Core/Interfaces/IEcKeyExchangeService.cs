using System.Threading.Tasks;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Interfaces;

/// <summary>
/// Defines the interface for Elliptic Curve key exchange operations.
/// </summary>
public interface IEcKeyExchangeService
{
    /// <summary>
    /// Generates a new EC key pair.
    /// </summary>
    /// <returns>A new key pair.</returns>
    Task<KeyPair> GenerateKeyPairAsync();

    /// <summary>
    /// Computes a shared secret using ECDH.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    /// <param name="publicKey">The public key.</param>
    /// <returns>The shared secret.</returns>
    Task<byte[]> ComputeSharedSecretAsync(byte[] privateKey, byte[] publicKey);

    /// <summary>
    /// Signs data using an EC private key.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature.</returns>
    Task<byte[]> SignAsync(byte[] privateKey, byte[] data);

    /// <summary>
    /// Verifies a signature using an EC public key.
    /// </summary>
    /// <param name="publicKey">The public key to verify with.</param>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    Task<bool> VerifyAsync(byte[] publicKey, byte[] data, byte[] signature);
} 