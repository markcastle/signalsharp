using System.Threading.Tasks;
using SignalSharp.Core.Models;

namespace SignalSharp.Core.Interfaces;

/// <summary>
/// Defines the interface for the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
/// </summary>
public interface IX3DHKeyAgreementService
{
    /// <summary>
    /// Generates a new identity key pair for a user.
    /// </summary>
    /// <returns>A new identity key pair.</returns>
    Task<KeyPair> GenerateIdentityKeyPairAsync();

    /// <summary>
    /// Generates a new signed prekey pair for a user.
    /// </summary>
    /// <param name="identityKeyPair">The user's identity key pair.</param>
    /// <returns>A new signed prekey pair.</returns>
    Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair);

    /// <summary>
    /// Generates a new one-time prekey pair.
    /// </summary>
    /// <returns>A new one-time prekey pair.</returns>
    Task<KeyPair> GenerateOneTimePreKeyPairAsync();

    /// <summary>
    /// Performs the X3DH key agreement protocol to establish a shared secret between two parties.
    /// </summary>
    /// <param name="initiatorIdentityKey">The initiator's identity public key.</param>
    /// <param name="initiatorEphemeralKey">The initiator's ephemeral public key.</param>
    /// <param name="recipientIdentityKey">The recipient's identity public key.</param>
    /// <param name="recipientSignedPreKey">The recipient's signed prekey public key.</param>
    /// <param name="recipientOneTimePreKey">The recipient's one-time prekey public key (optional).</param>
    /// <returns>The shared secret derived from the X3DH protocol.</returns>
    Task<byte[]> PerformKeyAgreementAsync(
        byte[] initiatorIdentityKey,
        byte[] initiatorEphemeralKey,
        byte[] recipientIdentityKey,
        byte[] recipientSignedPreKey,
        byte[]? recipientOneTimePreKey = null);
} 