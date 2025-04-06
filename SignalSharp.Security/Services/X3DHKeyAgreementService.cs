using System;
using System.Linq;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Security.Services;

/// <summary>
/// Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
/// This service handles the initial key agreement between two parties in the Signal protocol.
/// </summary>
public class X3DHKeyAgreementService : IX3DHKeyAgreementService
{
    private readonly IHashService _hashService;
    private readonly IEcKeyExchangeService _keyExchangeService;

    /// <summary>
    /// Initializes a new instance of the X3DHKeyAgreementService.
    /// </summary>
    /// <param name="hashService">The hash service used for key derivation.</param>
    /// <param name="keyExchangeService">The key exchange service for ECDH operations.</param>
    public X3DHKeyAgreementService(IHashService hashService, IEcKeyExchangeService keyExchangeService)
    {
        _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
        _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
    }

    /// <summary>
    /// Generates a new identity key pair for a user.
    /// </summary>
    /// <returns>A new identity key pair.</returns>
    public async Task<KeyPair> GenerateIdentityKeyPairAsync()
    {
        return await _keyExchangeService.GenerateKeyPairAsync();
    }

    /// <summary>
    /// Generates a new signed prekey pair for a user.
    /// </summary>
    /// <param name="identityKeyPair">The user's identity key pair.</param>
    /// <returns>A new signed prekey pair.</returns>
    public async Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair)
    {
        if (identityKeyPair == null)
            throw new ArgumentNullException(nameof(identityKeyPair));

        var preKeyPair = await _keyExchangeService.GenerateKeyPairAsync();
        var signature = await _keyExchangeService.SignAsync(identityKeyPair.PrivateKey, preKeyPair.PublicKey);
        
        // In a real implementation, we would store the prekey pair and its signature
        // For now, we'll just return the prekey pair
        return preKeyPair;
    }

    /// <summary>
    /// Generates a new one-time prekey pair.
    /// </summary>
    /// <returns>A new one-time prekey pair.</returns>
    public async Task<KeyPair> GenerateOneTimePreKeyPairAsync()
    {
        return await _keyExchangeService.GenerateKeyPairAsync();
    }

    /// <summary>
    /// Performs the X3DH key agreement protocol to establish a shared secret between two parties.
    /// </summary>
    /// <param name="initiatorIdentityKey">The initiator's identity public key.</param>
    /// <param name="initiatorEphemeralKey">The initiator's ephemeral public key.</param>
    /// <param name="recipientIdentityKey">The recipient's identity public key.</param>
    /// <param name="recipientSignedPreKey">The recipient's signed prekey public key.</param>
    /// <param name="recipientOneTimePreKey">The recipient's one-time prekey public key (optional).</param>
    /// <returns>The shared secret derived from the X3DH protocol.</returns>
    public async Task<byte[]> PerformKeyAgreementAsync(
        byte[] initiatorIdentityKey,
        byte[] initiatorEphemeralKey,
        byte[] recipientIdentityKey,
        byte[] recipientSignedPreKey,
        byte[]? recipientOneTimePreKey = null)
    {
        if (initiatorIdentityKey == null)
            throw new ArgumentNullException(nameof(initiatorIdentityKey));
        if (initiatorEphemeralKey == null)
            throw new ArgumentNullException(nameof(initiatorEphemeralKey));
        if (recipientIdentityKey == null)
            throw new ArgumentNullException(nameof(recipientIdentityKey));
        if (recipientSignedPreKey == null)
            throw new ArgumentNullException(nameof(recipientSignedPreKey));

        // 1. DH1 = DH(I_A, E_B) - Initiator's identity key with recipient's ephemeral key
        var dh1 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey);

        // 2. DH2 = DH(E_A, I_B) - Initiator's ephemeral key with recipient's identity key
        var dh2 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey);

        // 3. DH3 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's ephemeral key
        var dh3 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey);

        // 4. DH4 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's one-time prekey (if available)
        byte[]? dh4 = null;
        if (recipientOneTimePreKey != null)
        {
            dh4 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey);
        }

        // Combine all shared secrets
        var combinedInput = dh1.Concat(dh2).Concat(dh3);
        if (dh4 != null)
        {
            combinedInput = combinedInput.Concat(dh4);
        }

        // Use the combined shared secrets to derive the final key
        return await _hashService.ComputeKeyedHashAsync(combinedInput.ToArray(), initiatorIdentityKey);
    }
} 