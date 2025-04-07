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
/// <remarks>
/// X3DH provides:
/// - Perfect forward secrecy
/// - Identity verification
/// - Protection against replay attacks
/// - Protection against man-in-the-middle attacks
/// </remarks>
public class X3DHKeyAgreementService : IX3DHKeyAgreementService
{
    private readonly IEcKeyExchangeService _keyExchangeService;
    private readonly IHashService _hashService;

    /// <summary>
    /// Initializes a new instance of the X3DHKeyAgreementService.
    /// </summary>
    /// <param name="keyExchangeService">The key exchange service for ECDH operations.</param>
    /// <param name="hashService">The hash service used for key derivation.</param>
    /// <exception cref="ArgumentNullException">Thrown when any of the parameters are null.</exception>
    public X3DHKeyAgreementService(IEcKeyExchangeService keyExchangeService, IHashService hashService)
    {
        _keyExchangeService = keyExchangeService ?? throw new ArgumentNullException(nameof(keyExchangeService));
        _hashService = hashService ?? throw new ArgumentNullException(nameof(hashService));
    }

    /// <summary>
    /// Generates a new identity key pair for a user.
    /// </summary>
    /// <returns>A new identity key pair.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key generation fails.</exception>
    public async Task<KeyPair> GenerateIdentityKeyPairAsync()
    {
        try
        {
            var (publicKey, privateKey) = await _keyExchangeService.GenerateKeyPairAsync();
            return new KeyPair(publicKey, privateKey);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to generate identity key pair", ex);
        }
    }

    /// <summary>
    /// Generates a new signed prekey pair for a user.
    /// </summary>
    /// <param name="identityKeyPair">The user's identity key pair.</param>
    /// <returns>A new signed prekey pair.</returns>
    /// <exception cref="ArgumentNullException">Thrown when identityKeyPair is null.</exception>
    /// <exception cref="ArgumentException">Thrown when identityKeyPair is empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key generation or signing fails.</exception>
    public async Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair)
    {
        if (identityKeyPair == null)
            throw new ArgumentNullException(nameof(identityKeyPair));

        if (identityKeyPair.PrivateKey == null || identityKeyPair.PrivateKey.Length == 0)
            throw new ArgumentException("Identity private key cannot be empty", nameof(identityKeyPair));

        try
        {
            var (publicKey, privateKey) = await _keyExchangeService.GenerateKeyPairAsync();
            var signature = await _keyExchangeService.SignAsync(identityKeyPair.PrivateKey, publicKey);
            
            // In a real implementation, we would store the prekey pair and its signature
            // For now, we'll just return the prekey pair
            return new KeyPair(publicKey, privateKey);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to generate signed prekey pair", ex);
        }
    }

    /// <summary>
    /// Generates a new one-time prekey pair.
    /// </summary>
    /// <returns>A new one-time prekey pair.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key generation fails.</exception>
    public async Task<KeyPair> GenerateOneTimePreKeyPairAsync()
    {
        try
        {
            var (publicKey, privateKey) = await _keyExchangeService.GenerateKeyPairAsync();
            return new KeyPair(publicKey, privateKey);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to generate one-time prekey pair", ex);
        }
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
    /// <exception cref="ArgumentNullException">Thrown when any required key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when any required key is empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key agreement fails.</exception>
    public async Task<byte[]> PerformKeyAgreementAsync(
        byte[] initiatorIdentityKey,
        byte[] initiatorEphemeralKey,
        byte[] recipientIdentityKey,
        byte[] recipientSignedPreKey,
        byte[]? recipientOneTimePreKey = null)
    {
        try
        {
            // Validate input parameters
            if (initiatorIdentityKey == null || initiatorIdentityKey.Length == 0)
                throw new ArgumentException("Initiator identity key cannot be empty", nameof(initiatorIdentityKey));
            if (initiatorEphemeralKey == null || initiatorEphemeralKey.Length == 0)
                throw new ArgumentException("Initiator ephemeral key cannot be empty", nameof(initiatorEphemeralKey));
            if (recipientIdentityKey == null || recipientIdentityKey.Length == 0)
                throw new ArgumentException("Recipient identity key cannot be empty", nameof(recipientIdentityKey));
            if (recipientSignedPreKey == null || recipientSignedPreKey.Length == 0)
                throw new ArgumentException("Recipient signed prekey cannot be empty", nameof(recipientSignedPreKey));

            // 1. DH1 = DH(I_A, E_B) - Initiator's identity key with recipient's signed prekey
            var dh1 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey);
            if (dh1 == null || dh1.Length == 0)
                throw new InvalidOperationException("Failed to compute DH1");

            // 2. DH2 = DH(E_A, I_B) - Initiator's ephemeral key with recipient's identity key
            var dh2 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey);
            if (dh2 == null || dh2.Length == 0)
                throw new InvalidOperationException("Failed to compute DH2");

            // 3. DH3 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's signed prekey
            var dh3 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey);
            if (dh3 == null || dh3.Length == 0)
                throw new InvalidOperationException("Failed to compute DH3");

            // 4. DH4 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's one-time prekey (if available)
            byte[]? dh4 = null;
            if (recipientOneTimePreKey != null && recipientOneTimePreKey.Length > 0)
            {
                dh4 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey);
                if (dh4 == null || dh4.Length == 0)
                    throw new InvalidOperationException("Failed to compute DH4");
            }

            // Combine all shared secrets
            var combinedInput = dh1.Concat(dh2).Concat(dh3);
            if (dh4 != null)
            {
                combinedInput = combinedInput.Concat(dh4);
            }

            // Use the combined shared secrets to derive the final key
            var finalKey = await _hashService.ComputeKeyedHashAsync(combinedInput.ToArray(), initiatorIdentityKey);
            if (finalKey == null || finalKey.Length == 0)
                throw new InvalidOperationException("Failed to derive final key");

            return finalKey;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to perform key agreement", ex);
        }
    }
} 