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
/// 
/// Key lengths:
/// - Private keys: 32 bytes (256 bits)
/// - Public keys: 64 bytes (X and Y coordinates, each 32 bytes)
/// - Signatures: 64 bytes (ECDSA signature)
/// </remarks>
public class X3DHKeyAgreementService : IX3DHKeyAgreementService
{
    private readonly IEcKeyExchangeService _keyExchangeService;
    private readonly IHashService _hashService;
    private const int ExpectedPrivateKeyLength = 32; // 256 bits for NIST P-256
    private const int ExpectedPublicKeyLength = 64; // X and Y coordinates, each 32 bytes

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
    /// Validates a key pair according to the X3DH protocol specification.
    /// </summary>
    /// <param name="keyPair">The key pair to validate.</param>
    /// <param name="paramName">The parameter name for error messages.</param>
    /// <exception cref="ArgumentException">Thrown when the key pair is invalid.</exception>
    private static void ValidateKeyPair(KeyPair keyPair, string paramName)
    {
        if (keyPair == null)
            throw new ArgumentNullException(paramName);

        if (keyPair.PublicKey == null || keyPair.PublicKey.Length != ExpectedPublicKeyLength)
            throw new ArgumentException($"Public key must be {ExpectedPublicKeyLength} bytes", paramName);

        if (keyPair.PrivateKey == null || keyPair.PrivateKey.Length != ExpectedPrivateKeyLength)
            throw new ArgumentException($"Private key must be {ExpectedPrivateKeyLength} bytes", paramName);
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
            var keyPair = new KeyPair(publicKey, privateKey);
            ValidateKeyPair(keyPair, nameof(keyPair));
            return keyPair;
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
    /// <exception cref="ArgumentException">Thrown when identityKeyPair is invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key generation or signing fails.</exception>
    public async Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair)
    {
        ValidateKeyPair(identityKeyPair, nameof(identityKeyPair));

        try
        {
            var (publicKey, privateKey) = await _keyExchangeService.GenerateKeyPairAsync();
            var keyPair = new KeyPair(publicKey, privateKey);
            ValidateKeyPair(keyPair, nameof(keyPair));

            var signature = await _keyExchangeService.SignAsync(identityKeyPair.PrivateKey, publicKey);
            if (signature == null || signature.Length != ExpectedPublicKeyLength)
                throw new InvalidOperationException($"Signature must be {ExpectedPublicKeyLength} bytes");

            return keyPair;
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
            var keyPair = new KeyPair(publicKey, privateKey);
            ValidateKeyPair(keyPair, nameof(keyPair));
            return keyPair;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to generate one-time prekey pair", ex);
        }
    }

    /// <summary>
    /// Performs the X3DH key agreement protocol to establish a shared secret between two parties.
    /// </summary>
    /// <param name="initiatorIdentityKey">The initiator's identity private key (32 bytes).</param>
    /// <param name="initiatorEphemeralKey">The initiator's ephemeral private key (32 bytes).</param>
    /// <param name="recipientIdentityKey">The recipient's identity public key (64 bytes).</param>
    /// <param name="recipientSignedPreKey">The recipient's signed prekey public key (64 bytes).</param>
    /// <param name="recipientOneTimePreKey">The recipient's one-time prekey public key (64 bytes, optional).</param>
    /// <returns>The shared secret derived from the X3DH protocol.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when any required key has an invalid length.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key agreement fails.</exception>
    public async Task<byte[]> PerformKeyAgreementAsync(
        byte[] initiatorIdentityKey,
        byte[] initiatorEphemeralKey,
        byte[] recipientIdentityKey,
        byte[] recipientSignedPreKey,
        byte[]? recipientOneTimePreKey = null)
    {
        if (initiatorIdentityKey == null)
            throw new InvalidOperationException("Initiator identity key cannot be null");
        if (initiatorEphemeralKey == null)
            throw new InvalidOperationException("Initiator ephemeral key cannot be null");
        if (recipientIdentityKey == null)
            throw new InvalidOperationException("Recipient identity key cannot be null");
        if (recipientSignedPreKey == null)
            throw new InvalidOperationException("Recipient signed pre-key cannot be null");

        try
        {
            // Validate input parameters
            if (initiatorIdentityKey.Length != ExpectedPrivateKeyLength)
                throw new ArgumentException($"initiatorIdentityKey must be {ExpectedPrivateKeyLength} bytes", nameof(initiatorIdentityKey));
            if (initiatorEphemeralKey.Length != ExpectedPrivateKeyLength)
                throw new ArgumentException($"initiatorEphemeralKey must be {ExpectedPrivateKeyLength} bytes", nameof(initiatorEphemeralKey));
            if (recipientIdentityKey.Length != ExpectedPublicKeyLength)
                throw new ArgumentException($"recipientIdentityKey must be {ExpectedPublicKeyLength} bytes", nameof(recipientIdentityKey));
            if (recipientSignedPreKey.Length != ExpectedPublicKeyLength)
                throw new ArgumentException($"recipientSignedPreKey must be {ExpectedPublicKeyLength} bytes", nameof(recipientSignedPreKey));
            if (recipientOneTimePreKey != null && recipientOneTimePreKey.Length != ExpectedPublicKeyLength)
                throw new ArgumentException($"recipientOneTimePreKey must be {ExpectedPublicKeyLength} bytes", nameof(recipientOneTimePreKey));

            // 1. DH1 = DH(I_A, E_B) - Initiator's identity key with recipient's signed prekey
            var dh1 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorIdentityKey, recipientSignedPreKey);
            if (dh1 == null || dh1.Length != ExpectedPrivateKeyLength)
                throw new InvalidOperationException($"DH1 must be {ExpectedPrivateKeyLength} bytes");

            // 2. DH2 = DH(E_A, I_B) - Initiator's ephemeral key with recipient's identity key
            var dh2 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientIdentityKey);
            if (dh2 == null || dh2.Length != ExpectedPrivateKeyLength)
                throw new InvalidOperationException($"DH2 must be {ExpectedPrivateKeyLength} bytes");

            // 3. DH3 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's signed prekey
            var dh3 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientSignedPreKey);
            if (dh3 == null || dh3.Length != ExpectedPrivateKeyLength)
                throw new InvalidOperationException($"DH3 must be {ExpectedPrivateKeyLength} bytes");

            // 4. DH4 = DH(E_A, E_B) - Initiator's ephemeral key with recipient's one-time prekey (if available)
            byte[]? dh4 = null;
            if (recipientOneTimePreKey != null)
            {
                dh4 = await _keyExchangeService.ComputeSharedSecretAsync(initiatorEphemeralKey, recipientOneTimePreKey);
                if (dh4 == null || dh4.Length != ExpectedPrivateKeyLength)
                    throw new InvalidOperationException($"DH4 must be {ExpectedPrivateKeyLength} bytes");
            }

            // Combine the shared secrets
            var totalLength = ExpectedPrivateKeyLength * (dh4 != null ? 4 : 3);
            var combinedInput = new byte[totalLength];
            Buffer.BlockCopy(dh1, 0, combinedInput, 0, ExpectedPrivateKeyLength);
            Buffer.BlockCopy(dh2, 0, combinedInput, ExpectedPrivateKeyLength, ExpectedPrivateKeyLength);
            Buffer.BlockCopy(dh3, 0, combinedInput, ExpectedPrivateKeyLength * 2, ExpectedPrivateKeyLength);
            if (dh4 != null)
            {
                Buffer.BlockCopy(dh4, 0, combinedInput, ExpectedPrivateKeyLength * 3, ExpectedPrivateKeyLength);
            }

            // Use HKDF to derive the final key with proper info parameter
            var salt = new byte[ExpectedPrivateKeyLength]; // Zero salt
            var info = new byte[] { 0x01 }; // Info parameter for HKDF
            var finalKey = await _hashService.DeriveKeyAsync(combinedInput, salt, ExpectedPrivateKeyLength, info);
            if (finalKey == null || finalKey.Length != ExpectedPrivateKeyLength)
                throw new InvalidOperationException($"Final key must be {ExpectedPrivateKeyLength} bytes");

            return finalKey;
        }
        catch (Exception ex) when (!(ex is ArgumentException) && !(ex is ArgumentNullException))
        {
            throw new InvalidOperationException("Failed to perform key agreement", ex);
        }
    }
}