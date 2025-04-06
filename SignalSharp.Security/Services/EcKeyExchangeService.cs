using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;

namespace SignalSharp.Security.Services
{
    /// <summary>
    /// Provides ECDH-based key exchange operations.
    /// </summary>
    public class EcKeyExchangeService : IKeyExchangeService
    {
        /// <summary>
        /// Generates a new ECDH key pair.
        /// </summary>
        /// <returns>A tuple containing the public and private key.</returns>
        public async Task<(byte[] PublicKey, byte[] PrivateKey)> GenerateKeyPairAsync()
        {
            return await Task.Run(() =>
            {
                using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                var parameters = ecdh.ExportParameters(true);
                return (parameters.Q.X.Concat(parameters.Q.Y).ToArray(), parameters.D);
            });
        }

        /// <summary>
        /// Computes a shared secret using ECDH.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="remotePublicKey">The remote public key.</param>
        /// <returns>The computed shared secret.</returns>
        /// <exception cref="ArgumentNullException">Thrown when privateKey or remotePublicKey is null.</exception>
        /// <exception cref="CryptographicException">Thrown when key format is invalid.</exception>
        public async Task<byte[]> ComputeSharedSecretAsync(byte[] privateKey, byte[] remotePublicKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (remotePublicKey == null) throw new ArgumentNullException(nameof(remotePublicKey));

            return await Task.Run(() =>
            {
                using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                var parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = privateKey,
                    Q = new ECPoint
                    {
                        X = remotePublicKey.Take(32).ToArray(),
                        Y = remotePublicKey.Skip(32).ToArray()
                    }
                };

                ecdh.ImportParameters(parameters);

                using var remoteEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                var remoteParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = remotePublicKey.Take(32).ToArray(),
                        Y = remotePublicKey.Skip(32).ToArray()
                    }
                };
                remoteEcdh.ImportParameters(remoteParameters);

                return ecdh.DeriveKeyMaterial(remoteEcdh.PublicKey);
            });
        }

        /// <summary>
        /// Derives a symmetric key from the shared secret using HKDF.
        /// </summary>
        /// <param name="sharedSecret">The shared secret to derive the key from.</param>
        /// <param name="salt">Optional salt for key derivation.</param>
        /// <returns>The derived symmetric key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sharedSecret is null.</exception>
        public async Task<byte[]> DeriveSymmetricKeyAsync(byte[] sharedSecret, byte[]? salt = default)
        {
            if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));

            return await Task.Run(() =>
            {
                var hkdf = new HKDF(sharedSecret, salt ?? GenerateSalt());
                return hkdf.DeriveKey(32); // 256 bits
            });
        }

        /// <summary>
        /// Performs a key exchange operation using the X3DH protocol.
        /// </summary>
        /// <param name="localIdentityKey">The local identity key.</param>
        /// <param name="remoteIdentityKey">The remote identity key.</param>
        /// <param name="remotePreKey">The remote pre-key.</param>
        /// <returns>A tuple containing the root key, sending chain key, and receiving chain key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        public async Task<(byte[] RootKey, byte[] SendingChainKey, byte[] ReceivingChainKey)> PerformKeyExchangeAsync(
            byte[] localIdentityKey,
            byte[] remoteIdentityKey,
            byte[] remotePreKey)
        {
            if (localIdentityKey == null) throw new ArgumentNullException(nameof(localIdentityKey));
            if (remoteIdentityKey == null) throw new ArgumentNullException(nameof(remoteIdentityKey));
            if (remotePreKey == null) throw new ArgumentNullException(nameof(remotePreKey));

            // Generate ephemeral key pair
            var (ephemeralPublicKey, ephemeralPrivateKey) = await GenerateKeyPairAsync();

            // Compute DH1 = DH(IKa, SPKb)
            var dh1 = await ComputeSharedSecretAsync(localIdentityKey, remotePreKey);

            // Compute DH2 = DH(EKa, IKb)
            var dh2 = await ComputeSharedSecretAsync(ephemeralPrivateKey, remoteIdentityKey);

            // Compute DH3 = DH(EKa, SPKb)
            var dh3 = await ComputeSharedSecretAsync(ephemeralPrivateKey, remotePreKey);

            // Concatenate shared secrets
            var sharedSecret = new byte[dh1.Length + dh2.Length + dh3.Length];
            Buffer.BlockCopy(dh1, 0, sharedSecret, 0, dh1.Length);
            Buffer.BlockCopy(dh2, 0, sharedSecret, dh1.Length, dh2.Length);
            Buffer.BlockCopy(dh3, 0, sharedSecret, dh1.Length + dh2.Length, dh3.Length);

            // Derive root key and chain keys
            var hkdf = new HKDF(sharedSecret, GenerateSalt());
            var rootKey = hkdf.DeriveKey(32);
            var sendingChainKey = hkdf.DeriveKey(32);
            var receivingChainKey = hkdf.DeriveKey(32);

            return (rootKey, sendingChainKey, receivingChainKey);
        }

        private byte[] GenerateSalt()
        {
            var salt = new byte[32];
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            return salt;
        }
    }

    /// <summary>
    /// HKDF implementation based on RFC 5869.
    /// </summary>
    internal class HKDF
    {
        private readonly byte[] _prk;
        private readonly HMACSHA256 _hmac;

        public HKDF(byte[] inputKeyMaterial, byte[] salt)
        {
            using var hmac = new HMACSHA256(salt ?? Array.Empty<byte>());
            _prk = hmac.ComputeHash(inputKeyMaterial);
            _hmac = new HMACSHA256(_prk);
        }

        public byte[] DeriveKey(int length)
        {
            var n = (length + 32 - 1) / 32;
            var derivedKey = new byte[n * 32];
            var lastT = Array.Empty<byte>();

            for (var i = 1; i <= n; i++)
            {
                var t = new byte[lastT.Length + 1];
                lastT.CopyTo(t, 0);
                t[lastT.Length] = (byte)i;
                lastT = _hmac.ComputeHash(t);
                lastT.CopyTo(derivedKey, (i - 1) * 32);
            }

            var result = new byte[length];
            Array.Copy(derivedKey, result, length);
            return result;
        }
    }
} 