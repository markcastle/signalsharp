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
    public class EcKeyExchangeService : IEcKeyExchangeService
    {
        private const int ExpectedKeyLength = 32; // 256 bits for NIST P-256

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
                
                // Validate key lengths
                if (parameters.D?.Length != ExpectedKeyLength)
                    throw new InvalidOperationException($"Private key length must be {ExpectedKeyLength} bytes");
                
                if (parameters.Q.X?.Length != ExpectedKeyLength || parameters.Q.Y?.Length != ExpectedKeyLength)
                    throw new InvalidOperationException($"Public key X and Y coordinates must be {ExpectedKeyLength} bytes each");

                return (parameters.Q.X.Concat(parameters.Q.Y).ToArray(), parameters.D);
            });
        }

        /// <summary>
        /// Signs data using a private key.
        /// </summary>
        /// <param name="privateKey">The private key to sign with.</param>
        /// <param name="data">The data to sign.</param>
        /// <returns>The signature.</returns>
        public async Task<byte[]> SignAsync(byte[] privateKey, byte[] data)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (privateKey.Length != ExpectedKeyLength)
                throw new ArgumentException($"Private key must be {ExpectedKeyLength} bytes", nameof(privateKey));

            return await Task.Run(() =>
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = privateKey
                };
                ecdsa.ImportParameters(parameters);
                return ecdsa.SignData(data, HashAlgorithmName.SHA256);
            });
        }

        /// <summary>
        /// Verifies a signature using a public key.
        /// </summary>
        /// <param name="publicKey">The public key to verify with.</param>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public async Task<bool> VerifyAsync(byte[] publicKey, byte[] data, byte[] signature)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (publicKey.Length != ExpectedKeyLength * 2)
                throw new ArgumentException($"Public key must be {ExpectedKeyLength * 2} bytes", nameof(publicKey));

            return await Task.Run(() =>
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var parameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = publicKey.Take(ExpectedKeyLength).ToArray(),
                        Y = publicKey.Skip(ExpectedKeyLength).ToArray()
                    }
                };
                ecdsa.ImportParameters(parameters);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            });
        }

        /// <summary>
        /// Performs a Diffie-Hellman key agreement.
        /// </summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="privateKey">The private key of this party.</param>
        /// <returns>The shared secret.</returns>
        public Task<byte[]> DiffieHellmanAsync(byte[] publicKey, byte[] privateKey)
        {
            return ComputeSharedSecretAsync(privateKey, publicKey);
        }

        /// <summary>
        /// Computes a shared secret using ECDH.
        /// </summary>
        /// <param name="privateKey">The local private key.</param>
        /// <param name="publicKey">The remote public key.</param>
        /// <returns>The computed shared secret.</returns>
        /// <exception cref="ArgumentNullException">Thrown when privateKey or publicKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when key format is invalid.</exception>
        public async Task<byte[]> ComputeSharedSecretAsync(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (privateKey.Length != ExpectedKeyLength)
                throw new ArgumentException($"Private key must be {ExpectedKeyLength} bytes", nameof(privateKey));
            if (publicKey.Length != ExpectedKeyLength * 2)
                throw new ArgumentException($"Public key must be {ExpectedKeyLength * 2} bytes", nameof(publicKey));

            return await Task.Run(() =>
            {
                // Create local ECDH instance with private key
                using var localEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                var localParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = privateKey
                };
                localEcdh.ImportParameters(localParameters);

                // Create remote public key parameters
                var remoteParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = publicKey.Take(ExpectedKeyLength).ToArray(),
                        Y = publicKey.Skip(ExpectedKeyLength).ToArray()
                    }
                };

                // Create remote ECDH instance with public key
                using var remoteEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                remoteEcdh.ImportParameters(remoteParameters);

                // Derive shared secret
                return localEcdh.DeriveKeyMaterial(remoteEcdh.PublicKey);
            });
        }

        /// <summary>
        /// Derives a symmetric key from the shared secret using HKDF.
        /// </summary>
        /// <param name="sharedSecret">The shared secret to derive the key from.</param>
        /// <param name="salt">Optional salt for key derivation.</param>
        /// <returns>The derived symmetric key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when sharedSecret is null.</exception>
        public async Task<byte[]> DeriveSymmetricKeyAsync(byte[] sharedSecret, byte[] salt)
        {
            if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
            if (salt == null) throw new ArgumentNullException(nameof(salt));

            return await Task.Run(() =>
            {
                var hkdf = new HKDF(sharedSecret, salt);
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

            // Derive root key and chain keys
            var salt = new byte[32]; // Zero salt
            var rootKey = await DeriveSymmetricKeyAsync(dh1.Concat(dh2).ToArray(), salt);
            var sendingChainKey = await DeriveSymmetricKeyAsync(rootKey, ephemeralPublicKey);
            var receivingChainKey = await DeriveSymmetricKeyAsync(rootKey, remotePreKey);

            return (rootKey, sendingChainKey, receivingChainKey);
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