using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Security.Services
{
    /// <summary>
    /// Provides cryptographic hashing operations using SHA-256 and HMACSHA256.
    /// </summary>
    public class HashService : IHashService
    {
        /// <summary>
        /// Computes a hash of the specified data using SHA-256.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>The computed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data is null.</exception>
        public async Task<byte[]> ComputeHashAsync(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            return await Task.Run(() =>
            {
                using var sha256 = SHA256.Create();
                return sha256.ComputeHash(data);
            });
        }

        /// <summary>
        /// Computes a keyed hash (HMAC) of the specified data using HMACSHA256.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="key">The key to use for the HMAC.</param>
        /// <returns>The computed keyed hash.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data or key is null.</exception>
        public async Task<byte[]> ComputeKeyedHashAsync(byte[] data, byte[] key)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));

            return await Task.Run(() =>
            {
                using var hmac = new HMACSHA256(key);
                return hmac.ComputeHash(data);
            });
        }

        /// <summary>
        /// Verifies that the specified hash matches the computed hash of the data.
        /// </summary>
        /// <param name="data">The data to verify.</param>
        /// <param name="hash">The hash to verify against.</param>
        /// <returns>True if the hash matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data or hash is null.</exception>
        public async Task<bool> VerifyHashAsync(byte[] data, byte[] hash)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (hash == null) throw new ArgumentNullException(nameof(hash));

            var computedHash = await ComputeHashAsync(data);
            return ByteArraysEqual(computedHash, hash);
        }

        /// <summary>
        /// Verifies that the specified keyed hash matches the computed keyed hash of the data.
        /// </summary>
        /// <param name="data">The data to verify.</param>
        /// <param name="key">The key used for the HMAC.</param>
        /// <param name="hash">The hash to verify against.</param>
        /// <returns>True if the hash matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data, key, or hash is null.</exception>
        public async Task<bool> VerifyKeyedHashAsync(byte[] data, byte[] key, byte[] hash)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (hash == null) throw new ArgumentNullException(nameof(hash));

            var computedHash = await ComputeKeyedHashAsync(data, key);
            return ByteArraysEqual(computedHash, hash);
        }

        /// <summary>
        /// Derives a key from the specified input using HKDF (HMAC-based Key Derivation Function).
        /// </summary>
        /// <param name="input">The input data to derive the key from.</param>
        /// <param name="salt">The salt to use in the key derivation.</param>
        /// <param name="outputLength">The desired length of the derived key in bytes.</param>
        /// <returns>The derived key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when input or salt is null.</exception>
        /// <exception cref="ArgumentException">Thrown when outputLength is less than 1.</exception>
        public async Task<byte[]> DeriveKeyAsync(byte[] input, byte[] salt, int outputLength)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (outputLength < 1) throw new ArgumentException("Output length must be at least 1 byte", nameof(outputLength));

            return await Task.Run(() =>
            {
                using var hmac = new HMACSHA256(salt);
                var prk = hmac.ComputeHash(input);
                var result = new byte[outputLength];
                var block = new byte[0];
                var offset = 0;

                while (offset < outputLength)
                {
                    var blockSize = Math.Min(32, outputLength - offset);
                    block = hmac.ComputeHash(block.Length == 0 ? prk : Concat(block, prk));
                    Buffer.BlockCopy(block, 0, result, offset, blockSize);
                    offset += blockSize;
                }

                return result;
            });
        }

        /// <summary>
        /// Computes a Message Authentication Code (MAC) for the specified data using HMACSHA256.
        /// </summary>
        /// <param name="data">The data to compute the MAC for.</param>
        /// <param name="key">The key to use for the MAC computation.</param>
        /// <returns>The computed MAC.</returns>
        /// <exception cref="ArgumentNullException">Thrown when data or key is null.</exception>
        public async Task<byte[]> ComputeMacAsync(byte[] data, byte[] key)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));

            return await Task.Run(() =>
            {
                using var hmac = new HMACSHA256(key);
                return hmac.ComputeHash(data);
            });
        }

        /// <summary>
        /// Compares two byte arrays for equality in a constant-time manner to prevent timing attacks.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if the arrays are equal, false otherwise.</returns>
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }

        /// <summary>
        /// Concatenates two byte arrays.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>The concatenated byte array.</returns>
        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
} 