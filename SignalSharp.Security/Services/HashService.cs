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

        /// <inheritdoc/>
        public async Task<byte[]> DeriveKeyAsync(byte[] input, byte[] salt, int outputLength)
        {
            return await DeriveKeyAsync(input, salt, outputLength, new byte[] { 0x01 });
        }

        /// <inheritdoc/>
        public async Task<byte[]> DeriveKeyAsync(byte[] input, byte[] salt, int outputLength, byte[] info)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (info == null) throw new ArgumentNullException(nameof(info));
            if (outputLength <= 0) throw new ArgumentException("Output length must be positive", nameof(outputLength));

            return await Task.Run(() =>
            {
                // Extract phase: PRK = HMAC-Hash(salt, IKM)
                using var hmac = new HMACSHA256(salt);
                var prk = hmac.ComputeHash(input);

                // Expand phase
                var n = (outputLength + 31) / 32; // Number of iterations needed (ceiling division by 32)
                var t = new byte[n * 32]; // Temporary buffer for all blocks
                var okm = new byte[outputLength]; // Output keying material

                using var expandHmac = new HMACSHA256(prk);
                var lastBlock = new byte[0];

                // Generate blocks
                for (var i = 0; i < n; i++)
                {
                    // T(i) = HMAC-Hash(PRK, T(i-1) | info | i+1)
                    var blockInput = new byte[lastBlock.Length + info.Length + 1];
                    Buffer.BlockCopy(lastBlock, 0, blockInput, 0, lastBlock.Length);
                    Buffer.BlockCopy(info, 0, blockInput, lastBlock.Length, info.Length);
                    blockInput[blockInput.Length - 1] = (byte)(i + 1);

                    lastBlock = expandHmac.ComputeHash(blockInput);
                    Buffer.BlockCopy(lastBlock, 0, t, i * 32, 32);
                }

                // Copy the required number of bytes to the output
                Buffer.BlockCopy(t, 0, okm, 0, outputLength);
                return okm;
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