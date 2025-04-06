using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SignalSharp.Core.Interfaces;

namespace SignalSharp.Security.Services
{
    /// <summary>
    /// Provides AES-based encryption and decryption operations.
    /// </summary>
    public class AesEncryptionService : IEncryptionService
    {
        private const int KeySize = 256;
        private const int BlockSize = 128;
        private const int IvSize = 16; // 128 bits

        /// <summary>
        /// Encrypts the specified plain text using AES encryption with the provided key.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null.</exception>
        /// <exception cref="ArgumentException">Thrown when key length is invalid.</exception>
        public async Task<byte[]> EncryptAsync(byte[] plainText, byte[] key)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySize / 8) throw new ArgumentException($"Key must be {KeySize} bits", nameof(key));

            return await Task.Run(() =>
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.GenerateIV();

                using var encryptor = aes.CreateEncryptor();
                var encrypted = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);

                // Combine IV and encrypted data
                var result = new byte[IvSize + encrypted.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, IvSize);
                Buffer.BlockCopy(encrypted, 0, result, IvSize, encrypted.Length);

                return result;
            });
        }

        /// <summary>
        /// Decrypts the specified cipher text using AES decryption with the provided key.
        /// </summary>
        /// <param name="cipherText">The encrypted data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted plain text.</returns>
        /// <exception cref="ArgumentNullException">Thrown when cipherText or key is null.</exception>
        /// <exception cref="ArgumentException">Thrown when key length is invalid or cipherText is too short.</exception>
        public async Task<byte[]> DecryptAsync(byte[] cipherText, byte[] key)
        {
            if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySize / 8) throw new ArgumentException($"Key must be {KeySize} bits", nameof(key));
            if (cipherText.Length < IvSize) throw new ArgumentException("Cipher text is too short", nameof(cipherText));

            return await Task.Run(() =>
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;

                // Extract IV from cipher text
                var iv = new byte[IvSize];
                Buffer.BlockCopy(cipherText, 0, iv, 0, IvSize);
                aes.IV = iv;

                // Extract encrypted data
                var encrypted = new byte[cipherText.Length - IvSize];
                Buffer.BlockCopy(cipherText, IvSize, encrypted, 0, encrypted.Length);

                using var decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            });
        }

        /// <summary>
        /// Generates a new AES encryption key.
        /// </summary>
        /// <returns>A new encryption key.</returns>
        public async Task<byte[]> GenerateKeyAsync()
        {
            return await Task.Run(() =>
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.GenerateKey();
                return aes.Key;
            });
        }
    }
} 