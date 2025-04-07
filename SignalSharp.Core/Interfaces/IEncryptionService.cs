using System;
using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Provides methods for symmetric encryption and decryption operations.
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Encrypts the specified plain text using the provided key.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plainText or key is null.</exception>
        Task<byte[]> EncryptAsync(byte[] plainText, byte[] key);

        /// <summary>
        /// Decrypts the specified cipher text using the provided key.
        /// </summary>
        /// <param name="cipherText">The encrypted data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted plain text.</returns>
        /// <exception cref="ArgumentNullException">Thrown when cipherText or key is null.</exception>
        Task<byte[]> DecryptAsync(byte[] cipherText, byte[] key);

        /// <summary>
        /// Generates a new encryption key.
        /// </summary>
        /// <returns>A new encryption key.</returns>
        Task<byte[]> GenerateKeyAsync();

        /// <summary>
        /// Generates a new initialization vector (IV).
        /// </summary>
        /// <returns>A new initialization vector.</returns>
        Task<byte[]> GenerateIvAsync();
    }
} 