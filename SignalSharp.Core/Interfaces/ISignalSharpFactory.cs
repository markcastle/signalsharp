using System.Threading.Tasks;

namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Factory interface for creating Signal protocol components.
    /// </summary>
    public interface ISignalSharpFactory
    {
        /// <summary>
        /// Creates a new session manager instance.
        /// </summary>
        /// <returns>A new session manager instance.</returns>
        Task<ISessionManager> CreateSessionManagerAsync();

        /// <summary>
        /// Creates a new key store instance.
        /// </summary>
        /// <returns>A new key store instance.</returns>
        Task<IKeyStore> CreateKeyStoreAsync();

        /// <summary>
        /// Creates a new encryption service instance.
        /// </summary>
        /// <returns>A new encryption service instance.</returns>
        Task<IEncryptionService> CreateEncryptionServiceAsync();

        /// <summary>
        /// Creates a new key exchange service instance.
        /// </summary>
        /// <returns>A new key exchange service instance.</returns>
        Task<IEcKeyExchangeService> CreateKeyExchangeServiceAsync();

        /// <summary>
        /// Creates a new hash service instance.
        /// </summary>
        /// <returns>A new hash service instance.</returns>
        Task<IHashService> CreateHashServiceAsync();

        /// <summary>
        /// Creates a new double ratchet service instance.
        /// </summary>
        /// <returns>A new double ratchet service instance.</returns>
        Task<IDoubleRatchetService> CreateDoubleRatchetServiceAsync();

        /// <summary>
        /// Creates a new X3DH key agreement service instance.
        /// </summary>
        /// <returns>A new X3DH key agreement service instance.</returns>
        Task<IX3DHKeyAgreementService> CreateX3DHKeyAgreementServiceAsync();

        /// <summary>
        /// Creates a new JSON serializer instance.
        /// </summary>
        /// <returns>A new JSON serializer instance.</returns>
        Task<IJsonSerializer> CreateJsonSerializerAsync();
    }
} 