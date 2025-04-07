using System;
using Microsoft.Extensions.DependencyInjection;
using SignalSharp.Core.Interfaces;
using SignalSharp.Core.Models;
using SignalSharp.Core.Options;
using SignalSharp.Security.Services;
using SignalSharp.Storage.Services;
using SignalSharp.Serialization.SystemTextJson;
using SignalSharp.Serialization.NewtonsoftJson;

namespace SignalSharp.DependencyInjection
{
    /// <summary>
    /// Extension methods for configuring SignalSharp services.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds SignalSharp services to the service collection.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">An action to configure the SignalSharp options.</param>
        /// <returns>The service collection.</returns>
        public static IServiceCollection AddSignalSharp(this IServiceCollection services, Action<SignalSharpOptions> configure)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure));
            }

            var options = new SignalSharpOptions();
            configure(options);

            // Register options
            services.AddSingleton(options);

            // Register JSON serializer
            RegisterJsonSerializer(services, options.JsonSerializer);

            // Register key store
            RegisterKeyStore(services, options.KeyStore);

            // Register encryption services
            RegisterEncryptionServices(services);

            // Register session manager
            RegisterSessionManager(services, options.SessionManager);

            return services;
        }

        /// <summary>
        /// Registers the JSON serializer.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="options">The JSON serializer options.</param>
        private static void RegisterJsonSerializer(IServiceCollection services, JsonSerializerConfiguration options)
        {
            if (options.JsonSerializerFactory != null)
            {
                services.AddSingleton<IJsonSerializer>(options.JsonSerializerFactory);
                return;
            }

            switch (options.Type)
            {
                case JsonSerializerType.Default:
                    // Default to System.Text.Json
                    services.AddSingleton<IJsonSerializer, SystemTextJsonSerializer>();
                    break;
                case JsonSerializerType.Custom:
                    throw new InvalidOperationException("Custom JSON serializer type requires a factory to be specified.");
                default:
                    throw new ArgumentException($"Unsupported JSON serializer type: {options.Type}");
            }
        }

        /// <summary>
        /// Registers the key store.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="options">The key store options.</param>
        private static void RegisterKeyStore(IServiceCollection services, KeyStoreOptions options)
        {
            if (options.KeyStoreFactory != null)
            {
                services.AddSingleton<IKeyStore>(options.KeyStoreFactory);
                return;
            }

            services.AddSingleton<IKeyStore>(sp => new FileKeyStore(
                options.Path,
                sp.GetRequiredService<IJsonSerializer>(),
                sp.GetRequiredService<IEncryptionService>()));
        }

        /// <summary>
        /// Registers the encryption services.
        /// </summary>
        /// <param name="services">The service collection.</param>
        private static void RegisterEncryptionServices(IServiceCollection services)
        {
            // Register AES encryption service
            services.AddSingleton<IEncryptionService, AesEncryptionService>();

            // Register EC key exchange service
            services.AddSingleton<IEcKeyExchangeService, EcKeyExchangeService>();

            // Register hash service
            services.AddSingleton<IHashService, HashService>();

            // Register X3DH key agreement service
            services.AddSingleton<IX3DHKeyAgreementService>(sp => new X3DHKeyAgreementService(
                sp.GetRequiredService<IEcKeyExchangeService>(),
                sp.GetRequiredService<IHashService>()));

            // Register Double Ratchet service
            services.AddSingleton<IDoubleRatchetService>(sp => new DoubleRatchetService(
                sp.GetRequiredService<IEncryptionService>(),
                sp.GetRequiredService<IEcKeyExchangeService>(),
                sp.GetRequiredService<IHashService>()));
        }

        /// <summary>
        /// Registers the session manager.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="options">The session manager options.</param>
        private static void RegisterSessionManager(IServiceCollection services, SessionManagerOptions options)
        {
            if (options.SessionManagerFactory != null)
            {
                services.AddSingleton<ISessionManager>(options.SessionManagerFactory);
                return;
            }

            services.AddSingleton<ISessionManager>(sp => new FileSessionManager(
                options.Path,
                sp.GetRequiredService<IKeyStore>(),
                sp.GetRequiredService<IEncryptionService>(),
                sp.GetRequiredService<IJsonSerializer>()));
        }
    }
} 