# SignalSharp API Reference

This document provides detailed documentation of all public APIs in the SignalSharp library.

## Table of Contents

- [Core Interfaces](#core-interfaces)
  - [IKeyStore](#ikeystore)
  - [ISessionManager](#isessionmanager)
  - [IJsonSerializer](#ijsonserializer)
- [Security Services](#security-services)
  - [IX3DHKeyAgreementService](#ix3dhkeyagreementservice)
  - [IDoubleRatchetService](#idoubleratchetservice)
  - [IEncryptionService](#iencryptionservice)
  - [IHashService](#ihashservice)
  - [IKeyExchangeService](#ikeyexchangeservice)
- [Storage Services](#storage-services)
  - [FileKeyStore](#filekeystore)
- [Models](#models)
  - [KeyPair](#keypair)
  - [SessionState](#sessionstate)
  - [EncryptedMessage](#encryptedmessage)
  - [DecryptedMessage](#decryptedmessage)

## Core Interfaces

### IKeyStore

The `IKeyStore` interface provides methods for storing and retrieving cryptographic keys.

```csharp
public interface IKeyStore
{
    /// <summary>
    /// Stores a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <param name="key">The key data to store.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreKeyAsync(string keyId, byte[] key);

    /// <summary>
    /// Retrieves a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <returns>The key data, or null if the key does not exist.</returns>
    Task<byte[]> GetKeyAsync(string keyId);

    /// <summary>
    /// Deletes a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteKeyAsync(string keyId);

    /// <summary>
    /// Stores session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <param name="state">The session state to store.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreSessionStateAsync(string sessionId, SessionState state);

    /// <summary>
    /// Retrieves session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <returns>The session state, or null if the session does not exist.</returns>
    Task<SessionState> GetSessionStateAsync(string sessionId);

    /// <summary>
    /// Deletes session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteSessionStateAsync(string sessionId);
}
```

### ISessionManager

The `ISessionManager` interface provides methods for managing cryptographic sessions.

```csharp
public interface ISessionManager
{
    /// <summary>
    /// Creates a new session with the specified remote identity key and prekey.
    /// </summary>
    /// <param name="remoteIdentityKey">The remote party's identity key.</param>
    /// <param name="remotePreKey">The remote party's prekey.</param>
    /// <param name="remotePreKeySignature">The signature of the remote party's prekey.</param>
    /// <returns>The ID of the newly created session.</returns>
    Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey, byte[] remotePreKeySignature);

    /// <summary>
    /// Processes an incoming message and returns the decrypted message.
    /// </summary>
    /// <param name="sessionId">The ID of the session.</param>
    /// <param name="encryptedMessage">The encrypted message to process.</param>
    /// <returns>The decrypted message.</returns>
    Task<DecryptedMessage> ProcessIncomingMessageAsync(string sessionId, EncryptedMessage encryptedMessage);

    /// <summary>
    /// Encrypts a message for the specified session.
    /// </summary>
    /// <param name="sessionId">The ID of the session.</param>
    /// <param name="message">The message to encrypt.</param>
    /// <returns>The encrypted message.</returns>
    Task<EncryptedMessage> EncryptMessageAsync(string sessionId, byte[] message);

    /// <summary>
    /// Deletes a session with the specified ID.
    /// </summary>
    /// <param name="sessionId">The ID of the session to delete.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteSessionAsync(string sessionId);
}
```

### IJsonSerializer

The `IJsonSerializer` interface provides methods for serializing and deserializing objects to and from JSON.

```csharp
public interface IJsonSerializer
{
    /// <summary>
    /// Serializes an object to a JSON string.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <returns>The JSON string representation of the object.</returns>
    string Serialize<T>(T obj);

    /// <summary>
    /// Deserializes a JSON string to an object.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize.</typeparam>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>The deserialized object.</returns>
    T Deserialize<T>(string json);
}
```

## Security Services

### IX3DHKeyAgreementService

The `IX3DHKeyAgreementService` interface provides methods for performing the X3DH key agreement protocol.

```csharp
public interface IX3DHKeyAgreementService
{
    /// <summary>
    /// Generates an identity key pair.
    /// </summary>
    /// <returns>The generated identity key pair.</returns>
    Task<KeyPair> GenerateIdentityKeyPairAsync();

    /// <summary>
    /// Generates a signed prekey pair.
    /// </summary>
    /// <param name="identityKeyPair">The identity key pair to sign the prekey with.</param>
    /// <returns>The generated signed prekey pair.</returns>
    Task<KeyPair> GenerateSignedPreKeyPairAsync(KeyPair identityKeyPair);

    /// <summary>
    /// Generates a one-time prekey pair.
    /// </summary>
    /// <returns>The generated one-time prekey pair.</returns>
    Task<KeyPair> GenerateOneTimePreKeyPairAsync();

    /// <summary>
    /// Performs the X3DH key agreement protocol.
    /// </summary>
    /// <param name="identityKeyPair">The local identity key pair.</param>
    /// <param name="signedPreKeyPair">The local signed prekey pair.</param>
    /// <param name="oneTimePreKeyPair">The local one-time prekey pair.</param>
    /// <param name="remoteIdentityKey">The remote party's identity key.</param>
    /// <param name="remoteSignedPreKey">The remote party's signed prekey.</param>
    /// <param name="remoteOneTimePreKey">The remote party's one-time prekey.</param>
    /// <returns>The shared secret derived from the key agreement.</returns>
    Task<byte[]> PerformKeyAgreementAsync(
        KeyPair identityKeyPair,
        KeyPair signedPreKeyPair,
        KeyPair oneTimePreKeyPair,
        byte[] remoteIdentityKey,
        byte[] remoteSignedPreKey,
        byte[] remoteOneTimePreKey);
}
```

### IDoubleRatchetService

The `IDoubleRatchetService` interface provides methods for implementing the Double Ratchet algorithm.

```csharp
public interface IDoubleRatchetService
{
    /// <summary>
    /// Initializes the ratchet with the specified root key.
    /// </summary>
    /// <param name="rootKey">The root key to initialize the ratchet with.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task InitializeRatchetAsync(byte[] rootKey);

    /// <summary>
    /// Performs a ratchet step and returns the derived message key.
    /// </summary>
    /// <param name="isSending">Whether the ratchet step is for sending or receiving.</param>
    /// <returns>The derived message key.</returns>
    Task<byte[]> RatchetStepAsync(bool isSending);
}
```

### IEncryptionService

The `IEncryptionService` interface provides methods for symmetric encryption and decryption.

```csharp
public interface IEncryptionService
{
    /// <summary>
    /// Encrypts data using the specified key.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The key to use for encryption.</param>
    /// <returns>The encrypted data.</returns>
    Task<byte[]> EncryptAsync(byte[] data, byte[] key);

    /// <summary>
    /// Decrypts data using the specified key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data to decrypt.</param>
    /// <param name="key">The key to use for decryption.</param>
    /// <returns>The decrypted data.</returns>
    Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] key);
}
```

### IHashService

The `IHashService` interface provides methods for cryptographic hashing.

```csharp
public interface IHashService
{
    /// <summary>
    /// Computes the hash of the specified data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The hash of the data.</returns>
    Task<byte[]> HashAsync(byte[] data);

    /// <summary>
    /// Computes the HMAC of the specified data using the specified key.
    /// </summary>
    /// <param name="data">The data to compute the HMAC of.</param>
    /// <param name="key">The key to use for the HMAC.</param>
    /// <returns>The HMAC of the data.</returns>
    Task<byte[]> ComputeHmacAsync(byte[] data, byte[] key);
}
```

### IKeyExchangeService

The `IKeyExchangeService` interface provides methods for key exchange operations.

```csharp
public interface IKeyExchangeService
{
    /// <summary>
    /// Generates a key pair.
    /// </summary>
    /// <returns>The generated key pair.</returns>
    Task<KeyPair> GenerateKeyPairAsync();

    /// <summary>
    /// Computes a shared secret using the local private key and the remote public key.
    /// </summary>
    /// <param name="localKeyPair">The local key pair.</param>
    /// <param name="remotePublicKey">The remote party's public key.</param>
    /// <returns>The computed shared secret.</returns>
    Task<byte[]> ComputeSharedSecretAsync(KeyPair localKeyPair, byte[] remotePublicKey);
}
```

## Storage Services

### FileKeyStore

The `FileKeyStore` class provides a file-based implementation of the `IKeyStore` interface.

```csharp
public class FileKeyStore : IKeyStore
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FileKeyStore"/> class.
    /// </summary>
    /// <param name="baseDirectory">The base directory for storing keys.</param>
    /// <param name="encryptionService">The encryption service to use for encrypting keys.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public FileKeyStore(string baseDirectory, IEncryptionService encryptionService);

    /// <summary>
    /// Stores a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <param name="key">The key data to store.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public Task StoreKeyAsync(string keyId, byte[] key);

    /// <summary>
    /// Retrieves a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <returns>The key data, or null if the key does not exist.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null.</exception>
    public Task<byte[]> GetKeyAsync(string keyId);

    /// <summary>
    /// Deletes a key with the specified ID.
    /// </summary>
    /// <param name="keyId">The unique identifier for the key.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when keyId is null.</exception>
    public Task DeleteKeyAsync(string keyId);

    /// <summary>
    /// Stores session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <param name="state">The session state to store.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public Task StoreSessionStateAsync(string sessionId, SessionState state);

    /// <summary>
    /// Retrieves session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <returns>The session state, or null if the session does not exist.</returns>
    /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
    public Task<SessionState> GetSessionStateAsync(string sessionId);

    /// <summary>
    /// Deletes session state with the specified ID.
    /// </summary>
    /// <param name="sessionId">The unique identifier for the session.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when sessionId is null.</exception>
    public Task DeleteSessionStateAsync(string sessionId);
}
```

## Models

### KeyPair

The `KeyPair` class represents a cryptographic key pair.

```csharp
public class KeyPair
{
    /// <summary>
    /// Gets the public key.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Gets the private key.
    /// </summary>
    public byte[] PrivateKey { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    /// <param name="privateKey">The private key.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public KeyPair(byte[] publicKey, byte[] privateKey);
}
```

### SessionState

The `SessionState` class represents the state of a cryptographic session.

```csharp
public class SessionState
{
    /// <summary>
    /// Gets or sets the root key.
    /// </summary>
    public byte[] RootKey { get; set; }

    /// <summary>
    /// Gets or sets the sending chain key.
    /// </summary>
    public byte[] SendingChainKey { get; set; }

    /// <summary>
    /// Gets or sets the receiving chain key.
    /// </summary>
    public byte[] ReceivingChainKey { get; set; }

    /// <summary>
    /// Gets or sets the sending message count.
    /// </summary>
    public int SendingMessageCount { get; set; }

    /// <summary>
    /// Gets or sets the receiving message count.
    /// </summary>
    public int ReceivingMessageCount { get; set; }

    /// <summary>
    /// Gets or sets the skipped message keys.
    /// </summary>
    public Dictionary<int, byte[]> SkippedMessageKeys { get; set; }
}
```

### EncryptedMessage

The `EncryptedMessage` class represents an encrypted message.

```csharp
public class EncryptedMessage
{
    /// <summary>
    /// Gets or sets the encrypted data.
    /// </summary>
    public byte[] EncryptedData { get; set; }

    /// <summary>
    /// Gets or sets the message authentication code.
    /// </summary>
    public byte[] Mac { get; set; }

    /// <summary>
    /// Gets or sets the message number.
    /// </summary>
    public int MessageNumber { get; set; }
}
```

### DecryptedMessage

The `DecryptedMessage` class represents a decrypted message.

```csharp
public class DecryptedMessage
{
    /// <summary>
    /// Gets or sets the decrypted data.
    /// </summary>
    public byte[] DecryptedData { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the message was skipped.
    /// </summary>
    public bool WasSkipped { get; set; }
} 