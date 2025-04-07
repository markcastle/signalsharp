# Code Samples

This document provides code samples for common scenarios when using SignalSharp.

## Basic Usage

### Initializing Dependencies

```csharp
// Create a key store
var keyStore = new FileKeyStore("path/to/key/store");

// Create cryptographic services
var encryptionService = new AesEncryptionService();
var hashService = new HashService();
var ecKeyExchangeService = new EcKeyExchangeService();
var x3dhService = new X3DHKeyAgreementService(ecKeyExchangeService, hashService);
var doubleRatchetService = new DoubleRatchetService(encryptionService, ecKeyExchangeService, hashService);

// Create a session manager
var sessionManager = new SessionManager(keyStore, x3dhService, doubleRatchetService);
```

### Creating a Session

```csharp
// Generate identity keys
var identityKeyPair = await x3dhService.GenerateIdentityKeyPairAsync();
var signedPreKeyPair = await x3dhService.GenerateSignedPreKeyPairAsync(identityKeyPair.PrivateKey);
var oneTimePreKeyPair = await x3dhService.GenerateOneTimePreKeyPairAsync();

// Exchange keys with remote party
var remoteIdentityKey = // ... receive from remote party
var remotePreKey = // ... receive from remote party
var remotePreKeySignature = // ... receive from remote party

// Create a session
var sessionId = await sessionManager.CreateSessionAsync(
    remoteIdentityKey,
    remotePreKey,
    remotePreKeySignature);
```

### Encrypting a Message

```csharp
// Encrypt a message
var message = Encoding.UTF8.GetBytes("Hello, world!");
var encryptedMessage = await sessionManager.EncryptMessageAsync(sessionId, message);

// Send the encrypted message to the remote party
// ... send encryptedMessage.EncryptedData to remote party
```

### Decrypting a Message

```csharp
// Receive an encrypted message from the remote party
var encryptedData = // ... receive from remote party

// Decrypt the message
var decryptedMessage = await sessionManager.DecryptMessageAsync(sessionId, encryptedData);

// Process the decrypted message
var message = Encoding.UTF8.GetString(decryptedMessage.Data);
```

### Deleting a Session

```csharp
// Delete a session
await sessionManager.DeleteSessionAsync(sessionId);
```

## Advanced Usage

### Custom JSON Serialization

```csharp
// Using System.Text.Json
var jsonSerializer = new SystemTextJsonSerializer();

// Using Newtonsoft.Json
var jsonSerializer = new NewtonsoftJsonSerializer();

// Create a session manager with custom JSON serialization
var sessionManager = new SessionManager(keyStore, x3dhService, doubleRatchetService, jsonSerializer);
```

### Custom Key Storage

```csharp
// Implement a custom key store
public class CustomKeyStore : IKeyStore
{
    public async Task<byte[]> GetKeyAsync(string keyId)
    {
        // ... retrieve key from custom storage
    }

    public async Task StoreKeyAsync(string keyId, byte[] key)
    {
        // ... store key in custom storage
    }

    public async Task DeleteKeyAsync(string keyId)
    {
        // ... delete key from custom storage
    }
}

// Create a session manager with custom key storage
var keyStore = new CustomKeyStore();
var sessionManager = new SessionManager(keyStore, x3dhService, doubleRatchetService);
```

### Batch Operations

```csharp
// Batch key storage operations
public async Task StoreKeysAsync(IEnumerable<KeyValuePair<string, byte[]>> keys)
{
    foreach (var key in keys)
    {
        await _keyStore.StoreKeyAsync(key.Key, key.Value);
    }
}

// Batch message encryption operations
public async Task<IEnumerable<EncryptedMessage>> EncryptMessagesAsync(string sessionId, IEnumerable<byte[]> messages)
{
    var encryptedMessages = new List<EncryptedMessage>();

    foreach (var message in messages)
    {
        var encryptedMessage = await _sessionManager.EncryptMessageAsync(sessionId, message);
        encryptedMessages.Add(encryptedMessage);
    }

    return encryptedMessages;
}

// Batch message decryption operations
public async Task<IEnumerable<DecryptedMessage>> DecryptMessagesAsync(string sessionId, IEnumerable<byte[]> encryptedMessages)
{
    var decryptedMessages = new List<DecryptedMessage>();

    foreach (var encryptedMessage in encryptedMessages)
    {
        var decryptedMessage = await _sessionManager.DecryptMessageAsync(sessionId, encryptedMessage);
        decryptedMessages.Add(decryptedMessage);
    }

    return decryptedMessages;
}
```

### Error Handling

```csharp
// Proper error handling for key operations
public async Task<KeyPair> GenerateIdentityKeyPairAsync()
{
    try
    {
        // Generate an identity key pair
        var identityKeyPair = await _x3dhService.GenerateIdentityKeyPairAsync();

        // Validate the generated key pair
        if (identityKeyPair == null || identityKeyPair.PrivateKey == null || identityKeyPair.PublicKey == null)
        {
            throw new CryptographicException("Failed to generate a valid identity key pair");
        }

        // Store the private key
        await _keyStore.StoreKeyAsync("identity", identityKeyPair.PrivateKey);

        return identityKeyPair;
    }
    catch (Exception ex)
    {
        // Log the exception
        _logger.LogError(ex, "Error generating identity key pair");

        // Rethrow the exception
        throw;
    }
}

// Proper error handling for session operations
public async Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey, byte[] remotePreKeySignature)
{
    string sessionId = null;

    try
    {
        // Validate inputs
        if (remoteIdentityKey == null || remoteIdentityKey.Length == 0)
        {
            throw new ArgumentNullException(nameof(remoteIdentityKey));
        }

        if (remotePreKey == null || remotePreKey.Length == 0)
        {
            throw new ArgumentNullException(nameof(remotePreKey));
        }

        if (remotePreKeySignature == null || remotePreKeySignature.Length == 0)
        {
            throw new ArgumentNullException(nameof(remotePreKeySignature));
        }

        // Create a session
        sessionId = await _sessionManager.CreateSessionAsync(
            remoteIdentityKey,
            remotePreKey,
            remotePreKeySignature);

        return sessionId;
    }
    catch (Exception ex)
    {
        // Log the exception
        _logger.LogError(ex, "Error creating session");

        // Clean up any partially created session
        if (sessionId != null)
        {
            try
            {
                await _sessionManager.DeleteSessionAsync(sessionId);
            }
            catch (Exception cleanupEx)
            {
                _logger.LogError(cleanupEx, "Error cleaning up session {SessionId}", sessionId);
            }
        }

        // Rethrow the exception
        throw;
    }
}

// Proper error handling for message operations
public async Task<string> EncryptMessageAsync(string sessionId, byte[] message)
{
    try
    {
        // Validate inputs
        if (string.IsNullOrEmpty(sessionId))
        {
            throw new ArgumentNullException(nameof(sessionId));
        }

        if (message == null || message.Length == 0)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Encrypt the message
        var encryptedMessage = await _sessionManager.EncryptMessageAsync(sessionId, message);

        // Return the encrypted message
        return Convert.ToBase64String(encryptedMessage.EncryptedData);
    }
    catch (Exception ex)
    {
        // Log the exception
        _logger.LogError(ex, "Error encrypting message for session {SessionId}", sessionId);

        // Rethrow the exception
        throw;
    }
}
```

## Next Steps

- Check out the [API Reference](api-reference.md) for detailed documentation of all public APIs.
- Read the [Integration Guide](integration-guide.md) for step-by-step instructions on integrating SignalSharp into your application.
- Learn about [Best Practices](best-practices.md) when using SignalSharp.
- Learn about [Security Considerations](security-considerations.md) when using SignalSharp.
- If you encounter issues, check the [Troubleshooting](troubleshooting.md) guide. 