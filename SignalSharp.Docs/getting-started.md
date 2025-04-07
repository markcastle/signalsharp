# Getting Started with SignalSharp

This guide will help you get started with SignalSharp, a C# implementation of the Signal Protocol for end-to-end encryption.

## Installation

SignalSharp is available as a NuGet package. You can install it using the NuGet Package Manager or the .NET CLI:

```bash
dotnet add package SignalSharp
```

## Basic Usage

### Setting Up Dependencies

First, you need to set up the required dependencies:

```csharp
// Create a directory for storing keys
var keyStore = new FileKeyStore("./keys", new AesEncryptionService());

// Create cryptographic services
var encryptionService = new AesEncryptionService();
var hashService = new HashService();
var keyExchangeService = new EcKeyExchangeService();
var x3dhService = new X3DHKeyAgreementService(keyExchangeService, hashService);
var doubleRatchetService = new DoubleRatchetService(
    encryptionService,
    keyExchangeService,
    hashService);

// Create a session manager
var sessionManager = new SessionManager(
    keyStore,
    encryptionService,
    keyExchangeService,
    hashService,
    doubleRatchetService);
```

### Creating a Session

To create a session with another party, you need their identity key, prekey, and prekey signature:

```csharp
// Create a new session
var sessionId = await sessionManager.CreateSessionAsync(
    remoteIdentityKey,
    remotePreKey,
    remotePreKeySignature);
```

### Encrypting a Message

To encrypt a message for a session:

```csharp
// Encrypt a message
var message = Encoding.UTF8.GetBytes("Hello, Signal!");
var encryptedMessage = await sessionManager.EncryptMessageAsync(sessionId, message);
```

### Decrypting a Message

To decrypt a message from a session:

```csharp
// Decrypt a message
var decryptedMessage = await sessionManager.ProcessIncomingMessageAsync(sessionId, encryptedMessage);
var decryptedText = Encoding.UTF8.GetString(decryptedMessage.DecryptedData);
```

### Cleaning Up

When you're done with a session, you should delete it:

```csharp
// Delete a session
await sessionManager.DeleteSessionAsync(sessionId);
```

## Advanced Usage

### Custom JSON Serialization

SignalSharp supports pluggable JSON serialization. You can use either System.Text.Json or Newtonsoft.Json:

```csharp
// Using System.Text.Json
var jsonOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
};
var jsonSerializer = new SystemTextJsonSerializer(jsonOptions);

// Using Newtonsoft.Json
var jsonSettings = new JsonSerializerSettings
{
    NullValueHandling = NullValueHandling.Ignore,
    ContractResolver = new CamelCasePropertyNamesContractResolver()
};
var jsonSerializer = new NewtonsoftJsonSerializer(jsonSettings);
```

### Custom Key Storage

You can implement your own key storage by implementing the `IKeyStore` interface:

```csharp
public class CustomKeyStore : IKeyStore
{
    public async Task StoreKeyAsync(string keyId, byte[] key)
    {
        // Your implementation
    }

    public async Task<byte[]> GetKeyAsync(string keyId)
    {
        // Your implementation
        return null;
    }

    // Implement other interface methods
}
```

## Next Steps

- Check out the [API Reference](api-reference.md) for detailed documentation of all public APIs.
- Read the [Integration Guide](integration-guide.md) for step-by-step instructions on integrating SignalSharp into your application.
- Explore the [Code Samples](code-samples.md) for examples of common scenarios.
- Review the [Best Practices](best-practices.md) for recommended patterns and practices.
- Learn about [Security Considerations](security-considerations.md) when using SignalSharp.
- If you encounter issues, check the [Troubleshooting](troubleshooting.md) guide. 