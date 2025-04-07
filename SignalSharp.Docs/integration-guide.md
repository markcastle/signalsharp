# SignalSharp Integration Guide

This guide provides step-by-step instructions for integrating SignalSharp into your application.

## Prerequisites

- .NET Standard 2.1 or later
- Basic understanding of cryptographic concepts
- Familiarity with C# and asynchronous programming

## Step 1: Install SignalSharp

Install SignalSharp using the NuGet Package Manager or the .NET CLI:

```bash
dotnet add package SignalSharp
```

## Step 2: Set Up Dependencies

Create the necessary dependencies for SignalSharp:

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

## Step 3: Implement Key Exchange

### Generating Keys

Before you can establish a session, you need to generate identity keys and prekeys:

```csharp
// Generate identity key
var identityKeyPair = await x3dhService.GenerateIdentityKeyPairAsync();

// Generate signed prekey
var signedPreKeyPair = await x3dhService.GenerateSignedPreKeyPairAsync(identityKeyPair);

// Generate one-time prekey
var oneTimePreKeyPair = await x3dhService.GenerateOneTimePreKeyPairAsync();
```

### Exchanging Keys

You need to exchange these keys with the remote party. This typically involves:

1. Sending your identity key and signed prekey to the remote party
2. Receiving the remote party's identity key and signed prekey
3. Performing the X3DH key agreement

```csharp
// Perform key agreement
var sharedSecret = await x3dhService.PerformKeyAgreementAsync(
    identityKeyPair,
    signedPreKeyPair,
    oneTimePreKeyPair,
    remoteIdentityKey,
    remoteSignedPreKey,
    remoteOneTimePreKey);
```

## Step 4: Create a Session

Once you have the shared secret, you can create a session:

```csharp
// Create a new session
var sessionId = await sessionManager.CreateSessionAsync(
    remoteIdentityKey,
    remotePreKey,
    remotePreKeySignature);
```

## Step 5: Encrypt and Decrypt Messages

### Encrypting Messages

To encrypt a message for a session:

```csharp
// Encrypt a message
var message = Encoding.UTF8.GetBytes("Hello, Signal!");
var encryptedMessage = await sessionManager.EncryptMessageAsync(sessionId, message);

// Send the encrypted message to the remote party
// This depends on your application's communication mechanism
await SendMessageAsync(encryptedMessage);
```

### Decrypting Messages

To decrypt a message from a session:

```csharp
// Receive an encrypted message from the remote party
// This depends on your application's communication mechanism
var encryptedMessage = await ReceiveMessageAsync();

// Decrypt the message
var decryptedMessage = await sessionManager.ProcessIncomingMessageAsync(sessionId, encryptedMessage);
var decryptedText = Encoding.UTF8.GetString(decryptedMessage.DecryptedData);
```

## Step 6: Clean Up

When you're done with a session, you should delete it:

```csharp
// Delete a session
await sessionManager.DeleteSessionAsync(sessionId);
```

## Integration Examples

### Web Application

For a web application, you might integrate SignalSharp like this:

```csharp
public class SignalService
{
    private readonly ISessionManager _sessionManager;
    private readonly IX3DHKeyAgreementService _x3dhService;
    private readonly IKeyStore _keyStore;

    public SignalService(
        ISessionManager sessionManager,
        IX3DHKeyAgreementService x3dhService,
        IKeyStore keyStore)
    {
        _sessionManager = sessionManager;
        _x3dhService = x3dhService;
        _keyStore = keyStore;
    }

    public async Task<string> InitializeSessionAsync(string userId)
    {
        // Generate keys for the user
        var identityKeyPair = await _x3dhService.GenerateIdentityKeyPairAsync();
        var signedPreKeyPair = await _x3dhService.GenerateSignedPreKeyPairAsync(identityKeyPair);
        var oneTimePreKeyPair = await _x3dhService.GenerateOneTimePreKeyPairAsync();

        // Store the keys
        await _keyStore.StoreKeyAsync($"{userId}_identity", identityKeyPair.PrivateKey);
        await _keyStore.StoreKeyAsync($"{userId}_signed_prekey", signedPreKeyPair.PrivateKey);
        await _keyStore.StoreKeyAsync($"{userId}_one_time_prekey", oneTimePreKeyPair.PrivateKey);

        // Return the public keys for the client
        return JsonSerializer.Serialize(new
        {
            IdentityKey = Convert.ToBase64String(identityKeyPair.PublicKey),
            SignedPreKey = Convert.ToBase64String(signedPreKeyPair.PublicKey),
            OneTimePreKey = Convert.ToBase64String(oneTimePreKeyPair.PublicKey)
        });
    }

    public async Task<string> CreateSessionAsync(string userId, string remoteUserId)
    {
        // Get the remote user's keys from your database or key server
        var remoteIdentityKey = await GetRemoteIdentityKeyAsync(remoteUserId);
        var remoteSignedPreKey = await GetRemoteSignedPreKeyAsync(remoteUserId);
        var remoteOneTimePreKey = await GetRemoteOneTimePreKeyAsync(remoteUserId);

        // Create a session
        var sessionId = await _sessionManager.CreateSessionAsync(
            remoteIdentityKey,
            remoteSignedPreKey,
            remoteOneTimePreKey);

        // Store the session ID for the user
        await _keyStore.StoreKeyAsync($"{userId}_{remoteUserId}_session", Encoding.UTF8.GetBytes(sessionId));

        return sessionId;
    }

    public async Task<string> EncryptMessageAsync(string userId, string remoteUserId, string message)
    {
        // Get the session ID
        var sessionIdBytes = await _keyStore.GetKeyAsync($"{userId}_{remoteUserId}_session");
        var sessionId = Encoding.UTF8.GetString(sessionIdBytes);

        // Encrypt the message
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var encryptedMessage = await _sessionManager.EncryptMessageAsync(sessionId, messageBytes);

        // Serialize the encrypted message
        return JsonSerializer.Serialize(encryptedMessage);
    }

    public async Task<string> DecryptMessageAsync(string userId, string remoteUserId, string encryptedMessageJson)
    {
        // Get the session ID
        var sessionIdBytes = await _keyStore.GetKeyAsync($"{userId}_{remoteUserId}_session");
        var sessionId = Encoding.UTF8.GetString(sessionIdBytes);

        // Deserialize the encrypted message
        var encryptedMessage = JsonSerializer.Deserialize<EncryptedMessage>(encryptedMessageJson);

        // Decrypt the message
        var decryptedMessage = await _sessionManager.ProcessIncomingMessageAsync(sessionId, encryptedMessage);

        // Return the decrypted message
        return Encoding.UTF8.GetString(decryptedMessage.DecryptedData);
    }
}
```

### Mobile Application

For a mobile application, you might integrate SignalSharp like this:

```csharp
public class SignalClient
{
    private readonly ISessionManager _sessionManager;
    private readonly IX3DHKeyAgreementService _x3dhService;
    private readonly IKeyStore _keyStore;
    private readonly HttpClient _httpClient;

    public SignalClient(
        ISessionManager sessionManager,
        IX3DHKeyAgreementService x3dhService,
        IKeyStore keyStore,
        HttpClient httpClient)
    {
        _sessionManager = sessionManager;
        _x3dhService = x3dhService;
        _keyStore = keyStore;
        _httpClient = httpClient;
    }

    public async Task InitializeAsync()
    {
        // Generate keys
        var identityKeyPair = await _x3dhService.GenerateIdentityKeyPairAsync();
        var signedPreKeyPair = await _x3dhService.GenerateSignedPreKeyPairAsync(identityKeyPair);
        var oneTimePreKeyPair = await _x3dhService.GenerateOneTimePreKeyPairAsync();

        // Store the keys
        await _keyStore.StoreKeyAsync("identity", identityKeyPair.PrivateKey);
        await _keyStore.StoreKeyAsync("signed_prekey", signedPreKeyPair.PrivateKey);
        await _keyStore.StoreKeyAsync("one_time_prekey", oneTimePreKeyPair.PrivateKey);

        // Register with the server
        await RegisterWithServerAsync(
            identityKeyPair.PublicKey,
            signedPreKeyPair.PublicKey,
            oneTimePreKeyPair.PublicKey);
    }

    public async Task<string> StartChatAsync(string remoteUserId)
    {
        // Get the remote user's keys from the server
        var remoteKeys = await GetRemoteKeysAsync(remoteUserId);

        // Create a session
        var sessionId = await _sessionManager.CreateSessionAsync(
            remoteKeys.IdentityKey,
            remoteKeys.SignedPreKey,
            remoteKeys.OneTimePreKey);

        // Store the session ID
        await _keyStore.StoreKeyAsync($"{remoteUserId}_session", Encoding.UTF8.GetBytes(sessionId));

        return sessionId;
    }

    public async Task<string> SendMessageAsync(string remoteUserId, string message)
    {
        // Get the session ID
        var sessionIdBytes = await _keyStore.GetKeyAsync($"{remoteUserId}_session");
        var sessionId = Encoding.UTF8.GetString(sessionIdBytes);

        // Encrypt the message
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var encryptedMessage = await _sessionManager.EncryptMessageAsync(sessionId, messageBytes);

        // Send the encrypted message to the server
        await SendEncryptedMessageAsync(remoteUserId, encryptedMessage);

        return "Message sent";
    }

    public async Task<string> ReceiveMessageAsync(string remoteUserId, EncryptedMessage encryptedMessage)
    {
        // Get the session ID
        var sessionIdBytes = await _keyStore.GetKeyAsync($"{remoteUserId}_session");
        var sessionId = Encoding.UTF8.GetString(sessionIdBytes);

        // Decrypt the message
        var decryptedMessage = await _sessionManager.ProcessIncomingMessageAsync(sessionId, encryptedMessage);

        // Return the decrypted message
        return Encoding.UTF8.GetString(decryptedMessage.DecryptedData);
    }
}
```

## Next Steps

- Check out the [API Reference](api-reference.md) for detailed documentation of all public APIs.
- Explore the [Code Samples](code-samples.md) for more examples of common scenarios.
- Review the [Best Practices](best-practices.md) for recommended patterns and practices.
- Learn about [Security Considerations](security-considerations.md) when using SignalSharp.
- If you encounter issues, check the [Troubleshooting](troubleshooting.md) guide. 