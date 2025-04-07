# SignalSharp.DependencyInjection

This project provides dependency injection support for SignalSharp, making it easy to integrate SignalSharp into applications that use Microsoft's dependency injection framework.

## Installation

Install the SignalSharp.DependencyInjection package using the NuGet Package Manager:

```bash
dotnet add package SignalSharp.DependencyInjection
```

## Usage

### Basic Usage

Add SignalSharp services to your application's service collection:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddSignalSharp(options =>
    {
        // Configure options here
    });
}
```

### Configuration Options

The `AddSignalSharp` method accepts an action to configure the SignalSharp options:

```csharp
services.AddSignalSharp(options =>
{
    // Configure key store
    options.KeyStoreOptions.Type = KeyStoreType.File;
    options.KeyStoreOptions.Path = "path/to/keys";

    // Configure encryption
    options.EncryptionOptions.KeySize = 256;
    options.EncryptionOptions.Algorithm = "AES";
    options.EncryptionOptions.Mode = "CBC";
    options.EncryptionOptions.Padding = "PKCS7";

    // Configure JSON serializer
    options.JsonSerializerOptions.Type = JsonSerializerType.SystemTextJson;

    // Configure session manager
    options.SessionManagerOptions.Type = SessionManagerType.File;
    options.SessionManagerOptions.Path = "path/to/sessions";
});
```

### Using the SignalSharpFactory

The `SignalSharpFactory` class provides factory methods for common scenarios:

```csharp
// Create a factory with default options
var factory = SignalSharpFactory.CreateDefault("path/to/base/directory");

// Create an identity key pair
var identityKeyPair = await factory.CreateIdentityKeyPairAsync();

// Create a signed prekey pair
var signedPreKeyPair = await factory.CreateSignedPreKeyPairAsync(identityKeyPair);

// Create a one-time prekey pair
var oneTimePreKeyPair = await factory.CreateOneTimePreKeyPairAsync();

// Create a session with a remote party
var sessionId = await factory.CreateSessionAsync(
    remoteIdentityKey,
    remoteSignedPreKey,
    remoteOneTimePreKey,
    identityKeyPair,
    signedPreKeyPair);

// Encrypt a message
var encryptedMessage = await factory.EncryptMessageAsync(sessionId, "Hello, world!");

// Decrypt a message
var decryptedMessage = await factory.DecryptMessageAsync(sessionId, encryptedMessage);

// Delete a session
await factory.DeleteSessionAsync(sessionId);
```

### Custom Implementations

You can provide custom implementations for the key store, JSON serializer, and session manager:

```csharp
services.AddSignalSharp(options =>
{
    // Custom key store
    options.KeyStoreOptions.Type = KeyStoreType.Custom;
    options.KeyStoreOptions.KeyStoreFactory = sp => new CustomKeyStore();

    // Custom JSON serializer
    options.JsonSerializerOptions.Type = JsonSerializerType.Custom;
    options.JsonSerializerOptions.JsonSerializerFactory = sp => new CustomJsonSerializer();

    // Custom session manager
    options.SessionManagerOptions.Type = SessionManagerType.Custom;
    options.SessionManagerOptions.SessionManagerFactory = sp => new CustomSessionManager();
});
```

## Examples

### ASP.NET Core Web API

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSignalSharp(options =>
        {
            options.KeyStoreOptions.Path = Path.Combine(AppContext.BaseDirectory, "keys");
            options.SessionManagerOptions.Path = Path.Combine(AppContext.BaseDirectory, "sessions");
        });

        services.AddControllers();
    }
}

public class SignalController : ControllerBase
{
    private readonly SignalSharpFactory _signalFactory;

    public SignalController(SignalSharpFactory signalFactory)
    {
        _signalFactory = signalFactory;
    }

    [HttpPost("encrypt")]
    public async Task<IActionResult> Encrypt([FromBody] EncryptRequest request)
    {
        var encryptedMessage = await _signalFactory.EncryptMessageAsync(
            request.SessionId,
            request.Message);

        return Ok(encryptedMessage);
    }

    [HttpPost("decrypt")]
    public async Task<IActionResult> Decrypt([FromBody] DecryptRequest request)
    {
        var decryptedMessage = await _signalFactory.DecryptMessageAsync(
            request.SessionId,
            request.EncryptedMessage);

        return Ok(decryptedMessage);
    }
}
```

### Console Application

```csharp
class Program
{
    static async Task Main(string[] args)
    {
        var factory = SignalSharpFactory.CreateDefault("path/to/base/directory");

        // Create an identity key pair
        var identityKeyPair = await factory.CreateIdentityKeyPairAsync();
        Console.WriteLine($"Identity Key: {Convert.ToBase64String(identityKeyPair.PublicKey)}");

        // Create a signed prekey pair
        var signedPreKeyPair = await factory.CreateSignedPreKeyPairAsync(identityKeyPair);
        Console.WriteLine($"Signed Prekey: {Convert.ToBase64String(signedPreKeyPair.PublicKey)}");

        // Create a one-time prekey pair
        var oneTimePreKeyPair = await factory.CreateOneTimePreKeyPairAsync();
        Console.WriteLine($"One-Time Prekey: {Convert.ToBase64String(oneTimePreKeyPair.PublicKey)}");

        // Create a session with a remote party
        var sessionId = await factory.CreateSessionAsync(
            remoteIdentityKey,
            remoteSignedPreKey,
            remoteOneTimePreKey,
            identityKeyPair,
            signedPreKeyPair);

        Console.WriteLine($"Session ID: {sessionId}");

        // Encrypt a message
        var encryptedMessage = await factory.EncryptMessageAsync(sessionId, "Hello, world!");
        Console.WriteLine($"Encrypted Message: {Convert.ToBase64String(encryptedMessage.Ciphertext)}");

        // Decrypt a message
        var decryptedMessage = await factory.DecryptMessageAsync(sessionId, encryptedMessage);
        Console.WriteLine($"Decrypted Message: {decryptedMessage.Plaintext}");
    }
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 