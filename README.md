# SignalSharp 🔐

SignalSharp is a minimal viable implementation of the Signal protocol in C#. It provides end-to-end encryption capabilities while adhering to SOLID principles and maintaining high test coverage.

## ✨ Features

- 🔒 End-to-end encryption using modern cryptographic primitives
- 🤝 X3DH key agreement protocol with identity, signed prekey, and one-time prekey support
- 🔄 Double Ratchet algorithm for forward secrecy
- 💾 Secure key storage and management
- 📦 .NET Standard 2.1 compliant
- 🔌 Flexible JSON serialization with pluggable providers
- ✅ Comprehensive test coverage with 100+ unit tests

## 🏗️ Project Structure

- **SignalSharp.Core**: Core protocol logic and interfaces
- **SignalSharp.Security**: Cryptographic operations and key management
  - X3DH key agreement implementation
  - Hash and encryption services
- **SignalSharp.Storage**: Persistent storage of keys and sessions
- **SignalSharp.Serialization.SystemTextJson**: System.Text.Json implementation
- **SignalSharp.Serialization.NewtonsoftJson**: Newtonsoft.Json implementation
- **SignalSharp.Tests**: Unit, integration, and security tests

## 📋 Requirements

- .NET Standard 2.1
- System.Security.Cryptography
- xUnit (for testing)

## 🚀 Getting Started

1. Clone the repository
2. Build the solution
3. Run the tests
4. Start using the library in your project

## 💻 Usage Example

```csharp
// Initialize dependencies
var keyStore = new FileKeyStore("./keys");
var encryptionService = new EncryptionService();
var jsonSerializer = new SystemTextJsonSerializer();
var x3dhService = new X3DHKeyAgreementService(
    new HashService(),
    new EcKeyExchangeService());

// Generate identity and prekeys
var identityKeyPair = await x3dhService.GenerateIdentityKeyPairAsync();
var signedPreKeyPair = await x3dhService.GenerateSignedPreKeyPairAsync(identityKeyPair);
var oneTimePreKeyPair = await x3dhService.GenerateOneTimePreKeyPairAsync();

// Perform X3DH key agreement
var sharedSecret = await x3dhService.PerformKeyAgreementAsync(
    initiatorIdentityKey,
    initiatorEphemeralKey,
    recipientIdentityKey,
    recipientSignedPreKey,
    recipientOneTimePreKey);

// Create a session manager
var sessionManager = new FileSessionManager(
    "./sessions",
    keyStore,
    encryptionService,
    jsonSerializer);

// Create a new session
var sessionId = await sessionManager.CreateSessionAsync(
    remoteIdentityKey,
    remotePreKey,
    remotePreKeySignature);

// Encrypt a message
var encryptedMessage = await sessionManager.EncryptMessageAsync(
    sessionId,
    Encoding.UTF8.GetBytes("Hello, Signal!"));

// Decrypt a message
var decryptedMessage = await sessionManager.ProcessIncomingMessageAsync(
    sessionId,
    encryptedMessage);
```

## 🔒 Security Considerations

- All cryptographic operations use secure random number generation
- Keys are securely stored and managed
- Input validation and guard clauses prevent common vulnerabilities
- Memory safety is ensured through proper key handling
- JSON serialization is abstracted to allow secure implementations
- X3DH protocol implementation follows Signal Protocol specifications
- Comprehensive null checks and parameter validation
- Immutable key pairs and session states
- Secure key derivation using HMAC-based key derivation

## 🧪 Testing

The project maintains high test coverage with:
- Unit tests for all core components
- Integration tests for key agreement and session management
- Security tests for cryptographic operations
- Mock-based testing for external dependencies
- Comprehensive edge case and error handling tests

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Signal Protocol specification
- .NET Cryptography libraries
- Contributors and maintainers 