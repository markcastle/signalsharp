# SignalSharp 🔐

SignalSharp is a minimal viable implementation of the Signal protocol in C#. It provides end-to-end encryption capabilities while adhering to SOLID principles and maintaining high test coverage.

## ✨ Features

- 🔒 End-to-end encryption using modern cryptographic primitives
- 🤝 X3DH key agreement protocol
- 🔄 Double Ratchet algorithm for forward secrecy
- 💾 Secure key storage and management
- 📦 .NET Standard 2.1 compliant
- 🔌 Flexible JSON serialization with pluggable providers

## 🏗️ Project Structure

- **SignalSharp.Core**: Core protocol logic and interfaces
- **SignalSharp.Security**: Cryptographic operations and key management
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