# Unity Integration Guide 🎮

This guide explains how to integrate SignalSharp into Unity projects, including setup, usage, and best practices.

## 📋 Prerequisites

- Unity 2021.x or later (which supports .NET Standard 2.1)
- Visual Studio or Visual Studio Code
- Git (optional, for source control)

## 🏗️ Building for Unity

### Building the DLLs

```powershell
# Clone the repository if you haven't already
git clone https://github.com/yourusername/SignalSharp.git
cd SignalSharp

# Build in Release mode
dotnet build -c Release
```

### Required DLLs

Copy these DLLs from the `bin/Release/netstandard2.1` folders to your Unity project's `Assets/Plugins` folder:
- `SignalSharp.Core.dll`
- `SignalSharp.Security.dll`
- `SignalSharp.Storage.dll`
- `SignalSharp.Serialization.NewtonsoftJson.dll` (recommended over System.Text.Json for Unity)

## 💻 Unity-Specific Setup

### Unity Wrapper Class

```csharp
using SignalSharp.Core;
using SignalSharp.Security;
using SignalSharp.Storage;
using SignalSharp.Serialization.NewtonsoftJson;
using UnityEngine;

public class SignalSharpUnity : MonoBehaviour
{
    private SessionManager _sessionManager;
    private string _sessionId;

    private void Awake()
    {
        // Initialize with Unity's persistent data path
        string keyStorePath = Path.Combine(Application.persistentDataPath, "keys");
        Directory.CreateDirectory(keyStorePath);

        // Initialize services
        var keyStore = new FileKeyStore(keyStorePath);
        var encryptionService = new AesEncryptionService();
        var hashService = new HashService();
        var keyExchangeService = new EcKeyExchangeService();
        var jsonSerializer = new NewtonsoftJsonSerializer();
        var doubleRatchetService = new DoubleRatchetService(
            encryptionService,
            keyExchangeService,
            hashService);

        // Create session manager
        _sessionManager = new SessionManager(
            keyStore,
            encryptionService,
            keyExchangeService,
            hashService,
            doubleRatchetService);
    }

    public async Task<string> CreateSessionAsync(byte[] remoteIdentityKey, byte[] remotePreKey)
    {
        try
        {
            _sessionId = await _sessionManager.CreateSessionAsync(
                remoteIdentityKey,
                remotePreKey,
                null); // Optional one-time prekey
            return _sessionId;
        }
        catch (Exception ex)
        {
            Debug.LogError($"Failed to create session: {ex.Message}");
            throw;
        }
    }

    public async Task<byte[]> EncryptMessageAsync(string message)
    {
        try
        {
            return await _sessionManager.EncryptMessageAsync(
                _sessionId,
                System.Text.Encoding.UTF8.GetBytes(message));
        }
        catch (Exception ex)
        {
            Debug.LogError($"Failed to encrypt message: {ex.Message}");
            throw;
        }
    }

    public async Task<string> DecryptMessageAsync(byte[] encryptedMessage)
    {
        try
        {
            var decrypted = await _sessionManager.ProcessIncomingMessageAsync(
                _sessionId,
                encryptedMessage);
            return System.Text.Encoding.UTF8.GetString(decrypted);
        }
        catch (Exception ex)
        {
            Debug.LogError($"Failed to decrypt message: {ex.Message}");
            throw;
        }
    }

    private void OnDestroy()
    {
        if (!string.IsNullOrEmpty(_sessionId))
        {
            // Clean up session when the GameObject is destroyed
            _ = _sessionManager.DeleteSessionAsync(_sessionId);
        }
    }
}
```

## 🎯 Usage Examples

### Basic Usage

```csharp
public class ChatManager : MonoBehaviour
{
    private SignalSharpUnity _signalSharp;

    private async void Start()
    {
        _signalSharp = gameObject.AddComponent<SignalSharpUnity>();
        
        // Example usage
        try
        {
            // Create a session
            await _signalSharp.CreateSessionAsync(remoteIdentityKey, remotePreKey);

            // Encrypt a message
            byte[] encrypted = await _signalSharp.EncryptMessageAsync("Hello from Unity!");

            // Decrypt a message
            string decrypted = await _signalSharp.DecryptMessageAsync(encrypted);
            Debug.Log($"Decrypted message: {decrypted}");
        }
        catch (Exception ex)
        {
            Debug.LogError($"SignalSharp error: {ex.Message}");
        }
    }
}
```

### Secure Chat Implementation

```csharp
public class SecureChatManager : MonoBehaviour
{
    [SerializeField] private TMP_InputField messageInput;
    [SerializeField] private TMP_Text chatOutput;
    
    private SignalSharpUnity _signalSharp;
    private Queue<string> _messageQueue = new Queue<string>();

    private async void Start()
    {
        _signalSharp = gameObject.AddComponent<SignalSharpUnity>();
        
        // Initialize session (you would get these from your server)
        byte[] remoteIdentityKey = await GetRemoteIdentityKeyFromServer();
        byte[] remotePreKey = await GetRemotePreKeyFromServer();
        
        await _signalSharp.CreateSessionAsync(remoteIdentityKey, remotePreKey);
    }

    public async void SendMessage()
    {
        try
        {
            string message = messageInput.text;
            byte[] encrypted = await _signalSharp.EncryptMessageAsync(message);
            
            // Send encrypted message to your server/peer
            await SendToServer(encrypted);
            
            // Update UI
            AddMessageToChat($"Me: {message}");
            messageInput.text = "";
        }
        catch (Exception ex)
        {
            Debug.LogError($"Failed to send message: {ex.Message}");
        }
    }

    public async void OnMessageReceived(byte[] encryptedMessage)
    {
        try
        {
            string decrypted = await _signalSharp.DecryptMessageAsync(encryptedMessage);
            AddMessageToChat($"Other: {decrypted}");
        }
        catch (Exception ex)
        {
            Debug.LogError($"Failed to decrypt message: {ex.Message}");
        }
    }

    private void AddMessageToChat(string message)
    {
        _messageQueue.Enqueue(message);
        chatOutput.text = string.Join("\n", _messageQueue);
    }
}
```

## ⚠️ Important Unity Considerations

### Threading
- Unity requires most operations to run on the main thread
- Use `UnityMainThreadDispatcher` or similar for async operations that need to update UI

### File Storage
- Always use `Application.persistentDataPath` for storing keys and session data
- Be mindful of platform-specific file system restrictions

### Performance
- Encryption/decryption operations are async and may take time
- Consider implementing a message queue for real-time applications

### Platform Support
- Works on all Unity platforms that support .NET Standard 2.1
- Tested on Windows, macOS, iOS, and Android

### Security
- Store sensitive keys in the secure storage when available (iOS Keychain, Android Keystore)
- Clear memory properly when the application is paused or terminated

## 🔧 Troubleshooting

### Common Issues

1. **Missing DLLs**
   - Ensure all required DLLs are in the `Assets/Plugins` folder
   - Check that DLLs are compatible with your Unity version

2. **Threading Issues**
   - Use `UnityMainThreadDispatcher` for UI updates
   - Avoid blocking the main thread with encryption operations

3. **File Access Issues**
   - Verify permissions on `Application.persistentDataPath`
   - Handle platform-specific file system restrictions

4. **Memory Issues**
   - Implement proper cleanup in `OnDestroy`
   - Clear sensitive data when the application is paused

## 📚 Additional Resources

- [Unity Documentation](https://docs.unity3d.com/)
- [SignalSharp Main Documentation](../README.md)
- [Unity Threading Best Practices](https://docs.unity3d.com/Manual/Threading.html)
- [Unity Security Best Practices](https://docs.unity3d.com/Manual/SecurityBestPractices.html) 