using Alva_V1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Alva_V2_GUI
{
    // This class replaces "Program.cs". It handles the logic, but has NO UI code.
    public class ChatService
    {
        private NetworkClient _client;
        private string _myUsername;
        private string _myPrivateKeyXml;
        private string _serverUrl = "http://localhost:5000";

        public string CurrentUser => _myUsername;
        public bool IsLoggedIn => !string.IsNullOrEmpty(_myPrivateKeyXml);

        public ChatService()
        {
            _client = new NetworkClient(_serverUrl);
        }

        // Returns true if login successful, false otherwise
        public async Task<bool> Login(string username, string password)
        {
            string keyFilePath = CryptoUtils.EncryptedFilePathForUser(username + "_keys");

            if (!File.Exists(keyFilePath)) return false; // User needs to register

            try
            {
                // 1. Decrypt local key
                _myPrivateKeyXml = ChatHistoryCrypto.LoadEncryptedHistory(keyFilePath, username, password.ToCharArray());

                // 2. Login to server
                bool serverSuccess = await _client.LoginAsync(username, password);
                if (serverSuccess)
                {
                    _myUsername = username;
                    return true;
                }
            }
            catch
            {
                // Wrong password or decryption failed
                return false;
            }
            return false;
        }

        public async Task<bool> Register(string username, string password)
        {
            try
            {
                // 1. Generate RSA Keys
                var (publicXml, privateXml) = KeyManager.GenerateKeyPair();

                // 2. Register on Server
                if (await _client.RegisterAsync(username, password, publicXml))
                {
                    // 3. Login to get token
                    await _client.LoginAsync(username, password);

                    // 4. Save Encrypted Private Key
                    string keyFilePath = CryptoUtils.EncryptedFilePathForUser(username + "_keys");
                    ChatHistoryCrypto.SaveEncryptedHistory(keyFilePath, username, password.ToCharArray(), privateXml);

                    _myPrivateKeyXml = privateXml;
                    _myUsername = username;
                    return true;
                }
            }
            catch { }
            return false;
        }

        // Returns a list of DECRYPTED messages formatted for display
        public async Task<List<UIMessage>> CheckInbox()
        {
            var uiMessages = new List<UIMessage>();
            if (!IsLoggedIn) return uiMessages;

            var rawMsgs = await _client.GetInboxAsync();

            foreach (var msg in rawMsgs)
            {
                string decryptedContent;
                try
                {
                    decryptedContent = KeyManager.DecryptMyMessage(msg.Content, _myPrivateKeyXml);
                }
                catch
                {
                    decryptedContent = "⚠️ [Decryption Error]";
                }

                uiMessages.Add(new UIMessage
                {
                    Sender = msg.Sender,
                    Content = decryptedContent,
                    Timestamp = msg.SentAt.ToLocalTime().ToString("HH:mm")
                });
            }
            return uiMessages;
        }

        public async Task<bool> SendMessage(string recipient, string messageText)
        {
            if (string.IsNullOrEmpty(recipient) || string.IsNullOrEmpty(messageText)) return false;

            // 1. Get Public Key
            var recipientKeyXml = await _client.GetPublicKeyAsync(recipient);
            if (recipientKeyXml == null) return false;

            // 2. Encrypt
            byte[] encryptedBytes = KeyManager.EncryptForUser(messageText, recipientKeyXml);

            // 3. Send
            return await _client.SendMessageAsync(recipient, encryptedBytes);
        }
    }

    // A simple container for the UI to display
    public class UIMessage
    {
        public string Sender { get; set; }
        public string Content { get; set; }
        public string Timestamp { get; set; }
    }
}
