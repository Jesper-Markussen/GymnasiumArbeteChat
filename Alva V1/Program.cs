// NuGet dependency: Konscious.Security.Cryptography (used indirectly via ChatHistoryCrypto)
// Handles Argon2id key derivation for encryption/decryption.
//
// This is the main entry point for Alva.
// It authenticates the user, loads any encrypted chat history,
// allows message input, and securely re-encrypts the updated chat session.

using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Alva_V1
{
    class Program
    {
        // We keep the Private Key in memory while the app is running
        private static string _myPrivateKeyXml = "";
        private static string _myUsername = "";
        
        // The Postman
        private static readonly NetworkClient _client = new NetworkClient("http://localhost:5000");

        static async Task Main(string[] args)
        {
            Console.WriteLine("==== Alva V2: Secure Messenger ====");
            Console.WriteLine("Initializing Crypto Engines...\n");

            // 1. AUTHENTICATION PHASE
            if (!await AttemptLoginOrRegister())
            {
                Console.WriteLine("❌ Authentication failed. Exiting.");
                return;
            }

            Console.WriteLine($"\n✅ Welcome, {_myUsername}. You are connected.");
            Console.WriteLine("-------------------------------------------------");

            // 2. MAIN MENU LOOP
            while (true)
            {
                Console.WriteLine("\n[1] 📩 Check Inbox");
                Console.WriteLine("[2] 📝 Send Message");
                Console.WriteLine("[3] ❌ Exit");
                Console.Write("Select option: ");
                
                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        await CheckInbox();
                        break;
                    case "2":
                        await SendMessageSequence();
                        break;
                    case "3":
                        return;
                    default:
                        Console.WriteLine("Invalid option.");
                        break;
                }
            }
        }

        // --- AUTH LOGIC ---
        private static async Task<bool> AttemptLoginOrRegister()
        {
            Console.Write("Enter Username: ");
            _myUsername = Console.ReadLine()?.Trim() ?? "";
            
            Console.Write("Enter Password: ");
            var password = ReadPassword(); // Your existing secure reader

            // Define where we store the keys securely (using V1 Logic!)
            // We use the same 'EncryptedFilePathForUser' from V1
            string keyFilePath = CryptoUtils.EncryptedFilePathForUser(_myUsername + "_keys");

            try 
            {
                if (System.IO.File.Exists(keyFilePath))
                {
                    // === RETURNING USER ===
                    Console.WriteLine("\n🔐 Local keys found. Decrypting identity...");
                    
                    // 1. Load Private Key using V1 Crypto
                    // This will throw if password is wrong
                    _myPrivateKeyXml = ChatHistoryCrypto.LoadEncryptedHistory(keyFilePath, _myUsername, password);
                    
                    // 2. Login to Server
                    Console.WriteLine("🌍 Logging into server...");
                    if (await _client.LoginAsync(_myUsername, new string(password)))
                    {
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("⚠️ Server rejected login (Wrong password? Server down?)");
                        return false;
                    }
                }
                else
                {
                    // === NEW USER ===
                    Console.WriteLine("\n🆕 No local keys found. Registering new identity...");
                    
                    // 1. Generate RSA Keys (The "Crypto Scene" stuff)
                    Console.WriteLine("⚙️ Generating 2048-bit RSA Keypair...");
                    var (publicXml, privateXml) = KeyManager.GenerateKeyPair();
                    _myPrivateKeyXml = privateXml;

                    // 2. Register with Server (Send PUBLIC key only)
                    Console.WriteLine("🌍 Sending Public Key to Server...");
                    if (await _client.RegisterAsync(_myUsername, new string(password), publicXml))
                    {
                        // 3. Login to get the Token
                        await _client.LoginAsync(_myUsername, new string(password));

                        // 4. Save PRIVATE Key securely (Using V1 Crypto)
                        Console.WriteLine("💾 Encrypting and saving Private Key to disk...");
                        ChatHistoryCrypto.SaveEncryptedHistory(keyFilePath, _myUsername, password, privateXml);
                        
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("⚠️ Registration failed (Username taken?)");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error: {ex.Message}");
                return false;
            }
            finally
            {
                // Always clear password from memory
                Array.Clear(password, 0, password.Length);
            }
        }

        // --- MESSAGING LOGIC ---
        private static async Task CheckInbox()
        {
            Console.WriteLine("\n📥 Fetching messages...");
            var msgs = await _client.GetInboxAsync();

            if (msgs.Count == 0)
            {
                Console.WriteLine("📭 Inbox is empty.");
                return;
            }

            Console.WriteLine($"📬 You have {msgs.Count} new message(s):");
            foreach (var msg in msgs)
            {
                try 
                {
                    // The Magic Moment: Using Private Key to decrypt
                    string decryptedText = KeyManager.DecryptMyMessage(msg.Content, _myPrivateKeyXml);
                    
                    Console.WriteLine($"\n--- FROM: {msg.Sender} [{msg.SentAt.ToLocalTime()}] ---");
                    Console.WriteLine(decryptedText);
                }
                catch
                {
                    Console.WriteLine($"\n--- FROM: {msg.Sender} ---");
                    Console.WriteLine("⚠️ [Decryption Failed: Message may be corrupted or from wrong key]");
                }
            }
            Console.WriteLine("\n(Messages have been removed from server)");
        }

        private static async Task SendMessageSequence()
        {
            Console.Write("\nRecipient Username: ");
            var recipient = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(recipient)) return;

            // 1. Get Recipient's Public Key (The "Phonebook" Lookup)
            Console.Write($"🔍 Looking up public key for '{recipient}'... ");
            var recipientKeyXml = await _client.GetPublicKeyAsync(recipient);

            if (recipientKeyXml == null)
            {
                Console.WriteLine("❌ User not found.");
                return;
            }
            Console.WriteLine("✅ Found.");

            // 2. Type Message
            Console.Write("Message: ");
            var text = Console.ReadLine();
            if (string.IsNullOrEmpty(text)) return;

            // 3. Encrypt (Using THEIR Public Key)
            byte[] encryptedBytes = KeyManager.EncryptForUser(text, recipientKeyXml);

            // 4. Send
            Console.WriteLine("🚀 Sending encrypted payload...");
            bool success = await _client.SendMessageAsync(recipient, encryptedBytes);

            if (success) Console.WriteLine("✅ Message Sent!");
            else Console.WriteLine("❌ Failed to send.");
        }

        // Helper for secure password reading (Copied from your V1)
        static char[] ReadPassword()
        {
            var pass = new List<char>();
            ConsoleKeyInfo key;
            while (true)
            {
                key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace && pass.Count > 0)
                {
                    pass.RemoveAt(pass.Count - 1);
                    Console.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    pass.Add(key.KeyChar);
                    Console.Write('*');
                }
            }
            Console.WriteLine();
            return pass.ToArray();
        }
    }
}
