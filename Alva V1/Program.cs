// NuGet dependency: Konscious.Security.Cryptography (used indirectly via ChatHistoryCrypto)
// Handles Argon2id key derivation for encryption/decryption.
//
// This is the main entry point for Alva.
// It authenticates the user, loads any encrypted chat history,
// allows message input, and securely re-encrypts the updated chat session.

using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Alva_V1
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("==== Alva Secure Chat ====");
            Console.WriteLine("Version 1.0 - Gymnasiearbete by Jesper \"Grenade\" & [Partner Name]");
            Console.WriteLine();

            // --- USER LOGIN PHASE ---
            Console.Write("Enter username: ");
            string username = Console.ReadLine() ?? "";

            Console.Write("Enter password: ");
            char[] password = ReadPassword(); // Secure password input (no echo)

            // Optional: enforce strong passwords
            if (!IsAcceptablePassword(password))
            {
                Console.WriteLine("⚠️ Password too weak. Must be at least 12 characters with a mix of letters, digits, or symbols.");
                Array.Clear(password, 0, password.Length);
                return;
            }

            // --- LOAD & DISPLAY HISTORY ---
            Console.WriteLine();
            MessageHistory.Display(username, password); // Show old messages, if any

            // Load message list (existing or new)
            List<string> messages = MessageHistory.Load(username, password);

            // --- CHAT INPUT LOOP ---
            Console.WriteLine("Type your messages (type '/exit' to quit):");
            while (true)
            {
                Console.Write("> ");
                string line = Console.ReadLine() ?? "";

                if (line.Trim().Equals("/exit", StringComparison.OrdinalIgnoreCase))
                    break;

                if (!string.IsNullOrWhiteSpace(line))
                    messages.Add($"{DateTime.Now:HH:mm} {username}: {line}");
            }

            // --- SAVE PHASE ---
            string saveJson = JsonSerializer.Serialize(messages, new JsonSerializerOptions { WriteIndented = true });
            string filePath = CryptoUtils.EncryptedFilePathForUser(username);

            ChatHistoryCrypto.SaveEncryptedHistory(filePath, username, password, saveJson);

            Console.WriteLine($"\n💾 Chat history saved securely to {filePath}");

            // --- CLEANUP ---
            Array.Clear(password, 0, password.Length);
            messages.Clear();
        }

        // --- SECURE PASSWORD INPUT ---
        //
        // Cross-platform implementation that masks typed characters with '*'
        // Works in most terminal environments (Windows, macOS, Linux)
        //
        // Returns: char[] instead of string to allow secure memory clearing after use.
        static char[] ReadPassword()
        {
            var pass = new List<char>();
            ConsoleKeyInfo key;

            while (true)
            {
                key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                    break;

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

        // --- PASSWORD STRENGTH VALIDATION ---
        //
        // Enforces a minimum password complexity requirement to reduce the risk
        // of brute-force or dictionary attacks on encrypted chat files.
        static bool IsAcceptablePassword(char[] password)
        {
            if (password == null || password.Length < 12)
                return false;

            bool hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
            foreach (var c in password)
            {
                if (char.IsLower(c)) hasLower = true;
                else if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasSymbol = true;
            }

            int score = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
            return score >= 3;
        }
    }
}
