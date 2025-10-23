using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Alva_V1
{
    /// <summary>
    /// Provides a structured and secure interface for reading and displaying
    /// a user's decrypted chat message history.
    ///
    /// <para>
    /// This class forms part of the internal data-handling layer of Alva.
    /// It is designed for simplicity in version 1, while being extensible for
    /// richer metadata and visualization in later versions.
    /// </para>
    ///
    /// <remarks>
    /// The class currently supports:
    /// <list type="bullet">
    /// <item><description>Full decryption and loading of user chat history</description></item>
    /// <item><description>Formatted console output for human-readable viewing</description></item>
    /// </list>
    /// Future versions may support timestamped messages, sender metadata,
    /// and incremental loading for efficiency.
    /// </remarks>
    /// </summary>
    internal class MessageHistory
    {
        /// <summary>
        /// Loads and decrypts the chat history for the specified user.
        /// </summary>
        /// <param name="username">The user's account name.</param>
        /// <param name="password">The user's password (as a char array).</param>
        /// <returns>
        /// A list of decrypted chat messages. If the history file does not exist,
        /// an empty list is returned.
        /// </returns>
        public static List<string> Load(string username, char[] password)
        {
            string filePath = CryptoUtils.EncryptedFilePathForUser(username);

            if (!File.Exists(filePath))
                return new List<string>();

            try
            {
                string json = ChatHistoryCrypto.LoadEncryptedHistory(filePath, username, password);
                return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Could not load history: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Displays the user's decrypted chat history in a readable format.
        /// </summary>
        /// <param name="username">The user's account name.</param>
        /// <param name="password">The user's password (as a char array).</param>
        public static void Display(string username, char[] password)
        {
            var messages = Load(username, password);

            if (messages.Count == 0)
            {
                Console.WriteLine("📭 No previous messages found.\n");
                return;
            }

            Console.WriteLine("📜 Previous Messages:");
            foreach (var message in messages)
            {
                Console.WriteLine($" • {message}");
            }

            Console.WriteLine();
        }
    }
}
