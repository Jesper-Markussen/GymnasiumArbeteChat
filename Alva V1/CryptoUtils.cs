using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Alva_V1
{
    /// <summary>
    /// Provides helper utilities for cryptographic operations and secure file management.
    /// 
    /// <para>
    /// <b>Purpose:</b> Centralize all small cryptographic and filesystem utilities used
    /// across the Alva application. This ensures that filename handling, hashing, and 
    /// normalization rules remain consistent and secure across different modules.
    /// </para>
    /// 
    /// <para>
    /// While initially small, this class is designed to grow with the project — for example,
    /// it could later include digital signature utilities, hash verification, or secure 
    /// temporary file handling.
    /// </para>
    /// </summary>
    internal static class CryptoUtils
    {
        // --------------------------------------------------------------------
        // USERNAME NORMALIZATION
        // --------------------------------------------------------------------

        /// <summary>
        /// Normalizes a username into a consistent, lowercase, trimmed string.
        /// 
        /// <para>
        /// This ensures that usernames like "Alva", "alva ", and " ALVA" are treated as identical
        /// when generating file names or keys. The normalization removes accidental spaces and
        /// enforces a case-insensitive convention across the program.
        /// </para>
        /// </summary>
        /// <param name="username">The raw username entered by the user.</param>
        /// <returns>
        /// A normalized username string (lowercase, trimmed, or empty string if null).
        /// </returns>
        private static string NormalizeUsername(string username)
        {
            return (username ?? string.Empty).Trim().ToLowerInvariant();
        }

        // --------------------------------------------------------------------
        // HASHING UTILITIES
        // --------------------------------------------------------------------

        /// <summary>
        /// Computes a SHA-256 hash of a given string and returns it as a lowercase hexadecimal string.
        /// 
        /// <para>
        /// The SHA-256 hash is used to generate deterministic, anonymous filenames for chat history
        /// files. This approach hides actual usernames while guaranteeing that the same user
        /// always maps to the same file path.
        /// </para>
        /// 
        /// <para>
        /// Example:  
        /// Input: <c>"alva"</c> → Output: <c>"88fc30b35..."</c>
        /// </para>
        /// 
        /// <para>
        /// SHA-256 is not reversible, meaning that stored filenames reveal no user information.
        /// </para>
        /// </summary>
        /// <param name="input">Input string to hash (usually a normalized username).</param>
        /// <returns>SHA-256 hash as a lowercase hexadecimal string.</returns>
        private static string Sha256Hex(string input)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha.ComputeHash(bytes);

            // Convert byte array to lowercase hexadecimal string
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash)
                sb.AppendFormat("{0:x2}", b);

            return sb.ToString();
        }

        // --------------------------------------------------------------------
        // FILE PATH UTILITIES
        // --------------------------------------------------------------------

        /// <summary>
        /// Builds a safe and deterministic file path for a user’s encrypted chat history.
        /// 
        /// <para>
        /// The resulting file name is based on the SHA-256 hash of the normalized username.
        /// This avoids storing usernames in plain text while maintaining one file per user.
        /// </para>
        /// 
        /// <para>
        /// The method also ensures that the <c>chats/</c> directory exists before returning the path,
        /// allowing the caller to directly create or open the file.
        /// </para>
        /// 
        /// <para>
        /// Example:
        /// <code>
        /// var path = CryptoUtils.EncryptedFilePathForUser("Alva");
        /// // Result: "chats/history_88fc30b35d... .enc"
        /// </code>
        /// </para>
        /// </summary>
        /// <param name="username">Username associated with the chat history.</param>
        /// <returns>
        /// Full path to the user’s encrypted chat file, inside the "chats" directory.
        /// </returns>
        public static string EncryptedFilePathForUser(string username)
        {
            // Normalize username to prevent collisions or case differences
            var norm = NormalizeUsername(username);

            // Hash the normalized name for anonymity
            var hex = Sha256Hex(norm);

            // Ensure that the "chats" directory exists
            Directory.CreateDirectory("chats");

            // Combine into a safe file path
            return Path.Combine("chats", $"history_{hex}.enc");
        }
    }
}
