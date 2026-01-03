using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace Alva_V1
{
    /// <summary>
    /// Provides methods for encrypting and decrypting chat history files.
    /// 
    /// <para>
    /// This class implements secure local storage for chat history using:
    /// - <b>Argon2id</b> for password-based key derivation (resistant to GPU/ASIC brute force),
    /// - <b>AES-GCM</b> for authenticated encryption (provides confidentiality + integrity).
    /// </para>
    /// 
    /// <para>
    /// The encrypted file includes all necessary parameters for decryption:
    /// salt, Argon2 configuration, nonce, ciphertext, and authentication tag.
    /// </para>
    /// 
    /// <para>
    /// Design goal: provide strong, self-contained, verifiable encryption
    /// without external key management or configuration files.
    /// </para>
    /// </summary>
    public static class ChatHistoryCrypto
    {
        // --------------------------------------------------------------------
        // CONSTANTS
        // --------------------------------------------------------------------

        /// <summary>
        /// Magic identifier written at the start of every encrypted file.
        /// Used to verify that a file is actually a valid encrypted chat file.
        /// </summary>
        private const string MAGIC = "CHATHIST1"; // 9 ASCII bytes
        private const int AesGcmTagSize = 16; // 128-bit tag (recommended)


        // --------------------------------------------------------------------
        // PUBLIC METHODS
        // --------------------------------------------------------------------

        /// <summary>
        /// Encrypts the provided chat history JSON and writes it to disk.
        /// 
        /// <para>
        /// Encryption process:
        /// 1. Generate a random salt for key derivation.
        /// 2. Derive a 256-bit AES key using Argon2id (username + password + salt).
        /// 3. Generate a random 12-byte nonce for AES-GCM.
        /// 4. Encrypt the plaintext JSON using AES-GCM.
        /// 5. Write all data in a structured binary format to the given file path.
        /// </para>
        /// 
        /// <para>
        /// If the file already exists, it is overwritten safely with new encrypted data.
        /// </para>
        /// </summary>
        /// <param name="filePath">Destination file path for the encrypted chat history.</param>
        /// <param name="username">User's name, included in key derivation to ensure uniqueness per user.</param>
        /// <param name="password">User’s password as a character array (allows secure memory clearing).</param>
        /// <param name="plaintextJson">Plaintext chat history in JSON format.</param>
        public static void SaveEncryptedHistory(string filePath, string username, char[] password, string plaintextJson)
        {
            // --- STEP 1: Generate random salt ---
            // A unique salt ensures that even identical passwords generate different keys per file.
            var salt = RandomNumberGenerator.GetBytes(16); // 16 bytes = 128 bits

            // --- STEP 2: Argon2id configuration ---
            // Parameters control security and performance balance.
            // These values are suitable for a desktop or laptop environment.
            uint timeCost = 2;       // Number of Argon2 passes over memory (CPU cost)
            uint memoryKb = 32768;   // 32 MB memory usage (GPU/ASIC resistance)
            uint parallelism = 1;    // Thread count (keep 1 for simplicity and reproducibility)

            // --- STEP 3: Derive cryptographic key ---
            // Combine username and password for user-specific key material.
            var key = DeriveKey(username, password, salt, (int)timeCost, (int)memoryKb, (int)parallelism, 32);

            try
            {
                // --- STEP 4: Generate AES nonce ---
                // Nonce (Initialization Vector) must be unique for each encryption with the same key.
                var nonce = RandomNumberGenerator.GetBytes(12); // 96-bit nonce for AES-GCM

                // --- STEP 5: Encrypt plaintext ---
                byte[] plaintext = Encoding.UTF8.GetBytes(plaintextJson);
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16]; // 128-bit authentication tag (ensures integrity)

                // AES-GCM provides both encryption and message authentication in one step.
                using (var aes = new AesGcm(key, AesGcmTagSize))
                {
                    aes.Encrypt(
                        nonce.AsSpan(),
                        plaintext.AsSpan(),
                        ciphertext.AsSpan(),
                        tag.AsSpan()
                    );
                }


                // --- STEP 6: Write binary file structure ---
                // Layout (ordered):
                // [MAGIC] [saltLen] [salt] [timeCost] [memoryKb] [parallelism]
                // [nonceLen] [nonce] [cipherLen] [ciphertext] [tag]
                using (var fs = File.Create(filePath))
                using (var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: false))
                {
                    bw.Write(Encoding.ASCII.GetBytes(MAGIC));         // File header
                    bw.Write((byte)salt.Length);                      // Salt length
                    bw.Write(salt);                                   // Salt bytes
                    bw.Write(BitConverter.GetBytes(timeCost));         // Argon2 iteration count
                    bw.Write(BitConverter.GetBytes(memoryKb));         // Argon2 memory cost
                    bw.Write(BitConverter.GetBytes(parallelism));      // Argon2 thread count
                    bw.Write((byte)nonce.Length);                      // Nonce length (12)
                    bw.Write(nonce);                                  // Nonce bytes
                    bw.Write(BitConverter.GetBytes(ciphertext.Length));// Ciphertext length
                    bw.Write(ciphertext);                             // Ciphertext
                    bw.Write(tag);                                    // AES-GCM authentication tag
                }
            }
            finally
            {
                // Always clean up sensitive data.
                // Even if encryption fails, we must not leave keys or passwords in memory.
                Array.Clear(key);
                ClearChars(password);
            }
        }

        /// <summary>
        /// Loads and decrypts an encrypted chat history file using the given username and password.
        /// 
        /// <para>
        /// The method reads the file structure, extracts encryption parameters, 
        /// derives the same key using Argon2id, and decrypts the ciphertext with AES-GCM.
        /// </para>
        /// 
        /// <para>
        /// If decryption fails (due to wrong credentials or corrupted data),
        /// an <see cref="UnauthorizedAccessException"/> is thrown.
        /// </para>
        /// </summary>
        /// <param name="filePath">Path to the encrypted chat file.</param>
        /// <param name="username">Username associated with the file (used in key derivation).</param>
        /// <param name="password">Password used during encryption (as char[] for secure handling).</param>
        /// <returns>Decrypted chat history as a UTF-8 JSON string.</returns>
        /// <exception cref="InvalidDataException">Thrown if the file is not a valid chat file.</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown if decryption fails due to wrong credentials or corruption.</exception>
        public static string LoadEncryptedHistory(string filePath, string username, char[] password)
        {
            using (var fs = File.OpenRead(filePath))
            using (var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: false))
            {
                // --- STEP 1: Verify file header ---
                var magicBytes = br.ReadBytes(MAGIC.Length);
                if (Encoding.ASCII.GetString(magicBytes) != MAGIC)
                    throw new InvalidDataException("Not a valid chat file (magic header mismatch).");

                // --- STEP 2: Read stored parameters in the same order they were written ---
                var saltLen = br.ReadByte();
                var salt = br.ReadBytes(saltLen);
                var timeCost = BitConverter.ToUInt32(br.ReadBytes(4), 0);
                var memoryKb = BitConverter.ToUInt32(br.ReadBytes(4), 0);
                var parallelism = BitConverter.ToUInt32(br.ReadBytes(4), 0);
                var nonceLen = br.ReadByte();
                var nonce = br.ReadBytes(nonceLen);
                var cipherLen = BitConverter.ToInt32(br.ReadBytes(4), 0);
                var ciphertext = br.ReadBytes(cipherLen);
                var tag = br.ReadBytes(16);

                // --- STEP 3: Derive key again using stored salt and parameters ---
                var key = DeriveKey(username, password, salt, (int)timeCost, (int)memoryKb, (int)parallelism, 32);

                try
                {
                    // --- STEP 4: Decrypt ciphertext ---
                    byte[] plaintext = new byte[ciphertext.Length];
                    using (var aes = new AesGcm(key, AesGcmTagSize))
                    {
                        aes.Decrypt(
                            nonce.AsSpan(),
                            ciphertext.AsSpan(),
                            tag.AsSpan(),
                            plaintext.AsSpan()
                        );
                    }



                    // --- STEP 5: Convert decrypted bytes back to string ---
                    return Encoding.UTF8.GetString(plaintext);
                }
                catch (CryptographicException)
                {
                    // Authentication failure: wrong password, username, or corrupted data.
                    throw new UnauthorizedAccessException("Decryption failed: invalid credentials or file corruption.");
                }
                finally
                {
                    // Always clear sensitive data.
                    Array.Clear(key);
                    // NOTE: Do NOT clear the caller’s password here!
                    // The caller (Program.cs) may reuse it later for saving;
                    // clearing here caused previous “can’t log in / can’t decrypt” behavior.
                }
            }
        }

        // --------------------------------------------------------------------
        // PRIVATE METHODS
        // --------------------------------------------------------------------

        /// <summary>
        /// Derives a cryptographic key using the Argon2id password-hashing algorithm.
        /// 
        /// <para>
        /// Combines the password and username into one byte buffer to ensure
        /// that each user's key is unique even if the same password is reused.
        /// </para>
        /// 
        /// <para>
        /// The function returns a fixed-size key suitable for AES encryption.
        /// </para>
        /// </summary>
        /// <param name="username">Username string included for uniqueness.</param>
        /// <param name="password">Password as a char array (wiped after use).</param>
        /// <param name="salt">Random salt value unique to this file.</param>
        /// <param name="timeCost">Number of Argon2 iterations (computational cost).</param>
        /// <param name="memoryKb">Memory used by Argon2 in kilobytes (resistance to GPU attacks).</param>
        /// <param name="parallelism">Number of threads used by Argon2 (usually 1 for portability).</param>
        /// <param name="keyLen">Desired key length in bytes (typically 32 for AES-256).</param>
        /// <returns>Derived cryptographic key as a byte array.</returns>
        private static byte[] DeriveKey(string username, char[] password, byte[] salt,
            int timeCost, int memoryKb, int parallelism, int keyLen)
        {
            // Normalize username for deterministic key derivation
            string normUser = (username ?? string.Empty).Trim().ToLowerInvariant();

            // Convert both username and password to bytes
            // Replace the vulnerable line with this:
            int byteCount = Encoding.UTF8.GetByteCount(password);
            byte[] passBytes = new byte[byteCount];
            Encoding.UTF8.GetBytes(password, 0, password.Length, passBytes, 0);
            byte[] userBytes = Encoding.UTF8.GetBytes(normUser);

            try
            {
                // Combine username and password bytes into a single buffer
                byte[] combined = new byte[passBytes.Length + userBytes.Length];
                Buffer.BlockCopy(passBytes, 0, combined, 0, passBytes.Length);
                Buffer.BlockCopy(userBytes, 0, combined, passBytes.Length, userBytes.Length);

                // Configure and execute Argon2id key derivation
                var argon = new Argon2id(combined)
                {
                    DegreeOfParallelism = parallelism,
                    MemorySize = memoryKb,
                    Iterations = timeCost,
                    Salt = salt
                };

                // Generate and return derived key bytes
                return argon.GetBytes(keyLen);
            }
            finally
            {
                // Wipe password bytes to prevent leaks in memory dumps.
                Array.Clear(passBytes, 0, passBytes.Length);
            }
        }

        /// <summary>
        /// Securely clears a character array from memory.
        /// 
        /// <para>
        /// This is a defensive step to prevent sensitive data (passwords)
        /// from lingering in memory where they could be recovered later.
        /// </para>
        /// </summary>
        /// <param name="arr">Character array to clear. If null, no action is taken.</param>
        private static void ClearChars(char[] arr)
        {
            if (arr == null) return;
            for (int i = 0; i < arr.Length; i++)
                arr[i] = '\0'; // Overwrite with null character
        }
    }
}
