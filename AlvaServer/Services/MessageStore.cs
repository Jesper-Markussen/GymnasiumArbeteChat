using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;

namespace AlvaServer.Services;

public class MessageStore
{
    private readonly string _dbPath;

    // 1. Constructor: Sets the DB path and ensures the table exists
    public MessageStore(string dbPath = "users.db")
    {
        _dbPath = dbPath;
        Initialize();
    }

    // 2. Initialize: Creates the Messages table if it doesn't exist
    private void Initialize()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Messages (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                SenderUsername TEXT NOT NULL,
                RecipientUsername TEXT NOT NULL,
                EncryptedContent BLOB NOT NULL,
                Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ";
        cmd.ExecuteNonQuery();
    }

    // 3. SaveMessage: The "Drop" (Alice sends to Bob)
    public void SaveMessage(string sender, string recipient, byte[] encryptedContent)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO Messages (SenderUsername, RecipientUsername, EncryptedContent, Timestamp) 
            VALUES ($s, $r, $c, $t)";
        cmd.Parameters.AddWithValue("$s", sender);
        cmd.Parameters.AddWithValue("$r", recipient.ToLowerInvariant());
        cmd.Parameters.AddWithValue("$c", encryptedContent);
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow);
        cmd.ExecuteNonQuery();
    }

    // 4. GetAndClearInbox: The "Pickup" (Bob checks his mail)
    public List<MessageDto> GetAndClearInbox(string username)
    {
        var messages = new List<MessageDto>();
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        
        // Step A: Read messages
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT SenderUsername, EncryptedContent, Timestamp FROM Messages WHERE RecipientUsername = $u";
        cmd.Parameters.AddWithValue("$u", username.ToLowerInvariant());
        
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                messages.Add(new MessageDto 
                {
                    Sender = reader.GetString(0),
                    Content = (byte[])reader["EncryptedContent"],
                    SentAt = reader.GetDateTime(2)
                });
            }
        }

        // Step B: Delete them (POPPING the queue so server doesn't hog data)
        if (messages.Count > 0)
        {
            var delCmd = conn.CreateCommand();
            delCmd.CommandText = "DELETE FROM Messages WHERE RecipientUsername = $u";
            delCmd.Parameters.AddWithValue("$u", username.ToLowerInvariant());
            delCmd.ExecuteNonQuery();
        }

        return messages;
    }
}

// Data Transfer Object
public class MessageDto {
    public string Sender { get; set; } = "";
    public byte[] Content { get; set; } = Array.Empty<byte>();
    public DateTime SentAt { get; set; }
}