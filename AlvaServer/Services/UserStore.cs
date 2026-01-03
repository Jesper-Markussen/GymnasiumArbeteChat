using Microsoft.Data.Sqlite;
using AlvaServer.Models;

namespace AlvaServer.Services;

public class UserStore
{
    private readonly string _dbPath;

    public UserStore(string dbPath = "users.db")
    {
        _dbPath = dbPath;
        Initialize();
    }

    private void Initialize()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                Username TEXT PRIMARY KEY,
                PasswordHash TEXT NOT NULL,
                Salt BLOB NOT NULL
            );
        ";
        cmd.ExecuteNonQuery();
    }

    public bool UserExists(string username)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Users WHERE Username = $u";
        cmd.Parameters.AddWithValue("$u", username.ToLowerInvariant());
        return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
    }

    public void AddUser(User user)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, PasswordHash, Salt) VALUES ($u, $p, $s)";
        cmd.Parameters.AddWithValue("$u", user.Username.ToLowerInvariant());
        cmd.Parameters.AddWithValue("$p", user.PasswordHash);
        cmd.Parameters.AddWithValue("$s", user.Salt);
        cmd.ExecuteNonQuery();
    }

    public User? GetUser(string username)
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT PasswordHash, Salt FROM Users WHERE Username = $u";
        cmd.Parameters.AddWithValue("$u", username.ToLowerInvariant());

        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;

        return new User
        {
            Username = username.ToLowerInvariant(),
            PasswordHash = reader.GetString(0),
            Salt = (byte[])reader["Salt"]
        };
    }
}
