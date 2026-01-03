namespace AlvaServer.Models;

public class User
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty; // Derived Argon2id hash
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public string PublicKeyXml { get; set; } = string.Empty;
}