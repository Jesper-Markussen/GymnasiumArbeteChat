using System;
using System.Security.Cryptography;
using System.Text;

namespace Alva_V1;

public static class KeyManager
{
    // 1. Generate a new Identity (Public + Private Key Pair)
    // Returns: (PublicKeyXml, PrivateKeyXml)
    public static (string publicXml, string privateXml) GenerateKeyPair()
    {
        // 2048-bit RSA is the standard for secure messaging
        using var rsa = RSA.Create(2048);
        return (rsa.ToXmlString(false), rsa.ToXmlString(true));
    }

    // 2. Encrypt a message for someone else (Using THEIR Public Key)
    public static byte[] EncryptForUser(string message, string recipientPublicKeyXml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(recipientPublicKeyXml);

        var data = Encoding.UTF8.GetBytes(message);
        // OAEPSHA256 is the modern standard for padding (safer than PKCS1)
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    // 3. Decrypt a message sent to me (Using MY Private Key)
    public static string DecryptMyMessage(byte[] encryptedData, string myPrivateKeyXml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(myPrivateKeyXml);

        var decryptedBytes = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}