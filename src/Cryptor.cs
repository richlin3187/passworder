using System.Security.Cryptography;
using System.Text;

namespace Passworder;

internal class Cryptor 
{
    public EncryptedValue Encrypt(string plainText, string password, string hint)
    {
        var plainTextBytes = Encoding.ASCII.GetBytes(plainText);
        using MemoryStream ms = new();
        ms.Write(plainTextBytes);
        using Aes aes = Aes.Create();
        aes.GenerateIV();
        aes.Key = ToBytes(password);

        // create an encryptor
        using CryptoStream cse = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cse.Write(plainTextBytes, 0, plainTextBytes.Length);
        var cypherText = Convert.ToBase64String(ms.ToArray());
        var nonce = Convert.ToBase64String(aes.IV);
        return new EncryptedValue(cypherText, hint, nonce);
    }
    
    public string Decrypt(EncryptedValue encryptedObject, string password)
    {
        using MemoryStream ms = new();
        var cypherTextBytes = Encoding.ASCII.GetBytes(encryptedObject.CypherText);
        ms.Write(cypherTextBytes);
        using Aes aes = Aes.Create();
        // create a decryptor
        var key = ToBytes(password);
        var ivBytes = Convert.FromBase64String(encryptedObject.Nonce);
        using CryptoStream csd = new(ms, aes.CreateDecryptor(key, ivBytes), CryptoStreamMode.Read);
        csd.ReadExactly(cypherTextBytes);
        var decryptedText = Convert.ToBase64String(cypherTextBytes);
        return decryptedText;
    }

    private static byte[] ToBytes(string originalValue)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.ASCII.GetBytes(originalValue));
    }

    private static byte[] ToBytesHalved(string originalValue)
    {
        var fullBytes = ToBytes(originalValue);
        return [.. fullBytes.Take(16)];
    }
}