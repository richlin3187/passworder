using System.Security.Cryptography;
using System.Text;

public class Cryptor 
{
    public string Encrypt(string plainText, string password, string iv)
    {
        using MemoryStream ms = new(ToBytes(plainText));
        using Aes aes = Aes.Create();
        aes.GenerateIV(); // this is a salt value
        aes.Key = ToBytes(password);
        aes.IV = ToBytesHalved(iv);

        // create an encryptor
        using CryptoStream cse = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);

// Stream is not readable!?! wtf
        using StreamReader sr = new(cse);
        return sr.ReadToEnd();
    }
    
    public string Decrypt(string cypherText, string password, string iv)
    {
        using MemoryStream ms = new(ToBytes(cypherText));
        using Aes aes = Aes.Create();
        // create a decryptor
        var key = ToBytes(password);
        using CryptoStream csd = new(ms, aes.CreateDecryptor(ToBytes(password), ToBytesHalved(iv)), CryptoStreamMode.Read);

        using StreamReader sr = new(csd);
        string decryptedText = sr.ReadToEnd();
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