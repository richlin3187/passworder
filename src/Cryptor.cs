using System.Security.Cryptography;
using System.Text;

namespace Passworder;

public class Cryptor 
{
    public string Encrypt(string plainText, string password, string iv)
    {
        var plainTextBytes = ToBytes(plainText);
        using MemoryStream ms = new(plainTextBytes);
        using Aes aes = Aes.Create();
        //aes.GenerateIV(); // this is a salt value - is this actually needed since we're generating our own value?
        aes.Key = ToBytes(password);
        
        // need to use secure IV generator
        aes.IV = ToBytesHalved(iv);

        // create an encryptor
        using CryptoStream cse = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cse.Write(plainTextBytes, 0, plainTextBytes.Length);
        return Convert.ToBase64String(ms.ToArray());
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