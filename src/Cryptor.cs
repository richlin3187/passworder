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
        csd.Read(cypherTextBytes);
        var decryptedText = Convert.ToBase64String(cypherTextBytes);
        return decryptedText;
    }

    private void EncryptInternal(Stream input, Stream output)
    {
        Aes aes = Aes.Create();

        aes.Key = Key;
        aes.IV = IV;
        aes.Padding = PaddingMode.PKCS7;
        //aes.Mode = CipherMode.CBC;
        //aes.BlockSize = 128;

        ICryptoTransform aesEncryptor = aes.CreateEncryptor();

        using (CryptoStream cryptoStream = new(output, aesEncryptor, CryptoStreamMode.Write))
        {
            input.CopyTo(cryptoStream);
            cryptoStream.FlushFinalBlock();
        }
    }

    private void DecryptInternal(Stream input, Stream output)
    {
        Aes aes = Aes.Create();

        aes.Key = Key;
        aes.IV = IV;
        aes.Padding = PaddingMode.PKCS7;
        //aes.Mode = CipherMode.CBC;
        //aes.BlockSize = 128;

        ICryptoTransform aesDecryptor = aes.CreateDecryptor();

        using (CryptoStream cryptoStream = new(input, aesDecryptor, CryptoStreamMode.Read))
        {
            cryptoStream.CopyTo(output);
            cryptoStream.Close();
        }
        output.Flush();
    }

    private static byte[] ToBytes(string originalValue)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(Encoding.ASCII.GetBytes(originalValue));
    }
}