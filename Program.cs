using System.Security.Cryptography;
using System.Text;

byte[] Key = Encoding.UTF8.GetBytes("jW*Zq4t7w!z%C*F-JaNdRgUkXp2s5u8x");
byte[] IV = Encoding.UTF8.GetBytes("q3&9z$q31*_t6?z$");

string password = "8_1%tPRw%z%U!p^&3$V*A?73D^4!#J$";

string Encrypt(string plainText)
{
    using Aes aes = Aes.Create();
    aes.Key = Key;
    aes.IV = IV;

    ICryptoTransform encryptor = aes.CreateEncryptor();

    using MemoryStream msEncrypt = new();
    using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
    using (StreamWriter swEncrypt = new(csEncrypt))
    {
        swEncrypt.Write(plainText);
    }

    return Convert.ToBase64String(msEncrypt.ToArray());
}

string Decrypt(string cipheredText)
{
    using Aes aes = Aes.Create();
    aes.Key = Key;
    aes.IV = IV;

    ICryptoTransform decryptor = aes.CreateDecryptor();

    byte[] cipheredBytes = Convert.FromBase64String(cipheredText);
    using MemoryStream msEncrypt = new(cipheredBytes);
    using CryptoStream csEncrypt = new(msEncrypt, decryptor, CryptoStreamMode.Read);
    using StreamReader srDecrypt = new(csEncrypt);

    return srDecrypt.ReadToEnd();
}

string encryptedPassword = Encrypt(password);

Console.WriteLine($"Encrypted: {encryptedPassword}");

string decryptedPassword = Decrypt(encryptedPassword);

Console.WriteLine($"Decrypted: {decryptedPassword}");