using System;
using System.IO;
using System.Security.Cryptography;
//using static System.Security.Cryptography.MD5;
using System.Text;

namespace EncryptDecryptStr
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Crypto String");
            Console.WriteLine("-------------------------------------------");
            var chaine = "";
            Console.WriteLine("Saisissez une chaine à crypter");
            chaine = Console.ReadLine();
            using (var cryptor = Aes.Create())
            {
                var key = new byte[16];
                var iv = new byte[16];
                var encryptString = EncryptToByte(chaine, key, iv);

                var decryptByte = DecryptToString(encryptString, key, iv);


                Console.WriteLine("Chaine {0} cryptée en Aes : {1}", chaine, Encoding.UTF8.GetString(encryptString));
                Console.WriteLine("{0} decryptée en Aes : {1}", Encoding.UTF8.GetString(encryptString), decryptByte);
            }

            var encryptedMD5 = EncryptWithMD5(chaine);
            var decryptedMD5 = DecryptWithMD5(encryptedMD5);

            Console.WriteLine("Chaine cryptée avec SHA256 : {0}", Encoding.UTF8.GetString(CryptWithSHA256(chaine)));
            Console.WriteLine("Chaine cryptée avec MD5 => {0}", Encoding.UTF8.GetString(encryptedMD5));
            Console.WriteLine("Chaine decryptée MD5 => {0}", decryptedMD5);
        }
        static byte[] EncryptToByte(string TextToEncrypt, byte[] Key, byte[] IV)
        {
            //Verification des arguments
            if (TextToEncrypt == null || TextToEncrypt.Length <= 0)
                throw new ArgumentNullException("TextToEncrypt");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;

            using (var algoAes = Aes.Create())
            {
                algoAes.Key = Key;
                algoAes.IV = IV;

                //Creation du crypteur
                var crypto = algoAes.CreateEncryptor(algoAes.Key, algoAes.IV);

                //Creation des flux pour le cryptage
                using (var msEncrypt = new MemoryStream())
                {
                    using (var cryptoStm = new CryptoStream(msEncrypt, crypto, CryptoStreamMode.Write))
                    {
                        using (var stmWrite = new StreamWriter(cryptoStm))
                        {
                            //Données en stream
                            stmWrite.Write(TextToEncrypt);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        static string DecryptToString(byte[] cipherText, byte[] Key, byte[] IV)
        {
            //Verification des arguments
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("CipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            //Declaration de la chaine de caractere
            var textOriginal = "";

            //Creation de l'objet AES
            using (var algoAes = Aes.Create())
            {
                algoAes.Key = Key;
                algoAes.IV = IV;

                //Creation du decrypteur 
                var decryptor = algoAes.CreateDecryptor(algoAes.Key, algoAes.IV);

                //Creation de flux pour decrypter
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var decryptStm = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var read = new StreamReader(decryptStm))
                        {
                            textOriginal = read.ReadToEnd();
                        }
                    }
                }
            }
            return textOriginal;
        }

        static byte[] CryptWithSHA256(string Text)
        {
            byte[] encrypted;
            using (var algoSHA256= SHA256.Create())
            {
                encrypted = algoSHA256.ComputeHash(Encoding.UTF8.GetBytes(Text));
            }

            return encrypted;
        }
        
        static byte[] EncryptWithMD5(string Text)
        {
            byte[] encrypted, data;
            var pwd = "Mot_de_passe";
            data = Encoding.UTF8.GetBytes(Text);
            var md5 = new MD5CryptoServiceProvider();
            var triple = new TripleDESCryptoServiceProvider();
            triple.Key = md5.ComputeHash(Encoding.UTF8.GetBytes(pwd));
            triple.Mode = CipherMode.ECB;

            ICryptoTransform cryptoTransform = triple.CreateEncryptor();

            encrypted = cryptoTransform.TransformFinalBlock(data, 0, data.Length);

            return encrypted;

        }
        static string DecryptWithMD5(byte[] bytes)
        {
            var pwd = "Mot_de_passe";
            //byte[] data = bytes;
            string decrypted;
            var md5 = new MD5CryptoServiceProvider();
            var triple = new TripleDESCryptoServiceProvider();
            triple.Key = md5.ComputeHash(Encoding.UTF8.GetBytes(pwd));
            triple.Mode = CipherMode.ECB;

            ICryptoTransform crypto = triple.CreateDecryptor();

            decrypted = Encoding.UTF8.GetString(crypto.TransformFinalBlock(bytes, 0, bytes.Length));

            return decrypted;
        }
    }
}