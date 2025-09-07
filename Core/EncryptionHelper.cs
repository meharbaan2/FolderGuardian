using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace FolderGuardian.Core
{
    class EncryptionHelper
    {

        private static string keyFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FolderGuardian", "protected.key");

        // Save AES key+IV securely with DPAPI
        private static void SaveKey(byte[] key, byte[] iv)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(keyFilePath)!);


            byte[] combined = new byte[key.Length + iv.Length];
            Buffer.BlockCopy(key, 0, combined, 0, key.Length);
            Buffer.BlockCopy(iv, 0, combined, key.Length, iv.Length);

            byte[] protectedData = ProtectedData.Protect(combined, null, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(keyFilePath, protectedData);
        }

        // Load AES key+IV securely with DPAPI
        private static void LoadKey(out byte[] key, out byte[] iv)
        {
            if (!File.Exists(keyFilePath))
                throw new FileNotFoundException("No protected key found. You must encrypt at least once before decrypting.");

            byte[] protectedData = File.ReadAllBytes(keyFilePath);
            byte[] combined = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser);

            key = new byte[32];  // AES-256
            iv = new byte[16];   // AES block size = 128 bits

            Buffer.BlockCopy(combined, 0, key, 0, 32);
            Buffer.BlockCopy(combined, 32, iv, 0, 16);
        }

        // Encrypt a single file
        public static void EncryptFile(string inputFile)
        {
            byte[] key, iv;

            // Generate key if not already created
            if (!File.Exists(keyFilePath))
            {
                using (Aes aes = Aes.Create())
                {
                    key = aes.Key;
                    iv = aes.IV;
                    SaveKey(key, iv);
                }
            }
            else
            {
                LoadKey(out key, out iv);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (FileStream fsInput = new(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsEncrypted = new(inputFile + ".enc", FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }

            File.Delete(inputFile); // remove original
        }

        // Decrypt a single file
        public static void DecryptFile(string inputFile)
        {
            LoadKey(out byte[] key, out byte[] iv);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                string outputFile = inputFile.Replace(".enc", "");

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsDecrypted = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(fsDecrypted);
                }
            }

            File.Delete(inputFile); // remove encrypted
        }
    }
}
