using System.IO;

namespace FolderGuardian.Core
{
    class FolderEncryptor
    {
        public static void EncryptFolder(string folderPath)
        {
            foreach (string file in Directory.GetFiles(folderPath))
            {
                EncryptionHelper.EncryptFile(file);
                Console.WriteLine($"Encrypted: {file}");
            }
        }

        public static void DecryptFolder(string folderPath)
        {
            foreach (string file in Directory.GetFiles(folderPath, "*.enc"))
            {
                EncryptionHelper.DecryptFile(file);
                Console.WriteLine($"Decrypted: {file}");
            }
        }
    }
}
